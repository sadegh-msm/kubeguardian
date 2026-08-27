package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type allowPrivilegeEscalation struct{ meta }

func newAllowPrivilegeEscalation() allowPrivilegeEscalation {
	return allowPrivilegeEscalation{meta{
		id:        "KG-003",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	}}
}

func (c allowPrivilegeEscalation) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			sc := container.SecurityContext
			if sc != nil && sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation {
				continue
			}
			findings = append(findings, c.finding(
				containerRef(workload, container),
				fmt.Sprintf("container %q does not set allowPrivilegeEscalation to false, so a setuid binary can gain more privileges than its parent process", container.Name),
				"Set securityContext.allowPrivilegeEscalation to false. This is required by the restricted Pod Security Standard and safe for almost every application container.",
				containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/allowPrivilegeEscalation", "false"),
			))
		}
	}
	return findings
}
