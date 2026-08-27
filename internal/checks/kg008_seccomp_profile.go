package checks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type seccompProfile struct{ meta }

func newSeccompProfile() seccompProfile {
	return seccompProfile{meta{
		id:        "KG-008",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: referencePodSecurityStandards,
	}}
}

func (c seccompProfile) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			profile := effectiveSeccompProfile(workload.Template.Spec, container)

			switch {
			case profile == nil:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q sets no seccompProfile, so it runs without a syscall filter and cannot be admitted under the restricted Pod Security Standard", container.Name),
					"Set seccompProfile.type to RuntimeDefault on the pod so every container inherits the runtime syscall filter.",
					podPatch(workload.Kind, workload.Name, snap.Name(), "securityContext/seccompProfile", `{"type":"RuntimeDefault"}`),
				))
			case profile.Type == corev1.SeccompProfileTypeUnconfined:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q sets seccompProfile to Unconfined, which disables syscall filtering entirely", container.Name),
					"Change seccompProfile.type to RuntimeDefault unless the workload has a documented syscall it cannot make under the default filter.",
					podPatch(workload.Kind, workload.Name, snap.Name(), "securityContext/seccompProfile", `{"type":"RuntimeDefault"}`),
				))
			}
		}
	}
	return findings
}
