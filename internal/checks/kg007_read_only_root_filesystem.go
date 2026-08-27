package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type writableRootFilesystem struct{ meta }

func newWritableRootFilesystem() writableRootFilesystem {
	return writableRootFilesystem{meta{
		id:        "KG-007",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: referenceSecurityContext,
	}}
}

func (c writableRootFilesystem) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			sc := container.SecurityContext
			if sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
				continue
			}
			findings = append(findings, c.finding(
				containerRef(workload, container),
				fmt.Sprintf("container %q has a writable root filesystem, letting an attacker drop tooling or modify binaries inside the running container", container.Name),
				"Set securityContext.readOnlyRootFilesystem to true and mount an emptyDir over any directory the process must write to, such as /tmp.",
				containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/readOnlyRootFilesystem", "true"),
			))
		}
	}
	return findings
}
