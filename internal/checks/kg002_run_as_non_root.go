package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type runAsNonRoot struct{ meta }

func newRunAsNonRoot() runAsNonRoot {
	return runAsNonRoot{meta{
		id:        "KG-002",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: referencePodSecurityStandards,
	}}
}

func (c runAsNonRoot) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			nonRoot := effectiveRunAsNonRoot(workload.Template.Spec, container)
			user := effectiveRunAsUser(workload.Template.Spec, container)

			switch {
			case user != nil && *user == 0:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q is pinned to runAsUser 0, so its process runs as root inside the container", container.Name),
					"Set runAsUser to a non-zero UID and rebuild the image so its files are owned by that user.",
					containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/runAsUser", "1000"),
				))
			case nonRoot == nil:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q does not set runAsNonRoot, so it inherits the image default and may run as root", container.Name),
					"Set securityContext.runAsNonRoot to true so the kubelet refuses to start the container if the image resolves to UID 0.",
					containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/runAsNonRoot", "true"),
				))
			case !*nonRoot:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q sets runAsNonRoot to false, explicitly permitting the process to run as root", container.Name),
					"Set securityContext.runAsNonRoot to true unless the workload has a documented need for UID 0.",
					containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/runAsNonRoot", "true"),
				))
			}
		}
	}
	return findings
}
