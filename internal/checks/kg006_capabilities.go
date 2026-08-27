package checks

import (
	"fmt"
	"strings"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type capabilitiesNotDropped struct{ meta }

func newCapabilitiesNotDropped() capabilitiesNotDropped {
	return capabilitiesNotDropped{meta{
		id:        "KG-006",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: referencePodSecurityStandards,
	}}
}

func (c capabilitiesNotDropped) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			if dropsAllCapabilities(container) {
				if added := addedCapabilities(container); len(added) > 0 {
					findings = append(findings, c.finding(
						containerRef(workload, container),
						fmt.Sprintf("container %q drops ALL capabilities but adds back %s", container.Name, strings.Join(added, ", ")),
						"Confirm each added capability is required. NET_RAW and SYS_ADMIN in particular widen the blast radius of a container escape.",
						containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/capabilities/add", "[]"),
					))
				}
				continue
			}
			findings = append(findings, c.finding(
				containerRef(workload, container),
				fmt.Sprintf("container %q keeps the default Linux capability set instead of dropping ALL", container.Name),
				"Drop every capability and add back only what the process needs. Most application containers need none.",
				containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/capabilities", `{"drop":["ALL"]}`),
			))
		}
	}
	return findings
}
