package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type hostNamespaces struct{ meta }

func newHostNamespaces() hostNamespaces {
	return hostNamespaces{meta{
		id:        "KG-004",
		severity:  securityv1alpha1.SeverityCritical,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	}}
}

func (c hostNamespaces) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		spec := workload.Template.Spec
		shared := []struct {
			field   string
			enabled bool
			impact  string
		}{
			{"hostNetwork", spec.HostNetwork, "the pod shares the node network stack and can reach services bound to localhost on the node"},
			{"hostPID", spec.HostPID, "the pod can see and signal every process on the node"},
			{"hostIPC", spec.HostIPC, "the pod can read shared memory belonging to other processes on the node"},
		}

		for _, entry := range shared {
			if !entry.enabled {
				continue
			}
			findings = append(findings, c.finding(
				workloadRef(workload),
				fmt.Sprintf("%s is enabled, so %s", entry.field, entry.impact),
				fmt.Sprintf("Remove %s unless this is a node-level agent. Expose the workload through a Service instead of binding to the node namespace.", entry.field),
				podPatch(workload.Kind, workload.Name, snap.Name(), entry.field, "false"),
			))
		}
	}
	return findings
}
