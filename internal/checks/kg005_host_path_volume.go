package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type hostPathVolume struct{ meta }

func newHostPathVolume() hostPathVolume {
	return hostPathVolume{meta{
		id:        "KG-005",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
	}}
}

func (c hostPathVolume) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, volume := range workload.Template.Spec.Volumes {
			if volume.HostPath == nil {
				continue
			}
			findings = append(findings, c.finding(
				workloadRef(workload),
				fmt.Sprintf("volume %q mounts host path %s, which exposes the node filesystem to the pod", volume.Name, volume.HostPath.Path),
				"Replace the hostPath volume with an emptyDir for scratch space or a PersistentVolumeClaim for durable data. If node access is genuinely required, mount it read-only and restrict the path.",
				fmt.Sprintf("volumes:\n  - name: %s\n    emptyDir: {}", volume.Name),
			))
		}
	}
	return findings
}
