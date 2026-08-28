/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package checks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type missingResourceLimits struct{ meta }

func newMissingResourceLimits() missingResourceLimits {
	return missingResourceLimits{meta{
		id:        "KG-021",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategoryGovernance,
		reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
	}}
}

func (c missingResourceLimits) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			var missing []string
			if container.Resources.Limits.Name(corev1.ResourceMemory, "") == nil || container.Resources.Limits.Memory().IsZero() {
				missing = append(missing, "memory limit")
			}
			if container.Resources.Requests.Cpu().IsZero() {
				missing = append(missing, "cpu request")
			}
			if container.Resources.Requests.Memory().IsZero() {
				missing = append(missing, "memory request")
			}
			if len(missing) == 0 {
				continue
			}
			findings = append(findings, c.finding(
				containerRef(workload, container),
				fmt.Sprintf("container %q is missing %s, so it can starve neighbours on the node and makes the namespace a denial-of-service vector", container.Name, joinFields(missing)),
				"Set both requests and limits. Requests drive scheduling and limits cap the blast radius of a runaway process.",
				containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "resources",
					`{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"memory":"512Mi"}}`),
			))
		}
	}
	return findings
}
