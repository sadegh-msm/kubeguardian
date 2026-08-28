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

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type privilegedContainer struct{ meta }

func newPrivilegedContainer() privilegedContainer {
	return privilegedContainer{meta{
		id:        "KG-001",
		severity:  securityv1alpha1.SeverityCritical,
		category:  securityv1alpha1.CategoryPodSecurity,
		reference: referencePodSecurityStandards,
	}}
}

func (c privilegedContainer) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			sc := container.SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				continue
			}
			findings = append(findings, c.finding(
				containerRef(workload, container),
				fmt.Sprintf("container %q runs privileged, which grants full access to host devices and bypasses every kernel capability restriction", container.Name),
				"Set securityContext.privileged to false and add back only the individual capabilities the container genuinely needs.",
				containerPatch(workload.Kind, workload.Name, snap.Name(), containerIndex(workload, container), "securityContext/privileged", "false"),
			))
		}
	}
	return findings
}
