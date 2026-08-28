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

type mutableImageTag struct{ meta }

func newMutableImageTag() mutableImageTag {
	return mutableImageTag{meta{
		id:        "KG-020",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategorySupplyChain,
		reference: "https://kubernetes.io/docs/concepts/containers/images/#image-names",
	}}
}

func (c mutableImageTag) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, workload := range snap.Workloads() {
		for _, container := range workload.Containers() {
			tag, tagged := imageTag(container.Image)
			switch {
			case !tagged:
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q uses image %q with no tag, which resolves to latest and can change between restarts", container.Name, container.Image),
					"Pin the image to an immutable tag, or better a digest, so every replica runs the artifact you tested.",
					fmt.Sprintf("kubectl set image %s/%s %s=%s@sha256:<digest> -n %s", workload.Kind, workload.Name, container.Name, container.Image, snap.Name()),
				))
			case tag == "latest":
				findings = append(findings, c.finding(
					containerRef(workload, container),
					fmt.Sprintf("container %q uses the mutable tag latest, so the running image can drift from the reviewed one without any manifest change", container.Name),
					"Pin the image to a release tag or a digest, so rollouts are reproducible and auditable.",
					fmt.Sprintf("kubectl set image %s/%s %s=%s@sha256:<digest> -n %s", workload.Kind, workload.Name, container.Name, container.Image, snap.Name()),
				))
			}
		}
	}
	return findings
}
