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
	"strings"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func containerRef(w snapshot.Workload, container corev1.Container) securityv1alpha1.ResourceRef {
	return securityv1alpha1.ResourceRef{Kind: w.Kind, Name: w.Name, Container: container.Name}
}

func namespaceRef(snap *snapshot.Snapshot) securityv1alpha1.ResourceRef {
	return securityv1alpha1.ResourceRef{Kind: "Namespace", Name: snap.Name()}
}

func imageTag(image string) (string, bool) {
	ref := image
	if slash := strings.LastIndex(ref, "/"); slash != -1 {
		ref = ref[slash+1:]
	}
	if strings.Contains(ref, "@") {
		return "", true
	}
	colon := strings.LastIndex(ref, ":")
	if colon == -1 {
		return "", false
	}
	return ref[colon+1:], true
}

func containerPatch(kind, name, namespace string, index int, path, value string) string {
	return fmt.Sprintf(
		"kubectl patch %s %s -n %s --type=json -p='[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/%d/%s\",\"value\":%s}]'",
		strings.ToLower(kind), name, namespace, index, path, value,
	)
}

func containerIndex(w snapshot.Workload, target corev1.Container) int {
	for i, container := range w.Template.Spec.Containers {
		if container.Name == target.Name {
			return i
		}
	}
	return 0
}

func joinFields(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
