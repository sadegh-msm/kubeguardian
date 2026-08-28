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

func workloadRef(w snapshot.Workload) securityv1alpha1.ResourceRef {
	return securityv1alpha1.ResourceRef{Kind: w.Kind, Name: w.Name}
}

func namespaceRef(snap *snapshot.Snapshot) securityv1alpha1.ResourceRef {
	return securityv1alpha1.ResourceRef{Kind: "Namespace", Name: snap.Name()}
}

func effectiveRunAsNonRoot(pod corev1.PodSpec, container corev1.Container) *bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
		return container.SecurityContext.RunAsNonRoot
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.RunAsNonRoot
	}
	return nil
}

func effectiveRunAsUser(pod corev1.PodSpec, container corev1.Container) *int64 {
	if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
		return container.SecurityContext.RunAsUser
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.RunAsUser
	}
	return nil
}

func dropsAllCapabilities(container corev1.Container) bool {
	if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
		return false
	}
	for _, dropped := range container.SecurityContext.Capabilities.Drop {
		if strings.EqualFold(string(dropped), "ALL") {
			return true
		}
	}
	return false
}

func addedCapabilities(container corev1.Container) []string {
	if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
		return nil
	}
	added := make([]string, 0, len(container.SecurityContext.Capabilities.Add))
	for _, capability := range container.SecurityContext.Capabilities.Add {
		added = append(added, string(capability))
	}
	return added
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

func podPatch(kind, name, namespace, path, value string) string {
	return fmt.Sprintf(
		"kubectl patch %s %s -n %s --type=json -p='[{\"op\":\"replace\",\"path\":\"/spec/template/spec/%s\",\"value\":%s}]'",
		strings.ToLower(kind), name, namespace, path, value,
	)
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

func effectiveSeccompProfile(pod corev1.PodSpec, container corev1.Container) *corev1.SeccompProfile {
	if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
		return container.SecurityContext.SeccompProfile
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.SeccompProfile
	}
	return nil
}
