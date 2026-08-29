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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	testNamespace     = "demo"
	testContainer     = "api"
	enforceRestricted = "restricted"
	testImage         = "app:1.0"
)

func ptr[T any](value T) *T {
	return &value
}

func namespace(labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, Labels: labels}}
}

func deployment(name string, spec corev1.PodSpec) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: spec},
		},
	}
}

func snapshotOf(spec corev1.PodSpec) *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Namespace:   namespace(map[string]string{podSecurityEnforceLabel: enforceRestricted}),
		Deployments: []appsv1.Deployment{deployment("api", spec)},
	}
}

func podSpec(containers ...corev1.Container) corev1.PodSpec {
	return corev1.PodSpec{Containers: containers}
}

func secureContainer() corev1.Container {
	return corev1.Container{
		Name:  testContainer,
		Image: "registry.example.com/app:1.4.2",
		SecurityContext: &corev1.SecurityContext{
			Privileged:               ptr(false),
			RunAsNonRoot:             ptr(true),
			RunAsUser:                ptr(int64(1000)),
			AllowPrivilegeEscalation: ptr(false),
			ReadOnlyRootFilesystem:   ptr(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
		},
	}
}

func containerNames(findings []securityv1alpha1.Finding) []string {
	names := make([]string, 0, len(findings))
	for _, finding := range findings {
		names = append(names, finding.Resource.Container)
	}
	return names
}
