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

package controller

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const owningTeam = "payments"

func TestStripUnreadFieldsClearsWorkloadStatus(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "api",
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
			Annotations: map[string]string{
				corev1.LastAppliedConfigAnnotation: `{"a":"whole copy of the object"}`,
				"team":                             owningTeam,
			},
		},
		Spec:   appsv1.DeploymentSpec{Replicas: ptr(int32(3))},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 3, Replicas: 3},
	}

	if _, err := stripUnreadFields(deployment); err != nil {
		t.Fatalf("transform: %v", err)
	}

	if deployment.Status.ReadyReplicas != 0 {
		t.Error("status should be cleared: no check reads it")
	}
	if deployment.ManagedFields != nil {
		t.Error("managed fields should be cleared")
	}
	if _, found := deployment.Annotations[corev1.LastAppliedConfigAnnotation]; found {
		t.Error("last-applied-configuration should be dropped: it is a second copy of the object")
	}
	if deployment.Annotations["team"] != owningTeam {
		t.Error("other annotations must survive; a check could match on them")
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 3 {
		t.Error("spec must survive: it is what the checks read")
	}
}

func TestStripUnreadFieldsLeavesReportStatusAlone(t *testing.T) {
	// Scanner.updateStatus reads a report's status back through the cache inside
	// its conflict-retry loop, so a report must never be stripped.
	report := &securityv1alpha1.ManifestSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: "posture", Namespace: owningTeam},
		Status: securityv1alpha1.ReportStatus{
			Summary:  securityv1alpha1.SeveritySummary{High: 1, Total: 1},
			Findings: []securityv1alpha1.Finding{{ID: "KG-011"}},
		},
	}

	if _, err := stripUnreadFields(report); err != nil {
		t.Fatalf("transform: %v", err)
	}

	if len(report.Status.Findings) != 1 || report.Status.Summary.Total != 1 {
		t.Fatal("a report's status must survive the transform")
	}

	for object := range CacheOptions().ByObject {
		if _, isReport := object.(*securityv1alpha1.ManifestSecurityReport); isReport {
			t.Error("ManifestSecurityReport must not carry a stripping transform")
		}
		if _, isReport := object.(*securityv1alpha1.ImageSecurityReport); isReport {
			t.Error("ImageSecurityReport must not carry a stripping transform")
		}
	}
}

func ptr[T any](value T) *T {
	return &value
}
