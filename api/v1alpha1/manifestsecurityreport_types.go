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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ManifestSecurityReportSpec defines the desired state of ManifestSecurityReport.
// The report audits the namespace it lives in, so there is nothing to configure;
// creating the object is the request.
type ManifestSecurityReportSpec struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=msr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.high`
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.status.summary.medium`
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.status.summary.low`
// +kubebuilder:printcolumn:name="Suppressed",type=integer,JSONPath=`.status.summary.suppressed`
// +kubebuilder:printcolumn:name="Last-Scan",type=date,JSONPath=`.status.lastScanTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// ManifestSecurityReport is the Schema for the manifestsecurityreports API.
// Create one in a namespace to have that namespace's manifests audited: pod
// templates, NetworkPolicies, Pod Security Admission labels, RBAC and
// ServiceAccounts. Image contents are covered by ImageSecurityReport instead.
type ManifestSecurityReport struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec ManifestSecurityReportSpec `json:"spec,omitzero"`

	// +optional
	Status ReportStatus `json:"status,omitzero"`
}

func (r *ManifestSecurityReport) ReportStatus() *ReportStatus {
	return &r.Status
}

// +kubebuilder:object:root=true
// ManifestSecurityReportList contains a list of ManifestSecurityReport
type ManifestSecurityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ManifestSecurityReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ManifestSecurityReport{}, &ManifestSecurityReportList{})
		return nil
	})
}
