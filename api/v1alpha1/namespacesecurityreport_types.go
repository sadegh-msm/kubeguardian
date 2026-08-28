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

const (
	ConditionScanSucceeded = "ScanSucceeded"

	ReasonScanCompleted = "ScanCompleted"
	ReasonScanFailed    = "ScanFailed"
)

// NamespaceSecurityReportSpec defines the desired state of NamespaceSecurityReport.
// The report audits the namespace it lives in, so there is nothing to configure;
// creating the object is the request.
type NamespaceSecurityReportSpec struct {
}

// NamespaceSecurityReportStatus defines the observed state of NamespaceSecurityReport.
type NamespaceSecurityReportStatus struct {
	// +optional
	Summary SeveritySummary `json:"summary"`

	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// +optional
	LastScanTime metav1.Time `json:"lastScanTime,omitzero"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the NamespaceSecurityReport resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=nsr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.high`
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.status.summary.medium`
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.status.summary.low`
// +kubebuilder:printcolumn:name="Suppressed",type=integer,JSONPath=`.status.summary.suppressed`
// +kubebuilder:printcolumn:name="Last-Scan",type=date,JSONPath=`.status.lastScanTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// NamespaceSecurityReport is the Schema for the namespacesecurityreports API.
// Create one in a namespace to have that namespace audited.
type NamespaceSecurityReport struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec NamespaceSecurityReportSpec `json:"spec,omitzero"`

	// +optional
	Status NamespaceSecurityReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
// NamespaceSecurityReportList contains a list of NamespaceSecurityReport
type NamespaceSecurityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NamespaceSecurityReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &NamespaceSecurityReport{}, &NamespaceSecurityReportList{})
		return nil
	})
}
