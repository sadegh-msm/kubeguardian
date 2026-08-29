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
)

const (
	ConditionScanSucceeded = "ScanSucceeded"

	ReasonScanCompleted      = "ScanCompleted"
	ReasonScanFailed         = "ScanFailed"
	ReasonScannerUnavailable = "ScannerUnavailable"
)

// ReportStatus is the observed state shared by ManifestSecurityReport and
// ImageSecurityReport. Both kinds report the same shape; they differ only in
// which sources fill it in.
type ReportStatus struct {
	// +optional
	Summary SeveritySummary `json:"summary"`

	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// +optional
	LastScanTime metav1.Time `json:"lastScanTime,omitzero"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the report resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
