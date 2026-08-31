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
	ConditionReady = "Ready"

	ReasonCompiled      = "Compiled"
	ReasonCompileFailed = "CompileFailed"
)

// Scope is the subject a check is evaluated against. It decides which variables
// the expressions can name and how many findings one check can produce.
// +kubebuilder:validation:Enum=Namespace;Workload;Container;Role;ServiceAccount
type Scope string

const (
	// ScopeNamespace evaluates once for the namespace itself.
	ScopeNamespace Scope = "Namespace"

	// ScopeWorkload evaluates once per Deployment, StatefulSet, DaemonSet and CronJob.
	ScopeWorkload Scope = "Workload"

	// ScopeContainer evaluates once per container, including init containers.
	ScopeContainer Scope = "Container"

	// ScopeRole evaluates once per Role in the namespace.
	ScopeRole Scope = "Role"

	// ScopeServiceAccount evaluates once per ServiceAccount in the namespace.
	ScopeServiceAccount Scope = "ServiceAccount"
)

// SecurityCheckSpec defines a check as expressions rather than as Go code.
//
// Every expression is CEL, the same language Kubernetes uses for
// ValidatingAdmissionPolicy and CRD validation rules. Which variables are in
// scope depends on spec.scope; see the README for the table.
type SecurityCheckSpec struct {
	// ID is the finding identifier this check produces, such as KG-007. A
	// ScanException matches on it, so changing it changes which exceptions apply.
	// +kubebuilder:validation:MinLength=1
	// +required
	ID string `json:"id"`

	// +required
	Severity Severity `json:"severity"`

	// +required
	Category Category `json:"category"`

	// Reference is a documentation URL recorded on every finding.
	// +optional
	Reference string `json:"reference,omitempty"`

	// +required
	Scope Scope `json:"scope"`

	// Bindings are named expressions evaluated before everything else and
	// visible to violation and to the three message fields. Use them when a
	// message has to name which of several conditions failed.
	// +optional
	Bindings map[string]string `json:"bindings,omitempty"`

	// Violation must evaluate to a boolean. True means the subject has the
	// problem this check describes.
	// +kubebuilder:validation:MinLength=1
	// +required
	Violation string `json:"violation"`

	// Message states what is wrong with this specific subject. Text inside
	// ${...} is CEL and everything else is literal, so a YAML block keeps its
	// formatting.
	// +kubebuilder:validation:MinLength=1
	// +required
	Message string `json:"message"`

	// Suggestion states what to do about it, in prose.
	// +kubebuilder:validation:MinLength=1
	// +required
	Suggestion string `json:"suggestion"`

	// Remediation is a command or manifest that applies the fix.
	// +kubebuilder:validation:MinLength=1
	// +required
	Remediation string `json:"remediation"`
}

// SecurityCheckStatus reports whether the expressions compile. A check that does
// not compile produces no findings, and this is where that is visible.
type SecurityCheckStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecurityCheck resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=seccheck
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.spec.id`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Scope",type=string,JSONPath=`.spec.scope`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// SecurityCheck is the Schema for the securitychecks API.
// It defines one manifest check as CEL expressions, so adding or changing a rule
// is a manifest rather than a code change.
type SecurityCheck struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec SecurityCheckSpec `json:"spec,omitzero"`

	// +optional
	Status SecurityCheckStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
// SecurityCheckList contains a list of SecurityCheck
type SecurityCheckList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityCheck `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecurityCheck{}, &SecurityCheckList{})
		return nil
	})
}
