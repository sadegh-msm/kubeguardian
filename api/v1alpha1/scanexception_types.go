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

// WildcardCheck matches every check when listed in ScanExceptionSpec.Checks.
const WildcardCheck = "*"

// ResourceMatcher selects the resources an exception applies to. An empty field
// matches any value, so an empty matcher matches every resource in scope.
type ResourceMatcher struct {
	// +optional
	Kind string `json:"kind,omitempty"`

	// +optional
	Name string `json:"name,omitempty"`
}

// ScanExceptionSpec defines the desired state of ScanException
type ScanExceptionSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason"`

	// +required
	// +kubebuilder:validation:MinItems=1
	Checks []string `json:"checks"`

	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// +optional
	Resources []ResourceMatcher `json:"resources,omitempty"`

	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=scanexc
// +kubebuilder:printcolumn:name="Checks",type=string,JSONPath=`.spec.checks`
// +kubebuilder:printcolumn:name="Namespaces",type=string,JSONPath=`.spec.namespaces`
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.spec.expiresAt`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.spec.reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ScanException is the Schema for the scanexceptions API. It records an accepted
// risk so that matching findings stay visible in a report but stop counting
// against the namespace.
type ScanException struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ScanExceptionSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// ScanExceptionList contains a list of ScanException
type ScanExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ScanException `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ScanException{}, &ScanExceptionList{})
		return nil
	})
}
