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

type NamespaceSecurityReportSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	NamespaceRef string `json:"namespaceRef"`
}

type NamespaceSecurityReportStatus struct {
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Score int `json:"score"`

	// +optional
	Summary SeveritySummary `json:"summary,omitzero"`

	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// +optional
	LastScanTime metav1.Time `json:"lastScanTime,omitzero"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=nsr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Score",type=integer,JSONPath=`.status.score`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.high`
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.status.summary.medium`
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.status.summary.low`
// +kubebuilder:printcolumn:name="Last-Scan",type=date,JSONPath=`.status.lastScanTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type NamespaceSecurityReport struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec NamespaceSecurityReportSpec `json:"spec"`

	// +optional
	Status NamespaceSecurityReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
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
