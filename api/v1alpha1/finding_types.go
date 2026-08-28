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

// +kubebuilder:validation:Enum=Critical;High;Medium;Low
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
)

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
}

func (s Severity) Rank() int {
	if rank, ok := severityRank[s]; ok {
		return rank
	}
	return len(severityRank)
}

func (s Severity) AtLeast(min Severity) bool {
	return s.Rank() <= min.Rank()
}

func ParseSeverity(value string) (Severity, bool) {
	severity := Severity(value)
	_, ok := severityRank[severity]
	return severity, ok
}

// +kubebuilder:validation:Enum=PodSecurity;Network;RBAC;SupplyChain;Governance
type Category string

const (
	CategoryPodSecurity Category = "PodSecurity"
	CategoryNetwork     Category = "Network"
	CategoryRBAC        Category = "RBAC"
	CategorySupplyChain Category = "SupplyChain"
	CategoryGovernance  Category = "Governance"
)

type ResourceRef struct {
	// +required
	Kind string `json:"kind"`

	// +required
	Name string `json:"name"`

	// +optional
	Container string `json:"container,omitempty"`
}

func (r ResourceRef) String() string {
	out := r.Kind + "/" + r.Name
	if r.Container != "" {
		out += ":" + r.Container
	}
	return out
}

type Finding struct {
	// +required
	ID string `json:"id"`

	// +required
	Severity Severity `json:"severity"`

	// +required
	Category Category `json:"category"`

	// +required
	Resource ResourceRef `json:"resource"`

	// +required
	Message string `json:"message"`

	// +required
	Suggestion string `json:"suggestion"`

	// +optional
	Remediation string `json:"remediation,omitempty"`

	// +optional
	Reference string `json:"reference,omitempty"`

	// +required
	Source string `json:"source"`
}

type SeveritySummary struct {
	// +optional
	Critical int `json:"critical"`

	// +optional
	High int `json:"high"`

	// +optional
	Medium int `json:"medium"`

	// +optional
	Low int `json:"low"`

	// +optional
	Total int `json:"total"`
}
