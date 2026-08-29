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
	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	referenceSecurityContext = "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
)

type Check interface {
	ID() string
	Severity() securityv1alpha1.Severity
	Category() securityv1alpha1.Category
	Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding
}

type meta struct {
	id        string
	severity  securityv1alpha1.Severity
	category  securityv1alpha1.Category
	reference string
}

func (m meta) ID() string {
	return m.id
}

func (m meta) Severity() securityv1alpha1.Severity {
	return m.severity
}

func (m meta) Category() securityv1alpha1.Category {
	return m.category
}

func (m meta) finding(ref securityv1alpha1.ResourceRef, message, suggestion, remediation string) securityv1alpha1.Finding {
	return securityv1alpha1.Finding{
		ID:          m.id,
		Severity:    m.severity,
		Category:    m.category,
		Resource:    ref,
		Message:     message,
		Suggestion:  suggestion,
		Remediation: remediation,
		Reference:   m.reference,
	}
}

func All() []Check {
	return []Check{
		newWritableRootFilesystem(),
		newDefaultDenyNetworkPolicy(),
		newPodSecurityAdmissionLabels(),
		newDefaultServiceAccountToken(),
		newWildcardRBAC(),
		newMutableImageTag(),
		newMissingResourceLimits(),
	}
}
