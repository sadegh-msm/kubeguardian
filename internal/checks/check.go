package checks

import (
	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	referencePodSecurityStandards = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
	referenceSecurityContext      = "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
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
		newPrivilegedContainer(),
		newRunAsNonRoot(),
		newAllowPrivilegeEscalation(),
		newHostNamespaces(),
		newHostPathVolume(),
		newCapabilitiesNotDropped(),
		newWritableRootFilesystem(),
		newDefaultDenyNetworkPolicy(),
		newPodSecurityAdmissionLabels(),
		newDefaultServiceAccountToken(),
		newWildcardRBAC(),
		newMutableImageTag(),
		newMissingResourceLimits(),
	}
}
