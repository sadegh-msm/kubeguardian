package checks

import (
	"fmt"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const podSecurityEnforceLabel = "pod-security.kubernetes.io/enforce"

type podSecurityAdmissionLabels struct{ meta }

func newPodSecurityAdmissionLabels() podSecurityAdmissionLabels {
	return podSecurityAdmissionLabels{meta{
		id:        "KG-011",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryGovernance,
		reference: "https://kubernetes.io/docs/concepts/security/pod-security-admission/",
	}}
}

func (c podSecurityAdmissionLabels) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	level, labelled := snap.Namespace.Labels[podSecurityEnforceLabel]

	switch {
	case !labelled:
		return []securityv1alpha1.Finding{c.finding(
			namespaceRef(snap),
			fmt.Sprintf("namespace %q does not set %s, so Pod Security Admission enforces nothing and any pod spec is accepted", snap.Name(), podSecurityEnforceLabel),
			"Label the namespace with a Pod Security Standard. Start at baseline to catch the worst cases, then move to restricted once workloads comply.",
			fmt.Sprintf("kubectl label namespace %s %s=baseline", snap.Name(), podSecurityEnforceLabel),
		)}
	case level == "privileged":
		return []securityv1alpha1.Finding{c.finding(
			namespaceRef(snap),
			fmt.Sprintf("namespace %q enforces the privileged Pod Security Standard, which applies no restrictions at all", snap.Name()),
			"Raise enforcement to baseline or restricted. privileged is only appropriate for namespaces running node-level infrastructure.",
			fmt.Sprintf("kubectl label --overwrite namespace %s %s=baseline", snap.Name(), podSecurityEnforceLabel),
		)}
	}
	return nil
}
