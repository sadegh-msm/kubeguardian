package checks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type defaultServiceAccountToken struct{ meta }

func newDefaultServiceAccountToken() defaultServiceAccountToken {
	return defaultServiceAccountToken{meta{
		id:        "KG-012",
		severity:  securityv1alpha1.SeverityMedium,
		category:  securityv1alpha1.CategoryRBAC,
		reference: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
	}}
}

func (c defaultServiceAccountToken) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var users []string
	for _, workload := range snap.Workloads() {
		name := workload.Template.Spec.ServiceAccountName
		if name != "" && name != "default" {
			continue
		}
		if automount := workload.Template.Spec.AutomountServiceAccountToken; automount != nil && !*automount {
			continue
		}
		users = append(users, workload.Kind+"/"+workload.Name)
	}
	if len(users) == 0 {
		return nil
	}

	if account, found := findServiceAccount(snap, "default"); found {
		if automount := account.AutomountServiceAccountToken; automount != nil && !*automount {
			return nil
		}
	}

	return []securityv1alpha1.Finding{c.finding(
		securityv1alpha1.ResourceRef{Kind: "ServiceAccount", Name: "default"},
		fmt.Sprintf("the default ServiceAccount automounts an API token into %d workload(s) (%s) that do not appear to need API access", len(users), users[0]),
		"Disable automounting on the default ServiceAccount, and give workloads that do call the API their own ServiceAccount with a scoped Role.",
		fmt.Sprintf("kubectl patch serviceaccount default -n %s -p '{\"automountServiceAccountToken\":false}'", snap.Name()),
	)}
}

func findServiceAccount(snap *snapshot.Snapshot, name string) (corev1.ServiceAccount, bool) {
	for _, account := range snap.ServiceAccounts {
		if account.Name == name {
			return account, true
		}
	}
	return corev1.ServiceAccount{}, false
}
