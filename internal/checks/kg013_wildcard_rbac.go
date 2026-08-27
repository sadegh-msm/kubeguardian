package checks

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type wildcardRBAC struct{ meta }

func newWildcardRBAC() wildcardRBAC {
	return wildcardRBAC{meta{
		id:        "KG-013",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryRBAC,
		reference: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	}}
}

func (c wildcardRBAC) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding
	for _, role := range snap.Roles {
		for _, rule := range role.Rules {
			wildcards := wildcardFields(rule)
			if len(wildcards) == 0 {
				continue
			}
			findings = append(findings, c.finding(
				securityv1alpha1.ResourceRef{Kind: "Role", Name: role.Name},
				fmt.Sprintf("Role %q grants a wildcard on %s, which silently expands as new resources and verbs are added to the cluster", role.Name, strings.Join(wildcards, " and ")),
				"Replace each wildcard with the explicit apiGroups, resources and verbs the subject needs. Use kubectl auth can-i --list to confirm nothing breaks.",
				fmt.Sprintf("kubectl get role %s -n %s -o yaml", role.Name, snap.Name()),
			))
			break
		}
	}
	return findings
}

func wildcardFields(rule rbacv1.PolicyRule) []string {
	var fields []string
	if containsWildcard(rule.APIGroups) {
		fields = append(fields, "apiGroups")
	}
	if containsWildcard(rule.Resources) {
		fields = append(fields, "resources")
	}
	if containsWildcard(rule.Verbs) {
		fields = append(fields, "verbs")
	}
	return fields
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}
