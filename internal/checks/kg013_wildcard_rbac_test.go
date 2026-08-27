package checks

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func role(name string, rules ...rbacv1.PolicyRule) rbacv1.Role {
	return rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Rules:      rules,
	}
}

func TestWildcardRBAC(t *testing.T) {
	scoped := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list"},
	}
	wildcardVerbs := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"*"},
	}
	fullWildcard := rbacv1.PolicyRule{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	}

	build := func(roles ...rbacv1.Role) *snapshot.Snapshot {
		snap := snapshotOf(podSpec(secureContainer(testContainer)))
		snap.Roles = roles
		return snap
	}

	cases := []struct {
		name string
		snap *snapshot.Snapshot
		want int
	}{
		{"no roles", build(), 0},
		{"scoped role", build(role("reader", scoped)), 0},
		{"wildcard verbs", build(role("admin", wildcardVerbs)), 1},
		{"wildcard everything", build(role("admin", fullWildcard)), 1},
		{"one finding per role", build(role("admin", wildcardVerbs, fullWildcard)), 1},
		{"two offending roles", build(role("a", wildcardVerbs), role("b", fullWildcard)), 2},
		{"scoped rule before wildcard", build(role("mixed", scoped, wildcardVerbs)), 1},
	}

	check := newWildcardRBAC()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(tc.snap); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
