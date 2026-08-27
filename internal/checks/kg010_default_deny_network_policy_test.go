package checks

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func policy(name string, selector metav1.LabelSelector, types []networkingv1.PolicyType, rules []networkingv1.NetworkPolicyIngressRule) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selector,
			PolicyTypes: types,
			Ingress:     rules,
		},
	}
}

func TestDefaultDenyNetworkPolicy(t *testing.T) {
	ingress := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}

	withWorkload := func(policies ...networkingv1.NetworkPolicy) *snapshot.Snapshot {
		snap := snapshotOf(podSpec(secureContainer(testContainer)))
		snap.NetworkPolicies = policies
		return snap
	}

	cases := []struct {
		name string
		snap *snapshot.Snapshot
		want int
	}{
		{"no policies at all", withWorkload(), 1},
		{"default deny present", withWorkload(policy("deny", metav1.LabelSelector{}, ingress, nil)), 0},
		{"targeted policy only", withWorkload(policy("api", metav1.LabelSelector{
			MatchLabels: map[string]string{"app": testContainer},
		}, ingress, nil)), 1},
		{"empty selector but allows traffic", withWorkload(policy("allow", metav1.LabelSelector{}, ingress,
			[]networkingv1.NetworkPolicyIngressRule{{}})), 1},
		{"egress only policy", withWorkload(policy("egress", metav1.LabelSelector{},
			[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil)), 1},
		{"empty namespace is not flagged", &snapshot.Snapshot{Namespace: namespace(nil)}, 0},
	}

	check := newDefaultDenyNetworkPolicy()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(tc.snap); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
