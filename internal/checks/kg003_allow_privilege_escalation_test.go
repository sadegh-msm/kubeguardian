package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAllowPrivilegeEscalation(t *testing.T) {
	unset := secureContainer(testContainer)
	unset.SecurityContext.AllowPrivilegeEscalation = nil

	allowed := secureContainer(testContainer)
	allowed.SecurityContext.AllowPrivilegeEscalation = ptr(true)

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"escalation denied", podSpec(secureContainer(testContainer)), 0},
		{"field unset", podSpec(unset), 1},
		{"escalation allowed", podSpec(allowed), 1},
		{"no security context", podSpec(corev1.Container{Name: testContainer, Image: testImage}), 1},
	}

	check := newAllowPrivilegeEscalation()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
