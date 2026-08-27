package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPrivilegedContainer(t *testing.T) {
	privileged := secureContainer("api")
	privileged.SecurityContext.Privileged = ptr(true)

	initPrivileged := secureContainer("migrate")
	initPrivileged.SecurityContext.Privileged = ptr(true)

	noSecurityContext := corev1.Container{Name: "api", Image: "app:1.0"}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"compliant container", podSpec(secureContainer("api")), 0},
		{"privileged container", podSpec(privileged), 1},
		{"absent security context", podSpec(noSecurityContext), 0},
		{"privileged init container", corev1.PodSpec{
			InitContainers: []corev1.Container{initPrivileged},
			Containers:     []corev1.Container{secureContainer("api")},
		}, 1},
	}

	check := newPrivilegedContainer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check.Run(snapshotOf(tc.spec))
			if len(got) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(got), findingIDs(got), tc.want)
			}
			for _, finding := range got {
				if finding.Suggestion == "" || finding.Remediation == "" {
					t.Errorf("finding %s must carry a suggestion and remediation", finding.ID)
				}
			}
		})
	}
}
