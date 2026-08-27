package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestRunAsNonRoot(t *testing.T) {
	unset := secureContainer("api")
	unset.SecurityContext.RunAsNonRoot = nil
	unset.SecurityContext.RunAsUser = nil

	explicitFalse := secureContainer("api")
	explicitFalse.SecurityContext.RunAsNonRoot = ptr(false)

	rootUser := secureContainer("api")
	rootUser.SecurityContext.RunAsUser = ptr(int64(0))

	inheritsPod := corev1.Container{Name: "api", Image: "app:1.0"}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"compliant container", podSpec(secureContainer("api")), 0},
		{"unset run as non root", podSpec(unset), 1},
		{"explicitly allows root", podSpec(explicitFalse), 1},
		{"pinned to uid zero", podSpec(rootUser), 1},
		{"inherits compliant pod security context", corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
			Containers:      []corev1.Container{inheritsPod},
		}, 0},
	}

	check := newRunAsNonRoot()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check.Run(snapshotOf(tc.spec))
			if len(got) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(got), findingIDs(got), tc.want)
			}
		})
	}
}
