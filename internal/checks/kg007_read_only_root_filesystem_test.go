package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestWritableRootFilesystem(t *testing.T) {
	unset := secureContainer(testContainer)
	unset.SecurityContext.ReadOnlyRootFilesystem = nil

	writable := secureContainer(testContainer)
	writable.SecurityContext.ReadOnlyRootFilesystem = ptr(false)

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"read only root", podSpec(secureContainer(testContainer)), 0},
		{"field unset", podSpec(unset), 1},
		{"writable root", podSpec(writable), 1},
	}

	check := newWritableRootFilesystem()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
