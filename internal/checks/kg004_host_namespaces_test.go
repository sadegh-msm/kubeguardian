package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestHostNamespaces(t *testing.T) {
	base := podSpec(secureContainer("api"))

	hostNetwork := base
	hostNetwork.HostNetwork = true

	allShared := base
	allShared.HostNetwork = true
	allShared.HostPID = true
	allShared.HostIPC = true

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"isolated pod", base, 0},
		{"host network only", hostNetwork, 1},
		{"all host namespaces shared", allShared, 3},
	}

	check := newHostNamespaces()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(got), findingIDs(got), tc.want)
			}
		})
	}
}
