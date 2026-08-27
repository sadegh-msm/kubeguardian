package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCapabilitiesNotDropped(t *testing.T) {
	noCapabilities := secureContainer("api")
	noCapabilities.SecurityContext.Capabilities = nil

	addsBack := secureContainer("api")
	addsBack.SecurityContext.Capabilities = &corev1.Capabilities{
		Drop: []corev1.Capability{"ALL"},
		Add:  []corev1.Capability{"NET_BIND_SERVICE"},
	}

	dropsLowercase := secureContainer("api")
	dropsLowercase.SecurityContext.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"all"}}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"drops all capabilities", podSpec(secureContainer("api")), 0},
		{"keeps default capability set", podSpec(noCapabilities), 1},
		{"drops all then adds back", podSpec(addsBack), 1},
		{"lowercase all is honoured", podSpec(dropsLowercase), 0},
	}

	check := newCapabilitiesNotDropped()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
