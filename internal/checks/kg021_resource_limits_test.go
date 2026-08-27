package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestMissingResourceLimits(t *testing.T) {
	none := secureContainer("api")
	none.Resources = corev1.ResourceRequirements{}

	requestsOnly := secureContainer("api")
	requestsOnly.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"requests and limits set", podSpec(secureContainer("api")), 0},
		{"nothing set", podSpec(none), 1},
		{"requests without memory limit", podSpec(requestsOnly), 1},
		{"two offending containers", podSpec(none, requestsOnly), 2},
	}

	check := newMissingResourceLimits()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check.Run(snapshotOf(tc.spec))
			if len(got) != tc.want {
				t.Fatalf("got %d findings for %v, want %d", len(got), containerNames(got), tc.want)
			}
		})
	}
}
