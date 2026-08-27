package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSeccompProfile(t *testing.T) {
	runtimeDefault := secureContainer(testContainer)
	runtimeDefault.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeRuntimeDefault,
	}

	unconfined := secureContainer(testContainer)
	unconfined.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeUnconfined,
	}

	localhost := secureContainer(testContainer)
	profileName := "audit.json"
	localhost.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"runtime default", podSpec(runtimeDefault), 0},
		{"localhost profile", podSpec(localhost), 0},
		{"no profile", podSpec(secureContainer(testContainer)), 1},
		{"unconfined", podSpec(unconfined), 1},
		{"inherited from pod", corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{secureContainer(testContainer)},
		}, 0},
		{"container overrides compliant pod", corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{unconfined},
		}, 1},
	}

	check := newSeccompProfile()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
