package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestHostPathVolume(t *testing.T) {
	base := podSpec(secureContainer("api"))

	withHostPath := base
	withHostPath.Volumes = []corev1.Volume{{
		Name:         "docker-socket",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
	}}

	withEmptyDir := base
	withEmptyDir.Volumes = []corev1.Volume{{
		Name:         "cache",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"no volumes", base, 0},
		{"host path mounted", withHostPath, 1},
		{"ephemeral volume", withEmptyDir, 0},
	}

	check := newHostPathVolume()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
