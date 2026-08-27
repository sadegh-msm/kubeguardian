package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestMutableImageTag(t *testing.T) {
	withImage := func(image string) corev1.PodSpec {
		container := secureContainer("api")
		container.Image = image
		return podSpec(container)
	}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"pinned release tag", withImage("registry.example.com/app:1.4.2"), 0},
		{"digest pinned", withImage("registry.example.com/app@sha256:abc123"), 0},
		{"latest tag", withImage("registry.example.com/app:latest"), 1},
		{"no tag", withImage("nginx"), 1},
		{"registry port is not a tag", withImage("registry.example.com:5000/app"), 1},
		{"registry port with tag", withImage("registry.example.com:5000/app:2.1.0"), 0},
	}

	check := newMutableImageTag()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
