/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestMutableImageTag(t *testing.T) {
	withImage := func(image string) corev1.PodSpec {
		container := secureContainer(testContainer)
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
