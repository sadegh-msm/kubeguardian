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
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestMissingResourceLimits(t *testing.T) {
	none := secureContainer(testContainer)
	none.Resources = corev1.ResourceRequirements{}

	requestsOnly := secureContainer(testContainer)
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
		{"requests and limits set", podSpec(secureContainer(testContainer)), 0},
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
