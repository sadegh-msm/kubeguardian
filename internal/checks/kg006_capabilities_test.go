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

func TestCapabilitiesNotDropped(t *testing.T) {
	noCapabilities := secureContainer(testContainer)
	noCapabilities.SecurityContext.Capabilities = nil

	addsBack := secureContainer(testContainer)
	addsBack.SecurityContext.Capabilities = &corev1.Capabilities{
		Drop: []corev1.Capability{"ALL"},
		Add:  []corev1.Capability{"NET_BIND_SERVICE"},
	}

	dropsLowercase := secureContainer(testContainer)
	dropsLowercase.SecurityContext.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"all"}}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"drops all capabilities", podSpec(secureContainer(testContainer)), 0},
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
