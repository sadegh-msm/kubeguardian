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

func TestHostNamespaces(t *testing.T) {
	base := podSpec(secureContainer(testContainer))

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
