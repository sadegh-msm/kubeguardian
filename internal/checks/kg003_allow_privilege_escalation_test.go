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

func TestAllowPrivilegeEscalation(t *testing.T) {
	unset := secureContainer(testContainer)
	unset.SecurityContext.AllowPrivilegeEscalation = nil

	allowed := secureContainer(testContainer)
	allowed.SecurityContext.AllowPrivilegeEscalation = ptr(true)

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"escalation denied", podSpec(secureContainer(testContainer)), 0},
		{"field unset", podSpec(unset), 1},
		{"escalation allowed", podSpec(allowed), 1},
		{"no security context", podSpec(corev1.Container{Name: testContainer, Image: testImage}), 1},
	}

	check := newAllowPrivilegeEscalation()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(snapshotOf(tc.spec)); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
