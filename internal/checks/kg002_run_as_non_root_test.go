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

func TestRunAsNonRoot(t *testing.T) {
	unset := secureContainer(testContainer)
	unset.SecurityContext.RunAsNonRoot = nil
	unset.SecurityContext.RunAsUser = nil

	explicitFalse := secureContainer(testContainer)
	explicitFalse.SecurityContext.RunAsNonRoot = ptr(false)

	rootUser := secureContainer(testContainer)
	rootUser.SecurityContext.RunAsUser = ptr(int64(0))

	inheritsPod := corev1.Container{Name: testContainer, Image: testImage}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want int
	}{
		{"compliant container", podSpec(secureContainer(testContainer)), 0},
		{"unset run as non root", podSpec(unset), 1},
		{"explicitly allows root", podSpec(explicitFalse), 1},
		{"pinned to uid zero", podSpec(rootUser), 1},
		{"inherits compliant pod security context", corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
			Containers:      []corev1.Container{inheritsPod},
		}, 0},
	}

	check := newRunAsNonRoot()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check.Run(snapshotOf(tc.spec))
			if len(got) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(got), findingIDs(got), tc.want)
			}
		})
	}
}
