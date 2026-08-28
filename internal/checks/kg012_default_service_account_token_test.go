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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func defaultServiceAccount(automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: defaultServiceAccountName, Namespace: testNamespace},
		AutomountServiceAccountToken: automount,
	}
}

func TestDefaultServiceAccountToken(t *testing.T) {
	build := func(spec corev1.PodSpec, accounts ...corev1.ServiceAccount) *snapshot.Snapshot {
		snap := snapshotOf(spec)
		snap.ServiceAccounts = accounts
		return snap
	}

	base := podSpec(secureContainer(testContainer))

	dedicated := base
	dedicated.ServiceAccountName = testContainer

	optedOut := base
	optedOut.AutomountServiceAccountToken = ptr(false)

	cases := []struct {
		name string
		snap *snapshot.Snapshot
		want int
	}{
		{"default account automounts", build(base, defaultServiceAccount(nil)), 1},
		{"default account opts out", build(base, defaultServiceAccount(ptr(false))), 0},
		{"workload opts out", build(optedOut, defaultServiceAccount(nil)), 0},
		{"workload uses dedicated account", build(dedicated, defaultServiceAccount(nil)), 0},
		{"account object not collected", build(base), 1},
	}

	check := newDefaultServiceAccountToken()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(tc.snap); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
