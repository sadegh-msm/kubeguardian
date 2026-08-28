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

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func TestPodSecurityAdmissionLabels(t *testing.T) {
	withLabels := func(labels map[string]string) *snapshot.Snapshot {
		return &snapshot.Snapshot{Namespace: namespace(labels)}
	}

	cases := []struct {
		name string
		snap *snapshot.Snapshot
		want int
	}{
		{"restricted enforced", withLabels(map[string]string{podSecurityEnforceLabel: enforceRestricted}), 0},
		{"baseline enforced", withLabels(map[string]string{podSecurityEnforceLabel: "baseline"}), 0},
		{"label absent", withLabels(nil), 1},
		{"privileged enforced", withLabels(map[string]string{podSecurityEnforceLabel: "privileged"}), 1},
		{"only audit configured", withLabels(map[string]string{"pod-security.kubernetes.io/audit": "restricted"}), 1},
	}

	check := newPodSecurityAdmissionLabels()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(tc.snap); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
