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

import "testing"

func TestImageTag(t *testing.T) {
	cases := []struct {
		image  string
		tag    string
		tagged bool
	}{
		{"nginx", "", false},
		{"nginx:1.25", "1.25", true},
		{"registry.example.com/team/app:2.0", "2.0", true},
		{"registry.example.com:5000/app", "", false},
		{"registry.example.com:5000/app:2.0", "2.0", true},
		{"app@sha256:deadbeef", "", true},
		{"registry.example.com/app@sha256:deadbeef", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			tag, tagged := imageTag(tc.image)
			if tag != tc.tag || tagged != tc.tagged {
				t.Fatalf("got (%q, %v), want (%q, %v)", tag, tagged, tc.tag, tc.tagged)
			}
		})
	}
}

func TestRegistryIsUnique(t *testing.T) {
	seen := make(map[string]string)
	for _, check := range All() {
		if previous, duplicate := seen[check.ID()]; duplicate {
			t.Fatalf("check id %s used by both %s and %T", check.ID(), previous, check)
		}
		seen[check.ID()] = check.ID()

		if check.Severity() == "" || check.Category() == "" {
			t.Errorf("check %s must declare a severity and a category", check.ID())
		}
	}

	if len(seen) != len(All()) {
		t.Fatalf("registry has %d checks but %d unique ids", len(All()), len(seen))
	}
}
