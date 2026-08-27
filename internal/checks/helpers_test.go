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
