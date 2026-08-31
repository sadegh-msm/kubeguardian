package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func loadPolicies(t *testing.T) []securityv1alpha1.SecurityCheck {
	t.Helper()
	return loadPoliciesB(t)
}

func loadPoliciesB(t testing.TB) []securityv1alpha1.SecurityCheck {
	t.Helper()
	dir := filepath.Join("..", "..", "config", "policies")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading policies: %v", err)
	}
	var out []securityv1alpha1.SecurityCheck
	for _, e := range entries {
		if e.Name() == "kustomization.yaml" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		var check securityv1alpha1.SecurityCheck
		if err := yaml.Unmarshal(raw, &check); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out = append(out, check)
	}
	return out
}

func key(f securityv1alpha1.Finding) string {
	return strings.Join([]string{f.ID, string(f.Severity), string(f.Category), f.Resource.String(), f.Message, f.Suggestion, f.Remediation, f.Reference}, "\n  ")
}

func render(findings []securityv1alpha1.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, key(f))
	}
	slices.Sort(out)
	return out
}

// TestShippedPoliciesProduceTheExpectedFindings pins the shipped policies against
// output captured from the Go checks they replaced, before those were deleted.
// It is the evidence that moving the rules into configuration changed no finding,
// and it keeps the shipped manifests honest as they are edited.
func TestShippedPoliciesProduceTheExpectedFindings(t *testing.T) {
	policies := loadPolicies(t)
	if len(policies) != 9 {
		t.Fatalf("loaded %d policies, want the 9 shipped under config/policies", len(policies))
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "expected_findings.txt"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}

	var out strings.Builder
	for i, snap := range equivalenceFixtures() {
		fmt.Fprintf(&out, "### fixture %d\n", i)

		var findings []securityv1alpha1.Finding
		for j := range policies {
			compiled, err := Compile(policies[j].Spec)
			if err != nil {
				t.Fatalf("%s: compile: %v", policies[j].Name, err)
			}
			got, err := Evaluate(compiled, snap)
			if err != nil {
				t.Fatalf("%s: evaluate: %v", policies[j].Name, err)
			}
			findings = append(findings, got...)
		}
		for _, line := range render(findings) {
			fmt.Fprintf(&out, "%s\n---\n", line)
		}
	}

	if out.String() != string(golden) {
		wantLines := strings.Split(string(golden), "\n")
		gotLines := strings.Split(out.String(), "\n")
		for i := 0; i < max(len(wantLines), len(gotLines)); i++ {
			var a, b string
			if i < len(wantLines) {
				a = wantLines[i]
			}
			if i < len(gotLines) {
				b = gotLines[i]
			}
			if a != b {
				t.Fatalf("line %d differs from the captured behaviour:\n  want: %s\n  got:  %s", i+1, a, b)
			}
		}
		t.Fatal("output differs from the captured behaviour")
	}
}

var _ = snapshot.Snapshot{}
