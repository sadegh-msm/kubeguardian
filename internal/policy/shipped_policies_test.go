package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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

// TestZeroQuantitiesCountAsMissing covers a case the fixtures did not and the
// live cluster did: a container whose limits and requests are all present but
// set to "0". Testing presence alone let it pass, where the Go check this
// replaced treated a zero quantity as missing. A quantity of zero is not a
// limit, so the finding must fire.
func TestZeroQuantitiesCountAsMissing(t *testing.T) {
	zero := corev1.Container{
		Name:  testContainer,
		Image: "nginx:1.27",
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("0"),
				corev1.ResourceMemory: resource.MustParse("0"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("0"),
				corev1.ResourceMemory: resource.MustParse("0"),
			},
		},
	}

	snap := &snapshot.Snapshot{
		Namespace:   namespaceWith(nil),
		Deployments: []appsv1.Deployment{deploymentWith("uptime", []corev1.Container{zero}, corev1.PodSpec{})},
	}

	var found *securityv1alpha1.Finding
	for _, check := range loadPolicies(t) {
		if check.Spec.ID != "KG-021" {
			continue
		}
		compiled, err := Compile(check.Spec)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		findings, err := Evaluate(compiled, snap)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if len(findings) == 1 {
			found = &findings[0]
		}
	}

	if found == nil {
		t.Fatal("a container with every quantity set to 0 must still be reported as missing them")
	}
	want := `is missing memory limit, cpu request and memory request`
	if !strings.Contains(found.Message, want) {
		t.Fatalf("got %q, want it to contain %q", found.Message, want)
	}
}
