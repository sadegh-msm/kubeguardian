package sources

import (
	"testing"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

func finding(id string, severity securityv1alpha1.Severity, kind, name string) securityv1alpha1.Finding {
	return securityv1alpha1.Finding{
		ID:       id,
		Severity: severity,
		Resource: securityv1alpha1.ResourceRef{Kind: kind, Name: name},
		Source:   "builtin",
	}
}

func ids(findings []securityv1alpha1.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, item := range findings {
		out = append(out, item.ID+"/"+item.Resource.Name)
	}
	return out
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestNormalizeSortsBySeverityThenIdThenResource(t *testing.T) {
	input := []securityv1alpha1.Finding{
		finding("KG-021", securityv1alpha1.SeverityMedium, "Deployment", "worker"),
		finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "web"),
		finding("KG-010", securityv1alpha1.SeverityHigh, "Namespace", "demo"),
		finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "api"),
		finding("KG-020", securityv1alpha1.SeverityMedium, "Deployment", "worker"),
	}

	got := ids(Normalize(input, securityv1alpha1.SeverityLow))
	want := []string{"KG-001/api", "KG-001/web", "KG-010/demo", "KG-020/worker", "KG-021/worker"}

	if !equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeIsStableAcrossRuns(t *testing.T) {
	input := []securityv1alpha1.Finding{
		finding("KG-003", securityv1alpha1.SeverityHigh, "Deployment", "b"),
		finding("KG-003", securityv1alpha1.SeverityHigh, "Deployment", "a"),
		finding("KG-002", securityv1alpha1.SeverityHigh, "Deployment", "c"),
	}

	first := ids(Normalize(input, securityv1alpha1.SeverityLow))
	for range 20 {
		if got := ids(Normalize(input, securityv1alpha1.SeverityLow)); !equal(got, first) {
			t.Fatalf("ordering is not deterministic: %v then %v", first, got)
		}
	}
}

func TestNormalizeKeepsDistinctFindingsOnTheSameResource(t *testing.T) {
	hostNetwork := finding("KG-004", securityv1alpha1.SeverityCritical, "Deployment", "api")
	hostNetwork.Message = "hostNetwork is enabled"
	hostPID := finding("KG-004", securityv1alpha1.SeverityCritical, "Deployment", "api")
	hostPID.Message = "hostPID is enabled"

	got := Normalize([]securityv1alpha1.Finding{hostNetwork, hostPID}, securityv1alpha1.SeverityLow)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 distinct findings on the same resource", len(got))
	}
}

func TestNormalizeDropsDuplicates(t *testing.T) {
	duplicate := finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "api")
	got := Normalize([]securityv1alpha1.Finding{duplicate, duplicate}, securityv1alpha1.SeverityLow)

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func TestNormalizeAppliesMinimumSeverity(t *testing.T) {
	input := []securityv1alpha1.Finding{
		finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "api"),
		finding("KG-010", securityv1alpha1.SeverityHigh, "Namespace", "demo"),
		finding("KG-021", securityv1alpha1.SeverityMedium, "Deployment", "api"),
		finding("KG-030", securityv1alpha1.SeverityLow, "Deployment", "api"),
	}

	got := Normalize(input, securityv1alpha1.SeverityHigh)
	want := []string{"KG-001/api", "KG-010/demo"}

	if !equal(ids(got), want) {
		t.Fatalf("got %v, want %v", ids(got), want)
	}
}
