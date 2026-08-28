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

func suppressed(f securityv1alpha1.Finding) securityv1alpha1.Finding {
	f.Suppressed = true
	f.SuppressedBy = "accepted-risk"
	return f
}

func TestSummarizeCountsBySeverity(t *testing.T) {
	got := Summarize([]securityv1alpha1.Finding{
		finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "a"),
		finding("KG-002", securityv1alpha1.SeverityHigh, "Deployment", "b"),
		finding("KG-003", securityv1alpha1.SeverityHigh, "Deployment", "c"),
		finding("KG-021", securityv1alpha1.SeverityMedium, "Deployment", "d"),
	})

	want := securityv1alpha1.SeveritySummary{Critical: 1, High: 2, Medium: 1, Total: 4}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSummarizeExcludesSuppressedFromCounts(t *testing.T) {
	got := Summarize([]securityv1alpha1.Finding{
		suppressed(finding("KG-004", securityv1alpha1.SeverityCritical, "DaemonSet", "agent")),
		suppressed(finding("KG-004", securityv1alpha1.SeverityCritical, "DaemonSet", "agent2")),
		finding("KG-002", securityv1alpha1.SeverityHigh, "Deployment", "api"),
	})

	want := securityv1alpha1.SeveritySummary{High: 1, Total: 1, Suppressed: 2}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTruncateKeepsHighestSeveritiesFirst(t *testing.T) {
	input := Normalize([]securityv1alpha1.Finding{
		finding("KG-021", securityv1alpha1.SeverityMedium, "Deployment", "c"),
		finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "a"),
		finding("KG-002", securityv1alpha1.SeverityHigh, "Deployment", "b"),
	}, securityv1alpha1.SeverityLow)

	got, omitted := Truncate(input, 2)
	if omitted != 1 {
		t.Fatalf("omitted = %d, want 1", omitted)
	}
	if got[0].Severity != securityv1alpha1.SeverityCritical || got[1].Severity != securityv1alpha1.SeverityHigh {
		t.Fatalf("truncation must keep the most severe findings, got %v", ids(got))
	}
}

func TestTruncateIsNoopBelowLimit(t *testing.T) {
	input := []securityv1alpha1.Finding{finding("KG-001", securityv1alpha1.SeverityCritical, "Deployment", "a")}

	for _, limit := range []int{0, 1, 5} {
		got, omitted := Truncate(input, limit)
		if omitted != 0 || len(got) != 1 {
			t.Fatalf("limit %d: got %d findings and %d omitted, want 1 and 0", limit, len(got), omitted)
		}
	}
}
