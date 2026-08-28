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

package trivy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type stubReader struct {
	client.Reader
	vulnerabilities []unstructured.Unstructured
	secrets         []unstructured.Unstructured
}

func (s stubReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	items, ok := list.(*unstructured.UnstructuredList)
	if !ok {
		return nil
	}
	switch items.GroupVersionKind().Kind {
	case "VulnerabilityReportList":
		items.Items = s.vulnerabilities
	case "ExposedSecretReportList":
		items.Items = s.secrets
	}
	return nil
}

const (
	fieldSeverity = "severity"
	fieldRuleID   = "ruleID"
	fieldTitle    = "title"
	levelCritical = "CRITICAL"
)

func report(kind string, summary map[string]any, entries []any, entriesField string) unstructured.Unstructured {
	item := unstructured.Unstructured{Object: map[string]any{
		"report": map[string]any{
			"artifact":   map[string]any{"repository": "library/nginx", "tag": "1.21"},
			"summary":    summary,
			entriesField: entries,
		},
	}}
	item.SetName("replicaset-api-nginx")
	item.SetLabels(map[string]string{
		kindLabel:      kind,
		nameLabel:      "api-6d4cf56db6",
		containerLabel: "nginx",
	})
	return item
}

func counts(critical, high, medium, low int64) map[string]any {
	return map[string]any{
		"criticalCount": critical,
		"highCount":     high,
		"mediumCount":   medium,
		"lowCount":      low,
	}
}

func vulnerability(id, severity, pkg, fixed string) any {
	return map[string]any{
		"vulnerabilityID": id,
		fieldSeverity:     severity,
		"resource":        pkg,
		"fixedVersion":    fixed,
	}
}

func TestVulnerabilitySeverityIsTheHighestPresent(t *testing.T) {
	cases := []struct {
		name    string
		summary map[string]any
		want    securityv1alpha1.Severity
		emitted bool
	}{
		{"critical present", counts(2, 10, 5, 1), securityv1alpha1.SeverityCritical, true},
		{"high is highest", counts(0, 3, 5, 1), securityv1alpha1.SeverityHigh, true},
		{"medium is highest", counts(0, 0, 5, 1), securityv1alpha1.SeverityMedium, true},
		{"low only", counts(0, 0, 0, 4), securityv1alpha1.SeverityLow, true},
		{"clean image produces no finding", counts(0, 0, 0, 0), "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, ok := vulnerabilityFinding(report("ReplicaSet", tc.summary, nil, "vulnerabilities"))
			if ok != tc.emitted {
				t.Fatalf("emitted = %v, want %v", ok, tc.emitted)
			}
			if ok && finding.Severity != tc.want {
				t.Fatalf("severity = %q, want %q", finding.Severity, tc.want)
			}
		})
	}
}

func TestHundredsOfVulnerabilitiesCollapseToOneFinding(t *testing.T) {
	entries := make([]any, 0, 300)
	for i := range 300 {
		entries = append(entries, vulnerability(fmt.Sprintf("CVE-2026-%04d", i), "HIGH", "openssl", "3.0.1"))
	}

	finding, ok := vulnerabilityFinding(report("ReplicaSet", counts(0, 300, 0, 0), entries, "vulnerabilities"))
	if !ok {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(finding.Message, "300 high") {
		t.Errorf("message should report the count, got %q", finding.Message)
	}
	if strings.Count(finding.Remediation, "\n") >= 300 {
		t.Error("remediation must be capped, not list every vulnerability")
	}
	if !strings.Contains(finding.Remediation, "further fixable") {
		t.Errorf("remediation should say how many were omitted, got %q", finding.Remediation)
	}
}

func TestRemediationPrefersFixableVulnerabilities(t *testing.T) {
	entries := []any{
		vulnerability("CVE-1", "LOW", "zlib", "1.2.13"),
		vulnerability("CVE-2", levelCritical, "openssl", "3.0.7"),
		vulnerability("CVE-3", "HIGH", "curl", ""),
	}

	finding, ok := vulnerabilityFinding(report("ReplicaSet", counts(1, 1, 0, 1), entries, "vulnerabilities"))
	if !ok {
		t.Fatal("expected a finding")
	}
	if !strings.HasPrefix(finding.Remediation, "CVE-2:") {
		t.Errorf("most severe fixable vulnerability should lead, got %q", finding.Remediation)
	}
	if strings.Contains(finding.Remediation, "CVE-3") {
		t.Error("a vulnerability with no fixed version is not actionable and must be left out")
	}
}

func TestNoFixableVulnerabilitiesIsStatedPlainly(t *testing.T) {
	entries := []any{vulnerability("CVE-3", "HIGH", "curl", "")}

	finding, _ := vulnerabilityFinding(report("ReplicaSet", counts(0, 1, 0, 0), entries, "vulnerabilities"))
	if !strings.Contains(finding.Remediation, "No listed vulnerability has a fixed version") {
		t.Errorf("got %q", finding.Remediation)
	}
}

func TestExposedSecretFinding(t *testing.T) {
	entries := []any{
		map[string]any{fieldTitle: "AWS Access Key ID", fieldRuleID: "aws-access-key-id", fieldSeverity: levelCritical},
		map[string]any{fieldTitle: "AWS Access Key ID", fieldRuleID: "aws-access-key-id", fieldSeverity: levelCritical},
		map[string]any{fieldTitle: "GitHub Token", fieldRuleID: "github-pat", fieldSeverity: "HIGH"},
	}

	finding, ok := exposedSecretFinding(report("ReplicaSet", counts(2, 1, 0, 0), entries, "secrets"))
	if !ok {
		t.Fatal("expected a finding")
	}
	if finding.ID != ExposedSecretFindingID || finding.Severity != securityv1alpha1.SeverityCritical {
		t.Fatalf("got %s/%s", finding.ID, finding.Severity)
	}
	if strings.Count(finding.Remediation, "AWS Access Key ID") != 1 {
		t.Errorf("duplicate secret titles should be collapsed, got %q", finding.Remediation)
	}
	if !strings.Contains(finding.Remediation, "GitHub Token") {
		t.Errorf("got %q", finding.Remediation)
	}
}

func TestResourceRefComesFromTrivyLabels(t *testing.T) {
	finding, _ := vulnerabilityFinding(report("DaemonSet", counts(1, 0, 0, 0), nil, "vulnerabilities"))

	want := securityv1alpha1.ResourceRef{Kind: "DaemonSet", Name: "api-6d4cf56db6", Container: "nginx"}
	if finding.Resource != want {
		t.Fatalf("got %+v, want %+v", finding.Resource, want)
	}
	if !strings.Contains(finding.Message, "library/nginx:1.21") {
		t.Errorf("message should name the image, got %q", finding.Message)
	}
}

func TestCollectStampsTheSourceOnEveryFinding(t *testing.T) {
	adapter := &Adapter{enabled: true, reader: stubReader{
		vulnerabilities: []unstructured.Unstructured{report("ReplicaSet", counts(1, 0, 0, 0), nil, "vulnerabilities")},
		secrets:         []unstructured.Unstructured{report("ReplicaSet", counts(1, 0, 0, 0), nil, "secrets")},
	}}

	findings, err := adapter.Collect(context.Background(), &snapshot.Snapshot{
		Namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, finding := range findings {
		if finding.Source != SourceName {
			t.Errorf("%s has source %q, want %q", finding.ID, finding.Source, SourceName)
		}
	}
}

func TestDisabledAdapterCollectsNothing(t *testing.T) {
	adapter := &Adapter{}

	if adapter.Enabled() {
		t.Fatal("a zero adapter must report itself disabled")
	}

	findings, err := adapter.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("a disabled adapter must not error, got %v", err)
	}
	if findings != nil {
		t.Fatalf("a disabled adapter must return no findings, got %d", len(findings))
	}
}

func TestEveryFindingCarriesProvenanceAndGuidance(t *testing.T) {
	vulnerability, _ := vulnerabilityFinding(report("ReplicaSet", counts(1, 0, 0, 0), nil, "vulnerabilities"))
	secret, _ := exposedSecretFinding(report("ReplicaSet", counts(1, 0, 0, 0), nil, "secrets"))

	for _, finding := range []securityv1alpha1.Finding{vulnerability, secret} {
		if finding.Suggestion == "" || finding.Reference == "" || finding.Remediation == "" {
			t.Errorf("%s is missing actionable fields", finding.ID)
		}
		if finding.Category != securityv1alpha1.CategorySupplyChain {
			t.Errorf("%s category = %q", finding.ID, finding.Category)
		}
	}
}
