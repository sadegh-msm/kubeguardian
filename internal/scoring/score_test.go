package scoring

import (
	"testing"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

func finding(severity securityv1alpha1.Severity) securityv1alpha1.Finding {
	return securityv1alpha1.Finding{Severity: severity}
}

func repeat(severity securityv1alpha1.Severity, count int) []securityv1alpha1.Finding {
	findings := make([]securityv1alpha1.Finding, 0, count)
	for range count {
		findings = append(findings, finding(severity))
	}
	return findings
}

func TestCompute(t *testing.T) {
	cases := []struct {
		name    string
		input   []securityv1alpha1.Finding
		score   int
		summary securityv1alpha1.SeveritySummary
	}{
		{
			name:    "clean namespace",
			input:   nil,
			score:   100,
			summary: securityv1alpha1.SeveritySummary{},
		},
		{
			name:    "one critical",
			input:   repeat(securityv1alpha1.SeverityCritical, 1),
			score:   80,
			summary: securityv1alpha1.SeveritySummary{Critical: 1, Total: 1},
		},
		{
			name: "mixed severities",
			input: append(append(
				repeat(securityv1alpha1.SeverityCritical, 1),
				repeat(securityv1alpha1.SeverityHigh, 2)...),
				repeat(securityv1alpha1.SeverityLow, 1)...),
			score:   58,
			summary: securityv1alpha1.SeveritySummary{Critical: 1, High: 2, Low: 1, Total: 4},
		},
		{
			name:    "score floors at zero",
			input:   repeat(securityv1alpha1.SeverityCritical, 12),
			score:   0,
			summary: securityv1alpha1.SeveritySummary{Critical: 12, Total: 12},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, summary := Compute(tc.input)
			if score != tc.score {
				t.Errorf("got score %d, want %d", score, tc.score)
			}
			if summary != tc.summary {
				t.Errorf("got summary %+v, want %+v", summary, tc.summary)
			}
		})
	}
}
