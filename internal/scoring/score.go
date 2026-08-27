package scoring

import securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"

const maxScore = 100

var penalty = map[securityv1alpha1.Severity]int{
	securityv1alpha1.SeverityCritical: 20,
	securityv1alpha1.SeverityHigh:     10,
	securityv1alpha1.SeverityMedium:   5,
	securityv1alpha1.SeverityLow:      2,
}

func Compute(findings []securityv1alpha1.Finding) (int, securityv1alpha1.SeveritySummary) {
	summary := securityv1alpha1.SeveritySummary{Total: len(findings)}
	score := maxScore

	for _, finding := range findings {
		score -= penalty[finding.Severity]

		switch finding.Severity {
		case securityv1alpha1.SeverityCritical:
			summary.Critical++
		case securityv1alpha1.SeverityHigh:
			summary.High++
		case securityv1alpha1.SeverityMedium:
			summary.Medium++
		case securityv1alpha1.SeverityLow:
			summary.Low++
		}
	}

	if score < 0 {
		score = 0
	}
	return score, summary
}
