package sources

import (
	"context"
	"sort"
	"strings"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type Source interface {
	Name() string
	Collect(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error)
}

func Normalize(findings []securityv1alpha1.Finding, minSeverity securityv1alpha1.Severity) []securityv1alpha1.Finding {
	filtered := make([]securityv1alpha1.Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))

	for _, finding := range findings {
		if !finding.Severity.AtLeast(minSeverity) {
			continue
		}
		key := strings.Join([]string{finding.ID, finding.Resource.String(), finding.Source}, "|")
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, finding)
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		left, right := filtered[i], filtered[j]
		if left.Severity.Rank() != right.Severity.Rank() {
			return left.Severity.Rank() < right.Severity.Rank()
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return left.Resource.String() < right.Resource.String()
	})

	return filtered
}
