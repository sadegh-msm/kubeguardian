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
	"context"
	"slices"
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
		key := strings.Join([]string{finding.ID, finding.Resource.String(), finding.Source, finding.Message}, "|")
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, finding)
	}

	slices.SortStableFunc(filtered, func(left, right securityv1alpha1.Finding) int {
		if rank := left.Severity.Rank() - right.Severity.Rank(); rank != 0 {
			return rank
		}
		if left.ID != right.ID {
			return strings.Compare(left.ID, right.ID)
		}
		return strings.Compare(left.Resource.String(), right.Resource.String())
	})

	return filtered
}
