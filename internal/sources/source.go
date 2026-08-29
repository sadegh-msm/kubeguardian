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

type identity struct {
	id       string
	resource securityv1alpha1.ResourceRef
	source   string
	message  string
}

func Normalize(findings []securityv1alpha1.Finding, minSeverity securityv1alpha1.Severity) []securityv1alpha1.Finding {
	filtered := make([]securityv1alpha1.Finding, 0, len(findings))
	seen := make(map[identity]struct{}, len(findings))

	for _, finding := range findings {
		if !finding.Severity.AtLeast(minSeverity) {
			continue
		}
		key := identity{finding.ID, finding.Resource, finding.Source, finding.Message}
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
		return compareResource(left.Resource, right.Resource)
	})

	return filtered
}

func compareResource(left, right securityv1alpha1.ResourceRef) int {
	if order := strings.Compare(left.Kind, right.Kind); order != 0 {
		return order
	}
	if order := strings.Compare(left.Name, right.Name); order != 0 {
		return order
	}
	return strings.Compare(left.Container, right.Container)
}

func Summarize(findings []securityv1alpha1.Finding) securityv1alpha1.SeveritySummary {
	var summary securityv1alpha1.SeveritySummary

	for _, finding := range findings {
		if finding.Suppressed {
			summary.Suppressed++
			continue
		}

		summary.Total++

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

	return summary
}

func Truncate(findings []securityv1alpha1.Finding, max int) ([]securityv1alpha1.Finding, int) {
	if max <= 0 || len(findings) <= max {
		return findings, 0
	}
	return findings[:max], len(findings) - max
}
