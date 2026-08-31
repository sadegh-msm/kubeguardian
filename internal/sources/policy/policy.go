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

package policy

import (
	"context"
	"fmt"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/policy"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const SourceName = "policy"

// Source evaluates the SecurityCheck objects in the cluster against a namespace
// snapshot. Every manifest check lives in one of those objects, so adding a rule
// is applying a manifest rather than editing this package.
type Source struct {
	reader   client.Reader
	registry *policy.Registry
}

func New(reader client.Reader, registry *policy.Registry) *Source {
	return &Source{reader: reader, registry: registry}
}

func (s *Source) Name() string {
	return SourceName
}

func (s *Source) Collect(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	var list securityv1alpha1.SecurityCheckList
	if err := s.reader.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list security checks: %w", err)
	}

	// Checks arrive in whatever order the cache returns them. Sorting keeps a
	// scan's output stable, which is what lets an unchanged namespace produce an
	// unchanged report.
	slices.SortFunc(list.Items, func(left, right securityv1alpha1.SecurityCheck) int {
		if left.Name < right.Name {
			return -1
		}
		if left.Name > right.Name {
			return 1
		}
		return 0
	})

	evaluation := policy.NewContext(snap)

	var findings []securityv1alpha1.Finding
	for i := range list.Items {
		check := &list.Items[i]

		compiled, err := s.registry.Get(check)
		if err != nil {
			// A check that does not compile is reported on its own status by the
			// SecurityCheck controller. Failing every scan in the cluster because
			// one policy has a typo would be a worse outcome than scanning without
			// it, so this is logged and skipped.
			logf.FromContext(ctx).Error(err, "skipping security check that does not compile", "check", check.Name)
			continue
		}

		collected, err := evaluation.Evaluate(compiled)
		if err != nil {
			return nil, fmt.Errorf("check %s: %w", check.Name, err)
		}
		for _, finding := range collected {
			finding.Source = SourceName
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
