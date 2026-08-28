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

package builtin

import (
	"context"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/checks"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const SourceName = "builtin"

type Engine struct {
	checks []checks.Check
}

func NewEngine() *Engine {
	return &Engine{checks: checks.All()}
}

func (e *Engine) Name() string {
	return SourceName
}

func (e *Engine) Collect(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	var findings []securityv1alpha1.Finding

	for _, check := range e.checks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, finding := range check.Run(snap) {
			finding.Source = SourceName
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
