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
