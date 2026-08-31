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
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

// subject is one thing a check is evaluated against, together with the resource
// the resulting finding names.
type subject struct {
	variables map[string]any
	reference securityv1alpha1.ResourceRef
}

// Context holds everything about one namespace that every check in a scan reads.
// Building it per check would rebuild the workload views nine times over and
// dominate the cost of a scan, so a scan builds one and reuses it.
type Context struct {
	snap     *snapshot.Snapshot
	shared   map[string]any
	subjects map[securityv1alpha1.Scope][]subject
}

func NewContext(snap *snapshot.Snapshot) *Context {
	return &Context{
		snap:     snap,
		shared:   sharedVariables(snap),
		subjects: make(map[securityv1alpha1.Scope][]subject, 5),
	}
}

func (c *Context) subjectsFor(scope securityv1alpha1.Scope) []subject {
	if cached, ok := c.subjects[scope]; ok {
		return cached
	}
	subjects := subjectsFor(scope, c.snap)
	c.subjects[scope] = subjects
	return subjects
}

// Evaluate runs one compiled check over a namespace snapshot. An expression that
// errors at runtime aborts the scan rather than being skipped: a check that
// cannot be evaluated is a defect its author needs to see, and a report that
// quietly dropped it would look like a clean result.
func Evaluate(compiled *Compiled, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	return NewContext(snap).Evaluate(compiled)
}

func (c *Context) Evaluate(compiled *Compiled) ([]securityv1alpha1.Finding, error) {
	shared := c.shared

	var findings []securityv1alpha1.Finding
	for _, subject := range c.subjectsFor(compiled.Spec.Scope) {
		variables := make(map[string]any, len(shared)+len(subject.variables)+len(compiled.bindings))
		maps.Copy(variables, shared)
		maps.Copy(variables, subject.variables)

		for _, binding := range compiled.bindings {
			value, _, err := binding.program.Eval(variables)
			if err != nil {
				return nil, fmt.Errorf("check %s binding %q: %w", compiled.Spec.ID, binding.name, err)
			}
			variables[binding.name] = value
		}

		result, _, err := compiled.violation.Eval(variables)
		if err != nil {
			return nil, fmt.Errorf("check %s violation: %w", compiled.Spec.ID, err)
		}
		violated, ok := result.Value().(bool)
		if !ok || !violated {
			continue
		}

		finding := securityv1alpha1.Finding{
			ID:        compiled.Spec.ID,
			Severity:  compiled.Spec.Severity,
			Category:  compiled.Spec.Category,
			Resource:  subject.reference,
			Reference: compiled.Spec.Reference,
		}
		for _, field := range []struct {
			source template
			into   *string
			name   string
		}{
			{compiled.message, &finding.Message, "message"},
			{compiled.suggestion, &finding.Suggestion, "suggestion"},
			{compiled.remediation, &finding.Remediation, "remediation"},
		} {
			rendered, err := field.source.render(variables)
			if err != nil {
				return nil, fmt.Errorf("check %s %s: %w", compiled.Spec.ID, field.name, err)
			}
			*field.into = rendered
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (t template) render(variables map[string]any) (string, error) {
	var out strings.Builder
	for _, segment := range t {
		if segment.program == nil {
			out.WriteString(segment.literal)
			continue
		}
		value, _, err := segment.program.Eval(variables)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "%v", value.Value())
	}
	return out.String(), nil
}

func sharedVariables(snap *snapshot.Snapshot) map[string]any {
	return map[string]any{
		variableNamespace:       snap.Namespace,
		variableWorkloads:       workloadViews(snap),
		variableNetworkPolicies: snap.NetworkPolicies,
		variableServiceAccounts: snap.ServiceAccounts,
		variableRoles:           snap.Roles,
	}
}

func workloadViews(snap *snapshot.Snapshot) []Workload {
	workloads := snap.Workloads()
	views := make([]Workload, 0, len(workloads))
	for _, workload := range workloads {
		views = append(views, viewOf(workload))
	}
	return views
}

func viewOf(workload snapshot.Workload) Workload {
	return Workload{
		Kind:     workload.Kind,
		Name:     workload.Name,
		Metadata: workload.Template.ObjectMeta,
		Spec:     workload.Template.Spec,
	}
}

func subjectsFor(scope securityv1alpha1.Scope, snap *snapshot.Snapshot) []subject {
	switch scope {
	case securityv1alpha1.ScopeNamespace:
		return []subject{{
			variables: map[string]any{},
			reference: securityv1alpha1.ResourceRef{Kind: "Namespace", Name: snap.Name()},
		}}

	case securityv1alpha1.ScopeWorkload:
		subjects := make([]subject, 0, len(snap.Workloads()))
		for _, workload := range snap.Workloads() {
			subjects = append(subjects, subject{
				variables: map[string]any{variableWorkload: viewOf(workload)},
				reference: securityv1alpha1.ResourceRef{Kind: workload.Kind, Name: workload.Name},
			})
		}
		return subjects

	case securityv1alpha1.ScopeContainer:
		var subjects []subject
		for _, workload := range snap.Workloads() {
			view := viewOf(workload)
			for _, container := range workload.Containers() {
				tag, digest := imageReference(container.Image)
				subjects = append(subjects, subject{
					variables: map[string]any{
						variableWorkload:       view,
						variableContainer:      container,
						variableImageTag:       tag,
						variableImageDigest:    digest,
						variableContainerIndex: containerIndex(workload, container),
					},
					reference: securityv1alpha1.ResourceRef{Kind: workload.Kind, Name: workload.Name, Container: container.Name},
				})
			}
		}
		return subjects

	case securityv1alpha1.ScopeRole:
		subjects := make([]subject, 0, len(snap.Roles))
		for _, role := range snap.Roles {
			subjects = append(subjects, subject{
				variables: map[string]any{variableRole: role},
				reference: securityv1alpha1.ResourceRef{Kind: "Role", Name: role.Name},
			})
		}
		return subjects

	case securityv1alpha1.ScopeServiceAccount:
		subjects := make([]subject, 0, len(snap.ServiceAccounts))
		for _, account := range snap.ServiceAccounts {
			subjects = append(subjects, subject{
				variables: map[string]any{variableServiceAccount: account},
				reference: securityv1alpha1.ResourceRef{Kind: "ServiceAccount", Name: account.Name},
			})
		}
		return subjects
	}

	return nil
}

// imageReference splits an image into its tag and digest. This is a parsing
// primitive rather than a judgement: it reports what the reference says, and the
// check decides whether that is acceptable. Registry ports are why this is not a
// one-line expression, since "registry:5000/app" is untagged.
func imageReference(image string) (tag string, digest string) {
	ref := image
	if slash := strings.LastIndex(ref, "/"); slash != -1 {
		ref = ref[slash+1:]
	}
	if _, after, found := strings.Cut(ref, "@"); found {
		return "", after
	}
	if colon := strings.LastIndex(ref, ":"); colon != -1 {
		return ref[colon+1:], ""
	}
	return "", ""
}

func containerIndex(workload snapshot.Workload, target corev1.Container) int {
	for i, container := range workload.Template.Spec.Containers {
		if container.Name == target.Name {
			return i
		}
	}
	return 0
}
