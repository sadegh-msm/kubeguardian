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

package exceptions

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

type Set struct {
	items []securityv1alpha1.ScanException
}

func New(items []securityv1alpha1.ScanException, now time.Time) *Set {
	active := make([]securityv1alpha1.ScanException, 0, len(items))
	for _, item := range items {
		if item.Spec.ExpiresAt != nil && !item.Spec.ExpiresAt.After(now) {
			continue
		}
		active = append(active, item)
	}
	return &Set{items: active}
}

func Load(ctx context.Context, c client.Reader, now time.Time) (*Set, error) {
	var list securityv1alpha1.ScanExceptionList
	if err := c.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list scan exceptions: %w", err)
	}
	return New(list.Items, now), nil
}

func (s *Set) Apply(namespace corev1.Namespace, findings []securityv1alpha1.Finding) []securityv1alpha1.Finding {
	if s == nil || len(s.items) == 0 {
		return findings
	}

	out := make([]securityv1alpha1.Finding, len(findings))
	copy(out, findings)

	for i := range out {
		exception, matched := s.match(namespace, out[i])
		if !matched {
			continue
		}
		out[i].Suppressed = true
		out[i].SuppressedBy = exception.Name
		out[i].SuppressedReason = exception.Spec.Reason
	}

	return out
}

// NextExpiry returns the earliest moment at which an exception that could apply
// to this namespace stops applying, or nil if none of them expire. Expiry is the
// one thing about a report that changes on its own: no object is written when a
// timestamp passes, so there is no event to watch for. A caller can requeue on
// this instead of polling.
func (s *Set) NextExpiry(namespace corev1.Namespace) *time.Time {
	if s == nil {
		return nil
	}

	var earliest *time.Time
	for _, item := range s.items {
		if item.Spec.ExpiresAt == nil || !matchesNamespace(item.Spec, namespace) {
			continue
		}
		at := item.Spec.ExpiresAt.Time
		if earliest == nil || at.Before(*earliest) {
			earliest = &at
		}
	}
	return earliest
}

func (s *Set) match(namespace corev1.Namespace, finding securityv1alpha1.Finding) (securityv1alpha1.ScanException, bool) {
	for _, item := range s.items {
		if matchesCheck(item.Spec.Checks, finding.ID) &&
			matchesNamespace(item.Spec, namespace) &&
			matchesResource(item.Spec.Resources, finding.Resource) {
			return item, true
		}
	}
	return securityv1alpha1.ScanException{}, false
}

func matchesCheck(checks []string, id string) bool {
	return slices.Contains(checks, securityv1alpha1.WildcardCheck) || slices.Contains(checks, id)
}

func matchesNamespace(spec securityv1alpha1.ScanExceptionSpec, namespace corev1.Namespace) bool {
	if len(spec.Namespaces) > 0 && !slices.Contains(spec.Namespaces, namespace.Name) {
		return false
	}

	if spec.NamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(spec.NamespaceSelector)
		if err != nil {
			return false
		}
		if !selector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	}

	return true
}

func matchesResource(matchers []securityv1alpha1.ResourceMatcher, ref securityv1alpha1.ResourceRef) bool {
	if len(matchers) == 0 {
		return true
	}

	for _, matcher := range matchers {
		if matcher.Kind != "" && matcher.Kind != ref.Kind {
			continue
		}
		if matcher.Name != "" && matcher.Name != ref.Name {
			continue
		}
		return true
	}

	return false
}
