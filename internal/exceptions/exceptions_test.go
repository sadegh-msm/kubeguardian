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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const (
	kindDaemonSet = "DaemonSet"
	tierPlatform  = "platform"
	tierLabel     = "tier"
	checkHostNS   = "KG-004"
	nsMonitoring  = "monitoring"
)

var now = time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

func namespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func finding(id, kind, name string) securityv1alpha1.Finding {
	return securityv1alpha1.Finding{
		ID:       id,
		Severity: securityv1alpha1.SeverityCritical,
		Resource: securityv1alpha1.ResourceRef{Kind: kind, Name: name},
	}
}

func exception(name string, spec securityv1alpha1.ScanExceptionSpec) securityv1alpha1.ScanException {
	if spec.Reason == "" {
		spec.Reason = "documented and accepted"
	}
	return securityv1alpha1.ScanException{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func TestApplySuppressesMatchingFindings(t *testing.T) {
	cases := []struct {
		name      string
		exception securityv1alpha1.ScanExceptionSpec
		namespace corev1.Namespace
		finding   securityv1alpha1.Finding
		want      bool
	}{
		{
			name:      "check and namespace and resource all match",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, Namespaces: []string{nsMonitoring}, Resources: []securityv1alpha1.ResourceMatcher{{Kind: kindDaemonSet, Name: "node-exporter"}}},
			namespace: namespace(nsMonitoring, nil),
			finding:   finding(checkHostNS, kindDaemonSet, "node-exporter"),
			want:      true,
		},
		{
			name:      "different check does not match",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}},
			namespace: namespace(nsMonitoring, nil),
			finding:   finding("KG-001", kindDaemonSet, "node-exporter"),
			want:      false,
		},
		{
			name:      "different namespace does not match",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, Namespaces: []string{nsMonitoring}},
			namespace: namespace("payments", nil),
			finding:   finding(checkHostNS, kindDaemonSet, "node-exporter"),
			want:      false,
		},
		{
			name:      "different resource name does not match",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, Resources: []securityv1alpha1.ResourceMatcher{{Kind: kindDaemonSet, Name: "node-exporter"}}},
			namespace: namespace(nsMonitoring, nil),
			finding:   finding(checkHostNS, kindDaemonSet, "other-agent"),
			want:      false,
		},
		{
			name:      "resource kind alone matches any name of that kind",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, Resources: []securityv1alpha1.ResourceMatcher{{Kind: kindDaemonSet}}},
			namespace: namespace(nsMonitoring, nil),
			finding:   finding(checkHostNS, kindDaemonSet, "anything"),
			want:      true,
		},
		{
			name:      "empty namespaces and resources match everything for that check",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}},
			namespace: namespace("anywhere", nil),
			finding:   finding(checkHostNS, "Deployment", "api"),
			want:      true,
		},
		{
			name:      "wildcard check matches any finding",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{securityv1alpha1.WildcardCheck}, Namespaces: []string{"sandbox"}},
			namespace: namespace("sandbox", nil),
			finding:   finding("KG-021", "Deployment", "api"),
			want:      true,
		},
		{
			name:      "namespace selector matches on labels",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{tierLabel: tierPlatform}}},
			namespace: namespace(nsMonitoring, map[string]string{tierLabel: tierPlatform}),
			finding:   finding(checkHostNS, kindDaemonSet, "node-exporter"),
			want:      true,
		},
		{
			name:      "namespace selector rejects non matching labels",
			exception: securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{tierLabel: tierPlatform}}},
			namespace: namespace("payments", map[string]string{tierLabel: "app"}),
			finding:   finding(checkHostNS, kindDaemonSet, "node-exporter"),
			want:      false,
		},
		{
			name: "namespace list and selector must both hold",
			exception: securityv1alpha1.ScanExceptionSpec{
				Checks:            []string{checkHostNS},
				Namespaces:        []string{nsMonitoring},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{tierLabel: tierPlatform}},
			},
			namespace: namespace(nsMonitoring, map[string]string{tierLabel: "app"}),
			finding:   finding(checkHostNS, kindDaemonSet, "node-exporter"),
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := New([]securityv1alpha1.ScanException{exception("test", tc.exception)}, now)
			got := set.Apply(tc.namespace, []securityv1alpha1.Finding{tc.finding})

			if got[0].Suppressed != tc.want {
				t.Fatalf("suppressed = %v, want %v", got[0].Suppressed, tc.want)
			}
			if tc.want {
				if got[0].SuppressedBy != "test" {
					t.Errorf("suppressedBy = %q, want %q", got[0].SuppressedBy, "test")
				}
				if got[0].SuppressedReason == "" {
					t.Error("a suppressed finding must carry the reason")
				}
			}
		})
	}
}

func TestExpiredExceptionsAreIgnored(t *testing.T) {
	past := metav1.NewTime(now.Add(-time.Hour))
	future := metav1.NewTime(now.Add(time.Hour))

	cases := []struct {
		name    string
		expires *metav1.Time
		want    bool
	}{
		{"no expiry", nil, true},
		{"expires in the future", &future, true},
		{"already expired", &past, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := New([]securityv1alpha1.ScanException{
				exception("test", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, ExpiresAt: tc.expires}),
			}, now)

			got := set.Apply(namespace(nsMonitoring, nil), []securityv1alpha1.Finding{finding(checkHostNS, kindDaemonSet, "agent")})
			if got[0].Suppressed != tc.want {
				t.Fatalf("suppressed = %v, want %v", got[0].Suppressed, tc.want)
			}
		})
	}
}

func TestApplyLeavesFindingsUntouchedWithoutExceptions(t *testing.T) {
	set := New(nil, now)
	input := []securityv1alpha1.Finding{finding(checkHostNS, kindDaemonSet, "agent")}

	got := set.Apply(namespace(nsMonitoring, nil), input)
	if got[0].Suppressed {
		t.Fatal("no exception exists, the finding must not be suppressed")
	}
}

func TestApplyDoesNotMutateInput(t *testing.T) {
	set := New([]securityv1alpha1.ScanException{
		exception("test", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}}),
	}, now)

	input := []securityv1alpha1.Finding{finding(checkHostNS, kindDaemonSet, "agent")}
	_ = set.Apply(namespace(nsMonitoring, nil), input)

	if input[0].Suppressed {
		t.Fatal("Apply must not mutate the findings it was given")
	}
}

func TestNextExpiryReportsTheEarliestDeadlineThatAppliesHere(t *testing.T) {
	soon := metav1.NewTime(now.Add(time.Hour))
	later := metav1.NewTime(now.Add(4 * time.Hour))

	cases := []struct {
		name  string
		items []securityv1alpha1.ScanException
		want  *time.Time
	}{
		{
			name: "nothing expires",
			items: []securityv1alpha1.ScanException{
				exception("forever", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}}),
			},
			want: nil,
		},
		{
			name: "the earliest of several wins",
			items: []securityv1alpha1.ScanException{
				exception("later", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, ExpiresAt: &later}),
				exception("soon", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, ExpiresAt: &soon}),
			},
			want: &soon.Time,
		},
		{
			name: "an exception for another namespace is not our deadline",
			items: []securityv1alpha1.ScanException{
				exception("elsewhere", securityv1alpha1.ScanExceptionSpec{
					Checks:     []string{checkHostNS},
					Namespaces: []string{"payments"},
					ExpiresAt:  &soon,
				}),
			},
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := New(tc.items, now).NextExpiry(namespace(nsMonitoring, nil))

			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("got %s, want no deadline", got)
			case tc.want != nil && got == nil:
				t.Fatalf("got no deadline, want %s", tc.want)
			case tc.want != nil && !got.Equal(*tc.want):
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNextExpiryIgnoresAlreadyExpiredExceptions(t *testing.T) {
	past := metav1.NewTime(now.Add(-time.Hour))

	set := New([]securityv1alpha1.ScanException{
		exception("stale", securityv1alpha1.ScanExceptionSpec{Checks: []string{checkHostNS}, ExpiresAt: &past}),
	}, now)

	if got := set.NextExpiry(namespace(nsMonitoring, nil)); got != nil {
		t.Fatalf("got %s, want no deadline: an expired exception has nothing left to expire", got)
	}
}
