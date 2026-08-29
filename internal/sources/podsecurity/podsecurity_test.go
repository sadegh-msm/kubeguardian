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

package podsecurity

import (
	"context"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const containerName = "api"

func ptr[T any](value T) *T {
	return &value
}

func compliantContainer() corev1.Container {
	return corev1.Container{
		Name:  containerName,
		Image: "registry.example.com/app:1.4.2",
		SecurityContext: &corev1.SecurityContext{
			Privileged:               ptr(false),
			RunAsNonRoot:             ptr(true),
			RunAsUser:                ptr(int64(1000)),
			AllowPrivilegeEscalation: ptr(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}
}

func snapshotOf(spec corev1.PodSpec) *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: containerName, Namespace: "demo"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
		}},
	}
}

func collect(t *testing.T, spec corev1.PodSpec) []securityv1alpha1.Finding {
	t.Helper()

	source, err := New()
	if err != nil {
		t.Fatalf("building source: %v", err)
	}
	findings, err := source.Collect(context.Background(), snapshotOf(spec))
	if err != nil {
		t.Fatalf("collecting: %v", err)
	}
	return findings
}

func ids(findings []securityv1alpha1.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		if !slices.Contains(out, finding.ID) {
			out = append(out, finding.ID)
		}
	}
	slices.Sort(out)
	return out
}

func TestCompliantPodProducesNoFindings(t *testing.T) {
	got := collect(t, corev1.PodSpec{Containers: []corev1.Container{compliantContainer()}})

	if len(got) != 0 {
		t.Fatalf("a restricted-compliant pod must produce no findings, got %v", ids(got))
	}
}

func TestViolationsMapToTheExpectedKGIdentifiers(t *testing.T) {
	privileged := compliantContainer()
	privileged.SecurityContext.Privileged = ptr(true)

	escalating := compliantContainer()
	escalating.SecurityContext.AllowPrivilegeEscalation = ptr(true)

	rootUser := compliantContainer()
	rootUser.SecurityContext.RunAsNonRoot = ptr(false)
	rootUser.SecurityContext.RunAsUser = ptr(int64(0))

	keepsCapabilities := compliantContainer()
	keepsCapabilities.SecurityContext.Capabilities = nil

	noSeccomp := compliantContainer()
	noSeccomp.SecurityContext.SeccompProfile = nil

	hostPorted := compliantContainer()
	hostPorted.Ports = []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want string
	}{
		{"privileged container", corev1.PodSpec{Containers: []corev1.Container{privileged}}, checkPrivileged},
		{"runs as root", corev1.PodSpec{Containers: []corev1.Container{rootUser}}, checkRunAsRoot},
		{"privilege escalation allowed", corev1.PodSpec{Containers: []corev1.Container{escalating}}, checkPrivilegeEscalation},
		{"host namespaces", corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{compliantContainer()}}, checkHostNamespaces},
		{"host path volume", corev1.PodSpec{
			Containers: []corev1.Container{compliantContainer()},
			Volumes: []corev1.Volume{{
				Name:         "host-root",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}},
			}},
		}, checkHostPath},
		{"capabilities not dropped", corev1.PodSpec{Containers: []corev1.Container{keepsCapabilities}}, checkCapabilities},
		{"no seccomp profile", corev1.PodSpec{Containers: []corev1.Container{noSeccomp}}, checkSeccomp},
		{"host port", corev1.PodSpec{Containers: []corev1.Container{hostPorted}}, checkHostPorts},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(collect(t, tc.spec))
			if !slices.Contains(got, tc.want) {
				t.Fatalf("got %v, want it to contain %s", got, tc.want)
			}
		})
	}
}

func TestHostNamespacesCollapseToASingleFinding(t *testing.T) {
	got := collect(t, corev1.PodSpec{
		HostNetwork: true,
		HostPID:     true,
		HostIPC:     true,
		Containers:  []corev1.Container{compliantContainer()},
	})

	hostNamespace := 0
	for _, finding := range got {
		if finding.ID == checkHostNamespaces {
			hostNamespace++
		}
	}
	if hostNamespace != 1 {
		t.Fatalf("upstream reports host namespaces as one check, got %d findings", hostNamespace)
	}
}

func TestInitContainersAreEvaluated(t *testing.T) {
	privileged := compliantContainer()
	privileged.Name = "migrate"
	privileged.SecurityContext.Privileged = ptr(true)

	got := collect(t, corev1.PodSpec{
		InitContainers: []corev1.Container{privileged},
		Containers:     []corev1.Container{compliantContainer()},
	})

	if !slices.Contains(ids(got), checkPrivileged) {
		t.Fatalf("a privileged init container must be reported, got %v", ids(got))
	}
}

func TestEveryFindingIsActionable(t *testing.T) {
	privileged := compliantContainer()
	privileged.SecurityContext.Privileged = ptr(true)
	privileged.SecurityContext.SeccompProfile = nil

	got := collect(t, corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{privileged}})
	if len(got) == 0 {
		t.Fatal("expected findings")
	}

	for _, finding := range got {
		if finding.Suggestion == "" || finding.Remediation == "" || finding.Reference == "" {
			t.Errorf("%s is missing actionable fields", finding.ID)
		}
		if finding.Source != SourceName {
			t.Errorf("%s has source %q, want %q", finding.ID, finding.Source, SourceName)
		}
		if finding.Category != securityv1alpha1.CategoryPodSecurity {
			t.Errorf("%s category = %q", finding.ID, finding.Category)
		}
		if finding.Message == "" {
			t.Errorf("%s has no message", finding.ID)
		}
	}
}

func TestEveryUpstreamCheckIsMapped(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("building source: %v", err)
	}

	for _, check := range source.checks {
		if _, known := rules[check.id]; !known {
			t.Errorf("upstream check %q has no KubeGuardian rule mapping, so its findings would be dropped", check.id)
		}
	}
}

func TestRuleTableIsWellFormed(t *testing.T) {
	for id, mapped := range rules {
		if mapped.id == "" || mapped.severity == "" {
			t.Errorf("%s is missing an id or severity", id)
		}
		if mapped.suggestion == "" || mapped.remediation == "" {
			t.Errorf("%s is missing a suggestion or remediation", id)
		}
	}
}
