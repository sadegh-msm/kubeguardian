package policy

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func TestSmoke(t *testing.T) {
	spec := securityv1alpha1.SecurityCheckSpec{
		ID: "KG-007", Severity: "Medium", Category: "PodSecurity",
		Scope:     securityv1alpha1.ScopeContainer,
		Violation: `!container.securityContext.readOnlyRootFilesystem`,
		Message: `container "${container.name}" in ${workload.kind}/${workload.name} ` +
			`can write to its root filesystem (tag=${imageTag}, index=${containerIndex})`,
		Suggestion:  "Set readOnlyRootFilesystem to true.",
		Remediation: "securityContext:\n  readOnlyRootFilesystem: true",
	}

	compiled, err := Compile(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	snap := &snapshot.Snapshot{
		Namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: testContainer, Namespace: testNamespace},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "writable", Image: "registry:5000/app:1.2"},
					{Name: "locked", Image: "app@sha256:abc", SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem: func() *bool { b := true; return &b }()}},
				},
			}}},
		}},
	}

	findings, err := Evaluate(compiled, snap)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, f := range findings {
		t.Logf("%s %s %s | %s", f.ID, f.Severity, f.Resource.String(), f.Message)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}
