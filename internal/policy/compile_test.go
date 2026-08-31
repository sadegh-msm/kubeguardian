package policy

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

func specWith(scope securityv1alpha1.Scope, violation string) securityv1alpha1.SecurityCheckSpec {
	return securityv1alpha1.SecurityCheckSpec{
		ID: "TEST-1", Severity: securityv1alpha1.SeverityLow,
		Category: securityv1alpha1.CategoryGovernance, Scope: scope,
		Violation: violation, Message: "m", Suggestion: "s", Remediation: "r",
	}
}

func TestCompileRejectsExpressionsThatDoNotTypeCheck(t *testing.T) {
	cases := []struct {
		name string
		spec securityv1alpha1.SecurityCheckSpec
		want string
	}{
		{
			name: "unknown field",
			spec: specWith(securityv1alpha1.ScopeContainer, "container.securityContxt.privileged"),
			want: "undefined field",
		},
		{
			name: "variable belonging to another scope",
			spec: specWith(securityv1alpha1.ScopeNamespace, "container.name == ''"),
			want: "undeclared reference",
		},
		{
			name: "violation that is not a bool",
			spec: specWith(securityv1alpha1.ScopeNamespace, "namespaceObject.metadata.name"),
			want: "must evaluate to a bool",
		},
		{
			name: "unknown scope",
			spec: specWith("Pod", "true"),
			want: "unknown scope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.spec)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCompileReportsWhichFieldIsBroken(t *testing.T) {
	spec := specWith(securityv1alpha1.ScopeNamespace, "true")
	spec.Message = "namespace ${namespaceObject.nope}"

	_, err := Compile(spec)
	if err == nil || !strings.HasPrefix(err.Error(), "message:") {
		t.Fatalf("got %v, want the error to name the message field", err)
	}
}

func TestCompileRejectsAnUnterminatedInterpolation(t *testing.T) {
	spec := specWith(securityv1alpha1.ScopeNamespace, "true")
	spec.Remediation = "kubectl delete ns ${namespaceObject.metadata.name"

	_, err := Compile(spec)
	if err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("got %v, want an unterminated interpolation error", err)
	}
}

func TestEachScopeBindsOnlyItsOwnSubject(t *testing.T) {
	subjects := map[securityv1alpha1.Scope]string{
		securityv1alpha1.ScopeNamespace:      "namespaceObject",
		securityv1alpha1.ScopeWorkload:       "workload",
		securityv1alpha1.ScopeContainer:      "container",
		securityv1alpha1.ScopeRole:           "role",
		securityv1alpha1.ScopeServiceAccount: "serviceAccount",
	}

	for scope := range subjects {
		t.Run(string(scope), func(t *testing.T) {
			for other, variable := range subjects {
				// Every scope can read the namespace and the collections; the
				// subject variables are what scoping actually restricts.
				if variable == "namespaceObject" {
					continue
				}
				_, err := Compile(specWith(scope, variable+".metadata.name == ''"))
				sameScope := other == scope || (scope == securityv1alpha1.ScopeContainer && other == securityv1alpha1.ScopeWorkload)

				switch {
				case sameScope && err != nil && strings.Contains(err.Error(), "undeclared"):
					t.Errorf("%s should be visible in scope %s: %v", variable, scope, err)
				case !sameScope && err == nil:
					t.Errorf("%s should not be visible in scope %s", variable, scope)
				}
			}
		})
	}
}

func TestEvaluationIsStoppedByTheCostBudget(t *testing.T) {
	// Checks come from whoever runs the cluster, so an expression that walks the
	// namespace quadratically must be stopped rather than allowed to stall a
	// reconcile. The budget is enforced per evaluation, not at compile time,
	// because CEL cannot know how long the lists will be until it has them.
	spec := specWith(securityv1alpha1.ScopeNamespace,
		`workloads.exists(a, workloads.exists(b, a.name == b.name + 'never'))`)

	compiled, err := Compile(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	snap := &snapshot.Snapshot{Namespace: namespaceWith(nil)}
	for i := range 600 {
		snap.Deployments = append(snap.Deployments,
			deploymentWith(fmt.Sprintf("app-%d", i), []corev1.Container{{Name: testContainer, Image: "app:1"}}, corev1.PodSpec{}))
	}

	if _, err := Evaluate(compiled, snap); err == nil {
		t.Fatal("expected the cost budget to stop this evaluation")
	} else if !strings.Contains(err.Error(), "cost limit") {
		t.Fatalf("got %v, want a cost limit error", err)
	}
}
