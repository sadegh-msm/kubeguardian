package policy

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func benchSnapshot(workloads int) *snapshot.Snapshot {
	snap := &snapshot.Snapshot{Namespace: namespaceWith(nil)}
	for i := range workloads {
		snap.Deployments = append(snap.Deployments, deploymentWith(
			fmt.Sprintf("app-%d", i),
			[]corev1.Container{{Name: testContainer, Image: "registry.example.com/app"}},
			corev1.PodSpec{},
		))
	}
	snap.ServiceAccounts = []corev1.ServiceAccount{{ObjectMeta: metadataFor(defaultAccount)}}
	return snap
}

// benchmarkShippedPolicies measures what the manifest half of a scan now costs:
// the nine shipped checks compiled once, then evaluated over a namespace. The Go
// checks these replaced ran at 2.25 ms and 6.5 MB for 1000 workloads.
func benchmarkShippedPolicies(b *testing.B, workloads int) {
	policies := loadPoliciesB(b)
	compiled := make([]*Compiled, 0, len(policies))
	for i := range policies {
		program, err := Compile(policies[i].Spec)
		if err != nil {
			b.Fatalf("%s: %v", policies[i].Name, err)
		}
		compiled = append(compiled, program)
	}

	snap := benchSnapshot(workloads)

	b.ReportAllocs()
	for b.Loop() {
		evaluation := NewContext(snap)

		var findings []securityv1alpha1.Finding
		for _, program := range compiled {
			got, err := evaluation.Evaluate(program)
			if err != nil {
				b.Fatal(err)
			}
			findings = append(findings, got...)
		}
		if len(findings) == 0 {
			b.Fatal("expected findings")
		}
	}
}

func BenchmarkPolicies10(b *testing.B)   { benchmarkShippedPolicies(b, 10) }
func BenchmarkPolicies100(b *testing.B)  { benchmarkShippedPolicies(b, 100) }
func BenchmarkPolicies1000(b *testing.B) { benchmarkShippedPolicies(b, 1000) }

// BenchmarkCompile is why the Registry exists: compiling is orders of magnitude
// more expensive than evaluating, so it must not happen per scan.
func BenchmarkCompile(b *testing.B) {
	policies := loadPoliciesB(b)
	b.ReportAllocs()
	for b.Loop() {
		for i := range policies {
			if _, err := Compile(policies[i].Spec); err != nil {
				b.Fatal(err)
			}
		}
	}
}
