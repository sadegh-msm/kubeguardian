package sources_test

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
	"github.com/sadegh-msm/kubeguardian/internal/sources"
	"github.com/sadegh-msm/kubeguardian/internal/sources/podsecurity"
)

func benchSnapshot(n int) *snapshot.Snapshot {
	deployments := make([]appsv1.Deployment, 0, n)
	for i := range n {
		deployments = append(deployments, appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("app-%d", i), Namespace: "bench"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					HostNetwork: i%3 == 0,
					Containers: []corev1.Container{{
						Name:  "api",
						Image: "registry.example.com/app",
						SecurityContext: &corev1.SecurityContext{
							Privileged: func() *bool { b := i%5 == 0; return &b }(),
						},
					}},
				},
			}},
		})
	}
	return &snapshot.Snapshot{
		Namespace:   corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "bench"}},
		Deployments: deployments,
	}
}

func benchScan(b *testing.B, n int) {
	snap := benchSnapshot(n)
	ps, err := podsecurity.New()
	if err != nil {
		b.Fatal(err)
	}
	all := []sources.Source{ps}
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		var findings []securityv1alpha1.Finding
		for _, s := range all {
			got, err := s.Collect(ctx, snap)
			if err != nil {
				b.Fatal(err)
			}
			findings = append(findings, got...)
		}
		findings = sources.Normalize(findings, securityv1alpha1.SeverityLow)
		findings, _ = sources.Truncate(findings, 200)
		_ = sources.Summarize(findings)
	}
}

func BenchmarkScan10(b *testing.B)   { benchScan(b, 10) }
func BenchmarkScan100(b *testing.B)  { benchScan(b, 100) }
func BenchmarkScan1000(b *testing.B) { benchScan(b, 1000) }

func BenchmarkPodSecurity1000(b *testing.B) {
	snap := benchSnapshot(1000)
	ps, err := podsecurity.New()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ps.Collect(context.Background(), snap); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalize1000(b *testing.B) {
	snap := benchSnapshot(1000)
	ps, _ := podsecurity.New()
	raw, _ := ps.Collect(context.Background(), snap)
	b.ReportAllocs()
	for b.Loop() {
		_ = sources.Normalize(raw, securityv1alpha1.SeverityLow)
	}
}
