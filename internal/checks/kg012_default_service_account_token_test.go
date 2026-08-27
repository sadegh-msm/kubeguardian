package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

func serviceAccount(name string, automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		AutomountServiceAccountToken: automount,
	}
}

func TestDefaultServiceAccountToken(t *testing.T) {
	build := func(spec corev1.PodSpec, accounts ...corev1.ServiceAccount) *snapshot.Snapshot {
		snap := snapshotOf(spec)
		snap.ServiceAccounts = accounts
		return snap
	}

	base := podSpec(secureContainer("api"))

	dedicated := base
	dedicated.ServiceAccountName = "api"

	optedOut := base
	optedOut.AutomountServiceAccountToken = ptr(false)

	cases := []struct {
		name string
		snap *snapshot.Snapshot
		want int
	}{
		{"default account automounts", build(base, serviceAccount("default", nil)), 1},
		{"default account opts out", build(base, serviceAccount("default", ptr(false))), 0},
		{"workload opts out", build(optedOut, serviceAccount("default", nil)), 0},
		{"workload uses dedicated account", build(dedicated, serviceAccount("default", nil)), 0},
		{"account object not collected", build(base), 1},
	}

	check := newDefaultServiceAccountToken()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check.Run(tc.snap); len(got) != tc.want {
				t.Fatalf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}
