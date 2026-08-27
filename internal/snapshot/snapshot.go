package snapshot

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Workload struct {
	Kind     string
	Name     string
	Template corev1.PodTemplateSpec
}

func (w Workload) Ref() (string, string) {
	return w.Kind, w.Name
}

func (w Workload) Containers() []corev1.Container {
	spec := w.Template.Spec
	all := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	all = append(all, spec.InitContainers...)
	return append(all, spec.Containers...)
}

type Snapshot struct {
	Namespace       corev1.Namespace
	Deployments     []appsv1.Deployment
	StatefulSets    []appsv1.StatefulSet
	DaemonSets      []appsv1.DaemonSet
	CronJobs        []batchv1.CronJob
	NetworkPolicies []networkingv1.NetworkPolicy
	ServiceAccounts []corev1.ServiceAccount
	Roles           []rbacv1.Role
	RoleBindings    []rbacv1.RoleBinding
	ResourceQuotas  []corev1.ResourceQuota
	LimitRanges     []corev1.LimitRange
}

func (s *Snapshot) Name() string {
	return s.Namespace.Name
}

func (s *Snapshot) Workloads() []Workload {
	workloads := make([]Workload, 0, len(s.Deployments)+len(s.StatefulSets)+len(s.DaemonSets)+len(s.CronJobs))
	for _, d := range s.Deployments {
		workloads = append(workloads, Workload{Kind: "Deployment", Name: d.Name, Template: d.Spec.Template})
	}
	for _, s := range s.StatefulSets {
		workloads = append(workloads, Workload{Kind: "StatefulSet", Name: s.Name, Template: s.Spec.Template})
	}
	for _, d := range s.DaemonSets {
		workloads = append(workloads, Workload{Kind: "DaemonSet", Name: d.Name, Template: d.Spec.Template})
	}
	for _, c := range s.CronJobs {
		workloads = append(workloads, Workload{Kind: "CronJob", Name: c.Name, Template: c.Spec.JobTemplate.Spec.Template})
	}
	return workloads
}

func Collect(ctx context.Context, c client.Reader, namespace corev1.Namespace) (*Snapshot, error) {
	snap := &Snapshot{Namespace: namespace}
	inNamespace := client.InNamespace(namespace.Name)

	lists := []struct {
		kind   string
		list   client.ObjectList
		assign func(client.ObjectList)
	}{
		{"Deployment", &appsv1.DeploymentList{}, func(l client.ObjectList) {
			snap.Deployments = l.(*appsv1.DeploymentList).Items
		}},
		{"StatefulSet", &appsv1.StatefulSetList{}, func(l client.ObjectList) {
			snap.StatefulSets = l.(*appsv1.StatefulSetList).Items
		}},
		{"DaemonSet", &appsv1.DaemonSetList{}, func(l client.ObjectList) {
			snap.DaemonSets = l.(*appsv1.DaemonSetList).Items
		}},
		{"CronJob", &batchv1.CronJobList{}, func(l client.ObjectList) {
			snap.CronJobs = l.(*batchv1.CronJobList).Items
		}},
		{"NetworkPolicy", &networkingv1.NetworkPolicyList{}, func(l client.ObjectList) {
			snap.NetworkPolicies = l.(*networkingv1.NetworkPolicyList).Items
		}},
		{"ServiceAccount", &corev1.ServiceAccountList{}, func(l client.ObjectList) {
			snap.ServiceAccounts = l.(*corev1.ServiceAccountList).Items
		}},
		{"Role", &rbacv1.RoleList{}, func(l client.ObjectList) {
			snap.Roles = l.(*rbacv1.RoleList).Items
		}},
		{"RoleBinding", &rbacv1.RoleBindingList{}, func(l client.ObjectList) {
			snap.RoleBindings = l.(*rbacv1.RoleBindingList).Items
		}},
		{"ResourceQuota", &corev1.ResourceQuotaList{}, func(l client.ObjectList) {
			snap.ResourceQuotas = l.(*corev1.ResourceQuotaList).Items
		}},
		{"LimitRange", &corev1.LimitRangeList{}, func(l client.ObjectList) {
			snap.LimitRanges = l.(*corev1.LimitRangeList).Items
		}},
	}

	for _, entry := range lists {
		if err := c.List(ctx, entry.list, inNamespace); err != nil {
			return nil, fmt.Errorf("list %s in namespace %s: %w", entry.kind, namespace.Name, err)
		}
		entry.assign(entry.list)
	}

	return snap, nil
}
