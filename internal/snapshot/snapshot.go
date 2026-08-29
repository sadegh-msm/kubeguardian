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
	Template *corev1.PodTemplateSpec

	containers []corev1.Container
}

func newWorkload(kind, name string, template *corev1.PodTemplateSpec) Workload {
	spec := &template.Spec
	containers := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	containers = append(containers, spec.InitContainers...)
	containers = append(containers, spec.Containers...)

	return Workload{Kind: kind, Name: name, Template: template, containers: containers}
}

func (w Workload) Ref() (string, string) {
	return w.Kind, w.Name
}

func (w Workload) Containers() []corev1.Container {
	return w.containers
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

	workloads []Workload
}

func (s *Snapshot) Name() string {
	return s.Namespace.Name
}

func (s *Snapshot) Workloads() []Workload {
	if s.workloads != nil {
		return s.workloads
	}

	workloads := make([]Workload, 0, len(s.Deployments)+len(s.StatefulSets)+len(s.DaemonSets)+len(s.CronJobs))
	for i := range s.Deployments {
		d := &s.Deployments[i]
		workloads = append(workloads, newWorkload("Deployment", d.Name, &d.Spec.Template))
	}
	for i := range s.StatefulSets {
		set := &s.StatefulSets[i]
		workloads = append(workloads, newWorkload("StatefulSet", set.Name, &set.Spec.Template))
	}
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		workloads = append(workloads, newWorkload("DaemonSet", d.Name, &d.Spec.Template))
	}
	for i := range s.CronJobs {
		c := &s.CronJobs[i]
		workloads = append(workloads, newWorkload("CronJob", c.Name, &c.Spec.JobTemplate.Spec.Template))
	}

	s.workloads = workloads
	return s.workloads
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
	}

	for _, entry := range lists {
		if err := c.List(ctx, entry.list, inNamespace); err != nil {
			return nil, fmt.Errorf("list %s in namespace %s: %w", entry.kind, namespace.Name, err)
		}
		entry.assign(entry.list)
	}

	return snap, nil
}
