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

package controller

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CacheOptions configures what the manager keeps in memory.
//
// The cache is necessarily cluster-wide: a report can be created in any namespace
// at any time, and a cache's namespace set is fixed at startup. That makes its
// size the operator's main constraint on a cluster with many namespaces, so the
// objects it holds are stripped down to what the checks actually read.
//
// Report types are deliberately absent from ByObject. Scanner.updateStatus reads
// a report's status back through this cache inside its conflict-retry loop, so
// stripping status there would break writing a report rather than save anything.
func CacheOptions() cache.Options {
	watched := cache.ByObject{Transform: stripUnreadFields}

	return cache.Options{
		DefaultTransform: cache.TransformStripManagedFields(),
		ByObject: map[client.Object]cache.ByObject{
			&appsv1.Deployment{}:          watched,
			&appsv1.StatefulSet{}:         watched,
			&appsv1.DaemonSet{}:           watched,
			&batchv1.CronJob{}:            watched,
			&corev1.Namespace{}:           watched,
			&corev1.ServiceAccount{}:      watched,
			&networkingv1.NetworkPolicy{}: watched,
			&rbacv1.Role{}:                watched,
		},
	}
}

// stripUnreadFields drops the parts of a watched object no check consults. A
// per-type transform replaces DefaultTransform rather than running alongside it,
// so this strips managed fields too.
//
// Status is the largest of them, at roughly a tenth of the bytes on this
// cluster, and no check reads any of it. The last-applied-configuration
// annotation is a second copy of the whole object.
func stripUnreadFields(object any) (any, error) {
	metadata, err := meta.Accessor(object)
	if err != nil {
		return object, nil
	}

	metadata.SetManagedFields(nil)
	if annotations := metadata.GetAnnotations(); annotations != nil {
		delete(annotations, corev1.LastAppliedConfigAnnotation)
		metadata.SetAnnotations(annotations)
	}

	switch typed := object.(type) {
	case *appsv1.Deployment:
		typed.Status = appsv1.DeploymentStatus{}
	case *appsv1.StatefulSet:
		typed.Status = appsv1.StatefulSetStatus{}
	case *appsv1.DaemonSet:
		typed.Status = appsv1.DaemonSetStatus{}
	case *batchv1.CronJob:
		typed.Status = batchv1.CronJobStatus{}
	case *corev1.Namespace:
		// Phase is the only field here, and the reconciler uses
		// DeletionTimestamp rather than Phase to decide a namespace is going away.
		typed.Status = corev1.NamespaceStatus{}
	case *corev1.ServiceAccount, *networkingv1.NetworkPolicy, *rbacv1.Role:
		// No status worth clearing: ServiceAccount and Role have none, and
		// NetworkPolicy's is deprecated and unset in practice.
	}

	return object, nil
}
