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
	"context"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

// ManifestSecurityReportReconciler reconciles a ManifestSecurityReport object
type ManifestSecurityReportReconciler struct {
	Scanner
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=manifestsecurityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=manifestsecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=manifestsecurityreports/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=scanexceptions;securitychecks,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *ManifestSecurityReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var report securityv1alpha1.ManifestSecurityReport
	if err := r.Get(ctx, req.NamespacedName, &report); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return r.reconcile(ctx, &report, "ManifestSecurityReport")
}

func (r *ManifestSecurityReportReconciler) reportsIn(ctx context.Context, namespace string) []reconcile.Request {
	if namespace == "" {
		return nil
	}

	var reports securityv1alpha1.ManifestSecurityReportList
	if err := r.List(ctx, &reports, client.InNamespace(namespace)); err != nil {
		logf.FromContext(ctx).Error(err, "listing manifest reports", "namespace", namespace)
		return nil
	}
	return requestsFor(reports.Items)
}

func (r *ManifestSecurityReportReconciler) reportsForWorkload(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsIn(ctx, obj.GetNamespace())
}

func (r *ManifestSecurityReportReconciler) reportsForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsIn(ctx, obj.GetName())
}

func (r *ManifestSecurityReportReconciler) reportsForException(ctx context.Context, obj client.Object) []reconcile.Request {
	return requestsForException(ctx, obj, r.reportsIn, r.allReports)
}

func (r *ManifestSecurityReportReconciler) allReports(ctx context.Context, _ client.Object) []reconcile.Request {
	var reports securityv1alpha1.ManifestSecurityReportList
	if err := r.List(ctx, &reports); err != nil {
		logf.FromContext(ctx).Error(err, "listing manifest reports for exception fan-out")
		return nil
	}
	return requestsFor(reports.Items)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ManifestSecurityReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	workloadPredicate := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	toReports := handler.EnqueueRequestsFromMapFunc(r.reportsForWorkload)

	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ManifestSecurityReport{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.reportsForNamespace)).
		Watches(&appsv1.Deployment{}, toReports, workloadPredicate).
		Watches(&appsv1.StatefulSet{}, toReports, workloadPredicate).
		Watches(&appsv1.DaemonSet{}, toReports, workloadPredicate).
		Watches(&batchv1.CronJob{}, toReports, workloadPredicate).
		Watches(&networkingv1.NetworkPolicy{}, toReports).
		Watches(&rbacv1.Role{}, toReports).
		Watches(&corev1.ServiceAccount{}, toReports).
		Watches(&securityv1alpha1.ScanException{}, handler.EnqueueRequestsFromMapFunc(r.reportsForException)).
		Watches(&securityv1alpha1.SecurityCheck{}, handler.EnqueueRequestsFromMapFunc(r.allReports)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Named("manifestsecurityreport").
		Complete(r)
}
