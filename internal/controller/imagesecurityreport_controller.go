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

const scannerUnavailableMessage = "no image scanner is installed in this cluster, so no image data is available. " +
	"Install trivy-operator and restart the KubeGuardian manager."

// ImageSecurityReportReconciler reconciles an ImageSecurityReport object
type ImageSecurityReportReconciler struct {
	Scanner
	Scheme *runtime.Scheme

	// ScannerAvailable records whether an image scanner was found at startup. A
	// report that cannot be filled in says so rather than reading as a clean
	// namespace with no findings.
	ScannerAvailable bool
}

// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=imagesecurityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=imagesecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=imagesecurityreports/finalizers,verbs=update
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports;exposedsecretreports,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *ImageSecurityReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var report securityv1alpha1.ImageSecurityReport
	if err := r.Get(ctx, req.NamespacedName, &report); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !r.ScannerAvailable {
		if report.DeletionTimestamp.IsZero() {
			if err := r.recordScannerUnavailable(ctx, &report, scannerUnavailableMessage); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: r.requeueAfter()}, nil
	}

	return r.reconcile(ctx, &report, "ImageSecurityReport")
}

func (r *ImageSecurityReportReconciler) reportsIn(ctx context.Context, namespace string) []reconcile.Request {
	if namespace == "" {
		return nil
	}

	var reports securityv1alpha1.ImageSecurityReportList
	if err := r.List(ctx, &reports, client.InNamespace(namespace)); err != nil {
		logf.FromContext(ctx).Error(err, "listing image reports", "namespace", namespace)
		return nil
	}
	return requestsFor(reports.Items)
}

func (r *ImageSecurityReportReconciler) reportsForWorkload(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsIn(ctx, obj.GetNamespace())
}

func (r *ImageSecurityReportReconciler) reportsForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsIn(ctx, obj.GetName())
}

func (r *ImageSecurityReportReconciler) reportsForException(ctx context.Context, obj client.Object) []reconcile.Request {
	return requestsForException(ctx, obj, r.reportsIn, r.allReports)
}

func (r *ImageSecurityReportReconciler) allReports(ctx context.Context, _ client.Object) []reconcile.Request {
	var reports securityv1alpha1.ImageSecurityReportList
	if err := r.List(ctx, &reports); err != nil {
		logf.FromContext(ctx).Error(err, "listing image reports for exception fan-out")
		return nil
	}
	return requestsFor(reports.Items)
}

// SetupWithManager sets up the controller with the Manager.
//
// The watches are deliberately narrower than the manifest controller's. A
// NetworkPolicy, Role or ServiceAccount cannot change what is inside an image,
// so those are not watched. The workload watches are the fast path: changing an
// image is a spec change, so the generation moves and the report is rescanned
// immediately. Trivy's own reports cannot be watched because the adapter reads
// them with an uncached client, so new scan data lands within one rescan
// interval instead.
func (r *ImageSecurityReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	workloadPredicate := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	toReports := handler.EnqueueRequestsFromMapFunc(r.reportsForWorkload)

	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ImageSecurityReport{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.reportsForNamespace)).
		Watches(&appsv1.Deployment{}, toReports, workloadPredicate).
		Watches(&appsv1.StatefulSet{}, toReports, workloadPredicate).
		Watches(&appsv1.DaemonSet{}, toReports, workloadPredicate).
		Watches(&batchv1.CronJob{}, toReports, workloadPredicate).
		Watches(&securityv1alpha1.ScanException{}, handler.EnqueueRequestsFromMapFunc(r.reportsForException)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Named("imagesecurityreport").
		Complete(r)
}
