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
	"fmt"
	"math/rand/v2"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/exceptions"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
	"github.com/sadegh-msm/kubeguardian/internal/sources"
)

const namespaceRefIndex = "spec.namespaceRef"

// NamespaceSecurityReportReconciler reconciles a NamespaceSecurityReport object
type NamespaceSecurityReportReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Sources        []sources.Source
	RescanInterval time.Duration
	MinSeverity    securityv1alpha1.Severity
	MaxFindings    int
}

// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=scanexceptions,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports;exposedsecretreports,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts;resourcequotas;limitranges,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *NamespaceSecurityReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var report securityv1alpha1.NamespaceSecurityReport
	if err := r.Get(ctx, req.NamespacedName, &report); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !report.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: report.Spec.NamespaceRef}, &namespace); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("referenced namespace does not exist", "report", report.Name, "namespace", report.Spec.NamespaceRef)
			return ctrl.Result{RequeueAfter: r.requeueAfter()}, r.recordNamespaceMissing(ctx, &report)
		}
		return ctrl.Result{}, fmt.Errorf("get namespace %s: %w", report.Spec.NamespaceRef, err)
	}

	snap, err := snapshot.Collect(ctx, r.Client, namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("collect snapshot for namespace %s: %w", namespace.Name, err)
	}

	findings, scanErr := r.runSources(ctx, snap)
	if scanErr != nil {
		if reportErr := r.recordScanFailure(ctx, &report, scanErr); reportErr != nil {
			log.Error(reportErr, "recording scan failure", "report", report.Name)
		}
		return ctrl.Result{}, scanErr
	}

	findings = sources.Normalize(findings, r.minSeverity())

	accepted, err := exceptions.Load(ctx, r.Client, time.Now())
	if err != nil {
		return ctrl.Result{}, err
	}
	findings = accepted.Apply(namespace, findings)

	findings, omitted := sources.Truncate(findings, r.MaxFindings)
	summary := sources.Summarize(findings)

	if err := r.writeStatus(ctx, &report, findings, summary, omitted); err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("namespace scanned", "namespace", namespace.Name,
		"findings", summary.Total, "suppressed", summary.Suppressed)
	return ctrl.Result{RequeueAfter: r.requeueAfter()}, nil
}

func (r *NamespaceSecurityReportReconciler) runSources(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	var findings []securityv1alpha1.Finding
	for _, source := range r.Sources {
		collected, err := source.Collect(ctx, snap)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", source.Name(), err)
		}
		findings = append(findings, collected...)
	}
	return findings, nil
}

func (r *NamespaceSecurityReportReconciler) writeStatus(
	ctx context.Context,
	report *securityv1alpha1.NamespaceSecurityReport,
	findings []securityv1alpha1.Finding,
	summary securityv1alpha1.SeveritySummary,
	omitted int,
) error {
	err := r.updateStatus(ctx, report, func(current *securityv1alpha1.NamespaceSecurityReport) {
		current.Status.Summary = summary
		current.Status.Findings = findings
		current.Status.LastScanTime = metav1.Now()
		current.Status.ObservedGeneration = current.Generation
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionTrue,
			Reason:  securityv1alpha1.ReasonScanCompleted,
			Message: scanMessage(summary, omitted),
		})
	})
	if err != nil {
		return fmt.Errorf("update status of report %s: %w", report.Name, err)
	}
	return nil
}

func (r *NamespaceSecurityReportReconciler) recordScanFailure(
	ctx context.Context,
	report *securityv1alpha1.NamespaceSecurityReport,
	scanErr error,
) error {
	return r.updateStatus(ctx, report, func(current *securityv1alpha1.NamespaceSecurityReport) {
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  securityv1alpha1.ReasonScanFailed,
			Message: scanErr.Error(),
		})
	})
}

func (r *NamespaceSecurityReportReconciler) recordNamespaceMissing(
	ctx context.Context,
	report *securityv1alpha1.NamespaceSecurityReport,
) error {
	return r.updateStatus(ctx, report, func(current *securityv1alpha1.NamespaceSecurityReport) {
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  securityv1alpha1.ReasonNamespaceNotFound,
			Message: fmt.Sprintf("namespace %q does not exist", current.Spec.NamespaceRef),
		})
	})
}

func (r *NamespaceSecurityReportReconciler) updateStatus(
	ctx context.Context,
	report *securityv1alpha1.NamespaceSecurityReport,
	mutate func(*securityv1alpha1.NamespaceSecurityReport),
) error {
	key := client.ObjectKeyFromObject(report)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &securityv1alpha1.NamespaceSecurityReport{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		mutate(current)
		return r.Status().Update(ctx, current)
	})
}

func (r *NamespaceSecurityReportReconciler) rescanInterval() time.Duration {
	if r.RescanInterval <= 0 {
		return 10 * time.Minute
	}
	return r.RescanInterval
}

func (r *NamespaceSecurityReportReconciler) requeueAfter() time.Duration {
	base := r.rescanInterval()
	spread := int64(base) / 5
	if spread <= 0 {
		return base
	}
	return base - time.Duration(spread/2) + time.Duration(rand.Int64N(spread))
}

func (r *NamespaceSecurityReportReconciler) minSeverity() securityv1alpha1.Severity {
	if r.MinSeverity == "" {
		return securityv1alpha1.SeverityLow
	}
	return r.MinSeverity
}

func scanMessage(summary securityv1alpha1.SeveritySummary, omitted int) string {
	message := fmt.Sprintf("%d finding(s) across %d severity level(s)", summary.Total, distinctSeverities(summary))
	if summary.Suppressed > 0 {
		message += fmt.Sprintf(", %d suppressed by exception", summary.Suppressed)
	}
	if omitted > 0 {
		message += fmt.Sprintf(", %d omitted by --max-findings", omitted)
	}
	return message
}

func distinctSeverities(summary securityv1alpha1.SeveritySummary) int {
	count := 0
	for _, value := range []int{summary.Critical, summary.High, summary.Medium, summary.Low} {
		if value > 0 {
			count++
		}
	}
	return count
}

func (r *NamespaceSecurityReportReconciler) reportsFor(ctx context.Context, namespace string) []reconcile.Request {
	if namespace == "" {
		return nil
	}

	var reports securityv1alpha1.NamespaceSecurityReportList
	if err := r.List(ctx, &reports, client.MatchingFields{namespaceRefIndex: namespace}); err != nil {
		logf.FromContext(ctx).Error(err, "listing reports for namespace", "namespace", namespace)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(reports.Items))
	for _, report := range reports.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: report.Name}})
	}
	return requests
}

func (r *NamespaceSecurityReportReconciler) reportsForWorkload(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsFor(ctx, obj.GetNamespace())
}

func (r *NamespaceSecurityReportReconciler) reportsForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.reportsFor(ctx, obj.GetName())
}

func (r *NamespaceSecurityReportReconciler) allReports(ctx context.Context, _ client.Object) []reconcile.Request {
	var reports securityv1alpha1.NamespaceSecurityReportList
	if err := r.List(ctx, &reports); err != nil {
		logf.FromContext(ctx).Error(err, "listing reports for exception fan-out")
		return nil
	}

	requests := make([]reconcile.Request, 0, len(reports.Items))
	for _, report := range reports.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: report.Name}})
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *NamespaceSecurityReportReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	indexer := func(obj client.Object) []string {
		report, ok := obj.(*securityv1alpha1.NamespaceSecurityReport)
		if !ok || report.Spec.NamespaceRef == "" {
			return nil
		}
		return []string{report.Spec.NamespaceRef}
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &securityv1alpha1.NamespaceSecurityReport{}, namespaceRefIndex, indexer); err != nil {
		return fmt.Errorf("index reports by %s: %w", namespaceRefIndex, err)
	}

	workloadPredicate := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	toReports := handler.EnqueueRequestsFromMapFunc(r.reportsForWorkload)

	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.NamespaceSecurityReport{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.reportsForNamespace)).
		Watches(&appsv1.Deployment{}, toReports, workloadPredicate).
		Watches(&appsv1.StatefulSet{}, toReports, workloadPredicate).
		Watches(&appsv1.DaemonSet{}, toReports, workloadPredicate).
		Watches(&batchv1.CronJob{}, toReports, workloadPredicate).
		Watches(&networkingv1.NetworkPolicy{}, toReports).
		Watches(&rbacv1.Role{}, toReports).
		Watches(&corev1.ServiceAccount{}, toReports).
		Watches(&securityv1alpha1.ScanException{}, handler.EnqueueRequestsFromMapFunc(r.allReports)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Named("namespacesecurityreport").
		Complete(r)
}
