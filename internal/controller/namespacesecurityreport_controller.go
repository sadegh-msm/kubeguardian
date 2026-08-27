package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/scoring"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
	"github.com/sadegh-msm/kubeguardian/internal/sources"
)

type NamespaceSecurityReportReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	Sources            []sources.Source
	RescanInterval     time.Duration
	MinSeverity        securityv1alpha1.Severity
	ExcludedNamespaces []string
}

// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=namespacesecurityreports/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts;resourcequotas;limitranges,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch

func (r *NamespaceSecurityReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var namespace corev1.Namespace
	if err := r.Get(ctx, req.NamespacedName, &namespace); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !namespace.DeletionTimestamp.IsZero() || r.isExcluded(namespace.Name) {
		return ctrl.Result{}, nil
	}

	snap, err := snapshot.Collect(ctx, r.Client, namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("collect snapshot for namespace %s: %w", namespace.Name, err)
	}

	findings, scanErr := r.runSources(ctx, snap)
	if scanErr != nil {
		if reportErr := r.recordScanFailure(ctx, namespace, scanErr); reportErr != nil {
			log.Error(reportErr, "recording scan failure", "namespace", namespace.Name)
		}
		return ctrl.Result{}, scanErr
	}

	findings = sources.Normalize(findings, r.minSeverity())
	score, summary := scoring.Compute(findings)

	report, err := r.ensureReport(ctx, namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.writeStatus(ctx, report, findings, score, summary); err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("namespace scanned", "namespace", namespace.Name, "score", score, "findings", len(findings))
	return ctrl.Result{RequeueAfter: r.rescanInterval()}, nil
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

func (r *NamespaceSecurityReportReconciler) ensureReport(ctx context.Context, namespace corev1.Namespace) (*securityv1alpha1.NamespaceSecurityReport, error) {
	report := &securityv1alpha1.NamespaceSecurityReport{ObjectMeta: metav1.ObjectMeta{Name: namespace.Name}}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, report, func() error {
		report.Spec.NamespaceRef = namespace.Name
		return controllerutil.SetControllerReference(&namespace, report, r.Scheme)
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile report for namespace %s: %w", namespace.Name, err)
	}
	return report, nil
}

func (r *NamespaceSecurityReportReconciler) writeStatus(
	ctx context.Context,
	report *securityv1alpha1.NamespaceSecurityReport,
	findings []securityv1alpha1.Finding,
	score int,
	summary securityv1alpha1.SeveritySummary,
) error {
	unchanged := report.Status.Score == score &&
		apiequality.Semantic.DeepEqual(report.Status.Summary, summary) &&
		apiequality.Semantic.DeepEqual(report.Status.Findings, findings)

	if unchanged && time.Since(report.Status.LastScanTime.Time) < r.rescanInterval() {
		return nil
	}

	patch := client.MergeFrom(report.DeepCopy())
	report.Status.Score = score
	report.Status.Summary = summary
	report.Status.Findings = findings
	report.Status.LastScanTime = metav1.Now()
	report.Status.ObservedGeneration = report.Generation
	meta.SetStatusCondition(&report.Status.Conditions, metav1.Condition{
		Type:    securityv1alpha1.ConditionScanSucceeded,
		Status:  metav1.ConditionTrue,
		Reason:  securityv1alpha1.ReasonScanCompleted,
		Message: fmt.Sprintf("%d finding(s) across %d severity level(s)", summary.Total, distinctSeverities(summary)),
	})

	if err := r.Status().Patch(ctx, report, patch); err != nil {
		return fmt.Errorf("patch status of report %s: %w", report.Name, err)
	}
	return nil
}

func (r *NamespaceSecurityReportReconciler) recordScanFailure(ctx context.Context, namespace corev1.Namespace, scanErr error) error {
	report, err := r.ensureReport(ctx, namespace)
	if err != nil {
		return err
	}

	patch := client.MergeFrom(report.DeepCopy())
	meta.SetStatusCondition(&report.Status.Conditions, metav1.Condition{
		Type:    securityv1alpha1.ConditionScanSucceeded,
		Status:  metav1.ConditionFalse,
		Reason:  securityv1alpha1.ReasonScanFailed,
		Message: scanErr.Error(),
	})
	return r.Status().Patch(ctx, report, patch)
}

func (r *NamespaceSecurityReportReconciler) isExcluded(name string) bool {
	return slices.Contains(r.ExcludedNamespaces, name)
}

func (r *NamespaceSecurityReportReconciler) rescanInterval() time.Duration {
	if r.RescanInterval <= 0 {
		return 10 * time.Minute
	}
	return r.RescanInterval
}

func (r *NamespaceSecurityReportReconciler) minSeverity() securityv1alpha1.Severity {
	if r.MinSeverity == "" {
		return securityv1alpha1.SeverityLow
	}
	return r.MinSeverity
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

func (r *NamespaceSecurityReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	workloadPredicate := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	toNamespace := handler.EnqueueRequestsFromMapFunc(mapToNamespace)

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Owns(&securityv1alpha1.NamespaceSecurityReport{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(event.UpdateEvent) bool { return false },
		})).
		Watches(&appsv1.Deployment{}, toNamespace, workloadPredicate).
		Watches(&appsv1.StatefulSet{}, toNamespace, workloadPredicate).
		Watches(&appsv1.DaemonSet{}, toNamespace, workloadPredicate).
		Watches(&batchv1.CronJob{}, toNamespace, workloadPredicate).
		Watches(&networkingv1.NetworkPolicy{}, toNamespace).
		Watches(&rbacv1.Role{}, toNamespace).
		Watches(&corev1.ServiceAccount{}, toNamespace).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Named("namespacesecurityreport").
		Complete(r)
}
