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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/exceptions"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
	"github.com/sadegh-msm/kubeguardian/internal/sources"
)

// report is what ManifestSecurityReport and ImageSecurityReport have in common:
// a namespaced object carrying a ReportStatus. It is declared here rather than
// in the API package so the API types stay free of controller-runtime.
type report interface {
	client.Object
	ReportStatus() *securityv1alpha1.ReportStatus
}

// Scanner holds everything the two report controllers do identically. They differ
// only in which sources fill the report in and which objects they watch.
type Scanner struct {
	client.Client
	Sources        []sources.Source
	RescanInterval time.Duration
	MinSeverity    securityv1alpha1.Severity
	MaxFindings    int
}

func (s *Scanner) reconcile(ctx context.Context, obj report, kind string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if !obj.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, nil
	}

	var namespace corev1.Namespace
	if err := s.Get(ctx, types.NamespacedName{Name: obj.GetNamespace()}, &namespace); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !namespace.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	snap, err := snapshot.Collect(ctx, s.Client, namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("collect snapshot for namespace %s: %w", namespace.Name, err)
	}

	findings, scanErr := s.runSources(ctx, snap)
	if scanErr != nil {
		if reportErr := s.recordScanFailure(ctx, obj, scanErr); reportErr != nil {
			log.Error(reportErr, "recording scan failure", "report", obj.GetName())
		}
		return ctrl.Result{}, scanErr
	}

	findings = sources.Normalize(findings, s.minSeverity())

	accepted, err := exceptions.Load(ctx, s.Client, time.Now())
	if err != nil {
		return ctrl.Result{}, err
	}
	findings = accepted.Apply(namespace, findings)

	findings, omitted := sources.Truncate(findings, s.MaxFindings)
	summary := sources.Summarize(findings)

	if err := s.writeStatus(ctx, obj, findings, summary, omitted); err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("namespace scanned", "namespace", namespace.Name, "kind", kind,
		"findings", summary.Total, "suppressed", summary.Suppressed)
	return ctrl.Result{RequeueAfter: s.nextRequeue(accepted.NextExpiry(namespace))}, nil
}

// nextRequeue picks the sooner of the periodic rescan and the moment the next
// exception stops suppressing. A zero RescanInterval means the report is driven
// entirely by events, and then an expiry deadline is the only reason to come
// back on a timer at all.
func (s *Scanner) nextRequeue(deadline *time.Time) time.Duration {
	periodic := s.requeueAfter()
	if deadline == nil {
		return periodic
	}

	until := time.Until(*deadline) + time.Second
	if until > 0 && (periodic == 0 || until < periodic) {
		return until
	}
	return periodic
}

func (s *Scanner) runSources(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	var findings []securityv1alpha1.Finding
	for _, source := range s.Sources {
		collected, err := source.Collect(ctx, snap)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", source.Name(), err)
		}
		findings = append(findings, collected...)
	}
	return findings, nil
}

func (s *Scanner) writeStatus(
	ctx context.Context,
	obj report,
	findings []securityv1alpha1.Finding,
	summary securityv1alpha1.SeveritySummary,
	omitted int,
) error {
	err := s.updateStatus(ctx, obj, func(current report) {
		status := current.ReportStatus()
		status.Summary = summary
		status.Findings = findings
		status.LastScanTime = metav1.Now()
		status.ObservedGeneration = current.GetGeneration()
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionTrue,
			Reason:  securityv1alpha1.ReasonScanCompleted,
			Message: scanMessage(summary, omitted),
		})
	})
	if err != nil {
		return fmt.Errorf("update status of report %s: %w", obj.GetName(), err)
	}
	return nil
}

func (s *Scanner) recordScanFailure(ctx context.Context, obj report, scanErr error) error {
	return s.updateStatus(ctx, obj, func(current report) {
		meta.SetStatusCondition(&current.ReportStatus().Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  securityv1alpha1.ReasonScanFailed,
			Message: scanErr.Error(),
		})
	})
}

func (s *Scanner) recordScannerUnavailable(ctx context.Context, obj report, message string) error {
	return s.updateStatus(ctx, obj, func(current report) {
		status := current.ReportStatus()
		status.Summary = securityv1alpha1.SeveritySummary{}
		status.Findings = nil
		status.LastScanTime = metav1.Now()
		status.ObservedGeneration = current.GetGeneration()
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    securityv1alpha1.ConditionScanSucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  securityv1alpha1.ReasonScannerUnavailable,
			Message: message,
		})
	})
}

func (s *Scanner) updateStatus(ctx context.Context, obj report, mutate func(report)) error {
	key := client.ObjectKeyFromObject(obj)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, ok := obj.DeepCopyObject().(report)
		if !ok {
			return fmt.Errorf("report %T does not deep copy into a report", obj)
		}
		if err := s.Get(ctx, key, current); err != nil {
			return err
		}
		mutate(current)
		return s.Status().Update(ctx, current)
	})
}

// requeueAfter spreads the periodic rescan over ±10% of the interval. Without
// that, reports created together rescan together forever, and the operator
// alternates between doing nothing and scanning every namespace at once. A
// RescanInterval of zero or less turns the periodic rescan off entirely.
func (s *Scanner) requeueAfter() time.Duration {
	if s.RescanInterval <= 0 {
		return 0
	}

	base := s.RescanInterval
	spread := int64(base) / 5
	if spread <= 0 {
		return base
	}
	return base - time.Duration(spread/2) + time.Duration(rand.Int64N(spread))
}

func (s *Scanner) minSeverity() securityv1alpha1.Severity {
	if s.MinSeverity == "" {
		return securityv1alpha1.SeverityLow
	}
	return s.MinSeverity
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

// requestsForException maps a ScanException to the reports it can actually
// change. An exception that names its namespaces cannot affect a report anywhere
// else, and enqueueing every report in the cluster for one kubectl apply is a
// stampede on a cluster with many namespaces.
//
// Anything less specific still fans out: no namespaces at all means it matches
// everywhere, and a namespaceSelector would have to be resolved against every
// namespace to know, which is the work the fan-out was going to do anyway.
func requestsForException(
	ctx context.Context,
	obj client.Object,
	inNamespace func(context.Context, string) []reconcile.Request,
	everywhere func(context.Context, client.Object) []reconcile.Request,
) []reconcile.Request {
	exception, ok := obj.(*securityv1alpha1.ScanException)
	if !ok || exception.Spec.NamespaceSelector != nil || len(exception.Spec.Namespaces) == 0 {
		return everywhere(ctx, obj)
	}

	var requests []reconcile.Request
	for _, namespace := range exception.Spec.Namespaces {
		requests = append(requests, inNamespace(ctx, namespace)...)
	}
	return requests
}

// requestsFor turns the items of either report list into reconcile requests. The
// type parameter is what lets one function serve both kinds; the two lists have
// no common element type.
func requestsFor[T any, PT interface {
	*T
	client.Object
}](items []T) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for i := range items {
		item := PT(&items[i])
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: item.GetNamespace(), Name: item.GetName()},
		})
	}
	return requests
}
