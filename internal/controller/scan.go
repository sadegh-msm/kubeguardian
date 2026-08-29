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
	return ctrl.Result{RequeueAfter: s.requeueAfter()}, nil
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

func (s *Scanner) rescanInterval() time.Duration {
	if s.RescanInterval <= 0 {
		return 10 * time.Minute
	}
	return s.RescanInterval
}

func (s *Scanner) requeueAfter() time.Duration {
	base := s.rescanInterval()
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
