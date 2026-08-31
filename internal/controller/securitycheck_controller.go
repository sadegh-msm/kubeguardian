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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/policy"
)

// SecurityCheckReconciler compiles a SecurityCheck and reports whether it worked.
// It does not gate evaluation; the policy source compiles on demand from the same
// registry. This exists so an author of a broken expression finds out from the
// object they just applied rather than from a report that quietly lost a check.
type SecurityCheckReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Registry *policy.Registry
}

// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=securitychecks,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.kubeguardian.io,resources=securitychecks/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *SecurityCheckReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var check securityv1alpha1.SecurityCheck
	if err := r.Get(ctx, req.NamespacedName, &check); err != nil {
		if apierrors.IsNotFound(err) {
			r.Registry.Forget(req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	condition := metav1.Condition{
		Type:    securityv1alpha1.ConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  securityv1alpha1.ReasonCompiled,
		Message: "every expression compiled",
	}
	if _, err := r.Registry.Get(&check); err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = securityv1alpha1.ReasonCompileFailed
		condition.Message = err.Error()
	}

	return ctrl.Result{}, r.writeStatus(ctx, req, condition)
}

func (r *SecurityCheckReconciler) writeStatus(ctx context.Context, req ctrl.Request, condition metav1.Condition) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current securityv1alpha1.SecurityCheck
		if err := r.Get(ctx, req.NamespacedName, &current); err != nil {
			return client.IgnoreNotFound(err)
		}
		current.Status.ObservedGeneration = current.Generation
		meta.SetStatusCondition(&current.Status.Conditions, condition)
		return r.Status().Update(ctx, &current)
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecurityCheckReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.SecurityCheck{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("securitycheck").
		Complete(r)
}
