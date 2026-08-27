package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func mapToNamespace(_ context.Context, obj client.Object) []reconcile.Request {
	namespace := obj.GetNamespace()
	if namespace == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: namespace}}}
}
