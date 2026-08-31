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
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const reportName = "posture"

func TestRequestsForExceptionOnlyWakesNamespacesItNames(t *testing.T) {
	// Stands in for the whole cluster. Anything that reaches everywhere is the
	// stampede this exists to avoid.
	everywhere := func(_ context.Context, _ client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{Namespace: "a", Name: reportName}},
			{NamespacedName: types.NamespacedName{Namespace: "b", Name: reportName}},
			{NamespacedName: types.NamespacedName{Namespace: "c", Name: reportName}},
		}
	}
	inNamespace := func(_ context.Context, namespace string) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{Namespace: namespace, Name: reportName}},
		}
	}

	exception := func(spec securityv1alpha1.ScanExceptionSpec) *securityv1alpha1.ScanException {
		return &securityv1alpha1.ScanException{
			ObjectMeta: metav1.ObjectMeta{Name: "accepted"},
			Spec:       spec,
		}
	}

	cases := []struct {
		name   string
		object client.Object
		want   []string
	}{
		{
			name:   "one named namespace wakes only that report",
			object: exception(securityv1alpha1.ScanExceptionSpec{Namespaces: []string{"b"}}),
			want:   []string{"b"},
		},
		{
			name:   "several named namespaces wake exactly those",
			object: exception(securityv1alpha1.ScanExceptionSpec{Namespaces: []string{"a", "c"}}),
			want:   []string{"a", "c"},
		},
		{
			name:   "no namespaces means it matches anywhere, so everything wakes",
			object: exception(securityv1alpha1.ScanExceptionSpec{}),
			want:   []string{"a", "b", "c"},
		},
		{
			name: "a selector has to be resolved against every namespace anyway",
			object: exception(securityv1alpha1.ScanExceptionSpec{
				Namespaces:        []string{"b"},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "platform"}},
			}),
			want: []string{"a", "b", "c"},
		},
		{
			name:   "anything that is not an exception falls back to waking everything",
			object: &securityv1alpha1.SecurityCheck{ObjectMeta: metav1.ObjectMeta{Name: "kg011"}},
			want:   []string{"a", "b", "c"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := requestsForException(context.Background(), tc.object, inNamespace, everywhere)

			namespaces := make([]string, 0, len(got))
			for _, request := range got {
				namespaces = append(namespaces, request.Namespace)
			}
			slices.Sort(namespaces)

			if !slices.Equal(namespaces, tc.want) {
				t.Errorf("woke %v, want %v", namespaces, tc.want)
			}
		})
	}
}
