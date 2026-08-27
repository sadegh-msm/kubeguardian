package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const mappingNamespace = "demo"

func TestMapToNamespace(t *testing.T) {
	cases := []struct {
		name   string
		object client.Object
		want   string
	}{
		{
			name:   "deployment maps to its namespace",
			object: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments"}},
			want:   "payments",
		},
		{
			name:   "service account maps to its namespace",
			object: &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: mappingNamespace}},
			want:   mappingNamespace,
		},
		{
			name:   "cluster scoped object produces no request",
			object: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mappingNamespace}},
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := mapToNamespace(context.Background(), tc.object)

			if tc.want == "" {
				if len(requests) != 0 {
					t.Fatalf("got %d requests, want none", len(requests))
				}
				return
			}

			if len(requests) != 1 {
				t.Fatalf("got %d requests, want 1", len(requests))
			}
			if requests[0].Name != tc.want {
				t.Fatalf("got namespace %q, want %q", requests[0].Name, tc.want)
			}
			if requests[0].Namespace != "" {
				t.Fatalf("request must be cluster scoped, got namespace %q", requests[0].Namespace)
			}
		})
	}
}
