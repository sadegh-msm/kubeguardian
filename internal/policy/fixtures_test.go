package policy

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	testNamespace  = "demo"
	testContainer  = "api"
	defaultAccount = "default"
)

func boolPtr(v bool) *bool { return &v }

func deploymentWith(name string, containers []corev1.Container, spec corev1.PodSpec) appsv1.Deployment {
	spec.Containers = containers
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
	}
}

func hardenedContainer(name, image string) corev1.Container {
	return corev1.Container{
		Name:  name,
		Image: image,
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: boolPtr(true),
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
		},
	}
}

func metadataFor(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: testNamespace}
}

func namespaceWith(labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, Labels: labels}}
}

func denyAllIngress() networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny-ingress", Namespace: testNamespace},
		Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
	}
}

func equivalenceFixtures() []*snapshot.Snapshot {
	restricted := map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}

	insecure := &snapshot.Snapshot{
		Namespace: namespaceWith(nil),
		Deployments: []appsv1.Deployment{deploymentWith("legacy", []corev1.Container{
			{Name: testContainer, Image: "nginx"},
			{Name: "sidecar", Image: "registry.example.com:5000/proxy:latest"},
		}, corev1.PodSpec{})},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: defaultAccount, Namespace: testNamespace}}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: testNamespace},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
	}

	hardened := &snapshot.Snapshot{
		Namespace: namespaceWith(restricted),
		Deployments: []appsv1.Deployment{deploymentWith(testContainer, []corev1.Container{
			hardenedContainer(testContainer, "registry.example.com/app:1.4.2"),
		}, corev1.PodSpec{
			ServiceAccountName:           testContainer,
			AutomountServiceAccountToken: boolPtr(false),
		})},
		NetworkPolicies: []networkingv1.NetworkPolicy{denyAllIngress()},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: defaultAccount, Namespace: testNamespace}}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: testContainer, Namespace: testNamespace},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
		}},
	}

	privileged := &snapshot.Snapshot{
		Namespace: namespaceWith(map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}),
		Deployments: []appsv1.Deployment{deploymentWith(testContainer, []corev1.Container{
			hardenedContainer(testContainer, "app@sha256:0123456789abcdef"),
		}, corev1.PodSpec{ServiceAccountName: testContainer})},
		NetworkPolicies: []networkingv1.NetworkPolicy{denyAllIngress()},
	}

	partial := &snapshot.Snapshot{
		Namespace: namespaceWith(restricted),
		Deployments: []appsv1.Deployment{deploymentWith(testContainer, []corev1.Container{
			{
				Name:            testContainer,
				Image:           "registry.example.com:5000/app",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: boolPtr(false)},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
				},
			},
		}, corev1.PodSpec{})},
		NetworkPolicies: []networkingv1.NetworkPolicy{denyAllIngress()},
		ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta:                   metav1.ObjectMeta{Name: defaultAccount, Namespace: testNamespace},
			AutomountServiceAccountToken: boolPtr(false),
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: testNamespace},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}},
		}},
	}

	empty := &snapshot.Snapshot{Namespace: namespaceWith(restricted)}

	return []*snapshot.Snapshot{insecure, hardened, privileged, partial, empty}
}
