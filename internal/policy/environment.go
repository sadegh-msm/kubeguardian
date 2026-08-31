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

package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	celklib "k8s.io/apiserver/pkg/cel/library"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

// Workload is the shape a check sees for a Deployment, StatefulSet, DaemonSet or
// CronJob. It is flattened deliberately: spec.containers rather than
// template.spec.containers, so an expression reads the way someone who knows the
// pod API expects.
type Workload struct {
	Kind     string            `json:"kind"`
	Name     string            `json:"name"`
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     corev1.PodSpec    `json:"spec"`
}

// costLimit caps a single evaluation. Checks are supplied by whoever runs the
// cluster rather than compiled in, so an expression that walks every container of
// every workload must not be able to stall a reconcile.
const costLimit = 1_000_000

// variableNamespace is spelled namespaceObject because CEL reserves "namespace"
// as an identifier. ValidatingAdmissionPolicy names it the same way for the same
// reason, so the spelling is at least familiar.
const (
	variableNamespace       = "namespaceObject"
	variableWorkloads       = "workloads"
	variableNetworkPolicies = "networkPolicies"
	variableServiceAccounts = "serviceAccounts"
	variableRoles           = "roles"

	variableWorkload       = "workload"
	variableContainer      = "container"
	variableRole           = "role"
	variableServiceAccount = "serviceAccount"

	variableImageTag       = "imageTag"
	variableImageDigest    = "imageDigest"
	variableContainerIndex = "containerIndex"

	// resource.Quantity keeps its fields unexported, so CEL can see that a limit
	// exists but not what it says. These expose the same two maps with the
	// quantities as strings, which quantity() parses back.
	variableLimits   = "limits"
	variableRequests = "requests"
)

func typeNameOf[T any]() string {
	return reflect.TypeFor[T]().String()
}

// newEnv builds the CEL environment for one scope. Every scope can read the whole
// namespace; the scope only decides which subject is bound on top of that.
func newEnv(scope securityv1alpha1.Scope) (*cel.Env, error) {
	options := []cel.EnvOption{
		ext.NativeTypes(ext.ParseStructTag("json"),
			reflect.TypeFor[Workload](),
			reflect.TypeFor[corev1.Container](),
			reflect.TypeFor[corev1.Namespace](),
			reflect.TypeFor[corev1.ServiceAccount](),
			reflect.TypeFor[networkingv1.NetworkPolicy](),
			reflect.TypeFor[rbacv1.Role](),
		),
		ext.Strings(),
		ext.Lists(),
		celklib.Regex(),
		celklib.Quantity(),
		celklib.Lists(),
		joinFieldsFunction(),

		cel.Variable(variableNamespace, cel.ObjectType(typeNameOf[corev1.Namespace]())),
		cel.Variable(variableWorkloads, cel.ListType(cel.ObjectType(typeNameOf[Workload]()))),
		cel.Variable(variableNetworkPolicies, cel.ListType(cel.ObjectType(typeNameOf[networkingv1.NetworkPolicy]()))),
		cel.Variable(variableServiceAccounts, cel.ListType(cel.ObjectType(typeNameOf[corev1.ServiceAccount]()))),
		cel.Variable(variableRoles, cel.ListType(cel.ObjectType(typeNameOf[rbacv1.Role]()))),
	}

	switch scope {
	case securityv1alpha1.ScopeNamespace:
	case securityv1alpha1.ScopeWorkload:
		options = append(options, cel.Variable(variableWorkload, cel.ObjectType(typeNameOf[Workload]())))
	case securityv1alpha1.ScopeContainer:
		options = append(options,
			cel.Variable(variableWorkload, cel.ObjectType(typeNameOf[Workload]())),
			cel.Variable(variableContainer, cel.ObjectType(typeNameOf[corev1.Container]())),
			cel.Variable(variableImageTag, cel.StringType),
			cel.Variable(variableImageDigest, cel.StringType),
			cel.Variable(variableContainerIndex, cel.IntType),
			cel.Variable(variableLimits, cel.MapType(cel.StringType, cel.StringType)),
			cel.Variable(variableRequests, cel.MapType(cel.StringType, cel.StringType)),
		)
	case securityv1alpha1.ScopeRole:
		options = append(options, cel.Variable(variableRole, cel.ObjectType(typeNameOf[rbacv1.Role]())))
	case securityv1alpha1.ScopeServiceAccount:
		options = append(options, cel.Variable(variableServiceAccount, cel.ObjectType(typeNameOf[corev1.ServiceAccount]())))
	default:
		return nil, fmt.Errorf("unknown scope %q", scope)
	}

	return cel.NewEnv(options...)
}

// joinFieldsFunction renders a list as "a, b and c". Messages name the fields
// that failed, and CEL's own join produces "a, b, c", which reads as a fragment
// rather than as a sentence.
func joinFieldsFunction() cel.EnvOption {
	return cel.Function("joinFields",
		cel.Overload("joinFields_list", []*cel.Type{cel.ListType(cel.StringType)}, cel.StringType,
			cel.UnaryBinding(func(value ref.Val) ref.Val {
				items, err := value.ConvertToNative(reflect.TypeFor[[]string]())
				if err != nil {
					return types.WrapErr(err)
				}
				return types.String(JoinFields(items.([]string)))
			}),
		),
	)
}

// JoinFields renders a list of field names as prose.
func JoinFields(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
