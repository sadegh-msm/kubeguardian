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

package checks

import (
	"fmt"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

type defaultDenyNetworkPolicy struct{ meta }

func newDefaultDenyNetworkPolicy() defaultDenyNetworkPolicy {
	return defaultDenyNetworkPolicy{meta{
		id:        "KG-010",
		severity:  securityv1alpha1.SeverityHigh,
		category:  securityv1alpha1.CategoryNetwork,
		reference: "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
	}}
}

func (c defaultDenyNetworkPolicy) Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding {
	if len(snap.Workloads()) == 0 {
		return nil
	}
	if slices.ContainsFunc(snap.NetworkPolicies, isDefaultDenyIngress) {
		return nil
	}
	return []securityv1alpha1.Finding{c.finding(
		namespaceRef(snap),
		fmt.Sprintf("namespace %q has no default-deny ingress NetworkPolicy, so every pod in the cluster can reach every pod here", snap.Name()),
		"Apply a default-deny ingress policy, then add explicit allow policies for the traffic each workload actually serves.",
		fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
    - Ingress`, snap.Name()),
	)}
}

func isDefaultDenyIngress(policy networkingv1.NetworkPolicy) bool {
	if len(policy.Spec.PodSelector.MatchLabels) > 0 || len(policy.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}
	if len(policy.Spec.Ingress) > 0 {
		return false
	}
	return slices.Contains(policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
}
