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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const unusedText = "unreachable"

var _ = Describe("SecurityCheck controller", func() {

	// Checks are cluster scoped, so one left behind by a spec would be evaluated
	// for every namespace every other spec creates.
	createCheck := func(check *securityv1alpha1.SecurityCheck) {
		Expect(k8sClient.Create(ctx, check)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, check)).To(Succeed())
		})
	}

	readyCondition := func(name string) func() []metav1.Condition {
		return func() []metav1.Condition {
			check := &securityv1alpha1.SecurityCheck{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, check); err != nil {
				return nil
			}
			return check.Status.Conditions
		}
	}

	It("reports a check whose expressions compile as ready", func() {
		name := fmt.Sprintf("good-%d", time.Now().UnixNano())
		createCheck(&securityv1alpha1.SecurityCheck{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: securityv1alpha1.SecurityCheckSpec{
				ID: "ACME-1", Severity: securityv1alpha1.SeverityLow,
				Category:    securityv1alpha1.CategoryGovernance,
				Scope:       securityv1alpha1.ScopeNamespace,
				Violation:   `!('team' in namespaceObject.metadata.labels)`,
				Message:     `namespace "${namespaceObject.metadata.name}" has no team label`,
				Suggestion:  "Label the namespace with its owning team.",
				Remediation: "kubectl label namespace ${namespaceObject.metadata.name} team=<team>",
			},
		})

		Eventually(readyCondition(name), timeout, interval).Should(ContainElement(And(
			HaveField("Type", securityv1alpha1.ConditionReady),
			HaveField("Status", metav1.ConditionTrue),
			HaveField("Reason", securityv1alpha1.ReasonCompiled),
		)))
	})

	It("reports the compile error on a check that does not compile", func() {
		name := fmt.Sprintf("broken-%d", time.Now().UnixNano())
		createCheck(&securityv1alpha1.SecurityCheck{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: securityv1alpha1.SecurityCheckSpec{
				ID: "ACME-2", Severity: securityv1alpha1.SeverityLow,
				Category:    securityv1alpha1.CategoryGovernance,
				Scope:       securityv1alpha1.ScopeNamespace,
				Violation:   "namespaceObject.metadata.labals.size() > 0",
				Message:     unusedText,
				Suggestion:  unusedText,
				Remediation: unusedText,
			},
		})

		Eventually(readyCondition(name), timeout, interval).Should(ContainElement(And(
			HaveField("Type", securityv1alpha1.ConditionReady),
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", securityv1alpha1.ReasonCompileFailed),
		)))

		check := &securityv1alpha1.SecurityCheck{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, check)).To(Succeed())
		Expect(check.Status.Conditions[0].Message).To(ContainSubstring("undefined field 'labals'"))
	})

	It("keeps scanning the other checks when one is broken", func() {
		createCheck(&securityv1alpha1.SecurityCheck{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("also-broken-%d", time.Now().UnixNano())},
			Spec: securityv1alpha1.SecurityCheckSpec{
				ID: "ACME-3", Severity: securityv1alpha1.SeverityLow,
				Category:    securityv1alpha1.CategoryGovernance,
				Scope:       securityv1alpha1.ScopeNamespace,
				Violation:   "namespaceObject.nonsense",
				Message:     unusedText,
				Suggestion:  unusedText,
				Remediation: unusedText,
			},
		})

		namespaceName := fmt.Sprintf("broken-policy-%d", time.Now().UnixNano())
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
		})).To(Succeed())

		Expect(k8sClient.Create(ctx, &securityv1alpha1.ManifestSecurityReport{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespaceName, Name: namespaceName},
		})).To(Succeed())

		// KG-011 fires on any namespace with no Pod Security Admission label, so
		// the report proves the shipped checks still ran alongside the broken one.
		Eventually(func() []string {
			report := &securityv1alpha1.ManifestSecurityReport{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespaceName, Name: namespaceName}, report); err != nil {
				return nil
			}
			return findingIDs(&report.Status)
		}, timeout, interval).Should(ContainElement("KG-011"))
	})
})
