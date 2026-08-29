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

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

var _ = Describe("ImageSecurityReport controller", func() {
	var namespaceName string

	BeforeEach(func() {
		namespaceName = fmt.Sprintf("image-%d", time.Now().UnixNano())
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
		})).To(Succeed())
	})

	requestReport := func() {
		Expect(k8sClient.Create(ctx, &securityv1alpha1.ImageSecurityReport{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespaceName, Name: namespaceName},
		})).To(Succeed())
	}

	It("does not create a report on its own", func() {
		Consistently(func() error {
			_, err := imageReportFor(namespaceName)()
			return err
		}, 3*time.Second, 500*time.Millisecond).ShouldNot(Succeed())
	})

	It("says so when no image scanner is installed", func() {
		requestReport()

		Eventually(func() []metav1.Condition {
			report, err := imageReportFor(namespaceName)()
			if err != nil {
				return nil
			}
			return report.Status.Conditions
		}, timeout, interval).Should(ContainElement(And(
			HaveField("Type", securityv1alpha1.ConditionScanSucceeded),
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", securityv1alpha1.ReasonScannerUnavailable),
		)))

		report, err := imageReportFor(namespaceName)()
		Expect(err).NotTo(HaveOccurred())
		Expect(report.Status.Findings).To(BeEmpty())
		Expect(report.Status.Summary.Total).To(Equal(0))
		Expect(report.Status.LastScanTime.IsZero()).To(BeFalse())
	})

	It("stays empty when an insecure workload is created, because manifests are not its job", func() {
		requestReport()
		Expect(k8sClient.Create(ctx, insecureDeployment(namespaceName))).To(Succeed())

		Consistently(func() []string {
			report, err := imageReportFor(namespaceName)()
			if err != nil {
				return []string{"missing"}
			}
			return findingIDs(&report.Status)
		}, 3*time.Second, 500*time.Millisecond).Should(BeEmpty())
	})
})
