package controller

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const (
	timeout  = 30 * time.Second
	interval = 250 * time.Millisecond
)

func boolPtr(value bool) *bool {
	return &value
}

func insecureDeployment(namespace string) *appsv1.Deployment {
	labels := map[string]string{"app": "insecure"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "insecure", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:            "app",
						Image:           "nginx:latest",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					}},
				},
			},
		},
	}
}

func reportFor(name string) func() (*securityv1alpha1.NamespaceSecurityReport, error) {
	return func() (*securityv1alpha1.NamespaceSecurityReport, error) {
		report := &securityv1alpha1.NamespaceSecurityReport{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, report)
		return report, err
	}
}

func findingIDs(report *securityv1alpha1.NamespaceSecurityReport) []string {
	ids := make([]string, 0, len(report.Status.Findings))
	for _, finding := range report.Status.Findings {
		ids = append(ids, finding.ID)
	}
	return ids
}

var _ = Describe("NamespaceSecurityReport controller", func() {
	var namespaceName string

	BeforeEach(func() {
		namespaceName = fmt.Sprintf("scan-%d", time.Now().UnixNano())
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
		})).To(Succeed())
	})

	It("creates a report for a new namespace", func() {
		Eventually(func() error {
			_, err := reportFor(namespaceName)()
			return err
		}, timeout, interval).Should(Succeed())

		report, err := reportFor(namespaceName)()
		Expect(err).NotTo(HaveOccurred())
		Expect(report.Spec.NamespaceRef).To(Equal(namespaceName))
		Expect(report.OwnerReferences).To(HaveLen(1))
		Expect(report.OwnerReferences[0].Kind).To(Equal("Namespace"))
	})

	It("reports findings when an insecure workload is created", func() {
		Expect(k8sClient.Create(ctx, insecureDeployment(namespaceName))).To(Succeed())

		Eventually(func() []string {
			report, err := reportFor(namespaceName)()
			if err != nil {
				return nil
			}
			return findingIDs(report)
		}, timeout, interval).Should(And(
			ContainElement("KG-001"),
			ContainElement("KG-004"),
			ContainElement("KG-020"),
		))

		report, err := reportFor(namespaceName)()
		Expect(err).NotTo(HaveOccurred())
		Expect(report.Status.Summary.Critical).To(BeNumerically(">=", 2))
		Expect(report.Status.Score).To(BeNumerically("<", 100))

		for _, finding := range report.Status.Findings {
			Expect(finding.Suggestion).NotTo(BeEmpty())
			Expect(finding.Source).To(Equal("builtin"))
		}
	})

	It("rescans when an existing workload changes", func() {
		deployment := insecureDeployment(namespaceName)
		Expect(k8sClient.Create(ctx, deployment)).To(Succeed())

		Eventually(func() []string {
			report, err := reportFor(namespaceName)()
			if err != nil {
				return nil
			}
			return findingIDs(report)
		}, timeout, interval).Should(ContainElement("KG-001"))

		before, err := reportFor(namespaceName)()
		Expect(err).NotTo(HaveOccurred())

		patch := client.MergeFrom(deployment.DeepCopy())
		deployment.Spec.Template.Spec.HostNetwork = false
		deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged = boolPtr(false)
		Expect(k8sClient.Patch(ctx, deployment, patch)).To(Succeed())

		Eventually(func() []string {
			report, err := reportFor(namespaceName)()
			if err != nil {
				return nil
			}
			return findingIDs(report)
		}, timeout, interval).ShouldNot(ContainElement("KG-001"))

		after, err := reportFor(namespaceName)()
		Expect(err).NotTo(HaveOccurred())
		Expect(after.Status.Score).To(BeNumerically(">", before.Status.Score))
	})

	It("marks the scan as succeeded", func() {
		Eventually(func() []metav1.Condition {
			report, err := reportFor(namespaceName)()
			if err != nil {
				return nil
			}
			return report.Status.Conditions
		}, timeout, interval).Should(ContainElement(And(
			HaveField("Type", securityv1alpha1.ConditionScanSucceeded),
			HaveField("Status", metav1.ConditionTrue),
		)))
	})
})
