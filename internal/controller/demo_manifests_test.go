package controller

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

const demoNamespace = "kubeguardian-demo"

func applyManifest(path string) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "demo", path))
	Expect(err).NotTo(HaveOccurred())

	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		object := &unstructured.Unstructured{}
		err := decoder.Decode(object)
		if err == io.EOF {
			return
		}
		Expect(err).NotTo(HaveOccurred())
		if len(object.Object) == 0 {
			continue
		}
		Expect(k8sClient.Apply(ctx, client.ApplyConfigurationFromUnstructured(object),
			client.FieldOwner("kubeguardian-demo"), client.ForceOwnership)).To(Succeed())
	}
}

func demoReport() (*securityv1alpha1.NamespaceSecurityReport, error) {
	report := &securityv1alpha1.NamespaceSecurityReport{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: demoNamespace}, report)
	return report, err
}

var _ = Describe("Demo manifests", Ordered, func() {
	var insecureScore int

	It("flags the insecure namespace", func() {
		applyManifest("01-insecure-namespace.yaml")

		Eventually(func() []string {
			report, err := demoReport()
			if err != nil {
				return nil
			}
			return findingIDs(report)
		}, timeout, interval).Should(And(
			ContainElement("KG-001"),
			ContainElement("KG-004"),
			ContainElement("KG-005"),
			ContainElement("KG-010"),
			ContainElement("KG-011"),
			ContainElement("KG-013"),
			ContainElement("KG-008"),
			ContainElement("KG-020"),
			ContainElement("KG-021"),
		))

		report, err := demoReport()
		Expect(err).NotTo(HaveOccurred())
		insecureScore = report.Status.Score

		hostNamespaceFindings := 0
		for _, finding := range report.Status.Findings {
			if finding.ID == "KG-004" {
				hostNamespaceFindings++
			}
		}
		Expect(hostNamespaceFindings).To(Equal(2))
		Expect(insecureScore).To(Equal(0))
	})

	It("clears the findings once the hardened manifest is applied", func() {
		applyManifest("02-hardened-namespace.yaml")

		Eventually(func() int {
			report, err := demoReport()
			if err != nil {
				return -1
			}
			return report.Status.Score
		}, timeout, interval).Should(BeNumerically(">", insecureScore))

		report, err := demoReport()
		Expect(err).NotTo(HaveOccurred())
		Expect(findingIDs(report)).NotTo(ContainElement("KG-001"))
		Expect(findingIDs(report)).NotTo(ContainElement("KG-004"))
		Expect(findingIDs(report)).NotTo(ContainElement("KG-010"))
		Expect(findingIDs(report)).NotTo(ContainElement("KG-011"))
		Expect(findingIDs(report)).NotTo(ContainElement("KG-013"))
		Expect(findingIDs(report)).NotTo(ContainElement("KG-008"))
		Expect(report.Status.Score).To(Equal(100))
		Expect(report.Status.Summary.Total).To(Equal(0))
	})
})
