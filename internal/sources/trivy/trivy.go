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

package trivy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	SourceName = "trivy"

	VulnerabilityFindingID = "TRIVY-VULN"
	ExposedSecretFindingID = "TRIVY-SECRET"

	apiGroup   = "aquasecurity.github.io"
	apiVersion = "v1alpha1"

	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	containerLabel = "trivy-operator.container.name"

	maxListedItems = 5

	severityCritical = "CRITICAL"

	vulnerabilityReference = "https://aquasecurity.github.io/trivy-operator/latest/docs/crds/vulnerability-report/"
	exposedSecretReference = "https://aquasecurity.github.io/trivy-operator/latest/docs/crds/exposedsecret-report/"
)

var (
	vulnerabilityReportList = schema.GroupVersionKind{Group: apiGroup, Version: apiVersion, Kind: "VulnerabilityReportList"}
	exposedSecretReportList = schema.GroupVersionKind{Group: apiGroup, Version: apiVersion, Kind: "ExposedSecretReportList"}

	severityByName = map[string]securityv1alpha1.Severity{
		severityCritical: securityv1alpha1.SeverityCritical,
		"HIGH":           securityv1alpha1.SeverityHigh,
		"MEDIUM":         securityv1alpha1.SeverityMedium,
		"LOW":            securityv1alpha1.SeverityLow,
	}
)

type Adapter struct {
	reader  client.Reader
	enabled bool
}

func NewAdapter(cfg *rest.Config) (*Adapter, error) {
	available, err := reportsAvailable(cfg)
	if err != nil {
		return nil, err
	}
	if !available {
		return &Adapter{}, nil
	}

	reader, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("build trivy reader: %w", err)
	}
	return &Adapter{reader: reader, enabled: true}, nil
}

func (a *Adapter) Name() string {
	return SourceName
}

func (a *Adapter) Enabled() bool {
	return a.enabled
}

func (a *Adapter) Collect(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	if !a.enabled {
		return nil, nil
	}

	vulnerabilities, err := a.list(ctx, vulnerabilityReportList, snap.Name())
	if err != nil {
		return nil, err
	}
	secrets, err := a.list(ctx, exposedSecretReportList, snap.Name())
	if err != nil {
		return nil, err
	}

	findings := make([]securityv1alpha1.Finding, 0, len(vulnerabilities)+len(secrets))
	for _, item := range vulnerabilities {
		if finding, ok := vulnerabilityFinding(item); ok {
			finding.Source = SourceName
			findings = append(findings, finding)
		}
	}
	for _, item := range secrets {
		if finding, ok := exposedSecretFinding(item); ok {
			finding.Source = SourceName
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *Adapter) list(ctx context.Context, gvk schema.GroupVersionKind, namespace string) ([]unstructured.Unstructured, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk)

	if err := a.reader.List(ctx, list, client.InNamespace(namespace)); err != nil {
		if apimeta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list %s in namespace %s: %w", gvk.Kind, namespace, err)
	}
	return list.Items, nil
}

func reportsAvailable(cfg *rest.Config) (bool, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("build discovery client: %w", err)
	}

	resources, err := discoveryClient.ServerResourcesForGroupVersion(apiGroup + "/" + apiVersion)
	if err != nil {
		if apierrors.IsNotFound(err) || discovery.IsGroupDiscoveryFailedError(err) {
			return false, nil
		}
		return false, fmt.Errorf("discover %s: %w", apiGroup, err)
	}

	var vulnerabilities, secrets bool
	for _, resource := range resources.APIResources {
		switch resource.Kind {
		case "VulnerabilityReport":
			vulnerabilities = true
		case "ExposedSecretReport":
			secrets = true
		}
	}
	return vulnerabilities || secrets, nil
}

func vulnerabilityFinding(item unstructured.Unstructured) (securityv1alpha1.Finding, bool) {
	counts := summaryCounts(item)
	severity, ok := topSeverity(counts)
	if !ok {
		return securityv1alpha1.Finding{}, false
	}

	image := artifactImage(item)
	entries, _, _ := unstructured.NestedSlice(item.Object, "report", "vulnerabilities")

	return securityv1alpha1.Finding{
		ID:       VulnerabilityFindingID,
		Severity: severity,
		Category: securityv1alpha1.CategorySupplyChain,
		Resource: resourceRef(item),
		Message: fmt.Sprintf("image %s has %s",
			image, describeCounts(counts)),
		Suggestion:  "Rebuild the image on a patched base and redeploy. Vulnerabilities with a fixed version are actionable now; the rest need a base image upgrade or an accepted risk.",
		Remediation: fixableVulnerabilities(entries),
		Reference:   vulnerabilityReference,
	}, true
}

func exposedSecretFinding(item unstructured.Unstructured) (securityv1alpha1.Finding, bool) {
	counts := summaryCounts(item)
	severity, ok := topSeverity(counts)
	if !ok {
		return securityv1alpha1.Finding{}, false
	}

	entries, _, _ := unstructured.NestedSlice(item.Object, "report", "secrets")

	return securityv1alpha1.Finding{
		ID:       ExposedSecretFindingID,
		Severity: severity,
		Category: securityv1alpha1.CategorySupplyChain,
		Resource: resourceRef(item),
		Message: fmt.Sprintf("image %s has %s embedded in its layers",
			artifactImage(item), describeSecretCounts(counts)),
		Suggestion:  "Remove the credential from the image and rotate it. Supply secrets at runtime through a Secret or an external secret store instead of baking them into a layer.",
		Remediation: secretCategories(entries),
		Reference:   exposedSecretReference,
	}, true
}

func summaryCounts(item unstructured.Unstructured) map[securityv1alpha1.Severity]int64 {
	counts := make(map[securityv1alpha1.Severity]int64, 4)
	for name, severity := range severityByName {
		field := strings.ToLower(name) + "Count"
		value, _, _ := unstructured.NestedInt64(item.Object, "report", "summary", field)
		counts[severity] = value
	}
	return counts
}

func topSeverity(counts map[securityv1alpha1.Severity]int64) (securityv1alpha1.Severity, bool) {
	for _, severity := range []securityv1alpha1.Severity{
		securityv1alpha1.SeverityCritical,
		securityv1alpha1.SeverityHigh,
		securityv1alpha1.SeverityMedium,
		securityv1alpha1.SeverityLow,
	} {
		if counts[severity] > 0 {
			return severity, true
		}
	}
	return "", false
}

func describeCounts(counts map[securityv1alpha1.Severity]int64) string {
	return describe(counts, "vulnerabilities", "vulnerability")
}

func describeSecretCounts(counts map[securityv1alpha1.Severity]int64) string {
	return describe(counts, "exposed secrets", "exposed secret")
}

func describe(counts map[securityv1alpha1.Severity]int64, plural, singular string) string {
	var parts []string
	total := int64(0)
	for _, severity := range []securityv1alpha1.Severity{
		securityv1alpha1.SeverityCritical,
		securityv1alpha1.SeverityHigh,
		securityv1alpha1.SeverityMedium,
		securityv1alpha1.SeverityLow,
	} {
		if counts[severity] == 0 {
			continue
		}
		total += counts[severity]
		parts = append(parts, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(string(severity))))
	}

	noun := plural
	if total == 1 {
		noun = singular
	}
	return strings.Join(parts, ", ") + " " + noun
}

func artifactImage(item unstructured.Unstructured) string {
	repository, _, _ := unstructured.NestedString(item.Object, "report", "artifact", "repository")
	tag, _, _ := unstructured.NestedString(item.Object, "report", "artifact", "tag")
	digest, _, _ := unstructured.NestedString(item.Object, "report", "artifact", "digest")

	switch {
	case repository == "":
		return "unknown"
	case tag != "":
		return repository + ":" + tag
	case digest != "":
		return repository + "@" + digest
	default:
		return repository
	}
}

func resourceRef(item unstructured.Unstructured) securityv1alpha1.ResourceRef {
	labels := item.GetLabels()
	ref := securityv1alpha1.ResourceRef{
		Kind:      labels[kindLabel],
		Name:      labels[nameLabel],
		Container: labels[containerLabel],
	}
	if ref.Kind == "" {
		ref.Kind = "Unknown"
	}
	if ref.Name == "" {
		ref.Name = item.GetName()
	}
	return ref
}

func fixableVulnerabilities(entries []any) string {
	type fix struct {
		id       string
		pkg      string
		version  string
		severity securityv1alpha1.Severity
	}

	var fixes []fix
	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		fixed, _ := fields["fixedVersion"].(string)
		if fixed == "" {
			continue
		}
		name, _ := fields["vulnerabilityID"].(string)
		resource, _ := fields["resource"].(string)
		raw, _ := fields["severity"].(string)
		fixes = append(fixes, fix{id: name, pkg: resource, version: fixed, severity: severityByName[raw]})
	}

	if len(fixes) == 0 {
		return "No listed vulnerability has a fixed version yet. Track the base image for updates."
	}

	slices.SortStableFunc(fixes, func(left, right fix) int {
		return left.severity.Rank() - right.severity.Rank()
	})

	limit := min(len(fixes), maxListedItems)
	lines := make([]string, 0, limit+1)
	for _, item := range fixes[:limit] {
		lines = append(lines, fmt.Sprintf("%s: upgrade %s to %s", item.id, item.pkg, item.version))
	}
	if len(fixes) > limit {
		lines = append(lines, fmt.Sprintf("and %d further fixable vulnerabilities", len(fixes)-limit))
	}
	return strings.Join(lines, "\n")
}

func secretCategories(entries []any) string {
	seen := make(map[string]struct{}, len(entries))
	var categories []string

	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		title, _ := fields["title"].(string)
		if title == "" {
			title, _ = fields["ruleID"].(string)
		}
		if title == "" {
			continue
		}
		if _, duplicate := seen[title]; duplicate {
			continue
		}
		seen[title] = struct{}{}
		categories = append(categories, title)
	}

	if len(categories) == 0 {
		return "Inspect the ExposedSecretReport for the affected paths."
	}

	slices.Sort(categories)
	limit := min(len(categories), maxListedItems)
	return "Rotate and remove: " + strings.Join(categories[:limit], ", ")
}
