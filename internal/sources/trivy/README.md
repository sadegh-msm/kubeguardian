# Trivy adapter

Designed, not implemented. This directory documents how a second finding source would
plug into KubeGuardian so the seam in `internal/sources/source.go` can be judged on its
merits rather than taken on trust.

## Why the seam exists

The built-in engine answers questions that are visible in a workload spec: is this
container privileged, does the namespace have a default-deny NetworkPolicy, does this
Role use a wildcard. It cannot answer questions that need the image contents, such as
which CVEs a base image carries. Those answers come from a scanner that pulls and
unpacks images, which is a different operational concern: it needs registry credentials,
significant CPU, and a vulnerability database that must stay current.

Rather than grow the operator into an image scanner, `Source` lets a scanner that
already exists contribute findings into the same report.

## Shape of the adapter

```go
type Adapter struct {
    client client.Reader
}

func (a *Adapter) Name() string { return "trivy" }

func (a *Adapter) Collect(ctx context.Context, snap *snapshot.Snapshot) ([]v1alpha1.Finding, error) {
    var reports trivyv1alpha1.VulnerabilityReportList
    if err := a.client.List(ctx, &reports, client.InNamespace(snap.Name())); err != nil {
        return nil, fmt.Errorf("list vulnerability reports: %w", err)
    }
    ...
}
```

It reads the `VulnerabilityReport` and `ConfigAuditReport` resources that trivy-operator
already writes, maps their severities onto `v1alpha1.Severity`, and returns them tagged
with `Source: "trivy"`. `sources.Normalize` then merges, deduplicates and orders them
alongside the built-in findings with no change to the reconciler.

## What would need deciding first

- Whether trivy-operator is a hard dependency or an optional one. The adapter should
  degrade to returning no findings when the CRDs are absent, not fail the scan.
- How to map CVE severity onto the four-level scale here without letting a namespace
  full of low-severity CVEs dominate the score.
- Whether image findings belong in a per-namespace report at all, given the same image
  usually runs in many namespaces.

The third question is the reason this is documented rather than built: it is a design
question about the report boundary, not an implementation detail, and answering it
properly is outside the scope this project committed to.
