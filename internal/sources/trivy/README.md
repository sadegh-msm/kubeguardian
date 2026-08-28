# Trivy source

Reads the reports that [trivy-operator](https://aquasecurity.github.io/trivy-operator/)
writes and turns them into KubeGuardian findings, so image-level problems appear in the
same `NamespaceSecurityReport` as the built-in configuration checks.

## Why this exists

The built-in engine answers questions visible in a workload spec: is this container
privileged, does the namespace have a default-deny NetworkPolicy, does this Role use a
wildcard. It structurally cannot answer questions about image *contents* — which CVEs a
base layer carries, or whether a credential was baked into a layer. Those need a scanner
that pulls and unpacks images, with registry credentials, real CPU, and a vulnerability
database that must stay current.

Rather than grow KubeGuardian into an image scanner, this adapter lets a scanner that
already exists contribute findings through the `sources.Source` interface.

## What it consumes

| Trivy report | Finding ID | Why |
|---|---|---|
| `VulnerabilityReport` | `TRIVY-VULN` | CVEs in image layers, which the built-in engine cannot see |
| `ExposedSecretReport` | `TRIVY-SECRET` | Credentials baked into images |

`ConfigAuditReport` and `RbacAssessmentReport` are deliberately **not** consumed. KG-001
to KG-013 already cover that ground, and ingesting them would report the same privileged
container twice under two different IDs.

## Aggregation

A single `VulnerabilityReport` routinely carries hundreds of CVEs. One finding per CVE
would push a busy namespace past the etcd 1.5 MB object limit and make the report
unreadable, so each report collapses to **one finding per workload and container image**:

- Severity is the highest present in `report.summary`
- The message carries the counts: `image library/nginx:1.21 has 4 critical, 27 high vulnerabilities`
- The remediation lists up to five CVEs that have a `fixedVersion`, most severe first,
  because those are the ones actionable today

`--max-findings` caps the whole report as a second layer of protection.

## Degrading when Trivy is absent

The adapter is constructed at startup and queries discovery for
`aquasecurity.github.io/v1alpha1`. If the group is missing it is built disabled, `Collect`
returns nothing, and the operator behaves exactly as it does without Trivy. This is why
the adapter uses an **uncached reader**: a controller-runtime cached client starts an
informer on first use, which fails hard when the CRD does not exist.

Installing Trivy after KubeGuardian is already running requires an operator restart, since
detection happens once at startup.

## Installing trivy-operator

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace \
  --set operator.vulnerabilityScannerEnabled=true \
  --set operator.exposedSecretScannerEnabled=true \
  --set operator.configAuditScannerEnabled=false \
  --set operator.rbacAssessmentScannerEnabled=false \
  --set operator.infraAssessmentScannerEnabled=false \
  --set operator.clusterComplianceEnabled=false \
  --set operator.scanJobsConcurrentLimit=2 \
  --set operator.scannerReportTTL=24h
```

The scanners that are not consumed are switched off so the cluster does no work whose
output is thrown away. `scanJobsConcurrentLimit` throttles how many images are pulled and
unpacked at once; the default of 10 is a lot of load on a shared cluster.

Note the value is `operator.scanJobsConcurrentLimit`. Helm silently ignores unknown keys,
so a misspelling leaves the default of 10 in place with no error.

### Registries

The chart pulls its images from `mirror.gcr.io` by default. On networks where Google
registries are unreachable, repoint all four at Docker Hub:

```bash
  --set image.registry=docker.io \
  --set trivy.image.registry=docker.io \
  --set trivy.dbRegistry=docker.io \
  --set trivy.javaDbRegistry=docker.io
```

## Provenance

Every finding this adapter produces carries `source: trivy`, and both IDs are exemptable
through `ScanException` exactly like a built-in check.
