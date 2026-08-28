# KubeGuardian

KubeGuardian is a Kubernetes operator that continuously audits the security posture of
every namespace in a cluster and publishes what it finds as a Kubernetes resource.

You ask for a namespace to be audited by creating a `NamespaceSecurityReport` naming it.
KubeGuardian fills in the status: the problems it detected, a concrete suggestion for each
one, and a command or manifest you can apply to fix it. The report is refreshed
automatically whenever a workload in that namespace is created or changed, so it tracks the
cluster rather than a point in time.

Nothing is scanned unless you ask for it. Creating a namespace does not create a report.

The reasoning behind the design, and what was deliberately left out, is in
[DESIGN.md](DESIGN.md). Every test scenario and its observed result is in
[TESTING.md](TESTING.md).

## Asking for a scan

Create a report in the namespace you want audited:

```yaml
apiVersion: security.kubeguardian.io/v1alpha1
kind: NamespaceSecurityReport
metadata:
  name: posture
  namespace: payments
```

That is the whole object. The report audits the namespace it lives in, so there is nothing
to configure and no way to point it at the wrong place. Its name is free; `posture` or the
namespace name are both fine.

The report is namespaced rather than cluster-scoped so a team with access to only their own
namespace can read their own findings through the RoleBinding they already have, and cannot
read anyone else's. See DESIGN.md for why that constraint decides the design.

Deleting the report stops the scanning. Deleting the namespace takes the report with it.

## What a report looks like

```console
$ kubectl get nsr -n payments
NAME      CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
posture   0          1      0        0     0            31s         2m

$ kubectl get nsr -A
NAMESPACE           NAME      CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
payments            posture   0          1      0        0     0            31s         2m
monitoring-system   posture   1          29     37       0     2            12s         2m
```

```console
$ kubectl get nsr posture -n monitoring-system -o yaml
status:
  summary:
    critical: 1
    high: 29
    medium: 37
    low: 0
    total: 67
    suppressed: 2
  findings:
    - id: KG-001
      severity: Critical
      category: PodSecurity
      resource:
        kind: Deployment
        name: legacy-api
        container: api
      message: container "api" runs privileged, which grants full access to host devices
        and bypasses every kernel capability restriction
      suggestion: Set securityContext.privileged to false and add back only the individual
        capabilities the container genuinely needs.
      remediation: kubectl patch deployment legacy-api -n kubeguardian-demo --type=json
        -p='[{"op":"replace","path":"/spec/template/spec/containers/0/securityContext/privileged","value":false}]'
      reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
      source: builtin
  conditions:
    - type: ScanSucceeded
      status: "True"
      reason: ScanCompleted
      message: 67 finding(s) across 3 severity level(s), 2 suppressed by exception
  lastScanTime: "2026-08-27T17:50:54Z"
```

## Requirements

- Go 1.26 or newer, matching the `go` directive in `go.mod`
- `kubectl` with access to a cluster
- Docker, only if you want to build and push the controller image

## Running it

The fastest way to see it work is to install the CRD and run the controller on your
machine against a cluster. No image build is involved.

```bash
export KUBECONFIG=/path/to/your/kubeconfig

make install
make run
```

In a second terminal, create a deliberately insecure namespace, ask for it to be audited,
and read the result:

```bash
make demo
```

That applies `test/demo/01-insecure-namespace.yaml`, waits a moment, and prints the
report. It produces fifteen findings, three of them critical.

An untouched `default` namespace usually reports a single high finding: it has no
workloads, so most checks do not apply, but it does not enforce a Pod Security Standard.
To watch the findings clear, apply the hardened version of the same namespace:

```bash
make demo-harden
```

The hardened manifest fixes every finding, so the findings list empties. Both manifests describe the same workload and differ only in security
configuration, and both actually run: the hardened pod is admitted under `restricted`
Pod Security Admission. `make demo-clean` removes the namespace afterwards.

To prove that reports track changes rather than creation events, edit a workload
directly and watch the counts move:

```bash
kubectl patch deployment legacy-api -n kubeguardian-demo --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/hostNetwork","value":false}]'

kubectl get nsr -n kubeguardian-demo -w
```

## Deploying into the cluster

```bash
make docker-build docker-push IMG=<your-registry>/kubeguardian:v0.1.0
make deploy IMG=<your-registry>/kubeguardian:v0.1.0
```

The runtime base image defaults to `gcr.io/distroless/static:nonroot`. On networks where
Google-hosted registries are unreachable, override it:

```bash
make docker-build IMG=kubeguardian:test BASE_IMAGE=alpine:3.22
```

Prefer a distroless or otherwise minimal base in production; `alpine` ships a shell.

`make undeploy` removes the controller and `make uninstall` removes the CRD. Removing
the CRD deletes every report; it does not touch the namespaces themselves.

### Upgrading from a build older than v0.4.0

`NamespaceSecurityReport` was cluster-scoped before v0.4.0. A CRD's `spec.scope` is
immutable, so `kubectl apply` refuses the change:

```
The CustomResourceDefinition "namespacesecurityreports.security.kubeguardian.io"
is invalid: spec.scope: Invalid value: "Namespaced": field is immutable
```

Delete the CRD first, which also deletes the old reports. They hold only derived data and
are recreated by asking for a scan again:

```bash
kubectl delete crd namespacesecurityreports.security.kubeguardian.io
make deploy IMG=<your-image>
```

## Configuration

The controller is configured with flags on the manager binary.

| Flag | Default | Purpose |
|---|---|---|
| `--rescan-interval` | `10m` | How often each namespace is rescanned even when no workload event arrives, so drift and clock-dependent findings are still caught. |
| `--min-severity` | `Low` | Lowest severity recorded in a report. Set to `High` to keep reports focused on what matters most. |
| `--max-findings` | `200` | Upper bound on findings per report. The least severe are dropped first, so a pathological namespace cannot produce an object the API server refuses. |
| `--leader-elect` | `false` | Enable when running more than one replica. |

## The check catalog

Every finding carries an identifier from this table. Severities are fixed per check.

| ID | Check | Severity | Category |
|---|---|---|---|
| KG-001 | Container runs privileged | Critical | PodSecurity |
| KG-002 | Container may run as root | High | PodSecurity |
| KG-003 | Privilege escalation is not disabled | High | PodSecurity |
| KG-004 | Pod shares a host namespace (`hostNetwork`, `hostPID`, `hostIPC`) | Critical | PodSecurity |
| KG-005 | Pod mounts a `hostPath` volume | High | PodSecurity |
| KG-006 | Container does not drop all Linux capabilities | Medium | PodSecurity |
| KG-007 | Container has a writable root filesystem | Medium | PodSecurity |
| KG-008 | Container sets no seccomp profile, or sets it to `Unconfined` | Medium | PodSecurity |
| KG-010 | Namespace has no default-deny ingress NetworkPolicy | High | Network |
| KG-011 | Namespace does not enforce a Pod Security Standard | High | Governance |
| KG-012 | Default ServiceAccount automounts an API token | Medium | RBAC |
| KG-013 | Namespaced Role grants a wildcard | High | RBAC |
| KG-020 | Image uses a mutable tag or none at all | Medium | SupplyChain |
| KG-021 | Container is missing resource requests or limits | Medium | Governance |
| TRIVY-VULN | Image carries known CVEs | varies | SupplyChain |
| TRIVY-SECRET | Credential baked into an image layer | varies | SupplyChain |

Checks apply to Deployments, StatefulSets, DaemonSets and CronJobs, and cover init
containers as well as regular ones.

The two `TRIVY-` checks only appear when trivy-operator is installed; see
[Vulnerability scanning](#vulnerability-scanning). Their severity comes from the scan.

There is deliberately no overall score. An earlier version had one and it was removed:
it floored at zero, so most namespaces on a real cluster read `0` and the number stopped
discriminating exactly where triage matters. Severity counts say the same thing without
implying a precision the heuristic never had.

## Accepting a risk

Some workloads legitimately need what a check flags. A node metrics agent needs
`hostNetwork` and `hostPID`; reporting it every scan trains reviewers to ignore KG-004.

A `ScanException` records that decision:

```yaml
apiVersion: security.kubeguardian.io/v1alpha1
kind: ScanException
metadata:
  name: node-exporter-host-access
spec:
  reason: >-
    prometheus node-exporter reads host network and process metrics, which is
    the purpose of the agent. Reviewed by the platform team.
  expiresAt: "2027-01-01T00:00:00Z"   # optional
  checks:
    - KG-004
  namespaces:
    - monitoring-system
  resources:
    - kind: DaemonSet
      name: vm-stack-prometheus-node-exporter
```

A matching finding stays in the report with `suppressed: true`, the name of the exception
that accepted it, and the reason. It stops counting toward the severity totals and counts
under `suppressed` instead, so `critical: 0, suppressed: 2` reads as "two accepted risks,
nothing outstanding". Nothing is hidden.

`reason` is required and must be non-empty. `checks` accepts `"*"`. Leaving `namespaces`,
`namespaceSelector` or `resources` unset means "any", so a narrow exception is short and a
broad one is deliberate and visible. When both `namespaces` and `namespaceSelector` are
set, both must match.

An expired exception simply stops suppressing at the next scan of that namespace, which is
within one `--rescan-interval`.

```console
$ kubectl get scanexceptions
NAME                        CHECKS       NAMESPACES             EXPIRES                REASON
node-exporter-host-access   ["KG-004"]   ["monitoring-system"]  2027-01-01T00:00:00Z   prometheus node-exporter reads...
```

## Vulnerability scanning

KubeGuardian reads image scan results from
[trivy-operator](https://aquasecurity.github.io/trivy-operator/) when it is installed,
and reports them alongside the built-in checks. This covers what the built-in engine
structurally cannot see: CVEs in image layers, and credentials baked into images.

If trivy-operator is not installed, KubeGuardian detects that at startup, logs one line,
and runs exactly as it does without it. Nothing needs configuring to turn it off.

Installation and the design of the adapter are documented in
[internal/sources/trivy/README.md](internal/sources/trivy/README.md).

## Tests

```bash
make test
```

This regenerates manifests, runs `go vet`, downloads the envtest control plane binaries
if needed, and runs everything:

- Table-driven unit tests for every check, run against in-memory namespace snapshots
- Tests for scoring, ordering determinism, deduplication and severity filtering
- Integration tests against a real API server via envtest, which start the manager and
  assert that creating a namespace produces a report, that an insecure workload produces
  the expected findings, and that editing that workload changes the report
- A test that applies the shipped demo manifests and asserts the findings they produce, so
  the documented walkthrough cannot silently rot
- Table-driven tests for `ScanException` matching: check ID, namespace list, namespace
  selector, resource kind and name, expiry, and the wildcard
- Trivy adapter tests over fixture reports, including 300 CVEs collapsing to one finding
  and the disabled-adapter path returning nothing without erroring

```bash
make lint
```

Beyond these, the operator was deployed into a kind cluster and put through 26 acceptance
scenarios covering the report lifecycle, garbage collection, RBAC sufficiency, loop
stability, schema validation, flag handling and workload coverage. Results are recorded in
[TESTING.md](TESTING.md).

## Repository layout

```
api/v1alpha1/          CRD types for NamespaceSecurityReport and Finding
cmd/                   manager entrypoint and flags
internal/snapshot/     collects everything in a namespace in one pass
internal/checks/       one file per rule, plus the registry
internal/sources/      the Source interface, ordering, deduplication and summaries
internal/exceptions/   ScanException matching and suppression
internal/sources/builtin/   runs the built-in check registry
internal/sources/trivy/     reads trivy-operator reports
internal/controller/   reconciler and the workload-to-namespace event mapping
config/                kustomize manifests for CRD, RBAC and the manager
test/demo/             insecure and hardened namespaces used by make demo
```
