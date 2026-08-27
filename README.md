# KubeGuardian

KubeGuardian is a Kubernetes operator that continuously audits the security posture of
every namespace in a cluster and publishes what it finds as a Kubernetes resource.

For each namespace it produces a `NamespaceSecurityReport` containing the problems it
detected, a concrete suggestion for each one, and a command or manifest you can apply to
fix it. Reports are refreshed automatically whenever a workload in the namespace is
created or changed, so the report tracks the cluster rather than a point in time.

The reasoning behind the design, and what was deliberately left out, is in
[DESIGN.md](DESIGN.md).

## What a report looks like

```console
$ kubectl get namespacesecurityreports
NAME                SCORE   CRITICAL   HIGH   MEDIUM   LOW   LAST-SCAN   AGE
default             90      0          1      0        0     31s         2m
kubeguardian-demo   0       3          6      5        0     12s         2m
```

```console
$ kubectl get nsr kubeguardian-demo -o yaml
status:
  score: 0
  summary:
    critical: 3
    high: 6
    medium: 5
    low: 0
    total: 14
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
      message: 14 finding(s) across 3 severity level(s)
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

In a second terminal, create a deliberately insecure namespace and read the report:

```bash
make demo
```

That applies `test/demo/01-insecure-namespace.yaml`, waits a moment, and prints the
report. It scores 0, with fourteen findings.

An untouched `default` namespace usually scores 90: it has no workloads, so most checks
do not apply, but it does not enforce a Pod Security Standard. To watch the score recover, apply the hardened version of the same namespace:

```bash
make demo-harden
```

The hardened manifest fixes every finding, so the score returns to 100 and the findings
list empties. `make demo-clean` removes the namespace afterwards.

To prove that reports track changes rather than creation events, edit a workload
directly and watch the score move:

```bash
kubectl patch deployment legacy-api -n kubeguardian-demo --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/hostNetwork","value":false}]'

kubectl get nsr kubeguardian-demo -w
```

## Deploying into the cluster

```bash
make docker-build docker-push IMG=<your-registry>/kubeguardian:v0.1.0
make deploy IMG=<your-registry>/kubeguardian:v0.1.0
```

`make undeploy` removes the controller and `make uninstall` removes the CRD. Removing
the CRD deletes every report; it does not touch the namespaces themselves.

## Configuration

The controller is configured with flags on the manager binary.

| Flag | Default | Purpose |
|---|---|---|
| `--rescan-interval` | `10m` | How often each namespace is rescanned even when no workload event arrives, so drift and clock-dependent findings are still caught. |
| `--min-severity` | `Low` | Lowest severity recorded in a report. Set to `High` to keep reports focused on what matters most. |
| `--excluded-namespaces` | `kube-system,kube-public,kube-node-lease` | Namespaces that are never scanned. Control-plane namespaces legitimately run privileged workloads and would otherwise dominate every report. |
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
| KG-010 | Namespace has no default-deny ingress NetworkPolicy | High | Network |
| KG-011 | Namespace does not enforce a Pod Security Standard | High | Governance |
| KG-012 | Default ServiceAccount automounts an API token | Medium | RBAC |
| KG-013 | Namespaced Role grants a wildcard | High | RBAC |
| KG-020 | Image uses a mutable tag or none at all | Medium | SupplyChain |
| KG-021 | Container is missing resource requests or limits | Medium | Governance |

Checks apply to Deployments, StatefulSets, DaemonSets and CronJobs, and cover init
containers as well as regular ones.

The score starts at 100 and subtracts 20 per critical finding, 10 per high, 5 per medium
and 2 per low, with a floor of zero. It is a rough ordering signal for triage, not a risk
model; see DESIGN.md.

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
- A test that applies the shipped demo manifests and asserts the findings and score they
  produce, so the documented walkthrough cannot silently rot

```bash
make lint
```

## Repository layout

```
api/v1alpha1/          CRD types for NamespaceSecurityReport and Finding
cmd/                   manager entrypoint and flags
internal/snapshot/     collects everything in a namespace in one pass
internal/checks/       one file per rule, plus the registry
internal/sources/      the Source interface, ordering and deduplication
internal/sources/builtin/   runs the built-in check registry
internal/sources/trivy/     design note for an external scanner adapter
internal/scoring/      score and severity summary
internal/controller/   reconciler and the workload-to-namespace event mapping
config/                kustomize manifests for CRD, RBAC and the manager
test/demo/             insecure and hardened namespaces used by make demo
```
