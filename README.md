# KubeGuardian

KubeGuardian is a Kubernetes operator that continuously audits the security posture of
every namespace in a cluster and publishes what it finds as a Kubernetes resource.

You ask for a namespace to be audited by creating a report in it: a
`ManifestSecurityReport` for how the namespace is configured, an `ImageSecurityReport` for
what its images contain, or both. KubeGuardian fills in the status: the problems it
detected, a concrete suggestion for each one, and a command or manifest you can apply to
fix it. Reports are refreshed automatically whenever a workload in that namespace is
created or changed, so they track the cluster rather than a point in time.

Nothing is scanned unless you ask for it. Creating a namespace does not create a report.

The reasoning behind the design, and what was deliberately left out, is in
[DESIGN.md](DESIGN.md). Every test scenario and its observed result is in
[TESTING.md](TESTING.md).

## Asking for a scan

There are two kinds of report, and you ask for whichever you want by creating it in the
namespace you want audited.

| Kind | Short | Answers | Findings |
|---|---|---|---|
| `ManifestSecurityReport` | `msr` | is this namespace configured safely? | `KG-*` |
| `ImageSecurityReport` | `isr` | are the images it runs safe? | `TRIVY-*` |

```yaml
apiVersion: security.kubeguardian.io/v1alpha1
kind: ManifestSecurityReport
metadata:
  name: posture
  namespace: payments
---
apiVersion: security.kubeguardian.io/v1alpha1
kind: ImageSecurityReport
metadata:
  name: posture
  namespace: payments
```

That is the whole object, either of them. A report audits the namespace it lives in, so
there is nothing to configure and no way to point it at the wrong place. Its name is free;
`posture` or the namespace name are both fine.

They are separate because the two questions are separate. A manifest finding is fixed by
editing YAML and is usually the application team's; an image finding is fixed by rebuilding
or bumping an image and is often someone else's. They also refresh on different cadences: a
manifest report rescans the moment you edit a workload, while an image report only changes
when the scanner produces new data. One status per question means one `lastScanTime` and
one `ScanSucceeded` condition that each mean something precise.

Create one, the other, or both. Nothing is scanned unless you ask for it.

Reports are namespaced rather than cluster-scoped so a team with access to only their own
namespace can read their own findings through the RoleBinding they already have, and cannot
read anyone else's. See DESIGN.md for why that constraint decides the design.

Deleting a report stops that scanning. Deleting the namespace takes both with it.

## What a report looks like

```console
$ kubectl get msr,isr -n payments
NAME                                                    CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
manifestsecurityreport.security.kubeguardian.io/posture 0          1      0        0     0            31s         2m

NAME                                                    CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
imagesecurityreport.security.kubeguardian.io/posture    2          9      14       0     0            4m          2m

$ kubectl get msr -A
NAMESPACE           NAME      CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
payments            posture   0          1      0        0     0            31s         2m
monitoring-system   posture   0          17     31       0     1            12s         2m
```

The two `LAST-SCAN` values differ, and that is the point: the manifest report rescanned
when a workload was last edited, the image report on its own cadence.

```console
$ kubectl get msr posture -n monitoring-system -o yaml
status:
  summary:
    critical: 0
    high: 17
    medium: 31
    low: 0
    total: 48
    suppressed: 1
  findings:
    - id: KG-001
      severity: Critical
      category: PodSecurity
      resource:
        kind: Deployment
        name: legacy-api
      message: 'baseline Pod Security Standard, privileged: container "api" must not set
        securityContext.privileged=true'
      suggestion: Set securityContext.privileged to false and add back only the individual
        capabilities the container genuinely needs.
      remediation: |-
        securityContext:
          privileged: false
      reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
      source: pod-security
  conditions:
    - type: ScanSucceeded
      status: "True"
      reason: ScanCompleted
      message: 48 finding(s) across 2 severity level(s), 1 suppressed by exception
  lastScanTime: "2026-08-27T17:50:54Z"
```

## Requirements

- Go 1.26 or newer, matching the `go` directive in `go.mod`
- `kubectl` with access to a cluster
- Docker, only if you want to build and push the controller image

## Running it

The fastest way to see it work is to install the CRDs and the checks, then run the
controller on your machine against a cluster. No image build is involved.

```bash
export KUBECONFIG=/path/to/your/kubeconfig

make install            # the CRDs
make install-policies   # the nine shipped SecurityCheck objects
make run
```

`make deploy` does both for you; `install-policies` exists for the out-of-cluster path. The
manifest checks live in those objects, so without them a report legitimately contains no
`KG-` findings at all.

In a second terminal, create a deliberately insecure namespace, ask for it to be audited,
and read the result:

```bash
make demo
```

That applies `test/demo/01-insecure-namespace.yaml`, which asks for both kinds of report,
waits a moment, and prints them. The manifest report produces fifteen findings, two of
them critical. The image report stays empty unless trivy-operator is installed, and says
so in its `ScanSucceeded` condition rather than reading as a clean result.

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

kubectl get msr -n kubeguardian-demo -w
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

`make undeploy` removes the controller and `make uninstall` removes the CRDs. Removing
a CRD deletes every report of that kind; it does not touch the namespaces themselves.

### Upgrading from a build older than v0.6.0

`NamespaceSecurityReport` carried both kinds of finding until v0.6.0 and no longer exists.
The two new CRDs apply cleanly alongside it, so `make deploy` succeeds, but the old CRD
stays behind serving reports nothing writes to any more. Delete it:

```bash
make deploy IMG=<your-image>
kubectl delete crd namespacesecurityreports.security.kubeguardian.io
```

That deletes the old reports with it. They hold only derived data, so nothing is lost that
asking again does not rebuild. Recreate them as whichever kind you want:

```bash
kubectl get ns -o name | sed 's|namespace/||' | while read -r ns; do
  kubectl apply -f - <<EOF
apiVersion: security.kubeguardian.io/v1alpha1
kind: ManifestSecurityReport
metadata:
  name: posture
  namespace: $ns
EOF
done
```

`ScanException` objects are unaffected. They match on check ID, so an exception written
against the old report keeps suppressing the same finding in whichever kind it now lands.

### Upgrading from a build older than v0.4.0

`NamespaceSecurityReport` was also cluster-scoped before v0.4.0. If you are coming from
that far back, deleting the CRD as above covers both changes at once.

## Configuration

The controller is configured with flags on the manager binary.

| Flag | Default | Purpose |
|---|---|---|
| `--rescan-interval` | `3h` | How often an `ImageSecurityReport` is rescanned. It is the only way new Trivy scan data arrives, because Trivy's reports cannot be watched. `ManifestSecurityReport` ignores this: everything its checks read is watched, so it rescans on change. |
| `--min-severity` | `Low` | Lowest severity recorded in a report. Set to `High` to keep reports focused on what matters most. |
| `--max-findings` | `200` | Upper bound on findings per report. The least severe are dropped first, so a pathological namespace cannot produce an object the API server refuses. |
| `--leader-elect` | `false` | Enable when running more than one replica. |

## The check catalog

Every finding carries an identifier from this table. Severities are fixed per check.

Pod-level findings are produced by the upstream
[`k8s.io/pod-security-admission`](https://pkg.go.dev/k8s.io/pod-security-admission)
library rather than by rules written here, so they are exactly the Pod Security Standards
as Kubernetes publishes them. KubeGuardian evaluates every pod template at both the
`baseline` and `restricted` level and maps each upstream check onto a `KG-` identifier:

| ID | Check | Severity | Upstream check |
|---|---|---|---|
| KG-001 | Container runs privileged | Critical | `privileged` |
| KG-002 | Container may run as root | High | `runAsNonRoot`, `runAsUser` |
| KG-003 | Privilege escalation is not disabled | High | `allowPrivilegeEscalation` |
| KG-004 | Pod shares a host namespace (`hostNetwork`, `hostPID`, `hostIPC`) | Critical | `hostNamespaces` |
| KG-005 | Pod mounts a `hostPath` volume | High | `hostPathVolumes` |
| KG-006 | Container does not drop all Linux capabilities | Medium | `capabilities_baseline`, `capabilities_restricted` |
| KG-008 | Container sets no seccomp profile, or sets it to `Unconfined` | Medium | `seccompProfile_baseline`, `seccompProfile_restricted` |
| KG-030 | Container binds a port on the node | High | `hostPorts` |
| KG-031 | Windows container runs as a HostProcess container | Critical | `windowsHostProcess` |
| KG-032 | Container unmasks `/proc` | High | `procMount`, `procMount_restricted` |
| KG-033 | Container runs unconfined by AppArmor | Medium | `appArmorProfile` |
| KG-034 | Container overrides its SELinux type or user | Medium | `seLinuxOptions` |
| KG-035 | Pod sets a sysctl outside the safe set | Medium | `sysctls` |
| KG-036 | Probe or lifecycle hook targets a host address | Medium | `hostProbesAndHostLifecycle` |
| KG-037 | Pod uses a volume type `restricted` does not permit | Medium | `restrictedVolumes` |

The rest are `SecurityCheck` objects, not code. They are namespace and governance concerns
that nothing upstream evaluates, and they ship under `config/policies/` so you can read,
edit or replace them without rebuilding anything:

| ID | Check | Severity | Scope |
|---|---|---|---|
| KG-007 | Container has a writable root filesystem | Medium | Container |
| KG-010 | Namespace has no default-deny ingress NetworkPolicy | High | Namespace |
| KG-011 | Namespace does not enforce a Pod Security Standard | High | Namespace |
| KG-012 | Default ServiceAccount automounts an API token | Medium | ServiceAccount |
| KG-013 | Namespaced Role grants a wildcard | High | Role |
| KG-020 | Image uses a mutable tag or none at all | Medium | Container |
| KG-021 | Container is missing resource requests or limits | Medium | Container |

```console
$ kubectl get seccheck
NAME                                     ID       SEVERITY   SCOPE            READY   AGE
kg007-writable-root-filesystem           KG-007   Medium     Container        True    2d
kg010-default-deny-network-policy        KG-010   High       Namespace        True    2d
kg011-pod-security-admission-missing     KG-011   High       Namespace        True    2d
kg011-pod-security-admission-privileged  KG-011   High       Namespace        True    2d
kg012-default-service-account-token      KG-012   Medium     ServiceAccount   True    2d
kg013-wildcard-rbac                      KG-013   High       Role             True    2d
kg020-mutable-image-tag                  KG-020   Medium     Container        True    2d
kg020-untagged-image                     KG-020   Medium     Container        True    2d
kg021-resource-limits                    KG-021   Medium     Container        True    2d
```

Nine objects for seven identifiers, because two of the checks say two different things
depending on what is wrong, and one predicate per object reads better than a conditional
inside one. Several objects may share an `id`; a `ScanException` matches on the `id`, so it
covers all of them.

`readOnlyRootFilesystem` is deliberately in the second table: it is common hardening
advice but is not part of any Pod Security Standard level, so upstream does not check it.

Everything above lands in a `ManifestSecurityReport`. The two identifiers below are the
whole of `ImageSecurityReport`, and appear only when trivy-operator is installed; see
[Vulnerability scanning](#vulnerability-scanning). Their severity comes from the scan.

| ID | Check | Severity | Category |
|---|---|---|---|
| TRIVY-VULN | Image carries known CVEs | varies | SupplyChain |
| TRIVY-SECRET | Credential baked into an image layer | varies | SupplyChain |

Checks apply to Deployments, StatefulSets, DaemonSets and CronJobs, and cover init
containers as well as regular ones.

Because both Pod Security Standard levels are evaluated, one `hostPath` volume is reported
twice: KG-005 for violating `baseline`, and KG-037 for using a volume type `restricted`
does not permit. That is two levels of the same standard rather than two opinions about
the same rule, and a namespace that only targets `baseline` can accept KG-037 with a
`ScanException`.

Findings from the upstream evaluator carry a YAML snippet as their remediation rather than
a `kubectl patch` command. The evaluator reports which control was violated, not the exact
container index inside the pod template, so a patch path cannot be constructed reliably.

There is deliberately no overall score. An earlier version had one and it was removed:
it floored at zero, so most namespaces on a real cluster read `0` and the number stopped
discriminating exactly where triage matters. Severity counts say the same thing without
implying a precision the heuristic never had.

## Writing a check

A manifest check is a `SecurityCheck` object holding CEL expressions — the same language
Kubernetes uses for `ValidatingAdmissionPolicy` and CRD validation rules. Adding a rule is
applying a manifest.

```yaml
apiVersion: security.kubeguardian.io/v1alpha1
kind: SecurityCheck
metadata:
  name: require-team-label
spec:
  id: ACME-001
  severity: Low
  category: Governance
  scope: Namespace
  violation: "!('team' in namespaceObject.metadata.labels)"
  message: namespace "${namespaceObject.metadata.name}" has no team label, so nobody owns it
  suggestion: Label the namespace with the team that owns it.
  remediation: kubectl label namespace ${namespaceObject.metadata.name} team=<team>
```

`violation` must evaluate to a boolean; true means the subject has the problem. In
`message`, `suggestion` and `remediation`, text inside `${...}` is CEL and everything else
is literal, so a multi-line YAML remediation keeps its formatting.

`scope` decides the subject and how many findings one check can produce:

| `scope` | Evaluated | Subject variable |
|---|---|---|
| `Namespace` | once per namespace | — |
| `Workload` | once per Deployment, StatefulSet, DaemonSet, CronJob | `workload` |
| `Container` | once per container, init containers included | `container`, `workload` |
| `Role` | once per Role | `role` |
| `ServiceAccount` | once per ServiceAccount | `serviceAccount` |

Every scope can also read the whole namespace: `namespaceObject`, `workloads`,
`networkPolicies`, `serviceAccounts` and `roles`. It is spelled `namespaceObject` because
CEL reserves `namespace` as an identifier, the same reason `ValidatingAdmissionPolicy`
spells it that way.

`Container` scope adds three values computed before evaluation: `imageTag`, `imageDigest`
and `containerIndex`. They exist because splitting an image reference is fiddly —
`registry:5000/app` is untagged while `registry:5000/app:2.0` is not — and because a
`kubectl patch` path needs the container's index. **They are parsing primitives, never
judgements.** A derived value that encoded an opinion would put the rule back in the code
with a YAML wrapper around it.

When a message has to name which of several conditions failed, compute it in `bindings`,
which are evaluated first and visible everywhere after:

```yaml
  bindings:
    missing: >-
      [ 'memory' in container.resources.limits   ? '' : 'memory limit',
        'cpu'    in container.resources.requests ? '' : 'cpu request'
      ].filter(f, f != '')
  violation: missing.size() > 0
  message: container "${container.name}" is missing ${joinFields(missing)}
```

Besides the CEL standard library you get strings, lists, regex and Kubernetes `quantity()`
comparison, plus `joinFields()`, which renders a list as "a, b and c".

**A check that does not compile produces no findings and says so on its own object**, so a
typo is visible where you made it rather than as a report that quietly lost a rule:

```console
$ kubectl get seccheck require-team-label
NAME                 ID        SEVERITY   SCOPE       READY   AGE
require-team-label   ACME-001  Low        Namespace   False   10s

$ kubectl get seccheck require-team-label -o jsonpath='{.status.conditions[0].message}'
violation: ERROR: <input>:1:30: undefined field 'labals'
```

Evaluation is capped by a cost budget, so an expression that walks the namespace
quadratically is stopped rather than allowed to stall a reconcile.

Editing any `SecurityCheck` rescans every `ManifestSecurityReport`, so a change to a rule
shows up in the reports without waiting.

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

`expiresAt` is honoured to the second rather than polled for. When a report is scanned,
the controller finds the earliest expiry among the exceptions that could apply to that
namespace and schedules its next reconcile for exactly that moment. The suppression lifts
when the exception expires, not up to a rescan interval later.

```console
$ kubectl get scanexceptions
NAME                        CHECKS       NAMESPACES             EXPIRES                REASON
node-exporter-host-access   ["KG-004"]   ["monitoring-system"]  2027-01-01T00:00:00Z   prometheus node-exporter reads...
```

## Vulnerability scanning

`ImageSecurityReport` is filled in from
[trivy-operator](https://aquasecurity.github.io/trivy-operator/). This covers what reading
manifests structurally cannot see: CVEs in image layers, and credentials baked into images.

If trivy-operator is not installed, KubeGuardian detects that at startup and says so on
every image report rather than leaving one that reads as a clean result:

```console
$ kubectl get isr posture -n payments -o jsonpath='{.status.conditions[0]}' | jq
{
  "type": "ScanSucceeded",
  "status": "False",
  "reason": "ScannerUnavailable",
  "message": "no image scanner is installed in this cluster, so no image data is available. Install trivy-operator and restart the KubeGuardian manager."
}
```

`ManifestSecurityReport` is unaffected and runs exactly as it does with the scanner
present. Nothing needs configuring to turn image scanning off; not creating an
`ImageSecurityReport` is how you decline it.

Detection happens once at startup, so installing trivy-operator afterwards needs a restart
of the KubeGuardian manager before image reports start filling in.

Installation and the design of the adapter are documented in
[internal/sources/trivy/README.md](internal/sources/trivy/README.md).

## Tests

```bash
make test
```

This regenerates manifests, runs `go vet`, downloads the envtest control plane binaries
if needed, and runs everything:

- Table-driven unit tests for every check written here, run against in-memory namespace
  snapshots
- Tests that the upstream Pod Security Standards evaluator is wired correctly: every
  upstream check has a `KG-` mapping, each violation produces the expected identifier, and
  every finding it emits carries a suggestion, a remediation and a reference
- Tests for ordering determinism, deduplication and severity filtering
- Integration tests against a real API server via envtest, which start both managers and
  assert that asking for a scan produces findings, that an insecure workload produces
  the expected identifiers, and that editing that workload changes the report
- Integration tests that the two kinds are independent: a `ManifestSecurityReport` carries
  only `KG-` findings and does not bring an `ImageSecurityReport` into being, and an
  `ImageSecurityReport` with no scanner installed reports `ScannerUnavailable` rather than
  an empty success
- A test that applies the shipped demo manifests and asserts the findings they produce, so
  the documented walkthrough cannot silently rot
- Table-driven tests for `ScanException` matching: check ID, namespace list, namespace
  selector, resource kind and name, expiry, and the wildcard
- Trivy adapter tests over fixture reports, including 300 CVEs collapsing to one finding
  and the disabled-adapter path returning nothing without erroring
- Benchmarks in `internal/policy/bench_test.go` and `internal/sources/scan_bench_test.go`
  that measure a scan against namespaces of 10, 100 and 1000 workloads, so the cost of CEL
  evaluation is a number rather than an assumption

```bash
go test ./internal/sources/ -run '^$' -bench .
```

```bash
make lint
```

Beyond these, the operator was deployed into a kind cluster and put through 26 acceptance
scenarios covering the report lifecycle, garbage collection, RBAC sufficiency, loop
stability, schema validation, flag handling and workload coverage. Results are recorded in
[TESTING.md](TESTING.md).

## Repository layout

```
api/v1alpha1/          CRD types for the two reports, SecurityCheck, ScanException
cmd/                   manager entrypoint and flags
internal/snapshot/     collects everything in a namespace in one pass
internal/policy/       compiles and evaluates SecurityCheck expressions
internal/sources/      the Source interface, ordering, deduplication and summaries
internal/exceptions/   ScanException matching and suppression
internal/sources/policy/        evaluates the SecurityCheck objects in the cluster
internal/sources/podsecurity/   wraps the upstream Pod Security Standards evaluator
internal/sources/trivy/         reads trivy-operator reports
internal/controller/   the shared scanner, one reconciler per report kind, and the
                       SecurityCheck compiler that reports whether a rule is valid
config/policies/       the nine shipped SecurityCheck manifests
config/                kustomize manifests for CRDs, RBAC and the manager
test/demo/             insecure and hardened namespaces used by make demo
```
