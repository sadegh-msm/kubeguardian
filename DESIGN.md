# Design

Test scenarios and their observed results are in [TESTING.md](TESTING.md).

This document carries the explanatory load that comments normally would. The code has
none by choice, so the reasoning lives in one place a reviewer reads deliberately,
instead of scattered through files where it drifts out of date.

## The problem

Audit the security posture of every namespace, re-audit when workloads change, and
publish findings with actionable suggestions as a Kubernetes resource.

## Scope

What is built:

- A cluster-scoped `NamespaceSecurityReport` CRD, one per namespace
- A controller that watches namespaces and the workloads inside them
- Fourteen checks across pod security, network, RBAC, supply chain and governance
- A `Source` seam with two implementations: the built-in engine and a Trivy adapter
- A `ScanException` CRD for recording accepted risks without hiding them
- Unit tests per check, and integration tests against a real API server via envtest

What is deliberately not built is listed at the end, with reasons.

## Why a CRD

The requirement is that results are observable as a Kubernetes resource. That could mean
logs, Prometheus metrics, Events, a ConfigMap, or a custom resource. A CRD is the right
answer here for reasons the alternatives fail on:

- It is queryable the way operators expect. `kubectl get nsr`, label selectors, RBAC on
  the resource, and printer columns all work with no extra code.
- It has a schema. Severity and category are enum-validated by the API server, so a
  malformed finding is rejected at admission rather than discovered by a consumer.
- It carries status semantics. Findings are observed state, so they live in `.status`
  behind the status subresource, and `conditions` reports whether the last scan
  succeeded, which a ConfigMap cannot express.

Events were considered as an addition. They were dropped because a namespace with
fourteen findings would emit fourteen events on every rescan, and suppressing that noise
is real work for little gain when the report already holds the same information.

## Report shape and who creates it

The report is **namespaced**, and it audits the namespace it lives in. There is no
`spec.namespaceRef`; `metadata.namespace` is the target. The spec is empty.

**The user creates it; the operator never does.** An earlier version reconciled namespaces
and created a report for each one, which meant every new namespace silently acquired an
object nobody asked for. Scanning is now opt-in: the report *is* the request, and its
status is the answer.

### Why namespaced rather than cluster-scoped

This started cluster-scoped with a `spec.namespaceRef` pointer. The deciding argument
against that is RBAC, and it is a hard limitation rather than a preference.

Kubernetes RBAC can restrict a rule to named objects with `resourceNames`, but **`list` and
`watch` cannot be narrowed that way** — a collection request carries no resource name, so
the authorizer either allows the whole collection or denies it. For a cluster-scoped report,
a tenant confined to one namespace therefore gets:

```
kubectl get nsr payments     # works, via resourceNames
kubectl get nsr              # Forbidden
```

They cannot discover or watch their own report, and no dashboard or controller that lists
can work on their behalf. The only alternative is granting cluster-wide read, which exposes
every other tenant's findings — including which namespaces run privileged containers. In a
platform that hosts other people's workloads, that is a cross-tenant information leak.

Namespaced, the tenant's existing RoleBinding covers it. They see theirs and only theirs,
with no new RBAC machinery at all.

Four things fall out for free:

- **Lifecycle.** The report cannot outlive its namespace, so there is no owner reference to
  set, no finalizer, and no dangling-reference state to represent. An earlier iteration had
  a `NamespaceNotFound` condition for exactly that case; it is now unrepresentable and the
  code is gone.
- **Quota.** Namespaced objects count against `ResourceQuota`, so a tenant can be capped.
  Cluster-scoped objects cannot be.
- **Naming.** Report names are scoped, so two tenants cannot collide and no one can squat a
  useful name globally.
- **Convention.** trivy-operator, the Policy WG `PolicyReport`, and Kyverno all namespace
  their per-namespace findings and add a separate `Cluster*` kind for cluster-scoped
  subjects. Following that keeps the door open for a `ClusterSecurityReport` later without
  overloading this one.

The only thing given up is the single-command fleet view, and `kubectl get nsr -A` recovers
it. Genuinely cluster-level findings — ClusterRoleBinding analysis, node configuration —
want their own kind rather than a cluster-scoped per-namespace one.

`--excluded-namespaces` was removed along the way. It existed to stop auto-creation flooding
control-plane namespaces; with explicit opt-in it configured nothing, and a flag that does
nothing is worse than no flag.

## Reconcile flow

```
NamespaceSecurityReport ─┐   created by the user, never by the operator
Namespace                │
Deployment               │
StatefulSet              │
DaemonSet                ├─► reports in that namespace ─► Reconcile(report)
CronJob                  │                                       │
NetworkPolicy            │                             snapshot.Collect
Role                     │                                       │
ServiceAccount           │                        Source.Collect for each source
ScanException           ─┘                         ├─ builtin.Engine
                                                   └─ trivy.Adapter (when installed)
                                                                 │
                                                         sources.Normalize
                                                                 │
                                                exceptions.Apply, mark suppressed
                                                                 │
                                            sources.Truncate, sources.Summarize
                                                                 │
                                                     update report .status
```

Reconcile is keyed on the report, never on an individual workload. Any event in the target
namespace collapses to the same work item, so a rollout touching twenty objects produces
one scan rather than twenty.

The `For` watch carries `GenerationChangedPredicate`, which is what stops the controller
spinning on its own status writes: a status update does not change generation.

## Reacting to workload changes

This is the requirement most likely to be implemented badly, so it is worth being
explicit about the mechanism.

`For(&NamespaceSecurityReport{})` alone would only reconcile when a report changed. Workload
events reach the right reports by listing the reports in the workload's own namespace:
given a Deployment in `payments`, the map function enqueues every report in `payments`. An
object in a namespace nobody asked to audit maps to zero requests and costs nothing.

This is the mapping the cluster-scoped design needed a field index on `spec.namespaceRef`
to achieve. Namespacing the report made the index unnecessary.

Workload watches carry `predicate.GenerationChangedPredicate`. Without it, every replica
count update written by the deployment controller would trigger a full namespace rescan.
Generation only changes when the spec changes, which is exactly the trigger the
requirement asks for. NetworkPolicy, Role and ServiceAccount watches do not use the
predicate because those objects carry no status and every update to them is meaningful.

A `RequeueAfter` of `--rescan-interval` backs the watches up, so posture drift is caught
even in a namespace that produces no events at all.

## Not writing status in a loop

An operator that watches its own resource and writes to it on every reconcile will spin.
Two things prevent that here.

The `Owns` watch on the report drops update events entirely. It exists so a deleted
report is recreated, not so status writes feed back into the queue.

`writeStatus` writes on every completed scan, so `lastScanTime` means what its name says.
An earlier version skipped the write when findings had not changed, which froze the
timestamp on exactly the namespace you had just edited while untouched namespaces refreshed
on their shared periodic cadence. That is the wrong way round and it was reported as a bug.

The write is a full status update rather than a merge patch. A merge patch computed from Go
structs omits fields whose value equals the stored one, so a genuine `suppressed: 0` could
never be written and the column rendered blank instead of zero. A full update stores what
the struct says, and a conflict retry handles concurrent writers.

Deterministic ordering is what makes that comparison meaningful. `sources.Normalize`
sorts findings by severity, then ID, then resource, so two scans of an unchanged
namespace produce byte-identical output and the comparison actually holds. Without the
sort, map iteration order alone would make every scan look like a change.

## The check engine

A check is a pure function from a namespace snapshot to findings:

```go
type Check interface {
	ID() string
	Severity() securityv1alpha1.Severity
	Category() securityv1alpha1.Category
	Run(snap *snapshot.Snapshot) []securityv1alpha1.Finding
}
```

Purity is the point. Checks touch no client and no context, so their tests need no
cluster, run in milliseconds, and cover edge cases that would be tedious to stage against
a real API server.

Shared metadata lives in an embedded `meta` struct, so each rule file contains only its
logic and its remediation text, and no rule can accidentally emit a finding with a
mismatched severity or a missing reference.

`snapshot.Collect` gathers every relevant object in the namespace in one pass using the
manager's cache, and `Snapshot.Workloads()` flattens Deployments, StatefulSets, DaemonSets
and CronJobs into a single `Workload` type holding a pod template. That flattening is why
a rule is roughly fifteen lines and automatically covers four workload kinds and their
init containers.

### What is written here and what is not

There were fourteen rules here originally. Seven of them, covering privileged containers,
running as root, privilege escalation, host namespaces, `hostPath` volumes, capabilities
and seccomp, were a reimplementation of the Pod Security Standards. That is a
specification Kubernetes publishes and revises, and reimplementing it means diverging from
it silently at some future release, in a tool whose entire value is being right about what
the cluster enforces.

Those seven were deleted and replaced by `internal/sources/podsecurity`, which calls
`k8s.io/pod-security-admission` — the same package the API server uses for Pod Security
Admission. Three things follow from that:

- Findings match what enforcement would actually do, which makes KG-011's advice
  self-consistent: KubeGuardian tells a namespace to enforce a standard, and reports
  exactly what enforcing it would reject.
- Eight controls arrived for free that no hand-written rule had covered: host ports,
  Windows HostProcess containers, `procMount`, AppArmor, SELinux options, sysctls, host
  probes, and restricted volume types. They are KG-030 to KG-037.
- The library is on the same release train as `k8s.io/api`, so tracking a Kubernetes minor
  version updates the security logic as a side effect of an ordinary dependency bump.

The seven rules that remain are the ones with no upstream owner: `readOnlyRootFilesystem`,
which is common hardening advice but is not part of any Pod Security Standard level, and
the six namespace and governance checks — NetworkPolicy, Pod Security Admission labels,
default ServiceAccount tokens, wildcard RBAC, mutable image tags and resource limits.

One constraint the library imposed is worth recording. `policy.CheckResult` carries
`Allowed`, `ForbiddenReason` and `ForbiddenDetail`, but **not** the ID of the check that
produced it, so evaluating all checks in one pass yields failures that cannot be
attributed. `New()` therefore builds one `policy.Evaluator` per check and evaluates each
separately. That is more evaluator objects than strictly necessary, and it is what makes
the mapping from an upstream check to a `KG-` identifier possible at all.

Both `baseline` and `restricted` are evaluated for every workload, because a report should
describe posture rather than pass or fail against one chosen level. The visible
consequence is that a `hostPath` volume produces two findings, KG-005 and KG-037. They are
two levels of one standard rather than two tools disagreeing, and a namespace that only
targets `baseline` can accept KG-037 with a `ScanException`.

## The Source seam

```go
type Source interface {
	Name() string
	Collect(ctx context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error)
}
```

This is the one deliberate abstraction in the codebase. It exists because the built-in
engine is structurally incapable of answering a whole class of questions: anything
requiring image contents, such as CVEs in a base layer, needs a scanner that pulls and
unpacks images, with registry credentials, real CPU, and a vulnerability database.

Rather than grow this operator into an image scanner, a second source contributes findings
into the same report. Every finding records which source produced it.

Two more sources are now built, and neither required a change to the seam or to the
controller, which is the useful evidence that it was drawn in the right place.

`internal/sources/podsecurity` wraps the upstream Pod Security Standards evaluator.
`internal/sources/trivy` reads the `VulnerabilityReport` and `ExposedSecretReport`
resources that trivy-operator writes.

Two decisions in that adapter are worth stating here because they are not obvious:

**It uses an uncached reader.** A controller-runtime cached client starts an informer the
first time a type is used, and that fails hard when the CRD does not exist. Since Trivy is
optional, the adapter reads directly and gates itself on a startup discovery check. The
same binary runs unchanged on a cluster with no Trivy installed.

**It aggregates rather than enumerating.** A single `VulnerabilityReport` routinely carries
hundreds of CVEs. One finding per CVE would push a busy namespace past the etcd 1.5 MB
object limit and the API server would reject the status write outright. Each report
collapses to one finding per workload and image, listing only the CVEs that have a fixed
version, since those are the ones actionable today. `--max-findings` caps the whole report
as a second layer.

`ConfigAuditReport` and `RbacAssessmentReport` are not consumed. The upstream Pod Security
Standards evaluator and the remaining rules already cover that ground, and ingesting them
would report the same privileged container a second time under an unrelated `KSV-`
identifier, behind a hand-maintained mapping table that drifts as Aqua adds checks. Trivy
stays for what only Trivy can do.

## Exceptions

Real clusters contain workloads that legitimately need what a check flags. A node metrics
agent needs `hostNetwork` and `hostPID`. Reporting it on every scan is worse than useless:
it trains a reviewer to skim past KG-004, which is exactly the finding that matters when it
appears somewhere unexpected.

`ScanException` is cluster-scoped rather than an annotation on the workload, for two
reasons. Exceptions are a governance concern and belong somewhere a security reviewer can
list them in one command, not scattered across manifests. And most workloads that need an
exception are third-party — a Helm-installed node-exporter — so requiring an annotation
would mean forking chart values to record a security decision.

`reason` is required and validated non-empty. An exception without a justification is the
thing that makes exception systems rot into permanent blanket suppressions.

**Suppressed findings stay in the report**, marked with the exception that accepted them
and its reason, excluded from the severity counts and counted under `suppressed` instead.
Deleting them would make an accepted risk indistinguishable from a namespace nobody
scanned. `critical: 0, suppressed: 2` is a different statement from `critical: 0`, and the
difference is the whole point.

Expiry is handled by dropping expired exceptions at load time, so there is no reaper and no
timer. An expired exception stops suppressing at the next scan of its namespace, within one
`--rescan-interval`.

Editing an exception must re-evaluate every namespace, so the `ScanException` watch fans
out to all of them. It is the one deliberate fan-out in the controller, and it only fires
on exception writes, which are rare.

## API field semantics

The API types carry kubebuilder doc comments, so `kubectl explain` works and the generated
CRD carries descriptions. The field meanings are collected here as well.

| Field | Meaning |
|---|---|
| `metadata.namespace` | The namespace this report audits; the spec is empty |
| `status.summary` | Finding counts per severity, a total, and a suppressed count |
| `status.findings[].id` | Stable rule identifier, `KG-001` |
| `status.findings[].severity` | Enum-validated: `Critical`, `High`, `Medium`, `Low` |
| `status.findings[].category` | Enum-validated: `PodSecurity`, `Network`, `RBAC`, `SupplyChain`, `Governance` |
| `status.findings[].resource` | Kind, name, and container the finding attaches to |
| `status.findings[].message` | What is wrong |
| `status.findings[].suggestion` | What to do about it |
| `status.findings[].remediation` | A command or manifest that applies the fix |
| `status.findings[].reference` | Upstream documentation for the control |
| `status.findings[].source` | Which `Source` produced the finding, `builtin` or `trivy` |
| `status.findings[].suppressed` | True when a `ScanException` accepted this risk |
| `status.findings[].suppressedBy` | Name of the exception that accepted it |
| `status.findings[].suppressedReason` | The justification recorded on that exception |
| `status.conditions` | `ScanSucceeded` reports whether the last scan completed |

Severity and category are named string types with `+kubebuilder:validation:Enum` markers
rather than bare strings. The legal values are enforced by the API server rather than
merely documented, so an invalid value is rejected at admission instead of discovered by a
consumer.

## Why there is no score

An earlier version scored each namespace out of 100, subtracting per finding by severity.
It was removed after running against a real cluster.

The heuristic floored at zero, and on the Hamravesh platform cluster five of ten namespaces
sat at exactly `0`. At that point the number stops discriminating precisely where triage
matters most, and fixing a critical finding moved nothing, which is the opposite of the
feedback a remediation loop needs. It also invited comparison between namespaces of
different sizes, which the heuristic could not support: a large namespace accumulates
penalties simply for having more workloads.

Severity counts carry the same information without implying a precision that was never
there. `critical: 1, high: 29` is directly actionable; `score: 0` is not.


## Deliberately out of scope

The task states that full implementation is not expected and that a clear scope with
reliable output matters more. These were cut on purpose.

- **Validating admission webhook.** Blocking non-compliant workloads at creation is the
  natural next step, but certificate provisioning, rotation and `failurePolicy` tuning
  are a meaningful chunk of work, and a webhook that fails open is worse than no webhook.
  The requirement asks for detection, not prevention.
- **Historical trending.** Reports hold current state only. Storing a series of scans
  turns the CRD into a time-series database, which etcd is the wrong store for.
- **Kubernetes Events per finding.** Noise, as described above.
- **Helm chart.** Kustomize manifests under `config/` cover deployment. A chart is a
  straightforward addition that demonstrates nothing the manifests do not.
- **A hand-written CI pipeline.** The kubebuilder-scaffolded `lint` and `test` workflows
  under `.github/workflows/` are kept because they work and cost nothing. The scaffolded
  `test-e2e` workflow was removed along with the e2e harness it invoked.
- **A PolicyReport source.** The Hamravesh cluster already serves
  `policyreports.wgpolicyk8s.io`, the Kubernetes Policy WG standard that Trivy, Kyverno and
  Falco can all emit to. One adapter against that standard would pick up every such tool
  through a single vendor-neutral interface, and would fit the existing `Source` seam. It
  is the natural next extension, left out because Trivy was the integration asked for.
- **A policy engine of our own.** A `SecurityCheck` CRD holding CEL expressions would turn
  new rules into YAML instead of Go, and platform teams could add their own. It is also
  Kyverno rewritten badly: the security knowledge would stay ours to maintain, which is
  the cost the pod-security-admission move was made to avoid.
- **Kyverno or OPA Gatekeeper as the engine.** Both have large curated policy libraries and
  both background-scan existing resources. Both are also an additional admission controller
  and webhook on the platform, which is a large operational commitment for a reporting
  tool. `k8s.io/pod-security-admission` delivers the pod-security half as a Go import, with
  no new cluster dependency at all.
- **Cross-namespace and cluster-scoped RBAC analysis.** ClusterRoleBindings that grant
  namespace access from outside are a real gap, and closing it properly needs a
  cluster-wide binding graph rather than a per-namespace snapshot. That is a different
  shape of problem and deserves its own scope.

## Known limitations

- Checks read workload specs, not running pods. A pod created directly, or mutated after
  admission by another controller, is not evaluated.
- KG-010 only recognises a default-deny policy with an empty pod selector. A namespace
  secured by several narrower policies that collectively deny ingress is still reported.
- KG-012 reports the default ServiceAccount when a workload uses it without disabling
  automounting. It cannot tell whether that workload actually calls the API, so this is
  a prompt to check rather than proof of a problem.
- Findings from the upstream Pod Security Standards evaluator name the workload but leave
  `resource.container` empty, because `policy.CheckResult` reports a violated control
  rather than a path into the pod spec. The container name appears in the message instead,
  and the remediation is a YAML snippet rather than a `kubectl patch` command.
- Trivy detection happens once at startup, so installing trivy-operator after KubeGuardian
  requires an operator restart before its findings appear.
- Trivy labels its reports with the workload it actually scanned, which for a Deployment is
  the active ReplicaSet. Trivy findings therefore name a ReplicaSet where built-in findings
  name the Deployment.

## Code style

The code contains no comments. Kubebuilder markers, build tags and linter directives are
generator and tool input, not commentary, and are kept.

Where a comment would have carried information, that information was moved somewhere it
is enforced or where it is read on purpose: enum-validated named types instead of a
string plus a list of legal values in a comment, named functions instead of an explained
block, and this document instead of narration. `make lint` runs golangci-lint with the
project's default rule set and is clean.
