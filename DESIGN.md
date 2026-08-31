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

- Two namespaced report CRDs, `ManifestSecurityReport` and `ImageSecurityReport`, so the
  two questions can be asked and answered separately
- A controller per kind, watching the workloads each one actually reads
- Seven checks across network, RBAC, supply chain and governance, expressed as CEL in
  `SecurityCheck` objects rather than in Go, plus the upstream Pod Security Standards
  evaluator
- A `Source` seam with three implementations: the CEL policy evaluator, the Pod Security
  Standards evaluator and a Trivy adapter
- A `ScanException` CRD for recording accepted risks without hiding them
- Unit tests per check, and integration tests against a real API server via envtest

What is deliberately not built is listed at the end, with reasons.

## Why a CRD

The requirement is that results are observable as a Kubernetes resource. That could mean
logs, Prometheus metrics, Events, a ConfigMap, or a custom resource. A CRD is the right
answer here for reasons the alternatives fail on:

- It is queryable the way operators expect. `kubectl get msr`, label selectors, RBAC on
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

A report is **namespaced**, and it audits the namespace it lives in. There is no
`spec.namespaceRef`; `metadata.namespace` is the target. The spec is empty.

**The user creates it; the operator never does.** An earlier version reconciled namespaces
and created a report for each one, which meant every new namespace silently acquired an
object nobody asked for. Scanning is now opt-in: the report *is* the request, and its
status is the answer.

### Two kinds, not one

There are two report kinds rather than one, and no field to filter sources within a single
kind:

| Kind | Sources | Findings |
|---|---|---|
| `ManifestSecurityReport` | `builtin`, `pod-security` | `KG-*` |
| `ImageSecurityReport` | `trivy` | `TRIVY-*` |

They were one object until v0.6.0. Splitting them is not tidiness; a `spec.sources` filter
on one kind would have given the same selectivity and it would have been wrong for three
reasons.

**Status is the whole product of this operator, and one status cannot describe two
scans.** A manifest scan reruns the instant a workload is edited. An image scan changes
only when trivy-operator writes a new report, which is its own cadence entirely. Sharing a
`lastScanTime` between them means the field describes neither: a fresh timestamp would say
the image data is current when it might be an hour old. Two objects, two timestamps, two
`ScanSucceeded` conditions, each true of exactly one thing.

**A missing scanner becomes expressible.** With one kind, a cluster without trivy-operator
produced a report containing no image findings, which is indistinguishable from a report
whose images are clean. `ImageSecurityReport` reports `ScanSucceeded=False` with reason
`ScannerUnavailable` instead. That statement had nowhere to live before.

**The watches differ, and a filter field could not act on that.** A NetworkPolicy, Role or
ServiceAccount change cannot affect what is inside an image, so the image controller does
not watch them. A `spec.sources` filter would still have woken one controller for every
event either half cared about and then discarded the work. Two controllers means each one
subscribes to exactly what it reads.

The cost is the obvious one: a namespace that wants both answers holds two objects, and
`kubectl get msr,isr` is a longer command than `kubectl get nsr`. The two kinds share a
`ReportStatus` type in the API package and a `Scanner` in the controller package, so the
duplication is in the object model where it is meaningful, not in the code.

### Why namespaced rather than cluster-scoped

This started cluster-scoped with a `spec.namespaceRef` pointer. The deciding argument
against that is RBAC, and it is a hard limitation rather than a preference.

Kubernetes RBAC can restrict a rule to named objects with `resourceNames`, but **`list` and
`watch` cannot be narrowed that way** — a collection request carries no resource name, so
the authorizer either allows the whole collection or denies it. For a cluster-scoped report,
a tenant confined to one namespace therefore gets:

```
kubectl get msr payments     # works, via resourceNames
kubectl get msr              # Forbidden
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

The only thing given up is the single-command fleet view, and `kubectl get msr -A` recovers
it. Genuinely cluster-level findings — ClusterRoleBinding analysis, node configuration —
want their own kind rather than a cluster-scoped per-namespace one.

`--excluded-namespaces` was removed along the way. It existed to stop auto-creation flooding
control-plane namespaces; with explicit opt-in it configured nothing, and a flag that does
nothing is worse than no flag.

## Reconcile flow

Both controllers run the same pipeline over the same snapshot. They differ in what they
watch and in which sources they hand to it.

```
ManifestSecurityReport ─┐  created by the user, never by the operator
Namespace               │
Deployment              │
StatefulSet             ├─► manifest reports in that namespace ─┐
DaemonSet               │                                       │
CronJob                 │                                       │
NetworkPolicy           │                                       │
Role                    │                                       │
ServiceAccount          │                                       │
ScanException          ─┘                                       │
                                                                ▼
ImageSecurityReport    ─┐                                  Scanner.reconcile
Namespace               │                                       │
Deployment              │                             snapshot.Collect
StatefulSet             ├─► image reports in that namespace ────┤
DaemonSet               │                        Source.Collect for each source
CronJob                 │              manifest: builtin.Engine, podsecurity.Source
ScanException          ─┘              image:    trivy.Adapter
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

The `For` watch carries `GenerationChangedPredicate`, which is what stops each controller
spinning on its own status writes: a status update does not change generation.

`Scanner` in `internal/controller/scan.go` holds everything the two do identically, and a
small `report` interface — `client.Object` plus `ReportStatus() *ReportStatus` — is what
lets one status writer serve both kinds. The interface is declared in the controller
package rather than the API package so the API types keep importing nothing but
apimachinery.

## Reacting to workload changes

This is the requirement most likely to be implemented badly, so it is worth being
explicit about the mechanism.

`For(&ManifestSecurityReport{})` alone would only reconcile when a report changed. Workload
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

The image controller watches a strict subset: the four workload kinds, the namespace and
`ScanException`. Changing an image is a spec change, so the generation moves and the image
report rescans immediately, which is the fast path that matters. It does not watch
NetworkPolicy, Role or ServiceAccount, because none of them can change what is inside an
image.

### Only the image report rescans on a timer

`--rescan-interval` defaults to three hours and applies to `ImageSecurityReport` alone.
`ManifestSecurityReport` has no periodic rescan at all.

That asymmetry follows from what each one reads. The manifest checks read exactly five
things — the four workload kinds through `Snapshot.Workloads()`, plus `NetworkPolicies`,
`ServiceAccounts`, `Roles` and the `Namespace` — and every one of them is watched. A
periodic rescan could not discover anything a watch has not already delivered, so it would
only rewrite an identical status on a timer. The image report is the opposite case: Trivy's
`VulnerabilityReport`s are read with an uncached client so the optional CRDs need not
exist, which means they cannot be watched, and the timer is the only path new scan data
has.

One thing does change without an event, and it changes for both kinds: a `ScanException`
reaching its `expiresAt`. No object is written when a timestamp passes. Rather than poll
for it, `Scanner.nextRequeue` takes the earliest expiry among the exceptions that could
apply to the namespace and requeues for exactly that moment, so a suppression lifts on
time rather than up to an interval late. When there is no expiry and no periodic interval,
the reconcile returns no requeue at all and the report simply waits for an event.

The controller-runtime cache resync, ten hours by default, is the backstop against a
dropped watch event. It re-delivers updates for every cached object, and the
NetworkPolicy, Role, ServiceAccount and Namespace watches carry no predicate, so every
namespace gets a free full rescan on that cycle without anything being configured for it.

Three lists were removed from `snapshot.Collect` while establishing the above:
`RoleBindings`, `ResourceQuotas` and `LimitRanges` were collected and read by nothing. They
cost three cluster-wide informers and their RBAC for data no check consults.

## The unit of work is the namespace, not the workload

A workload event does not rescan that workload. It rescans the namespace the workload is
in: `snapshot.Collect` lists all seven resource types, and every source evaluates every
workload. This is deliberate, and it is worth saying why, because "rescan only what
changed" is the obvious alternative.

**The report is a namespace-level aggregate.** Its status has to hold the findings for
every workload in the namespace, so any incremental scheme has to keep the previous
findings somewhere and splice the changed workload's findings into them. That means
tracking which stored finding belongs to which workload, evicting findings when a workload
is deleted, and rebuilding the whole thing after an operator restart. Cache invalidation,
in other words, in exchange for saving CPU that is already cheap.

**The reads are free.** `snapshot.Collect` uses the manager's cached client, so every
`List` is served from the informer's namespace-indexed local store. No API server round
trip happens, whatever the size of the namespace.

**The evaluation is cheap and linear.** Measured on `internal/sources/scan_bench_test.go`,
which runs both sources plus `Normalize`, `Truncate` and `Summarize` over a synthetic
namespace:

| Workloads in namespace | Time | Allocated |
|---|---|---|
| 10 | 0.15 ms | 177 KB |
| 100 | 1.1 ms | 1.6 MB |
| 1000 | 8.8 ms | 19 MB |

A thousand-workload namespace costs about nine milliseconds of CPU. The two things a
reconcile does that are *not* free are the Trivy adapter's two uncached `List` calls and
the status write to etcd, and both are fixed costs per reconcile that incremental
evaluation would not remove. At the point where re-evaluating the namespace is the
bottleneck, the API traffic already is.

**The reconcile count is bounded, not the event count.** A Helm release touching fifty
Deployments enqueues the same report key fifty times, and the workqueue collapses them:
adding a key that is already queued is a no-op. Fifty events produce one or two scans, not
fifty.

What this does mean is that the scan itself should not waste work, and two places did:

- `Snapshot.Workloads()` flattened the four workload kinds on every call, and six checks
  and sources call it. The flattened list and each workload's container list are now built
  once per snapshot and reused. A snapshot belongs to a single reconcile and is never
  shared across goroutines, so no locking is involved.
- `sources.Normalize` built its deduplication key by joining four strings, and its sort
  comparator called `ResourceRef.String()` on every comparison, so an O(n log n) sort
  allocated on every step. The key is now a comparable struct and the comparator compares
  the fields directly. At a thousand workloads that took `Normalize` from about 70,000
  allocations to 34.

Together those cut a thousand-workload scan by roughly a fifth in time and by 44% in
allocations, without changing a single finding.

The cache is cluster-wide, which is the one genuine cost that grows with the cluster rather
than with the namespace: the operator holds every Deployment, ServiceAccount, Role and the
rest in memory, including namespaces nobody asked to audit. `DefaultTransform:
cache.TransformStripManagedFields()` drops the `managedFields` bookkeeping from every
cached object, which is often a large fraction of it. Scoping the cache to only the
namespaces that hold a report would be better still, but controller-runtime fixes a cache's
namespace set at startup and reports are created at any time, so that is not available
without watching the whole cluster anyway.

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

A check is a pure function from a namespace snapshot to findings. It is now spelled as
expressions rather than as Go, but the shape is unchanged: no client, no context, nothing
but the snapshot in and findings out. That is why the tests need no cluster and why one
`Snapshot` can be shared across every check in a scan.

`snapshot.Collect` gathers every relevant object in the namespace in one pass using the
manager's cache, and `Snapshot.Workloads()` flattens Deployments, StatefulSets, DaemonSets
and CronJobs into a single `Workload` type holding a pod template. That flattening is why
one expression covers four workload kinds and their init containers without saying so.

`internal/policy` turns a `SecurityCheck` into programs and runs them:

- `newEnv(scope)` builds the CEL environment. Kubernetes structs are bound natively through
  `ext.NativeTypes` with `ext.ParseStructTag("json")`, so an expression reads
  `container.securityContext.readOnlyRootFilesystem` rather than a Go field name, nested
  types resolve on their own, and a nil pointer reads as the zero value instead of erroring.
- `Compile` type checks every expression against that environment. Because CEL is typed, a
  misspelt field is caught when the object is applied rather than when a namespace happens
  to exercise that branch.
- `Context` holds the variables shared by every check in one scan and caches the subject
  list per scope, so nine checks do not flatten a thousand workloads nine times over.
- `Registry` caches compiled programs by name and generation, including failures, so a
  check with a typo is not recompiled on every scan of every namespace.

### Checks are configuration, not code

The seven rules that remained after the pod-security move are now `SecurityCheck` objects
holding CEL expressions, shipped under `config/policies/`. `internal/checks` and
`internal/sources/builtin` are gone.

**This reverses a decision this document used to record.** *Deliberately out of scope* had
an entry reading "a policy engine of our own ... is Kyverno rewritten badly", and that
reasoning was sound for what it described: a general engine, in a project that would then
own the security knowledge anyway. Two things changed it. The pod-security migration moved
the security knowledge upstream, so what was left was seven small declarative predicates
rather than a body of expertise. And `github.com/google/cel-go` turned out to be already
linked into the binary as an indirect dependency of `k8s.io/apiserver`, so the engine costs
no new module — `internal/policy` is a few hundred lines of environment construction and
evaluation, not a project.

**Why CEL rather than Rego.** Rego is the more expressive language and OPA the more
established ecosystem, and for a general-purpose policy system it would be the better
answer. Here it would add a large dependency tree to a 77 MB image, a second language for
whoever writes rules, and a weaker sandbox. CEL is what Kubernetes itself uses for
`ValidatingAdmissionPolicy` and CRD validation rules, so anyone operating the cluster has
likely already written some, and it is non-Turing-complete with an enforceable cost
budget. That last property is what makes it safe to evaluate expressions the operator did
not compile.

**What that costs.** CEL evaluation is roughly thirty times slower than the equivalent Go,
measured in `internal/policy/bench_test.go`: about 67 ms and 79 MB for the nine checks over
a thousand-workload namespace, against 2.25 ms and 6.5 MB for the Go checks they replaced.
That sounds worse than it is. A namespace on the Hamravesh cluster holds seventeen
workloads, which puts a real scan near a millisecond, well below the etcd status write and
the two Trivy API calls that happen regardless. Compilation, at about 5 ms for all nine, is
the expensive part, which is why `policy.Registry` caches it by generation rather than
compiling per scan.

**Where the line sits.** `Container` scope exposes `imageTag`, `imageDigest` and
`containerIndex`, computed in Go. They exist because splitting an image reference is fiddly
enough to be worth doing once — `registry:5000/app` is untagged, `registry:5000/app:2.0` is
not — and because a `kubectl patch` remediation needs an index. They are parsing
primitives. A derived value that encoded a judgement would move the rule back into the code
and leave a YAML wrapper pretending otherwise, and it is worth refusing the first one.

**Failure is visible rather than silent.** A check that does not compile produces no
findings, and the `SecurityCheck` controller writes the CEL error onto its own `Ready`
condition. The scan skips it and logs, rather than failing every report in the cluster
because one policy has a typo. A check that errors at *evaluation* time does fail the scan,
because CEL catches type errors at compile time, so a runtime error means something the
author could not have anticipated and should not be swallowed.

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

The seven rules that remain are the ones with no upstream owner, and they are now
`SecurityCheck` objects rather than Go: `readOnlyRootFilesystem`,
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

`internal/sources/policy` evaluates the `SecurityCheck` objects in the cluster.
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
- **Kyverno or OPA Gatekeeper as the engine.** Both have large curated policy libraries and
  both background-scan existing resources. Both are also an additional admission controller
  and webhook on the platform, which is a large operational commitment for a reporting
  tool. The `SecurityCheck` CRD covers the same ground for this operator's purposes without
  putting anything new in the cluster.
- **Embedding OPA to evaluate Rego.** Rego is more expressive than CEL, particularly for
  joins, and has a large body of existing policy. It also adds a substantial dependency
  tree to a 77 MB image, is a separate language to learn, evaluates more slowly, and is
  harder to sandbox. CEL was already linked into the binary; see the CEL section above.
- **Cross-namespace and cluster-scoped RBAC analysis.** ClusterRoleBindings that grant
  namespace access from outside are a real gap, and closing it properly needs a
  cluster-wide binding graph rather than a per-namespace snapshot. That is a different
  shape of problem and deserves its own scope.

## The scaling ceiling

The operator scales vertically only, and it is worth naming where that ends rather than
discovering it.

**The cache is cluster-wide by necessity.** A report can be created in any namespace at any
time, and controller-runtime fixes a cache's namespace set when the manager starts. So the
operator holds every Deployment, ServiceAccount, Role and NetworkPolicy in the cluster,
including in namespaces nobody asked to audit. Memory therefore tracks cluster size rather
than scanning load, which is the opposite of what the opt-in report model suggests.

Two mitigations are in `internal/controller/cache.go`, both of them shaving rather than
solving: `managedFields` is stripped from everything, and `status` plus the
`last-applied-configuration` annotation are stripped from watched workload types. Status
alone is around a tenth of the bytes and no check reads any of it. Report types are
deliberately excluded, because `Scanner.updateStatus` reads a report's status back through
the cache inside its conflict-retry loop.

**Fan-out is bounded where it can be.** A `ScanException` that names its namespaces wakes
only the reports in them; one with a `namespaceSelector`, or none at all, still wakes
everything, because resolving the selector is the work the fan-out would have done. A
`SecurityCheck` edit wakes every report, which is correct — a policy applies everywhere.

**Beyond that, the answer is sharding, and it is not available.** Running one operator per
slice of namespaces would need each to cache only its slice, which the fixed-at-startup
namespace set almost supports — except that reports appear at any time, so a new namespace
outside every shard's set would never be scanned. Making that work needs either a
convention that namespaces are labelled for a shard before a report is created, or a
restart when the assignment changes. Neither is free, and neither is needed at the size
this runs at today.

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
- Evaluating CEL costs about thirty times what the equivalent Go did. It is immaterial at
  real namespace sizes and measurable at a thousand workloads; see the check engine section.
- A `ManifestSecurityReport` has no periodic rescan, so a finding that depends on state
  nothing watches would go stale. Today none does: every object its checks read is watched,
  and the one time-dependent input, `ScanException` expiry, is requeued on its deadline. A
  future check that reads something unwatched would have to add the watch with it.
- Trivy detection happens once at startup, so installing trivy-operator after KubeGuardian
  requires an operator restart before its findings appear. Until then every
  `ImageSecurityReport` reports `ScannerUnavailable`, which is at least visible rather than
  silent.
- New Trivy scan data reaches an `ImageSecurityReport` within one `--rescan-interval`
  rather than immediately. `VulnerabilityReport` and `ExposedSecretReport` cannot be
  watched without putting them in the manager cache, which would require the CRDs to exist
  and is exactly what the uncached reader avoids.
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
