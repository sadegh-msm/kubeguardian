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

## Report shape

The report is **cluster-scoped**, named after the namespace it describes, with
`spec.namespaceRef` naming it explicitly.

This buys a specific thing. `Namespace` is cluster-scoped, and Kubernetes garbage
collection only accepts an owner reference when the owner is cluster-scoped or in the
same namespace as the dependent. Making the report cluster-scoped lets the namespace own
it, so deleting a namespace deletes its report automatically. No finalizer, no cleanup
path, no risk of leaking reports for namespaces that no longer exist.

The alternative, a namespaced report living inside the namespace it describes, cannot
have the namespace as its owner in a useful way and would need explicit cleanup.

## Reconcile flow

```
Namespace event ─┐
Deployment       │
StatefulSet      │
DaemonSet        ├─► mapToNamespace ─► workqueue ─► Reconcile(namespace)
CronJob          │                                        │
NetworkPolicy    │                              snapshot.Collect
Role             │                                        │
ServiceAccount   │                              Source.Collect for each source
ScanException   ─┘                               ├─ builtin.Engine
                                                 └─ trivy.Adapter   (when installed)
                                                          │
                                                   sources.Normalize
                                                          │
                                              exceptions.Apply, mark suppressed
                                                          │
                                          sources.Truncate, sources.Summarize
                                                          │
                                           CreateOrUpdate report, update .status
```

Reconcile is keyed on the namespace, never on an individual workload. Any event in the
namespace collapses to the same work item, so a rollout touching twenty objects produces
one scan rather than twenty.

## Reacting to workload changes

This is the requirement most likely to be implemented badly, so it is worth being
explicit about the mechanism.

`For(&corev1.Namespace{})` alone would only reconcile on namespace events. Workload
events reach the same reconcile key through
`handler.EnqueueRequestsFromMapFunc(mapToNamespace)`, which maps any namespaced object to
a request for its namespace. `mapToNamespace` returns no request for cluster-scoped
objects, so a stray watch cannot enqueue an empty key.

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
a real API server. Check coverage is 98.6% as a result.

Shared metadata lives in an embedded `meta` struct, so each rule file contains only its
logic and its remediation text, and no rule can accidentally emit a finding with a
mismatched severity or a missing reference.

`snapshot.Collect` gathers every relevant object in the namespace in one pass using the
manager's cache, and `Snapshot.Workloads()` flattens Deployments, StatefulSets, DaemonSets
and CronJobs into a single `Workload` type holding a pod template. That flattening is why
each pod-security rule is roughly fifteen lines and automatically covers four workload
kinds and their init containers.

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

That second source is now built. `internal/sources/trivy` reads the `VulnerabilityReport`
and `ExposedSecretReport` resources that trivy-operator writes, and the seam needed no
change to accommodate it, which is the useful evidence that it was drawn in the right
place.

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

`ConfigAuditReport` and `RbacAssessmentReport` are not consumed: KG-001 to KG-013 already
cover that ground, and ingesting them would report the same privileged container twice.

Nothing else in the codebase has an interface with a single implementer.

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

The API types carry no doc comments, which means `kubectl explain` returns empty
descriptions. That trade was made knowingly; the field meanings are here.

| Field | Meaning |
|---|---|
| `spec.namespaceRef` | The namespace this report describes |
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
rather than bare strings. The legal values are enforced by the API server and visible in
the generated CRD, which is a stronger guarantee than the comment that would otherwise
have listed them.

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
- The excluded namespace list is exact-match, not a selector.
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
