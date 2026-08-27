# Design

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
- Thirteen checks across pod security, network, RBAC, supply chain and governance
- A `Source` seam so findings can come from somewhere other than the built-in engine
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
ServiceAccount  ─┘                              Source.Collect for each source
                                                 ├─ builtin.Engine   (implemented)
                                                 └─ trivy.Adapter    (designed)
                                                          │
                                              sources.Normalize, scoring.Compute
                                                          │
                                            CreateOrUpdate report, patch .status
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

`writeStatus` compares the computed score, summary and findings against what is already
stored and returns without writing when nothing changed and the last scan is recent. This
also keeps `lastScanTime` from being rewritten every few seconds, which would make the
resource churn its resourceVersion for no reason.

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
a real API server. Check coverage is 98.5% as a result.

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

Rather than grow this operator into an image scanner, a second source can contribute
findings into the same report. Every finding records which source produced it.
`internal/sources/trivy/README.md` documents the adapter and, more usefully, the design
question that has to be answered before building it.

Nothing else in the codebase has an interface with a single implementer.

## API field semantics

The API types carry no doc comments, which means `kubectl explain` returns empty
descriptions. That trade was made knowingly; the field meanings are here.

| Field | Meaning |
|---|---|
| `spec.namespaceRef` | The namespace this report describes |
| `status.score` | 0 to 100, higher is better |
| `status.summary` | Finding counts per severity plus a total |
| `status.findings[].id` | Stable rule identifier, `KG-001` |
| `status.findings[].severity` | Enum-validated: `Critical`, `High`, `Medium`, `Low` |
| `status.findings[].category` | Enum-validated: `PodSecurity`, `Network`, `RBAC`, `SupplyChain`, `Governance` |
| `status.findings[].resource` | Kind, name, and container the finding attaches to |
| `status.findings[].message` | What is wrong |
| `status.findings[].suggestion` | What to do about it |
| `status.findings[].remediation` | A command or manifest that applies the fix |
| `status.findings[].reference` | Upstream documentation for the control |
| `status.findings[].source` | Which `Source` produced the finding |
| `status.conditions` | `ScanSucceeded` reports whether the last scan completed |

Severity and category are named string types with `+kubebuilder:validation:Enum` markers
rather than bare strings. The legal values are enforced by the API server and visible in
the generated CRD, which is a stronger guarantee than the comment that would otherwise
have listed them.

## Scoring

`score = max(0, 100 - 20·critical - 10·high - 5·medium - 2·low)`.

This is a triage ordering signal, not a risk model. It has known weaknesses: a namespace
with six medium findings scores worse than one with a single critical, and a large
namespace accumulates penalties simply for having more workloads. Both are acceptable for
sorting a `kubectl get nsr` listing, which is what the score is for. Anything more
defensible needs a notion of exploitability and exposure that this operator does not
have.

The severity of each finding is the field to act on. The score is the field to sort by.

## Deliberately out of scope

The task states that full implementation is not expected and that a clear scope with
reliable output matters more. These were cut on purpose.

- **Validating admission webhook.** Blocking non-compliant workloads at creation is the
  natural next step, but certificate provisioning, rotation and `failurePolicy` tuning
  are a meaningful chunk of work, and a webhook that fails open is worse than no webhook.
  The requirement asks for detection, not prevention.
- **Trivy adapter implementation.** Designed and documented. Not built, because whether
  image findings belong in a per-namespace report is a genuine design question, given the
  same image usually runs in many namespaces.
- **Historical trending.** Reports hold current state only. Storing a series of scans
  turns the CRD into a time-series database, which etcd is the wrong store for.
- **Kubernetes Events per finding.** Noise, as described above.
- **Helm chart.** Kustomize manifests under `config/` cover deployment. A chart is a
  straightforward addition that demonstrates nothing the manifests do not.
- **A hand-written CI pipeline.** The kubebuilder-scaffolded `lint` and `test` workflows
  under `.github/workflows/` are kept because they work and cost nothing. The scaffolded
  `test-e2e` workflow was removed along with the e2e harness it invoked.
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

## Code style

The code contains no comments. Kubebuilder markers, build tags and linter directives are
generator and tool input, not commentary, and are kept.

Where a comment would have carried information, that information was moved somewhere it
is enforced or where it is read on purpose: enum-validated named types instead of a
string plus a list of legal values in a comment, named functions instead of an explained
block, and this document instead of narration. `make lint` runs golangci-lint with the
project's default rule set and is clean.
