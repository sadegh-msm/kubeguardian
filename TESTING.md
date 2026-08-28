# Testing

Three layers, each answering a different question.

| Layer | Question | Mechanism | Result |
|---|---|---|---|
| Unit | Does each rule decide correctly? | Pure functions over in-memory snapshots | 38 test functions, all pass |
| Integration | Does the controller behave against a real API server? | envtest control plane, manager started | 6 specs, all pass |
| Acceptance | Does the built image work in a real cluster? | Hamravesh platform cluster | 26 scenarios plus the exception and Trivy rounds, all pass |

Reproduce layers one and two with `make test`, and layer three with the commands in each
scenario below.

## Environment

```
Go            1.27.0 darwin/arm64
kind          v0.32.0
Kubernetes    v1.36.1 (kind node), v1.36.2 (envtest control plane)
Docker        20.10.21
Registries    gcr.io and registry.k8s.io return 403 on this network; Docker Hub and
              ghcr.io are reachable. See defect 6.
Deployment    image kubeguardian:test, built by make docker-build, loaded with kind load
```

The operator was deployed the full way for acceptance testing, not run out-of-cluster:
image built, loaded into kind, `make deploy` applied the kustomize manifests, and the
controller ran as a Deployment in `kubeguardian-system` under its generated ClusterRole.

## Layer 1: unit tests

Checks are pure functions from a namespace snapshot to findings, so they need no cluster.
Coverage: `internal/checks` 98.6%, `internal/sources` 97.4%, `internal/exceptions` 87.5%,
`internal/sources/trivy` 76.5%, `internal/controller` 77.4%.

Each rule has its own table-driven test covering the positive case, the compliant case,
and the edge cases that matter for that rule. Examples of the edge cases covered:

- Pod-level security context inherited by a container that sets nothing (KG-002, KG-008)
- A container overriding a compliant pod-level setting (KG-008)
- `runAsUser: 0` distinguished from an unset `runAsNonRoot` (KG-002)
- Lowercase `all` accepted as a capability drop (KG-006)
- Capabilities dropped and then added back (KG-006)
- Registry ports not mistaken for image tags: `registry:5000/app` is untagged, but
  `registry:5000/app:2.0` is tagged (KG-020)
- Digest-pinned images treated as immutable (KG-020)
- Egress-only and pod-selecting NetworkPolicies not counted as default-deny (KG-010)
- A namespace with no workloads not flagged for a missing NetworkPolicy (KG-010)
- `audit` label present but `enforce` absent (KG-011)
- One finding per Role even when several rules use wildcards (KG-013)

Ordering and aggregation are tested separately in `internal/sources`: severity ordering,
stability across twenty repeated runs, deduplication, minimum-severity filtering, and
retention of two distinct findings that share an ID and a resource. `Summarize` is tested
to confirm suppressed findings are excluded from the severity counts, and `Truncate` to
confirm it keeps the most severe findings when a report exceeds `--max-findings`.

`internal/exceptions` is table-tested over every matching dimension: check ID, the `*`
wildcard, namespace list, namespace selector, resource kind alone, resource kind and name,
the narrowing case where the list matches but the selector does not, expiry in the past and
the future, and that `Apply` does not mutate its input.

`internal/sources/trivy` is tested over fixture reports: severity taken from the highest
non-zero count, a clean image producing no finding at all, 300 CVEs collapsing to one
finding with the remainder counted rather than listed, fixable vulnerabilities preferred
over unfixable ones in the remediation, duplicate secret titles collapsed, and the
disabled-adapter path returning no findings and no error.

## Layer 2: integration tests (envtest)

`internal/controller` starts a real API server and runs the manager against it.

| Spec | Asserts |
|---|---|
| does not create a report on its own | A new namespace produces no report over a `Consistently` window |
| populates a report that the user creates | Creating the report in a namespace drives it to `ScanSucceeded=True` |
| reports findings when an insecure workload is created | Expected finding IDs present, every finding has a suggestion, source is `builtin` |
| rescans when an existing workload changes | Patching the Deployment removes KG-001 and lowers the critical count |
| marks the scan as succeeded | `ScanSucceeded` condition is True |
| flags the insecure namespace | The shipped demo manifest yields the documented IDs and exactly two KG-004 findings |
| clears the findings once the hardened manifest is applied | Zero findings, KG-001/004/008/010/011/013 all absent |

The last two apply the real files from `test/demo/`, so the documented walkthrough cannot
drift from the code without a test failing.

## Layer 3: cluster acceptance (kind)

Every scenario below was executed against the deployed operator. Results are the actual
observed output.

These were run before scoring was removed, so the captured output still shows a `SCORE`
column. The behaviour each scenario verifies is unchanged; only that column is gone. The
second round below re-verifies the current build against the Hamravesh cluster.

### Discovery and scoping

**T1/T2 — reports are created for every non-excluded namespace.**
Six namespaces existed; the three control-plane namespaces are excluded by default.

```
NAME                  SCORE   CRITICAL   HIGH   MEDIUM   LOW   LAST-SCAN   AGE
default               90      0          1      0        0     59s         59s
kubeguardian-system   90      0          1      0        0     59s         59s
local-path-storage    40      0          4      4        0     59s         59s
```

No reports for `kube-system`, `kube-public`, `kube-node-lease`. Pass.

**T3 — the operator audits its own namespace.**
`kubeguardian-system` scores 90 with one finding: KG-010, no default-deny NetworkPolicy.
It passes every other check, including the `restricted` Pod Security Standard it enforces
on itself. The remaining KG-010 is deliberate; see Known limitations.

**T4 — findings on a real third-party workload.**
kind's own `local-path-provisioner` is correctly flagged for KG-002, KG-003, KG-006,
KG-007, KG-008, KG-021 and the namespace-level KG-010 and KG-011. The checks fire on
software nobody wrote for this demo.

### Report lifecycle

**T5 — a new namespace produces a report.** Appeared in under one second, with an owner
reference carrying `controller: true` and `blockOwnerDeletion: true`.

**T6 — deleting a namespace garbage-collects its report.** Report gone, no finalizer
involved. This is the payoff of making the report cluster-scoped.

**T7 — deleting a report by hand recreates it.** Recreated in 1s with a new UID, driven by
the `Owns` watch, which keeps delete events while dropping create and update events.

**T8 — twenty namespaces created concurrently.** All twenty reports present immediately,
no errors, no controller restarts. Bulk deletion garbage-collected all twenty.

### Findings and remediation

**T9 — the insecure demo namespace.** Fifteen findings, score 0.

```
Critical  KG-001  Deployment/legacy-api
Critical  KG-004  Deployment/legacy-api      (hostNetwork)
Critical  KG-004  Deployment/legacy-api      (hostPID)
High      KG-002  Deployment/legacy-api
High      KG-003  Deployment/legacy-api
High      KG-005  Deployment/legacy-api
High      KG-010  Namespace/kubeguardian-demo
High      KG-011  Namespace/kubeguardian-demo
High      KG-013  Role/legacy-api
Medium    KG-006  Deployment/legacy-api
Medium    KG-007  Deployment/legacy-api
Medium    KG-008  Deployment/legacy-api
Medium    KG-012  ServiceAccount/default
Medium    KG-020  Deployment/legacy-api
Medium    KG-021  Deployment/legacy-api
```

Two separate KG-004 findings for `hostNetwork` and `hostPID` confirm the deduplication fix
holds against a real API server.

**T10 — every finding is actionable.** No finding in the report was missing a `message`,
`suggestion`, `remediation`, `reference` or `source`.

**T11 — the operator's own remediation command works.** The `remediation` string for
KG-001 was extracted from the report and executed verbatim:

```bash
kubectl patch deployment legacy-api -n kubeguardian-demo --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/securityContext/privileged","value":false}]'
```

The patch applied, and KG-001 disappeared from the report on the next reconcile. The
advice the operator gives is executable as printed.

**T12 — ordering is deterministic.** Repeated reads returned an identical finding
sequence, grouped Critical, then High, then Medium, and ordered by ID and resource within
each group.

### Reacting to change, which is requirement 2

**T13 — editing a workload triggers a rescan.** Patching `hostPID` to false moved the
critical count from 3 to 2, observed in under a second.

**T14 — hardening the namespace clears the report.** Applying the hardened manifest took
the score from 0 to 100 with zero findings and a `ScanSucceeded` condition.

**T15 — periodic rescan with no events at all.** With `--rescan-interval=30s` and nothing
changing in the cluster, `lastScanTime` advanced on schedule:

```
19:02:17  ->  19:02:47  ->  19:03:17
```

### Stability

**T16 — no reconcile hot loop.** Over a 60-second idle window with the default 10-minute
interval: zero new scan log lines, and the report's `resourceVersion` was unchanged. This
is the property that the `Owns` update predicate and the unchanged-status comparison exist
to guarantee.

**T17 — the generated RBAC is sufficient.** Zero `forbidden`, `is not allowed` or `ERROR`
lines across the controller's entire log, through every scenario above.

**T18 — controller restart.** After deleting the pod, every report was still present and
`lastScanTime` was not rewritten, confirming the unchanged-status skip survives a restart.

### Schema and configuration

**T19 — the API server rejects invalid severities.**

```
The NamespaceSecurityReport "schema-probe" is invalid:
status.findings[0].severity: Unsupported value: "Catastrophic":
supported values: "Critical", "High", "Medium", "Low"
```

`spec.namespaceRef: ""` is rejected too. Enum-validated named types replaced what would
otherwise have been a comment listing legal values, and the API server enforces them.

**T20 — `--min-severity=High` filters correctly.** Summary went from
`critical 3, high 5, medium 5, total 13` to `critical 3, high 5, medium 0, total 8`, and
back when the flag was removed.

**T21 — an invalid `--min-severity` fails fast.**

```
ERROR setup Invalid min-severity {"value": "Bogus"}
exit code 1  ->  CrashLoopBackOff
```

The rolling update never promoted the broken pod, so the running operator stayed
available throughout.

### Workload coverage

**T22 — all four workload kinds and init containers.** A namespace containing a
StatefulSet, a DaemonSet and a CronJob produced findings against each:

```
KG-001  Critical  StatefulSet/db        db
KG-004  Critical  DaemonSet/agent
KG-001  Critical  CronJob/backup        prepare     <- init container
KG-020  Medium    CronJob/backup        prepare     <- untagged image
```

The privileged **init container** `prepare` was flagged, while the compliant
`alpine:3.20` main container was correctly not flagged for KG-020.

### Documented workflow

**T23 — the README walkthrough works verbatim.** `make demo-clean`, `make demo`,
`make demo-harden` produced score 0 with fifteen findings, then score 100 with none.

**T24 — both demo workloads actually run.** The insecure pod runs, and the hardened pod is
admitted under `restricted` Pod Security Admission and reaches Running. The two manifests
describe the same workload and differ only in security configuration.

## Defects found and fixed during testing

Testing was worth doing. Five real defects surfaced, four of which no amount of unit
testing would have caught.

**1. The container image could never be built.** The kubebuilder-scaffolded
`.dockerignore` ignores everything with `**` and then re-includes `!**/*.go`. Docker does
not descend into an excluded directory to honour a re-include inside it, so the build
context contained only `go.mod` and `go.sum`, and the build failed with
`package cmd/main.go is not in std`. Replaced with a plain exclude list. Found only by
building the image; `make build` and `make test` both passed throughout.

**2. Two findings on the same resource silently collapsed.** The deduplication key was
`ID | Resource | Source`. A pod with both `hostNetwork` and `hostPID` produces two KG-004
findings with identical values for all three, so one was discarded. The same bug hid every
`hostPath` volume after the first. `Message` was added to the key, with a regression test.
Found by comparing a real report against the demo manifest.

**3. The hardened demo was not deployable.** It set `enforce: restricted` on the namespace
but omitted `seccompProfile`, so its pods were rejected by Pod Security Admission while
the report happily said score 100. The operator was blessing a configuration Kubernetes
itself refuses. Two fixes: the manifest now sets `seccompProfile: RuntimeDefault`, and a
new check **KG-008** closes the underlying gap, since the operator checked that a
namespace *enforces* a standard but never that workloads *satisfy* it.

**4. The hardened demo workload crashed.** Even once admitted, nginx cannot run as UID
1000 with a read-only root filesystem. A "secure" example that does not run is not an
example. Both demo manifests now use the same busybox workload and differ only in security
configuration, and both were verified Running.

**5. A clean report rendered blank columns.** `summary` used `omitzero`, so an all-zero
summary was omitted entirely and `kubectl get nsr` printed empty cells instead of `0`.

**6. The image could not be rebuilt on this network.** `gcr.io` and `registry.k8s.io`
both return 403 here, while Docker Hub and ghcr.io are reachable, so the distroless base
image in the Dockerfile could not be resolved. This is an environment constraint rather
than a defect, but it made the project unbuildable on the machine it was developed on. The
runtime base is now a `BASE_IMAGE` build argument, defaulting to distroless and overridable:

```bash
make docker-build IMG=kubeguardian:test BASE_IMAGE=alpine:3.22
```

The acceptance run above was performed twice: once on an image built with the distroless
default, and once on an image built through the override, to confirm both paths deploy and
behave identically.

One further improvement came out of testing rather than a defect: each namespace was
reconciling twice at startup, because creating the report re-enqueued its own namespace.
The `Owns` predicate now drops create events as well as updates.

## Known limitations, confirmed by testing

These are real and observed, not hypothetical.

- **The score floors at zero.** Fixing KG-001 in the demo moved critical findings from 3
  to 2 but left the score at 0, because the accumulated penalty was 125. The score is a
  triage ordering signal; the severity counts are what to act on during remediation.
- **The operator reports KG-010 against its own namespace.** Shipping a default-deny
  ingress NetworkPolicy in `config/` risks breaking kubelet probes and metrics scraping
  depending on the CNI, which is worse than the finding. Left as a visible, honest finding
  rather than silently suppressed.
- **Specs are audited, not running pods.** A pod created directly, or mutated after
  admission, is not evaluated.
- **KG-010 only recognises an empty-pod-selector default-deny policy.** A namespace
  secured by several narrower policies that collectively deny ingress is still reported.
- **KG-012 cannot know whether a workload actually calls the API.** It is a prompt to
  check, not proof of a problem.


---

# Second round: exceptions and Trivy

Scoring was removed, `ScanException` was added, and the Trivy adapter was built. All of the
following was executed against the Hamravesh cluster `interview-mohammadi-c243`. The kind
cluster was deleted; unit and envtest layers do not need it.

## E1 — the score is gone, suppressed counts are present

```
NAME                  CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
backup-system         0          1      0        0     0            1s          79m
hamlb-system          1          11     13       0     3            1s          79m
monitoring-system     1          29     37       0     2            1s          79m
platform-system       5          15     28       0     0            1s          79m
```

No `SCORE` column, and `SUPPRESSED` renders `0` rather than blank.

## E2 — exceptions suppress without hiding

Applying `config/samples/security_v1alpha1_scanexception.yaml`:

```
                    before                          after
monitoring-system   CRITICAL 3  SUPPRESSED -        CRITICAL 1  SUPPRESSED 2
hamlb-system        CRITICAL 3  SUPPRESSED -        CRITICAL 0  SUPPRESSED 3
```

The findings are still in the report:

```
KG-004  DaemonSet/vm-stack-prometheus-node-exporter
  suppressedBy=node-exporter-host-access
  reason=prometheus node-exporter reads host network and process metrics,
         which is the purpose of the agent. Reviewed by the platform team.
```

Both host-namespace findings for node-exporter are suppressed independently, which also
re-confirms that the KG-004 deduplication fix holds.

## E3 — Trivy integration on a real cluster

trivy-operator 0.36.0 installed into `trivy-system`. KubeGuardian logged
`Trivy integration enabled` at startup, and findings appeared alongside the built-in ones:

```
platform-system  TRIVY-VULN  Critical  DaemonSet/kubenurse
  image postfinance/kubenurse:v1.14.6 has 3 critical, 18 high, 8 medium, 3 low vulnerabilities
platform-system  TRIVY-VULN  Critical  Pod/network-tcp-github-1787905721
  image kuberhealthy/network-connection-check:v0.2.0 has 5 critical, 61 high, 32 medium, 1 low vulnerabilities
hamlb-system     TRIVY-VULN  Critical  StatefulSet/platform-system--hamlb-redis
  image library/redis:8.10.0-trixie has 3 critical, 7 high, 21 medium, 60 low vulnerabilities
```

The `network-connection-check` image carries 99 vulnerabilities and produces **one**
finding, which is the aggregation working as intended.

Remediation is specific and actionable:

```
CVE-2026-31789: upgrade libcrypto3 to 3.5.6-r0
CVE-2026-31789: upgrade libssl3 to 3.5.6-r0
CVE-2025-68121: upgrade stdlib to 1.24.13, 1.25.7, 1.26.0-rc.3
CVE-2025-69421: upgrade libcrypto3 to 3.5.5-r0
CVE-2026-28387: upgrade libcrypto3 to 3.5.6-r0
and 176 further fixable vulnerabilities
```

Every Trivy finding carries `source: trivy` and `category: SupplyChain`. Zero RBAC errors
against the new `aquasecurity.github.io` group.

## Defects found in this round

**7. `suppressed: 0` could never be written.** Status was written with a JSON merge patch,
which omits any field whose value equals the stored one. A genuine zero was therefore never
persisted and `kubectl get nsr` printed a blank cell instead of `0` — the same class of
problem as the earlier `omitzero` defect. Status is now written with a full update guarded
by a conflict retry.

**8. The Helm concurrency limit was silently ignored.** The trivy-operator chart key is
`operator.scanJobsConcurrentLimit`, not `operator.concurrentScanJobsLimit`. Helm does not
error on unknown values, so the install reported success while
`OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT` stayed at its default of 10, and twelve image scans
ran at once on the platform cluster. Caught by checking the rendered ConfigMap rather than
trusting the install output.

**9. The trivy-operator chart could not pull its own images.** It defaults to
`mirror.gcr.io`, which returns 403 from the Hamravesh nodes — the same Google-registry
block seen locally, so it is a property of the network rather than of one machine. Fixed by
repointing `image.registry`, `trivy.image.registry`, `trivy.dbRegistry` and
`trivy.javaDbRegistry` at Docker Hub, which those nodes can reach. Each image was verified
to exist on Docker Hub before applying the change, rather than risking a second failed
rollout on their cluster.

---

# Third round: opt-in reports

Reports are no longer created automatically. The user creates a `NamespaceSecurityReport`
naming the namespace to audit, and the operator fills in its status.

## O1 — envtest coverage of the new model

| Spec | Asserts |
|---|---|
| does not create a report on its own | A new namespace is created and, over a three-second `Consistently` window, no report appears |
| populates a report that the user creates | Creating the report drives it to `ScanSucceeded=True` |
| reports a missing namespace instead of scanning | A report naming a non-existent namespace reaches `ScanSucceeded=False` with reason `NamespaceNotFound` rather than being silently ignored or deleted |

The existing specs for findings, rescan-on-change and scan-time recording were kept and now
create their report explicitly first.

`Consistently` rather than `Eventually` is the point of the first spec: proving something
*does not* happen needs a window, not a retry loop.

## O2 — the scheduling failure behind the stuck Trivy job

A `scan-vulnerabilityreport` pod sat `Pending` with `FailedScheduling: No nodes available`.

The cluster has six Ready nodes, but four carry taints:

```
c243-gw1       nodepool=gw:NoSchedule
c243-m1        node-role.kubernetes.io/control-plane:NoSchedule
c243-p1        nodepool=p:NoSchedule
c243-p2        nodepool=p:NoSchedule
c243-worker1   (none)
c243-worker2   (none)
```

Scan pods carry only the default not-ready and unreachable tolerations, so they can land on
`worker1` and `worker2` alone. Those two were already at 82% and 88% of allocatable CPU
requested, leaving roughly 250m and 160m free.

The stuck pod was scanning a four-container CSI driver workload. trivy-operator requests
100m of CPU per scanned container, so the pod asked for 400m and fitted on neither worker.
Single-container scans, which is most of them, fitted fine — which is why exactly one job
was stuck rather than all of them.

Fixed by lowering the per-container scan request rather than by granting tolerations for
the `nodepool` taints. Those pools are dedicated for a reason, and pushing scan load onto
them is a decision for whoever owns the cluster, not a side effect of installing a scanner:

```bash
--set trivy.resources.requests.cpu=25m
--set trivy.resources.requests.memory=64M
```

The CPU *limit* stays at 500m, so scans still burst; only the scheduling reservation
shrank. A four-container scan now reserves 100m instead of 400m.

---

# Fourth round: namespaced reports

`NamespaceSecurityReport` moved from cluster-scoped with a `spec.namespaceRef` pointer to
namespace-scoped, auditing the namespace it lives in.

## N1 — the CRD scope change cannot be applied in place

Confirmed against the live API server before attempting the upgrade:

```
$ kubectl apply --dry-run=server -f config/crd/bases/...namespacesecurityreports.yaml
The CustomResourceDefinition "namespacesecurityreports.security.kubeguardian.io"
is invalid: spec.scope: Invalid value: "Namespaced": field is immutable
```

The migration therefore deletes and recreates the CRD, which drops existing reports. They
hold only derived data, so nothing is lost that a rescan does not rebuild. Checking this
with a server-side dry run first meant the failure surfaced as a message rather than as a
half-applied deploy.

## N2 — what the migration removed

The namespaced model made three things unrepresentable rather than merely handled:

| Removed | Why it is gone |
|---|---|
| `spec.namespaceRef` | `metadata.namespace` is the target; a report cannot point at the wrong namespace |
| The field index on `spec.namespaceRef` | Workload mapping is "reports in my own namespace" |
| The `NamespaceNotFound` condition and its code path | A report cannot outlive its namespace |

The spec is now empty. Its own test for a dangling namespace reference was deleted along
with the state it tested, which is the right outcome: the bug class is designed out rather
than covered.
