# Testing

Three layers, each answering a different question.

| Layer | Question | Mechanism | Result |
|---|---|---|---|
| Unit | Does each rule decide correctly? | Pure functions over in-memory snapshots | 39 test functions, all pass |
| Integration | Do the controllers behave against a real API server? | envtest control plane, both managers started | 12 specs, all pass |
| Acceptance | Does the built image work in a real cluster? | Hamravesh platform cluster | 26 scenarios plus eight later rounds; the ninth is pending a deploy |

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
Coverage: `internal/checks` 98.3%, `internal/sources` 97.4%, `internal/exceptions` 87.5%,
`internal/sources/podsecurity` 73.9%, `internal/sources/trivy` 76.5%,
`internal/controller` 76.9%.

Each rule written here has its own table-driven test covering the positive case, the
compliant case, and the edge cases that matter for that rule. Examples of the edge cases
covered:

- Registry ports not mistaken for image tags: `registry:5000/app` is untagged, but
  `registry:5000/app:2.0` is tagged (KG-020)
- Digest-pinned images treated as immutable (KG-020)
- Egress-only and pod-selecting NetworkPolicies not counted as default-deny (KG-010)
- A namespace with no workloads not flagged for a missing NetworkPolicy (KG-010)
- `audit` label present but `enforce` absent (KG-011)
- One finding per Role even when several rules use wildcards (KG-013)

The pod-security source is not tested by reimplementing the Pod Security Standards a
second time in assertions; upstream tests its own logic. `internal/sources/podsecurity`
tests the wiring, which is what can actually break here:

- Every check `policy.DefaultChecks()` returns has a `KG-` mapping, so a Kubernetes bump
  that adds a control fails the build rather than silently dropping its findings
- A compliant pod produces no findings at all
- Each violated control produces the expected identifier: privileged, root user, privilege
  escalation, host namespaces, `hostPath`, capabilities, seccomp and host ports
- Host namespaces collapse to a single finding, because upstream treats `hostNetwork`,
  `hostPID` and `hostIPC` as one check rather than three
- Init containers are evaluated, not only regular ones
- Every finding carries a suggestion, a remediation, a reference, the `pod-security`
  source and the `PodSecurity` category, so nothing arrives in a report unactionable
- The rule table is well formed: no empty identifier, suggestion or remediation

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
| reports findings when an insecure workload is created | Expected finding IDs present, every finding has a suggestion, source is `builtin` or `pod-security` |
| rescans when an existing workload changes | Patching the Deployment removes KG-001 and lowers the critical count |
| marks the scan as succeeded | `ScanSucceeded` condition is True |
| flags the insecure namespace | The shipped demo manifest yields the documented IDs, exactly one KG-004 finding, and a summary of 15 findings with 2 critical |
| clears the findings once the hardened manifest is applied | Zero findings, KG-001/004/008/010/011/013 all absent |

The last two apply the real files from `test/demo/`, so the documented walkthrough cannot
drift from the code without a test failing.

## Layer 3: cluster acceptance (kind)

Every scenario below was executed against the deployed operator. Results are the actual
observed output.

These were run before scoring was removed, so the captured output still shows a `SCORE`
column, and before the Pod Security Standards checks moved to the upstream library, so
`hostNetwork` and `hostPID` still appear as two KG-004 findings. The behaviour each
scenario verifies is unchanged. Each later round re-verifies the current build, and the
fifth round covers the pod-security migration specifically.

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

---

# Fifth round: the Pod Security Standards move upstream

Seven hand-written rules — KG-001, 002, 003, 004, 005, 006 and 008 — were deleted and
replaced by `internal/sources/podsecurity`, which calls `k8s.io/pod-security-admission`.
This round establishes that the replacement preserves behaviour and what changed visibly.

## P1 — the upstream API forced one evaluator per check

`policy.CheckResult` carries `Allowed`, `ForbiddenReason` and `ForbiddenDetail`, and no
check ID. Evaluating all checks with a single evaluator therefore returns a list of
failures with nothing to attribute them to, and every finding would have to be reported
under one generic identifier.

Enumerated at runtime, `policy.DefaultChecks()` returns nineteen checks:

```
allowPrivilegeEscalation  appArmorProfile          capabilities_baseline
capabilities_restricted   hostNamespaces           hostPathVolumes
hostPorts                 hostProbesAndHostLifecycle
privileged                procMount                procMount_restricted
restrictedVolumes         runAsNonRoot             runAsUser
seccompProfile_baseline   seccompProfile_restricted
seLinuxOptions            sysctls                  windowsHostProcess
```

`New()` builds one evaluator per check and keeps the ID alongside it, which is what makes
the mapping to a `KG-` identifier possible. `TestEveryUpstreamCheckIsMapped` iterates the
same list, so a Kubernetes bump that introduces a twentieth check fails the build instead
of silently dropping its findings.

## P2 — the demo namespace before and after

Same manifest, `test/demo/01-insecure-namespace.yaml`, asserted by the envtest demo spec.

| | Before | After |
|---|---|---|
| Total findings | 15 | 15 |
| Critical | 3 | 2 |
| KG-004 findings | 2 | 1 |
| New identifiers | — | KG-037 |

The critical count moved because upstream treats `hostNetwork`, `hostPID` and `hostIPC` as
a single `hostNamespaces` check rather than one finding per flag. The count of distinct
problems is unchanged; the pod shares host namespaces, which is one decision to reverse
and now reads as one finding. KG-037 is new: the `hostPath` volume also violates the
`restricted` volume-type allow-list, which no hand-written rule covered.

The current pod-security findings for that Deployment, with the messages the upstream
evaluator produces:

```
KG-001  Critical  baseline Pod Security Standard, privileged: container "api" must not
                  set securityContext.privileged=true
KG-004  Critical  baseline Pod Security Standard, host namespaces: hostNetwork=true,
                  hostPID=true
KG-002  High      restricted Pod Security Standard, runAsNonRoot != true: pod or
                  container "api" must set securityContext.runAsNonRoot=true
KG-003  High      restricted Pod Security Standard, allowPrivilegeEscalation != false:
                  container "api" must set securityContext.allowPrivilegeEscalation=false
KG-005  High      baseline Pod Security Standard, hostPath volumes: volume "host-root"
KG-006  Medium    restricted Pod Security Standard, unrestricted capabilities: container
                  "api" must set securityContext.capabilities.drop=["ALL"]
KG-008  Medium    restricted Pod Security Standard, seccompProfile: pod or container "api"
                  must set securityContext.seccompProfile.type to "RuntimeDefault" or
                  "Localhost"
KG-037  Medium    restricted Pod Security Standard, restricted volume types: volume
                  "host-root" uses restricted volume type "hostPath"
```

Each message names the level that rejects it, which the hand-written messages did not.

## P3 — the deduplication regression test was re-anchored

The original evidence that deduplication does not collapse distinct findings was "one pod
with `hostNetwork` and `hostPID` yields two KG-004 findings". Upstream makes that a single
check, so that assertion no longer proves anything.

The unit test in `internal/sources` that covers the dedup key directly — two findings
sharing an ID and a resource but differing in message are both retained — is unchanged and
still the real regression test. The envtest demo spec now asserts the opposite property,
that KG-004 appears exactly once, so the collapse is pinned rather than assumed.

## P4 — what the deletion exposed

`make lint` failed after the seven rule files and their tests were removed, and both
findings were consequences of the deletion rather than of the new code:

```
internal/checks/fixtures_test.go:64:22: secureContainer - name always receives
    testContainer ("api") (unparam)
internal/checks/fixtures_test.go:88:6: func findingIDs is unused (unused)
```

Every caller that passed a varying name to `secureContainer` lived in a deleted test file.
The linter noticing is a reasonable signal that the deletion was complete rather than
half-done. Seven helpers in `internal/checks/helpers.go` were orphaned the same way
and removed — `workloadRef`, `effectiveRunAsNonRoot`, `effectiveRunAsUser`,
`dropsAllCapabilities`, `addedCapabilities`, `effectiveSeccompProfile` and `podPatch` —
along with the `referencePodSecurityStandards` constant in `check.go`, since the only
rules that cited that document now live upstream.

Final state: `make lint` reports 0 issues, and every suite passes.

## P5 — the same cluster, before and after

`v0.5.0` was built for `linux/amd64`, pushed to `docker.io/sadegh81/kubeguardian` and
rolled out on the Hamravesh cluster `interview-mohammadi-c243`. The CRDs and RBAC applied
unchanged; only the Deployment was reconfigured. Every report was rescanned within 90
seconds of the new leader taking the lease.

```
                        before (v0.4.0)                 after (v0.5.0)
NAMESPACE               CRIT HIGH MED SUPPRESSED        CRIT HIGH MED SUPPRESSED
backup-system              0    1   0     0                0    1   0     0
cilium-secrets             0    1   0     0                0    1   0     0
default                    0    1   0     0                0    1   0     0
hamlb-system               2   11  13     3                2   10  15     2
kubeguardian-system        0    2   0     0                0    1   0     0
lb-system                  0    1   0     0                0    1   0     0
logging-system             4   23  29     0                4   15  22     0
monitoring-system          9   29  37     2                9   17  31     1
platform-system           10   15  28     0               13   13  28     0
security-system            0   16  19     0                0   14  17     0
trivy-system               0    3   2     0                0    3   2     0
```

**Exceptions still match, which is the point of the round.** The two `ScanException`
objects were written against the old hand-written rules and were not touched:

```
hamlb-system       KG-001 DaemonSet/platform-system--hamlb-gateway  hamlb-gateway-host-access
hamlb-system       KG-004 DaemonSet/platform-system--hamlb-gateway  hamlb-gateway-host-access
monitoring-system  KG-004 DaemonSet/vm-stack-prometheus-node-exporter  node-exporter-host-access
```

Both accepted risks are still suppressed, on the same workloads, by the same exceptions.
The suppressed counts fell from 3 to 2 and from 2 to 1 because each pod's `hostNetwork`
and `hostPID` used to be suppressed as two findings and is now one.

**High counts fell because findings are now per pod, not per container.** The upstream
evaluator reports a violated control once for the pod and names every container that
violates it:

```
KG-002  Deployment/vmagent-vmagent
        restricted Pod Security Standard, runAsNonRoot != true: pod or containers
        "config-init", "config-reloader", "vmagent" must set securityContext.runAsNonRoot=true
```

Three containers, one finding, one fix. The hand-written rule emitted three. No workload
stopped being reported; the same problems are stated more compactly.

**The newly covered controls found real problems immediately.** Neither has any
hand-written equivalent:

```
KG-030  DaemonSet/node-metrics-exporter
        baseline Pod Security Standard, hostPort: container "node-metrics-exporter"
        uses hostPort 9800
KG-037  DaemonSet/vm-stack-prometheus-node-exporter
        restricted Pod Security Standard, restricted volume types: volumes "proc",
        "sys", "root" use restricted volume type "hostPath"
```

`monitoring-system` also shows the expected KG-005 and KG-037 overlap: two `hostPath`
findings at `baseline` and two restricted-volume findings for the same volumes.

**Two count changes are not this migration, and both resolved themselves.**
`platform-system` went from 10 critical to 13, then to 12 one rescan later. All of them
are `TRIVY-VULN`, and no workload in that namespace is privileged or shares a host
namespace, so the movement is trivy-operator's own rescan cadence rather than anything
this change did.

`kubeguardian-system` briefly dropped from two high findings to one, then returned to two.
The rollout changed the operator's own image, so trivy-operator had to scan `v0.5.0` from
scratch, and the first report after the rollout was written before that scan existed. The
next rescan picked it up. This is the startup-detection and rescan behaviour documented
under Known limitations, observed rather than assumed.

**The operator's own namespace reports no pod-security finding at all.** Its two findings
are KG-010, no default-deny NetworkPolicy, and a `TRIVY-VULN` for CVEs in its own image.
It passes the `restricted` Pod Security Standard under the upstream evaluator, which is a
stronger statement than passing the rules this project used to write itself.

## P6 — rebuilding when `gcr.io` is unreachable

`gcr.io` times out from this network, so `docker buildx build` failed while resolving
metadata for the `gcr.io/distroless/static:nonroot` runtime base. `mirror.gcr.io`,
`quay.io`, `cgr.dev` and `registry.access.redhat.com` all return 403 or time out as well;
only Docker Hub is reachable.

Rather than substitute a different base and change what is actually shipped, the exact
base was recovered from the `v0.4.0` image already in the local image store: `docker save`,
drop the single top layer that contains `/manager` from `manifest.json` and from the
config's `rootfs.diff_ids` and `history`, `docker load` the remainder under the original
name. That yields a 2.23 MB image, matching distroless static, so `v0.5.0` and `v0.4.0`
share byte-identical base layers and the only difference between them is the binary.

`make docker-build` with `BASE_IMAGE=alpine:3.22`, documented in the README, remains the
option for anyone who does not already have the base on disk. It is not what was pushed.

The push itself needed the usual retries — one layer retried for about a minute before
completing — and was verified with `docker buildx imagetools inspect` rather than trusting
the push output, since `make docker-buildx` ignores buildx failures by design.

---

# Sixth round: what a reconcile actually costs

A workload event rescans the whole namespace rather than the changed workload. This round
measures that, so the choice rests on numbers rather than on intuition.

## S1 — scan cost against namespace size

`internal/sources/scan_bench_test.go` builds a synthetic namespace of N Deployments, a
third of them on `hostNetwork` and a fifth privileged, and runs the full in-memory scan:
both sources, then `Normalize`, `Truncate` and `Summarize`. Apple M-series, `go test
-bench`, three sizes:

```
                       before            after
BenchmarkScan10      208 µs   256 KB    152 µs   177 KB
BenchmarkScan100     1.42 ms  2.43 MB   1.11 ms  1.57 MB
BenchmarkScan1000    10.9 ms  26.7 MB   8.83 ms  19.0 MB
```

Cost is linear in the number of workloads, as expected from checks that are pure functions
over a snapshot. A thousand-workload namespace — far larger than anything on the Hamravesh
cluster, where the biggest is 17 workloads — costs about nine milliseconds of CPU.

Broken down by stage at 1000 workloads, before the changes below:

```
BenchmarkBuiltin1000       2.25 ms   6.5 MB    34,129 allocs
BenchmarkPodSecurity1000   2.93 ms   6.8 MB    60,216 allocs
BenchmarkNormalize1000     4.41 ms   4.9 MB    70,186 allocs
```

`Normalize` was the most expensive stage, which was not the expected answer.

## S2 — two pieces of waste the measurement exposed

**`Snapshot.Workloads()` was rebuilt on every call.** Five checks and the pod-security
source each call it, so the four workload kinds were flattened six times per scan and every
pod template was copied six times. It is now computed once per snapshot and reused, along
with each workload's combined init and regular container list. A snapshot is built inside
one reconcile and never shared, so no locking is needed.

**`sources.Normalize` allocated inside its sort comparator.** The deduplication key was a
four-way `strings.Join`, and the comparator called `ResourceRef.String()` on both sides of
every comparison — an allocation on every step of an O(n log n) sort. The key is now a
comparable struct, and the comparator compares `Kind`, `Name` and `Container` directly.

```
BenchmarkNormalize1000     4.41 ms → 3.30 ms
                          70,186 allocs → 34 allocs
```

The full scan at 1000 workloads improved by 19% in time, 29% in allocated bytes and 44% in
allocation count. No finding changed: the whole suite passes unmodified, including the
determinism and deduplication tests in `internal/sources`.

Sort order does change in one edge case. Comparing the joined string ordered
`Deployment/a:b` before `Deployment/a-c`, because `:` sorts after `-`; comparing fields
orders by name first, so `a` now precedes `a-c`. Both are total orders and both are
deterministic, which is all the determinism test and the status-write comparison require.

## S3 — the deployed operator

`v0.5.1` rolled out on the Hamravesh cluster. Every report was rescanned, the findings and
both suppressions are unchanged from `v0.5.0`, and the log shows no errors.

Resident memory was 26 Mi on `v0.5.0` and settles at 17 Mi on `v0.5.1`, sampled three
times over two minutes with the pod fifteen minutes old in both cases. It reads 28 Mi in
the first minute after start, before the cache has finished filling and the first GC has
run, so the number is only meaningful once it settles.

`cache.TransformStripManagedFields()`, added in this round, strips the `managedFields`
bookkeeping from every object the cluster-wide cache holds — 36 Deployments, 102
ServiceAccounts, 31 Roles and the rest across 14 namespaces here. The saving is
proportional to how many objects are cached, so it is worth more on a KaaS cluster than on
this one. Attributing all 9 Mi to it would be too strong a claim with one sample per
version, but the direction is consistent and the change carries no behavioural risk: the
transform runs on the way into the cache, and nothing here uses server-side apply from a
cached object.

The Trivy critical counts moved again during the round — `monitoring-system` 9 to 10,
`platform-system` 12 to 14 — which is trivy-operator rescanning on its own cadence, the
same drift recorded in P5.

---

# Seventh round: one report becomes two

`NamespaceSecurityReport` was replaced by `ManifestSecurityReport` (`msr`) and
`ImageSecurityReport` (`isr`). Each is namespaced, each has its own status, and you create
whichever you want.

## R1 — envtest coverage of the split

| Spec | Asserts |
|---|---|
| manifest report does not create itself | A new namespace produces no `msr` over a `Consistently` window |
| manifest report carries only manifest findings | Every finding starts `KG-`, no finding has source `trivy`, and asking for an `msr` brings no `isr` into being |
| image report does not create itself | Same, for `isr` |
| image report says so when no scanner is installed | `ScanSucceeded=False`, reason `ScannerUnavailable`, findings empty, `lastScanTime` still set |
| image report ignores manifests | An insecure Deployment produces no `isr` finding at all over a `Consistently` window |

The envtest suite runs with no image scanner, which makes the `ScannerUnavailable` path the
default there rather than an awkward case to stage. `lastScanTime` is deliberately still
written on that path: the report is current, it just has nothing to report.

## R2 — the migration on the live cluster

`v0.6.0` deployed to the Hamravesh cluster. The two new CRDs applied cleanly alongside the
old one, so `make deploy` succeeded before anything was deleted:

```
customresourcedefinition.../imagesecurityreports.security.kubeguardian.io created
customresourcedefinition.../manifestsecurityreports.security.kubeguardian.io created
deployment.apps/kubeguardian-controller-manager configured
```

The old CRD was then deleted, taking the eleven reports with it, along with the three
`namespacesecurityreport-*` helper ClusterRoles that kustomize leaves behind because
nothing prunes them. `~/.kube/cache/discovery` was cleared, as after the v0.4.0 scope
change, and the new kinds resolve:

```
NAME                      SHORTNAMES   NAMESPACED   KIND
imagesecurityreports      isr          true         ImageSecurityReport
manifestsecurityreports   msr          true         ManifestSecurityReport
scanexceptions            scanexc      false        ScanException
```

## R3 — the split adds up

Reports were recreated as both kinds in all eleven namespaces. Every finding moved to
exactly one of them and none went missing:

```
                     before (v0.5.1)          msr (v0.6.0)         isr (v0.6.0)
NAMESPACE            CRIT HIGH MED SUPP       CRIT HIGH MED SUPP   CRIT HIGH MED
backup-system           0    1   0    0          0    1   0    0      0    0   0
cilium-secrets          0    1   0    0          0    1   0    0      0    0   0
default                 0    1   0    0          0    1   0    0      0    0   0
hamlb-system            2   10  15    2          0   10  15    2      2    0   0
kubeguardian-system     0    2   0    0          0    1   0    0      0    0   0
lb-system               0    1   0    0          0    1   0    0      0    0   0
logging-system          4   15  22    0          0   14  22    0      4    1   0
monitoring-system      10   17  31    1          0   17  31    1     10    0   0
platform-system        19   13  28    0          0   13  28    0     18    0   0
security-system         0   14  17    0          0   14  17    0      0    0   0
trivy-system            0    3   2    0          0    3   2    0      0    0   0
```

Every row adds up. `hamlb-system` 2+10+15 becomes 0+10+15 on the manifest side and 2+0+0 on
the image side. `logging-system`'s one high was a `TRIVY-VULN` and moved with it, leaving
14 manifest highs. `platform-system` reads 18 rather than 19 for the familiar reason:
trivy-operator rescans on its own cadence. `kubeguardian-system` again lost its image
finding to the image change, and picks it up on the next Trivy scan.

Critical counts on the manifest side are now `0` everywhere on this cluster, and that is
information rather than a gap: every `KG-` critical here is either suppressed by an
exception or does not exist. All the criticals were CVEs.

**Each kind carries only its own findings.**

```
$ kubectl get msr posture -n monitoring-system -o json | ...
Counter({'pod-security': 30, 'builtin': 19})
['KG-002', 'KG-003', 'KG-004', 'KG-005', 'KG-006', 'KG-007', 'KG-008', 'KG-010',
 'KG-011', 'KG-012', 'KG-013', 'KG-021', 'KG-030', 'KG-037']

$ kubectl get isr posture -n platform-system -o json | ...
Counter({'trivy': 18})
['TRIVY-VULN']
```

**Exceptions still match.** Neither `ScanException` was touched, and both still suppress the
same findings on the same workloads, now on the manifest report:

```
hamlb-system       KG-001, KG-004  DaemonSet/platform-system--hamlb-gateway
                                   hamlb-gateway-host-access
monitoring-system  KG-004          DaemonSet/vm-stack-prometheus-node-exporter
                                   node-exporter-host-access
```

**Asking for one kind does not produce the other.** A fresh namespace given only a
`ManifestSecurityReport`:

```
$ kubectl get msr -n kg-split-check
NAME      CRITICAL   HIGH   MEDIUM   LOW   SUPPRESSED   LAST-SCAN   AGE
posture   0          1      0        0     0            20s         20s

$ kubectl get isr -n kg-split-check
No resources found in kg-split-check namespace.
```

The controller log shows no errors and no RBAC denials across the whole round.

---

# Eighth round: why LAST-SCAN kept moving on its own

Reports were resetting their `LAST-SCAN` in namespaces nobody had touched. This round
establishes what was causing it, and what changed as a result.

## C1 — it was the periodic rescan, measured

Every report was sampled every 20 seconds for 13 minutes and the gaps between distinct
`lastScanTime` values recorded. 27 rescans across 22 reports:

```
541 543 544 545 550 554 558 566 574 576 580 598 606 608 610 616
616 616 618 621 628 633 646 651 653 653 654

min 9m01s   max 10m54s   mean 9m58s
```

Every gap falls inside **[9m, 11m)**, which is exactly what `requeueAfter` produced from a
10 minute interval: `base - base/10 + rand[0, base/5)`. The ±10% jitter is why they did not
move together, and that is what made it look arbitrary from outside.

Nothing was reacting to an event. The resourceVersion of all 206 watched objects was
snapshotted three minutes apart, and exactly one moved: a `kube-system` DaemonSet whose
generation did not change, so `GenerationChangedPredicate` drops it, in a namespace with no
report anyway.

## C2 — the manifest report does not need a timer

Auditing what the manifest checks actually read settled it:

```
kg007_read_only_root_filesystem.go   snap.Workloads
kg010_default_deny_network_policy.go snap.NetworkPolicies snap.Workloads
kg011_pod_security_admission_labels.go snap.Namespace
kg012_default_service_account_token.go snap.ServiceAccounts snap.Workloads
kg013_wildcard_rbac.go               snap.Roles
kg020_image_tag.go                   snap.Workloads
kg021_resource_limits.go             snap.Workloads
```

Five inputs — the four workload kinds behind `Workloads()`, plus NetworkPolicies,
ServiceAccounts, Roles and the Namespace — and every one is watched. A periodic rescan
could not discover anything a watch had not already delivered; it only rewrote an identical
status on a timer. `ManifestSecurityReport` now has no periodic rescan at all, and
`--rescan-interval` defaults to `3h` and governs `ImageSecurityReport` alone, which needs
it because Trivy's reports cannot be watched.

The same audit found `RoleBindings`, `ResourceQuotas` and `LimitRanges` were collected by
`snapshot.Collect` and read by no check at all. They were removed, along with their RBAC:
three cluster-wide informers for data nothing consulted.

## C3 — expiry is a deadline, not a poll

One thing about a manifest report does change without an event: a `ScanException` reaching
`expiresAt`. Removing the periodic rescan would have left an expired exception suppressing
a finding until something else in the namespace happened to change.

`Scanner.nextRequeue` takes the earliest expiry among the exceptions that could apply to
the namespace and requeues for that moment plus a second. Verified on the cluster with an
exception set to expire at 15:37:37:

```
15:35:08   suppressed=1  crit=0   lastScanTime=15:35:08   exception created
15:37:11   suppressed=1  crit=0   lastScanTime=15:35:08   26s before expiry, no polling in between
15:38:21   suppressed=0  crit=1   lastScanTime=15:37:38   one second after expiry
```

The report woke exactly once, one second after the deadline. Under the old design this
would have taken up to a full rescan interval, and under the new interval it would have
taken up to three hours.

## C4 — the event path still works

A scratch namespace with a privileged Deployment and a `ManifestSecurityReport`:

```
create        lastScanTime=15:33:44  critical=1
+40s idle     lastScanTime=15:33:44  unchanged
patch away privileged
+15s          lastScanTime=15:34:39  critical=0
```

Idle means idle; an edit is picked up within seconds.

## C5 — fifteen minutes on the live cluster

`v0.7.0` deployed, then every report sampled every 20 seconds for 15 minutes. Three
rescans happened in that window, all cluster-wide, and every one has a cause:

```
15:33:20   22 reports   the rollout: a new leader's informers deliver initial events
15:35:08   22 reports   a ScanException was created
15:38:30   22 reports   that ScanException was deleted
```

Zero timer-driven rescans, where the previous build would have produced about 22. Eleven
minutes after the last of them, every report still read `LAST-SCAN 10m` and climbing.

Worth noting for later: creating or deleting **any** `ScanException` rescans every report
in the cluster, because the fan-out maps to all of them. That is correct — an exception
with no `namespaces` and no `namespaceSelector` matches everywhere — but it is now the
largest remaining source of a synchronised rescan, and on a cluster with thousands of
namespaces it would be a thundering herd. Narrowing it to the namespaces an exception names
is possible and is not done here.

---

# Ninth round: the checks become configuration

The seven remaining hand-written checks became `SecurityCheck` objects holding CEL
expressions. `internal/checks` and `internal/sources/builtin` are gone. This round is
mostly about one question: did any finding change?

## E1 — the migration is provably behaviour-preserving

Before deleting anything, the shipped policies were run side by side with the Go checks
they replace over five fixtures — an insecure namespace, a hardened one, one enforcing the
privileged Pod Security Standard, one with partial resource requests and a registry-port
image, and one with no workloads at all — and every field of every finding compared: id,
severity, category, resource, message, suggestion, remediation and reference.

That comparison found three real differences, all of which were fixed rather than
accepted:

```
KG-011  indexing a missing map key errors in CEL rather than defaulting, so the
        privileged check needed an `in` guard before the lookup
KG-020  the Go remediation used the capitalised Kind ("Deployment/api"); the policy
        lowercased it
KG-010  a YAML block scalar written with `|` keeps its trailing newline, which the Go
        raw string did not have; `|-` fixed it
```

Two further differences were design choices rather than defects, and the policies were
reshaped instead:

- **KG-012 moved from Namespace scope to ServiceAccount scope.** The Go check emitted a
  finding naming `ServiceAccount/default` while iterating workloads. Scoping the check to
  the ServiceAccount makes the resource reference fall out naturally instead of needing an
  override field in the API.
- **KG-011 and KG-020 became two objects each.** Both said two different things depending
  on what was wrong — no label versus `privileged`, no tag versus `latest`. One predicate
  per object reads better than a conditional inside one message. Nine objects now produce
  seven identifiers, and a `ScanException` matching on the id covers both halves.

With those settled, the output matches exactly. The comparison is now frozen as a golden
file, `internal/policy/testdata/expected_findings.txt`, captured from the Go checks before
they were deleted, so the shipped manifests stay honest as they are edited.

## E2 — what the CEL environment can and cannot do

Established by probing before writing any of it, since the whole design depended on it:

- `ext.ParseStructTag("json")` gives Kubernetes field names, so an expression reads
  `container.securityContext.readOnlyRootFilesystem`. `ext.ParseStructTags(true)` does
  **not** — it parses the `cel` tag, which Kubernetes types do not carry.
- Nested types resolve from registering only the top-level struct.
- A nil pointer reads as the zero value rather than erroring, so
  `!container.securityContext.readOnlyRootFilesystem` is correct for a container with no
  security context at all.
- `has()` distinguishes a pointer to `false` from a nil pointer, which is what lets KG-012
  tell "automounting explicitly disabled" from "not configured".
- `namespace` is a **reserved identifier** in CEL. The variable is `namespaceObject`, which
  is what `ValidatingAdmissionPolicy` calls it for the same reason.
- `ResourceList` binds as a map, so `'memory' in container.resources.limits` works without
  touching `resource.Quantity`, whose fields are unexported.
- `exists()` short-circuits, which matters when reasoning about cost.

## E3 — a broken check is visible, not silent

In envtest:

| Spec | Asserts |
|---|---|
| a check that compiles | `Ready=True`, reason `Compiled` |
| a check that does not | `Ready=False`, reason `CompileFailed`, message contains `undefined field 'labals'` |
| a broken check alongside good ones | the report still contains KG-011, so one bad policy does not stop the scan |

Compile failures are cached alongside successes in `policy.Registry`, so a check with a
typo is not recompiled on every scan of every namespace.

Unit tests cover the rest: an expression naming a variable from another scope is rejected,
a `violation` that does not evaluate to a bool is rejected, an unterminated `${` is
rejected, and the error names which field was at fault.

## E4 — the cost budget stops a quadratic expression

Checks come from whoever runs the cluster rather than being compiled in, so evaluation is
capped. A quadratic walk over 600 workloads, written so `exists()` cannot short-circuit,
is stopped:

```
workloads.exists(a, workloads.exists(b, a.name == b.name + 'never'))
=> check TEST-1 violation: operation cancelled: actual cost limit exceeded
```

## E5 — what CEL costs

Measured in `internal/policy/bench_test.go`, nine checks over one namespace:

```
                    time       allocated    allocations
10 workloads       0.83 ms      0.84 MB          7,974
100 workloads      6.96 ms      7.95 MB         75,076
1000 workloads    66.83 ms     79.15 MB        747,263

compiling all nine   5.16 ms     4.86 MB         80,768
```

Against the Go checks these replaced — 2.25 ms and 6.5 MB at a thousand workloads — CEL
is about **thirty times slower and twelve times heavier**. That is the honest price of
moving rules into configuration, and it is worth stating plainly rather than burying.

It is also mostly irrelevant at real sizes. The largest namespace on the Hamravesh cluster
holds seventeen workloads, which puts a scan near a millisecond, well under the etcd status
write and the two Trivy API calls that happen on every reconcile regardless. The
thousand-workload figure is a pathological case that no namespace here approaches.

Compilation is the expensive part, at 5 ms for all nine, which is why `policy.Registry`
caches by name and generation. Compiling per scan rather than per edit would have cost more
than the evaluation it enables.

One structural fix came out of this benchmark: `policy.Context` now holds the variables
shared by every check in a scan and caches the subject list per scope, so nine checks do not
flatten the same thousand workloads nine times over.

## E6 — envtest needed a ServiceAccount it does not create

The demo spec lost KG-012 after the migration, and the cause was the test environment
rather than the policy. envtest runs `kube-apiserver` and etcd but no
`kube-controller-manager`, so the `default` ServiceAccount that every real namespace has is
absent, and a ServiceAccount-scoped check has nothing to evaluate. The suite now creates it
explicitly.

This is a genuine behaviour change worth recording: with KG-012 scoped to the
ServiceAccount, a namespace with no `default` ServiceAccount object produces no KG-012
finding, where the Go check would have emitted one. No real namespace is in that state.

## E7 — cluster deployment

**Not yet done.** Docker was not running when this round was written, so `v0.8.0` has not
been built, pushed or deployed, and the confirmations that matter on a live cluster are
still outstanding:

- every namespace reporting the same findings as it does under `v0.7.0`
- both `ScanException`s still suppressing, since they match on `id`, which is unchanged
- editing a `SecurityCheck` rescanning the manifest reports
- a deliberately broken `SecurityCheck` showing `Ready=False` without disturbing the rest
