# Testing

Three layers, each answering a different question.

| Layer | Question | Mechanism | Result |
|---|---|---|---|
| Unit | Does each rule decide correctly? | Pure functions over in-memory snapshots | 23 test functions, 79 table cases, all pass |
| Integration | Does the controller behave against a real API server? | envtest control plane, manager started | 6 specs, all pass |
| Acceptance | Does the built image work in a real cluster? | kind, image built and deployed | 26 scenarios, all pass |

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
Coverage: `internal/checks` 98.6%, `internal/sources` 100%, `internal/scoring` 94.1%.

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
retention of two distinct findings that share an ID and a resource.

## Layer 2: integration tests (envtest)

`internal/controller` starts a real API server and runs the manager against it.

| Spec | Asserts |
|---|---|
| creates a report for a new namespace | Report appears, `spec.namespaceRef` set, owner reference points at the namespace |
| reports findings when an insecure workload is created | Expected finding IDs present, every finding has a suggestion, source is `builtin` |
| rescans when an existing workload changes | Patching the Deployment removes KG-001 and raises the score |
| marks the scan as succeeded | `ScanSucceeded` condition is True |
| flags the insecure namespace | The shipped demo manifest yields the documented IDs, score 0, and exactly two KG-004 findings |
| clears the findings once the hardened manifest is applied | Score 100, zero findings, KG-001/004/008/010/011/013 all absent |

The last two apply the real files from `test/demo/`, so the documented walkthrough cannot
drift from the code without a test failing.

## Layer 3: cluster acceptance (kind)

Every scenario below was executed against the deployed operator. Results are the actual
observed output.

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
