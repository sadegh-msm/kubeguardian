/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package podsecurity

import (
	"context"
	"fmt"

	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
	"github.com/sadegh-msm/kubeguardian/internal/snapshot"
)

const (
	SourceName = "pod-security"

	reference = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
)

const (
	checkPrivileged          = "KG-001"
	checkRunAsRoot           = "KG-002"
	checkPrivilegeEscalation = "KG-003"
	checkHostNamespaces      = "KG-004"
	checkHostPath            = "KG-005"
	checkCapabilities        = "KG-006"
	checkSeccomp             = "KG-008"
	checkHostPorts           = "KG-030"
	checkWindowsHostProcess  = "KG-031"
	checkProcMount           = "KG-032"
	checkAppArmor            = "KG-033"
	checkSELinux             = "KG-034"
	checkSysctls             = "KG-035"
	checkHostProbes          = "KG-036"
	checkRestrictedVolumes   = "KG-037"
)

type rule struct {
	id          string
	severity    securityv1alpha1.Severity
	suggestion  string
	remediation string
}

var rules = map[policy.CheckID]rule{
	"privileged": {
		id:          checkPrivileged,
		severity:    securityv1alpha1.SeverityCritical,
		suggestion:  "Set securityContext.privileged to false and add back only the individual capabilities the container genuinely needs.",
		remediation: "securityContext:\n  privileged: false",
	},
	"runAsNonRoot": {
		id:          checkRunAsRoot,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Set securityContext.runAsNonRoot to true so the kubelet refuses to start the container if the image resolves to UID 0.",
		remediation: "securityContext:\n  runAsNonRoot: true",
	},
	"runAsUser": {
		id:          checkRunAsRoot,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Set runAsUser to a non-zero UID and rebuild the image so its files are owned by that user.",
		remediation: "securityContext:\n  runAsUser: 1000",
	},
	"allowPrivilegeEscalation": {
		id:          checkPrivilegeEscalation,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Set securityContext.allowPrivilegeEscalation to false. This is required by the restricted Pod Security Standard and safe for almost every application container.",
		remediation: "securityContext:\n  allowPrivilegeEscalation: false",
	},
	"hostNamespaces": {
		id:          checkHostNamespaces,
		severity:    securityv1alpha1.SeverityCritical,
		suggestion:  "Remove hostNetwork, hostPID and hostIPC unless this is a node-level agent. Expose the workload through a Service instead of binding to the node namespace.",
		remediation: "hostNetwork: false\nhostPID: false\nhostIPC: false",
	},
	"hostPathVolumes": {
		id:          checkHostPath,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Replace the hostPath volume with an emptyDir for scratch space or a PersistentVolumeClaim for durable data. If node access is genuinely required, mount it read-only and restrict the path.",
		remediation: "volumes:\n  - name: scratch\n    emptyDir: {}",
	},
	"capabilities_baseline": {
		id:          checkCapabilities,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Confirm each added capability is required. NET_RAW and SYS_ADMIN in particular widen the blast radius of a container escape.",
		remediation: "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
	},
	"capabilities_restricted": {
		id:          checkCapabilities,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Drop every capability and add back only what the process needs. Most application containers need none.",
		remediation: "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
	},
	"seccompProfile_baseline": {
		id:          checkSeccomp,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Do not set seccompProfile to Unconfined. The runtime default filter blocks syscalls almost no application needs.",
		remediation: "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
	},
	"seccompProfile_restricted": {
		id:          checkSeccomp,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Set seccompProfile.type to RuntimeDefault on the pod so every container inherits the runtime syscall filter.",
		remediation: "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
	},
	"hostPorts": {
		id:          checkHostPorts,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Remove hostPort and expose the workload through a Service. A host port binds the node's network interface and bypasses Service-level policy.",
		remediation: "ports:\n  - containerPort: 8080",
	},
	"windowsHostProcess": {
		id:          checkWindowsHostProcess,
		severity:    securityv1alpha1.SeverityCritical,
		suggestion:  "Disable hostProcess. A Windows HostProcess container runs with node-level privileges and is equivalent to running directly on the host.",
		remediation: "securityContext:\n  windowsOptions:\n    hostProcess: false",
	},
	"procMount": {
		id:          checkProcMount,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Use the Default proc mount. An unmasked /proc exposes kernel interfaces that are a known container escape path.",
		remediation: "securityContext:\n  procMount: Default",
	},
	"procMount_restricted": {
		id:          checkProcMount,
		severity:    securityv1alpha1.SeverityHigh,
		suggestion:  "Use the Default proc mount. An unmasked /proc exposes kernel interfaces that are a known container escape path.",
		remediation: "securityContext:\n  procMount: Default",
	},
	"appArmorProfile": {
		id:          checkAppArmor,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Use the runtime default AppArmor profile rather than unconfined, so the container keeps its mandatory access control policy.",
		remediation: "securityContext:\n  appArmorProfile:\n    type: RuntimeDefault",
	},
	"seLinuxOptions": {
		id:          checkSELinux,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Remove the custom SELinux type or user. Overriding them can grant the container a more permissive domain than the runtime intends.",
		remediation: "securityContext:\n  seLinuxOptions: {}",
	},
	"sysctls": {
		id:          checkSysctls,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Remove the unsafe sysctl. Kernel parameters outside the safe set affect the node, not just this pod.",
		remediation: "securityContext:\n  sysctls: []",
	},
	"hostProbesAndHostLifecycle": {
		id:          checkHostProbes,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Point probes and lifecycle hooks at the pod itself rather than at a host address, so they cannot reach services bound to the node.",
		remediation: "livenessProbe:\n  httpGet:\n    host: \"\"",
	},
	"restrictedVolumes": {
		id:          checkRestrictedVolumes,
		severity:    securityv1alpha1.SeverityMedium,
		suggestion:  "Use only the volume types the restricted Pod Security Standard permits: configMap, secret, emptyDir, projected, downwardAPI, persistentVolumeClaim and ephemeral.",
		remediation: "volumes:\n  - name: data\n    persistentVolumeClaim:\n      claimName: data",
	},
}

type evaluated struct {
	id        policy.CheckID
	level     api.Level
	evaluator policy.Evaluator
}

type Source struct {
	checks []evaluated
}

func New() (*Source, error) {
	defaults := policy.DefaultChecks()
	checks := make([]evaluated, 0, len(defaults))

	for _, check := range defaults {
		evaluator, err := policy.NewEvaluator([]policy.Check{check}, nil)
		if err != nil {
			return nil, fmt.Errorf("build evaluator for pod security check %s: %w", check.ID, err)
		}
		checks = append(checks, evaluated{id: check.ID, level: check.Level, evaluator: evaluator})
	}

	return &Source{checks: checks}, nil
}

func (s *Source) Name() string {
	return SourceName
}

func (s *Source) Collect(_ context.Context, snap *snapshot.Snapshot) ([]securityv1alpha1.Finding, error) {
	var findings []securityv1alpha1.Finding

	for _, workload := range snap.Workloads() {
		metadata := workload.Template.ObjectMeta
		spec := workload.Template.Spec

		for _, check := range s.checks {
			levelVersion := api.LevelVersion{Level: check.level, Version: api.LatestVersion()}

			for _, result := range check.evaluator.EvaluatePod(levelVersion, &metadata, &spec) {
				if result.Allowed {
					continue
				}
				if finding, ok := toFinding(check, workload, result); ok {
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

func toFinding(check evaluated, workload snapshot.Workload, result policy.CheckResult) (securityv1alpha1.Finding, bool) {
	mapped, known := rules[check.id]
	if !known {
		return securityv1alpha1.Finding{}, false
	}

	return securityv1alpha1.Finding{
		ID:       mapped.id,
		Severity: mapped.severity,
		Category: securityv1alpha1.CategoryPodSecurity,
		Resource: securityv1alpha1.ResourceRef{Kind: workload.Kind, Name: workload.Name},
		Message: fmt.Sprintf("%s Pod Security Standard, %s: %s",
			check.level, result.ForbiddenReason, describe(result)),
		Suggestion:  mapped.suggestion,
		Remediation: mapped.remediation,
		Reference:   reference,
		Source:      SourceName,
	}, true
}

func describe(result policy.CheckResult) string {
	if result.ForbiddenDetail != "" {
		return result.ForbiddenDetail
	}
	return result.ForbiddenReason
}

func KnownRuleIDs() []string {
	seen := make(map[string]struct{}, len(rules))
	ids := make([]string, 0, len(rules))
	for _, mapped := range rules {
		if _, duplicate := seen[mapped.id]; duplicate {
			continue
		}
		seen[mapped.id] = struct{}{}
		ids = append(ids, mapped.id)
	}
	return ids
}
