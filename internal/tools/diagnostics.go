package tools

import (
	"slices"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"

	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

// BuildDiagnosticTools constructs KubeGuard's read-only Kubernetes diagnostic tools
// with explicit input/output JSON schemas, comprehensive docstrings, PII scrubbing,
// and guided error recovery.
func BuildDiagnosticTools(cluster k8s.ClusterBackend, redactor privacy.Redactor) ([]tool.Tool, error) {
	nsTool, err := newListMonitoredNamespacesTool(cluster)
	if err != nil {
		return nil, err
	}
	unhealthyTool, err := newListUnhealthyWorkloadsTool(cluster)
	if err != nil {
		return nil, err
	}
	logsTool, err := newFetchCrashingPodLogsTool(cluster, redactor)
	if err != nil {
		return nil, err
	}
	rolloutTool, err := newInspectRolloutHistoryTool(cluster, redactor)
	if err != nil {
		return nil, err
	}
	return []tool.Tool{nsTool, unhealthyTool, logsTool, rolloutTool}, nil
}

// newListMonitoredNamespacesTool creates the list_monitored_namespaces tool.
// Purpose: Enumerates Kubernetes namespaces available for incident triage.
func newListMonitoredNamespacesTool(cluster k8s.ClusterBackend) (tool.Tool, error) {
	inSchema, err := MustSchema[ListNamespacesInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[ListNamespacesOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "list_monitored_namespaces",
		Description: "Lists all Kubernetes namespaces monitored by KubeGuard. " +
			"Call this tool first when an alert or user prompt omits the exact namespace or when a lookup returns NAMESPACE_NOT_FOUND. " +
			"Parameter 'include_system' optionally includes protected control-plane namespaces for read-only visibility.",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in ListNamespacesInput) (ListNamespacesOutput, error) {
		nsList, err := cluster.ListNamespaces(ctx)
		if err != nil {
			return ListNamespacesOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, "", ""),
			}, nil
		}
		if !in.IncludeSystem {
			nsList = slices.DeleteFunc(nsList, k8s.IsProtectedNamespace)
		}
		return ListNamespacesOutput{
			Status:     "succeeded",
			Namespaces: nsList,
		}, nil
	})
}

// newListUnhealthyWorkloadsTool creates the list_unhealthy_workloads tool.
// Purpose: Scans one or all namespaces for degraded pods, OOMKills, CrashLoopBackOff, or CPU saturation.
func newListUnhealthyWorkloadsTool(cluster k8s.ClusterBackend) (tool.Tool, error) {
	inSchema, err := MustSchema[ListUnhealthyWorkloadsInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[ListUnhealthyWorkloadsOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "list_unhealthy_workloads",
		Description: "Scans Kubernetes deployments for unhealthy pod states (CrashLoopBackOff, OOMKilled, readiness failures, or >=85% CPU saturation). " +
			"Pass 'namespace' (DNS-1123 string, e.g. 'payments') to scope to one namespace, or omit it to scan all application namespaces.",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in ListUnhealthyWorkloadsInput) (ListUnhealthyWorkloadsOutput, error) {
		workloads, err := cluster.ListUnhealthyWorkloads(ctx, strings.TrimSpace(in.Namespace))
		if err != nil {
			return ListUnhealthyWorkloadsOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, in.Namespace, ""),
			}, nil
		}
		return ListUnhealthyWorkloadsOutput{
			Status:    "succeeded",
			Workloads: workloads,
		}, nil
	})
}

// newFetchCrashingPodLogsTool creates the fetch_crashing_pod_logs tool.
// Purpose: Retrieves recent container logs, exit codes, and warning events while actively scrubbing PII/tokens.
func newFetchCrashingPodLogsTool(cluster k8s.ClusterBackend, redactor privacy.Redactor) (tool.Tool, error) {
	inSchema, err := MustSchema[FetchPodLogsInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[FetchPodLogsOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "fetch_crashing_pod_logs",
		Description: "Fetches recent container crash logs, last termination reason (e.g. OOMKilled exit 137 or Error exit 1), restart counts, and Kubernetes Warning events for a specific deployment. " +
			"Automatically scrubs PII, emails, JWTs, and bearer tokens via KubeGuard's DLP redactor before returning lines. " +
			"Requires 'namespace' and 'deployment'; optional 'tail_lines' (1..200, default 50).",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in FetchPodLogsInput) (FetchPodLogsOutput, error) {
		tail := in.TailLines
		if tail <= 0 {
			tail = 50
		}
		if tail > 200 {
			return FetchPodLogsOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "TAIL_LINES_OUT_OF_RANGE",
					ErrorMessage: "tail_lines exceeds maximum allowed window of 200 lines.",
					RecoveryHint: "Retry 'fetch_crashing_pod_logs' with tail_lines between 1 and 200 (recommended: 50).",
				},
			}, nil
		}

		snap, err := cluster.FetchPodLogs(ctx, strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Deployment), tail)
		if err != nil {
			return FetchPodLogsOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, in.Namespace, in.Deployment),
			}, nil
		}

		piiRedacted := false
		if redactor != nil {
			for i, raw := range snap.ScrubbedLogLines {
				clean := redactor.RedactText(ctx, raw)
				if clean != raw {
					piiRedacted = true
				}
				snap.ScrubbedLogLines[i] = clean
			}
			for i, warn := range snap.WarningEvents {
				snap.WarningEvents[i] = redactor.RedactText(ctx, warn)
			}
		}

		return FetchPodLogsOutput{
			Status:      "succeeded",
			Snapshot:    snap,
			PIIRedacted: piiRedacted,
		}, nil
	})
}

// newInspectRolloutHistoryTool creates the inspect_deployment_rollout_history tool.
// Purpose: Lists chronological ReplicaSet revisions, images, memory limits, and env diffs to pinpoint bad rollouts.
func newInspectRolloutHistoryTool(cluster k8s.ClusterBackend, redactor privacy.Redactor) (tool.Tool, error) {
	inSchema, err := MustSchema[InspectRolloutHistoryInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[InspectRolloutHistoryOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "inspect_deployment_rollout_history",
		Description: "Inspects chronological Deployment ReplicaSet rollout revisions, container image tags, memory limits, environment variable diffs, and health flags. " +
			"Always call this tool before 'execute_deployment_rollback' to identify the exact 'target_revision' number that was previously healthy.",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in InspectRolloutHistoryInput) (InspectRolloutHistoryOutput, error) {
		ns := strings.TrimSpace(in.Namespace)
		dep := strings.TrimSpace(in.Deployment)
		revs, err := cluster.InspectRolloutHistory(ctx, ns, dep)
		if err != nil {
			return InspectRolloutHistoryOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, ns, dep),
			}, nil
		}
		if redactor != nil {
			for i := range revs {
				revs[i].ChangeSummary = redactor.RedactText(ctx, revs[i].ChangeSummary)
			}
		}
		return InspectRolloutHistoryOutput{
			Status:     "succeeded",
			Namespace:  ns,
			Deployment: dep,
			Revisions:  revs,
		}, nil
	})
}
