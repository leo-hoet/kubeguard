package tools

import (
	"fmt"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"

	"github.com/leo-hoet/kubeguard/internal/k8s"
)

// BuildRemediationTools constructs KubeGuard's high-stakes cluster mutation tools.
// Every mutating tool enforces ADK v2 Human-in-the-Loop confirmation (RequireConfirmation: true)
// so no production rollback or replica change executes without explicit operator sign-off.
func BuildRemediationTools(cluster k8s.ClusterBackend) ([]tool.Tool, error) {
	rbTool, err := newExecuteDeploymentRollbackTool(cluster)
	if err != nil {
		return nil, err
	}
	scaleTool, err := newScaleDeploymentReplicasTool(cluster)
	if err != nil {
		return nil, err
	}
	return []tool.Tool{rbTool, scaleTool}, nil
}

// newExecuteDeploymentRollbackTool creates execute_deployment_rollback with RequireConfirmation: true.
func newExecuteDeploymentRollbackTool(cluster k8s.ClusterBackend) (tool.Tool, error) {
	inSchema, err := MustSchema[ExecuteRollbackInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[RemediationToolOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "execute_deployment_rollback",
		Description: "Rolls back a Kubernetes Deployment to a verified healthy ReplicaSet revision ('target_revision'). " +
			"HIGH-STAKES ACTION: Enforces Human-in-the-Loop (HITL) operator confirmation before mutating cluster state. " +
			"Preconditions: (1) Never target protected namespaces ('kube-system', 'istio-system', etc.); " +
			"(2) Always verify 'target_revision' via 'inspect_deployment_rollout_history' first; " +
			"(3) Provide a clear evidence-backed 'reason' summarizing root cause and blast radius.",
		InputSchema:         inSchema,
		OutputSchema:        outSchema,
		RequireConfirmation: true,
	}, func(ctx agent.Context, in ExecuteRollbackInput) (RemediationToolOutput, error) {
		ns := strings.TrimSpace(in.Namespace)
		dep := strings.TrimSpace(in.Deployment)
		if in.TargetRevision < 1 {
			return RemediationToolOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "INVALID_TARGET_REVISION",
					ErrorMessage: fmt.Sprintf("target_revision=%d must be >= 1.", in.TargetRevision),
					RecoveryHint: fmt.Sprintf("Call 'inspect_deployment_rollout_history' for %s/%s and pass a positive revision number marked healthy=true.", ns, dep),
				},
			}, nil
		}
		if strings.TrimSpace(in.Reason) == "" {
			return RemediationToolOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "MISSING_REMEDIATION_REASON",
					ErrorMessage: "reason is required for auditability and human operator review.",
					RecoveryHint: "Retry 'execute_deployment_rollback' with a concise 'reason' citing the failing symptom and healthy revision.",
				},
			}, nil
		}

		outcome, err := cluster.RollbackDeployment(ctx, ns, dep, in.TargetRevision, in.Reason)
		if err != nil {
			return RemediationToolOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, ns, dep),
			}, nil
		}

		return RemediationToolOutput{
			Status:  "succeeded",
			Outcome: outcome,
			Message: fmt.Sprintf("Rolled back %s/%s from revision %d to healthy revision %d (%s).",
				ns, dep, outcome.PreviousRevision, outcome.AppliedRevision, outcome.AppliedImage),
		}, nil
	})
}

// newScaleDeploymentReplicasTool creates scale_deployment_replicas with RequireConfirmation: true.
func newScaleDeploymentReplicasTool(cluster k8s.ClusterBackend) (tool.Tool, error) {
	inSchema, err := MustSchema[ScaleDeploymentInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[RemediationToolOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "scale_deployment_replicas",
		Description: "Horizontally scales a Kubernetes Deployment's replica count within cluster safety bounds [1..50] to mitigate verified CPU throttling or queue backlog spikes. " +
			"HIGH-STAKES ACTION: Enforces Human-in-the-Loop (HITL) operator confirmation before execution. " +
			"Do NOT use horizontal scaling to mask OOMKilled crashes or fatal startup config errors—use 'execute_deployment_rollback' for broken rollouts instead.",
		InputSchema:         inSchema,
		OutputSchema:        outSchema,
		RequireConfirmation: true,
	}, func(ctx agent.Context, in ScaleDeploymentInput) (RemediationToolOutput, error) {
		ns := strings.TrimSpace(in.Namespace)
		dep := strings.TrimSpace(in.Deployment)
		if in.DesiredReplicas < 1 || in.DesiredReplicas > 50 {
			return RemediationToolOutput{
				Status: "policy_blocked",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "REPLICA_BOUNDS_VIOLATION",
					ErrorMessage: fmt.Sprintf("desired_replicas=%d violates cluster safety bounds [1..50].", in.DesiredReplicas),
					RecoveryHint: "Choose a replica count between 1 and 50 proportional to current CPU/queue saturation (never scale production workloads to 0).",
				},
			}, nil
		}
		if strings.TrimSpace(in.Reason) == "" {
			return RemediationToolOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "MISSING_SCALING_REASON",
					ErrorMessage: "reason is required for human operator review.",
					RecoveryHint: "Provide a concise 'reason' citing observed CPU utilization or queue backlog metrics.",
				},
			}, nil
		}

		outcome, err := cluster.ScaleDeployment(ctx, ns, dep, in.DesiredReplicas, in.Reason)
		if err != nil {
			return RemediationToolOutput{
				Status:   "recoverable_error",
				Recovery: BuildK8sGuidedRecovery(err, ns, dep),
			}, nil
		}

		return RemediationToolOutput{
			Status:  "succeeded",
			Outcome: outcome,
			Message: fmt.Sprintf("Scaled %s/%s from %d to %d replicas.", ns, dep, outcome.PreviousReplicas, outcome.AppliedReplicas),
		}, nil
	})
}
