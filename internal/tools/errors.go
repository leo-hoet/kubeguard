package tools

import (
	"errors"
	"fmt"

	"github.com/leo-hoet/kubeguard/internal/k8s"
)

// BuildK8sGuidedRecovery maps domain errors from ClusterBackend into actionable,
// LLM-friendly recovery instructions instead of opaque stack traces or panics.
func BuildK8sGuidedRecovery(err error, namespace, deployment string) *GuidedRecoveryInfo {
	switch {
	case errors.Is(err, k8s.ErrInvalidIdentifier):
		return &GuidedRecoveryInfo{
			ErrorCode:    "INVALID_K8S_IDENTIFIER",
			ErrorMessage: err.Error(),
			RecoveryHint: "Pass lowercase alphanumeric DNS-1123 labels (1-63 chars, hyphens allowed) for 'namespace' and 'deployment'. Call 'list_monitored_namespaces' if unsure of exact names.",
		}
	case errors.Is(err, k8s.ErrProtectedNamespace):
		return &GuidedRecoveryInfo{
			ErrorCode:    "PROTECTED_NAMESPACE_BLOCKED",
			ErrorMessage: fmt.Sprintf("Namespace %q is protected by KubeGuard's cluster safety constitution.", namespace),
			RecoveryHint: "Do NOT attempt automated rollbacks or scaling in 'kube-system', 'kube-public', 'kube-node-lease', 'istio-system', or 'cert-manager'. Escalate control-plane changes to a human cluster administrator with manual kubectl runbook steps.",
		}
	case errors.Is(err, k8s.ErrNamespaceNotFound):
		return &GuidedRecoveryInfo{
			ErrorCode:    "NAMESPACE_NOT_FOUND",
			ErrorMessage: fmt.Sprintf("Namespace %q was not found in the cluster.", namespace),
			RecoveryHint: "Call 'list_monitored_namespaces' first to discover valid namespaces, then retry with an exact namespace match.",
		}
	case errors.Is(err, k8s.ErrDeploymentNotFound):
		return &GuidedRecoveryInfo{
			ErrorCode:    "DEPLOYMENT_NOT_FOUND",
			ErrorMessage: fmt.Sprintf("Deployment %q was not found in namespace %q.", deployment, namespace),
			RecoveryHint: fmt.Sprintf("Call 'list_unhealthy_workloads' with namespace=%q to list exact deployment names before retrying.", namespace),
		}
	case errors.Is(err, k8s.ErrRevisionNotFound):
		return &GuidedRecoveryInfo{
			ErrorCode:    "REVISION_NOT_FOUND",
			ErrorMessage: fmt.Sprintf("Target revision does not exist in rollout history for %s/%s.", namespace, deployment),
			RecoveryHint: fmt.Sprintf("Call 'inspect_deployment_rollout_history' for namespace=%q deployment=%q and select a revision where healthy=true.", namespace, deployment),
		}
	default:
		return &GuidedRecoveryInfo{
			ErrorCode:    "CLUSTER_OPERATION_FAILED",
			ErrorMessage: "Kubernetes backend reported a transient or validation error.",
			RecoveryHint: "Verify target namespace and deployment via 'list_unhealthy_workloads', check rollout revisions via 'inspect_deployment_rollout_history', and retry with validated parameters.",
		}
	}
}
