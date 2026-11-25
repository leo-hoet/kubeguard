// Package tools defines KubeGuard's strongly typed Kubernetes diagnostic,
// runbook retrieval, and HITL-gated remediation tools with explicit JSON schemas,
// comprehensive docstrings, and guided LLM error recovery.
package tools

import (
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/memory"
)

// GuidedRecoveryInfo provides actionable recovery steps back to the LLM whenever
// a tool call encounters invalid arguments, missing resources, or policy constraints.
type GuidedRecoveryInfo struct {
	ErrorCode    string `json:"error_code" jsonschema:"Machine-readable error classification code."`
	ErrorMessage string `json:"error_message" jsonschema:"Human- and LLM-readable explanation of what went wrong."`
	RecoveryHint string `json:"recovery_hint" jsonschema:"Actionable step-by-step instruction telling the LLM how to recover on its next turn."`
}

// ListNamespacesInput defines arguments for list_monitored_namespaces.
type ListNamespacesInput struct {
	IncludeSystem bool `json:"include_system,omitempty" jsonschema:"When true, includes protected platform namespaces such as kube-system in the read-only listing."`
}

// ListNamespacesOutput defines the structured response of list_monitored_namespaces.
type ListNamespacesOutput struct {
	Status     string              `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Namespaces []string            `json:"namespaces,omitempty" jsonschema:"Sorted list of Kubernetes namespaces visible to KubeGuard."`
	Recovery   *GuidedRecoveryInfo `json:"recovery,omitempty" jsonschema:"Populated with recovery instructions when status is recoverable_error."`
}

// ListUnhealthyWorkloadsInput defines arguments for list_unhealthy_workloads.
type ListUnhealthyWorkloadsInput struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional Kubernetes namespace (DNS-1123 label, e.g. 'payments'). Leave empty to scan all monitored namespaces."`
}

// ListUnhealthyWorkloadsOutput defines the output of list_unhealthy_workloads.
type ListUnhealthyWorkloadsOutput struct {
	Status    string               `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Workloads []k8s.WorkloadHealth `json:"workloads,omitempty" jsonschema:"Degraded, crashing, or CPU-saturated Kubernetes deployments."`
	Recovery  *GuidedRecoveryInfo  `json:"recovery,omitempty" jsonschema:"Guided recovery instructions if the namespace is invalid or unknown."`
}

// FetchPodLogsInput defines strict parameters for fetch_crashing_pod_logs.
type FetchPodLogsInput struct {
	Namespace  string `json:"namespace" jsonschema:"Target Kubernetes namespace containing the failing deployment (required, DNS-1123 label)."`
	Deployment string `json:"deployment" jsonschema:"Name of the Kubernetes Deployment whose crashing pod logs should be inspected (required)."`
	TailLines  int32  `json:"tail_lines,omitempty" jsonschema:"Maximum number of recent log lines to retrieve (1..200; defaults to 50)."`
}

// FetchPodLogsOutput returns PII-scrubbed container logs and Kubernetes warning events.
type FetchPodLogsOutput struct {
	Status       string              `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Snapshot     *k8s.PodLogSnapshot `json:"snapshot,omitempty" jsonschema:"PII-redacted pod termination state, log lines, and warning events."`
	PIIRedacted  bool                `json:"pii_redacted" jsonschema:"True when KubeGuard's DLP/regex scrubber redacted sensitive tokens or PII from raw logs."`
	Recovery     *GuidedRecoveryInfo `json:"recovery,omitempty" jsonschema:"Actionable recovery instructions if the namespace or deployment does not exist."`
}

// InspectRolloutHistoryInput defines parameters for inspect_deployment_rollout_history.
type InspectRolloutHistoryInput struct {
	Namespace  string `json:"namespace" jsonschema:"Target Kubernetes namespace (required, DNS-1123 label)."`
	Deployment string `json:"deployment" jsonschema:"Target Kubernetes Deployment name (required)."`
}

// InspectRolloutHistoryOutput returns chronological ReplicaSet revisions for change correlation.
type InspectRolloutHistoryOutput struct {
	Status    string              `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Namespace string              `json:"namespace,omitempty" jsonschema:"Inspected Kubernetes namespace."`
	Deployment string             `json:"deployment,omitempty" jsonschema:"Inspected Kubernetes Deployment."`
	Revisions []k8s.RevisionEntry `json:"revisions,omitempty" jsonschema:"Ordered revision history including container images, env diffs, and health flags."`
	Recovery  *GuidedRecoveryInfo `json:"recovery,omitempty" jsonschema:"Guided recovery instructions if lookup fails."`
}

// SearchRunbooksInput defines parameters for search_sre_runbooks.
type SearchRunbooksInput struct {
	SymptomQuery string `json:"symptom_query" jsonschema:"Incident symptom keywords such as 'OOMKilled exit 137 memory limit' or 'CrashLoopBackOff config rollback'."`
	MaxResults   int    `json:"max_results,omitempty" jsonschema:"Maximum number of runbooks to return (1..10; defaults to 3)."`
}

// SearchRunbooksOutput returns matching SRE playbooks.
type SearchRunbooksOutput struct {
	Status   string              `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Runbooks []memory.SRERunbook `json:"runbooks,omitempty" jsonschema:"Ranked SRE runbooks matching the symptom query."`
	Recovery *GuidedRecoveryInfo `json:"recovery,omitempty" jsonschema:"Recovery guidance when query is empty or malformed."`
}

// QueryPostmortemsInput defines parameters for query_past_incident_postmortems.
type QueryPostmortemsInput struct {
	ServiceOrSymptom string `json:"service_or_symptom" jsonschema:"Workload identifier (e.g. 'payments/checkout-api') or failure symptom to match in historical postmortems."`
	MaxResults       int    `json:"max_results,omitempty" jsonschema:"Maximum number of postmortem records to retrieve (1..10; defaults to 3)."`
}

// QueryPostmortemsOutput returns PII-scrubbed historical incident summaries.
type QueryPostmortemsOutput struct {
	Status      string                            `json:"status" jsonschema:"Execution status: succeeded or recoverable_error."`
	Postmortems []memory.IncidentPostmortemRecord `json:"postmortems,omitempty" jsonschema:"Matching historical incident postmortem summaries."`
	Recovery    *GuidedRecoveryInfo               `json:"recovery,omitempty" jsonschema:"Recovery guidance when query is invalid."`
}

// ExecuteRollbackInput defines validated arguments for execute_deployment_rollback.
type ExecuteRollbackInput struct {
	Namespace      string `json:"namespace" jsonschema:"Target Kubernetes namespace (must NOT be a protected system namespace such as kube-system)."`
	Deployment     string `json:"deployment" jsonschema:"Target Kubernetes Deployment to roll back."`
	TargetRevision int64  `json:"target_revision" jsonschema:"Verified healthy ReplicaSet revision number from inspect_deployment_rollout_history (must be >= 1)."`
	Reason         string `json:"reason" jsonschema:"Concise root-cause justification and blast-radius summary presented to the human approver."`
}

// ScaleDeploymentInput defines validated arguments for scale_deployment_replicas.
type ScaleDeploymentInput struct {
	Namespace       string `json:"namespace" jsonschema:"Target Kubernetes namespace (must NOT be a protected system namespace)."`
	Deployment      string `json:"deployment" jsonschema:"Target Kubernetes Deployment to scale horizontally."`
	DesiredReplicas int32  `json:"desired_replicas" jsonschema:"Desired replica count within cluster safety bounds [1..50]."`
	Reason          string `json:"reason" jsonschema:"Evidence-backed justification explaining why horizontal scaling resolves saturation."`
}

// RemediationToolOutput defines the structured output for HITL-gated cluster mutations.
type RemediationToolOutput struct {
	Status   string                  `json:"status" jsonschema:"Execution status: succeeded, rejected_by_operator, policy_blocked, or recoverable_error."`
	Outcome  *k8s.RemediationOutcome `json:"outcome,omitempty" jsonschema:"Applied cluster state diff when status is succeeded."`
	Message  string                  `json:"message,omitempty" jsonschema:"Human-readable summary of the remediation outcome."`
	Recovery *GuidedRecoveryInfo     `json:"recovery,omitempty" jsonschema:"Actionable recovery instructions when blocked or failed."`
}

// MustSchema builds an explicit JSON schema from Go type T with strict validation constraints,
// ensuring ADK exposes explicit input and output JSON schemas for every tool declaration.
func MustSchema[T any]() (*jsonschema.Schema, error) {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, fmt.Errorf("generating explicit json schema for %T: %w", *new(T), err)
	}
	return s, nil
}
