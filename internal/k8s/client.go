// Package k8s provides a clean Kubernetes cluster abstraction supporting both
// a deterministic SimulatedCluster (for hermetic testing, evaluation, and demos)
// and a live client-go implementation for GKE / kind clusters.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrNamespaceNotFound indicates the target namespace does not exist in the cluster.
	ErrNamespaceNotFound = errors.New("namespace not found")
	// ErrDeploymentNotFound indicates the target deployment does not exist in the namespace.
	ErrDeploymentNotFound = errors.New("deployment not found")
	// ErrRevisionNotFound indicates the requested deployment revision is not in rollout history.
	ErrRevisionNotFound = errors.New("revision not found")
	// ErrProtectedNamespace blocks automated mutations against control-plane/platform namespaces.
	ErrProtectedNamespace = errors.New("protected namespace mutation forbidden")
	// ErrInvalidIdentifier rejects malformed Kubernetes DNS-1123 identifiers.
	ErrInvalidIdentifier = errors.New("invalid kubernetes DNS-1123 identifier")

	dns1123LabelRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

	protectedNamespaces = map[string]struct{}{
		"kube-system":     {},
		"kube-public":     {},
		"kube-node-lease": {},
		"istio-system":    {},
		"cert-manager":    {},
	}
)

// ValidateIdentifier enforces strict Kubernetes DNS-1123 label validation (1..63 chars)
// to prevent injection or path traversal when interacting with Kubernetes APIs.
func ValidateIdentifier(value string) error {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) == 0 || len(trimmed) > 63 || !dns1123LabelRegex.MatchString(trimmed) {
		return fmt.Errorf("%w: %q must match ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ (1..63 chars)", ErrInvalidIdentifier, value)
	}
	return nil
}

// IsProtectedNamespace reports whether automated mutations against namespace are prohibited.
func IsProtectedNamespace(namespace string) bool {
	_, blocked := protectedNamespaces[strings.ToLower(strings.TrimSpace(namespace))]
	return blocked
}

// WorkloadHealth summarizes deployment and pod health signals.
type WorkloadHealth struct {
	Namespace         string   `json:"namespace"`
	Deployment        string   `json:"deployment"`
	DesiredReplicas   int32    `json:"desired_replicas"`
	ReadyReplicas     int32    `json:"ready_replicas"`
	CurrentRevision   int64    `json:"current_revision"`
	Image             string   `json:"image"`
	PodStatus         string   `json:"pod_status"`
	TerminationReason string   `json:"termination_reason,omitempty"`
	ExitCode          int32    `json:"exit_code,omitempty"`
	RestartCount      int32    `json:"restart_count"`
	CPUUtilizationPct int32    `json:"cpu_utilization_pct"`
	MemoryLimit       string   `json:"memory_limit"`
	RecentWarnings    []string `json:"recent_warnings,omitempty"`
}

// PodLogSnapshot holds container crash logs and associated Kubernetes warning events.
type PodLogSnapshot struct {
	Namespace         string    `json:"namespace"`
	Deployment        string    `json:"deployment"`
	PodName           string    `json:"pod_name"`
	ContainerName     string    `json:"container_name"`
	TerminationReason string    `json:"termination_reason"`
	ExitCode          int32     `json:"exit_code"`
	RestartCount      int32     `json:"restart_count"`
	ScrubbedLogLines  []string  `json:"scrubbed_log_lines"`
	WarningEvents     []string  `json:"warning_events"`
	CapturedAt        time.Time `json:"captured_at"`
}

// RevisionEntry represents a single Deployment ReplicaSet revision in rollout history.
type RevisionEntry struct {
	Revision      int64             `json:"revision"`
	Image         string            `json:"image"`
	MemoryLimit   string            `json:"memory_limit"`
	EnvSummary    map[string]string `json:"env_summary,omitempty"`
	ChangeSummary string            `json:"change_summary"`
	Healthy       bool              `json:"healthy"`
	DeployedAt    time.Time         `json:"deployed_at"`
}

// RemediationOutcome describes the applied state change after an approved remediation.
type RemediationOutcome struct {
	Action           string    `json:"action"`
	Namespace        string    `json:"namespace"`
	Deployment       string    `json:"deployment"`
	PreviousRevision int64     `json:"previous_revision,omitempty"`
	AppliedRevision  int64     `json:"applied_revision,omitempty"`
	PreviousReplicas int32     `json:"previous_replicas"`
	AppliedReplicas  int32     `json:"applied_replicas"`
	AppliedImage     string    `json:"applied_image"`
	CurrentPodStatus string    `json:"current_pod_status"`
	AppliedAt        time.Time `json:"applied_at"`
}

// ClusterBackend defines all read-only diagnostic and HITL-gated remediation operations.
type ClusterBackend interface {
	ListNamespaces(ctx context.Context) ([]string, error)
	ListUnhealthyWorkloads(ctx context.Context, namespace string) ([]WorkloadHealth, error)
	FetchPodLogs(ctx context.Context, namespace, deployment string, tailLines int32) (*PodLogSnapshot, error)
	InspectRolloutHistory(ctx context.Context, namespace, deployment string) ([]RevisionEntry, error)
	RollbackDeployment(ctx context.Context, namespace, deployment string, targetRevision int64, reason string) (*RemediationOutcome, error)
	ScaleDeployment(ctx context.Context, namespace, deployment string, replicas int32, reason string) (*RemediationOutcome, error)
}
