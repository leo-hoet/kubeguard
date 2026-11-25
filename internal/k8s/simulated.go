package k8s

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

type simulatedWorkload struct {
	health    WorkloadHealth
	podName   string
	container string
	rawLogs   []string
	revisions []RevisionEntry
}

// SimulatedCluster provides a deterministic, thread-safe Kubernetes cluster state
// pre-seeded with realistic SRE incident scenarios (OOMKilled with PII in logs,
// CrashLoopBackOff bad config rollout, traffic saturation, and protected kube-system).
type SimulatedCluster struct {
	mu         sync.RWMutex
	namespaces []string
	workloads  map[string]*simulatedWorkload // key: "namespace/deployment"
}

// NewSimulatedCluster constructs a fresh cluster populated with realistic incident state.
func NewSimulatedCluster() *SimulatedCluster {
	now := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)
	c := &SimulatedCluster{
		namespaces: []string{"payments", "catalog", "orders", "kube-system"},
		workloads:  make(map[string]*simulatedWorkload),
	}

	// Scenario 1: payments/checkout-api — OOMKilled after revision 4 increased batch size
	// while keeping 256Mi limit; raw crash logs intentionally contain synthetic PII + JWT
	// to exercise Cloud DLP / regex PII scrubbing end-to-end.
	c.workloads["payments/checkout-api"] = &simulatedWorkload{
		podName:   "checkout-api-7f9c8d6b4-xk9p2",
		container: "checkout-server",
		health: WorkloadHealth{
			Namespace:         "payments",
			Deployment:        "checkout-api",
			DesiredReplicas:   4,
			ReadyReplicas:     1,
			CurrentRevision:   4,
			Image:             "us-docker.pkg.dev/acme-prod/payments/checkout-api:v2.5.0",
			PodStatus:         "CrashLoopBackOff",
			TerminationReason: "OOMKilled",
			ExitCode:          137,
			RestartCount:      14,
			CPUUtilizationPct: 68,
			MemoryLimit:       "256Mi",
			RecentWarnings: []string{
				"BackOff: Back-off restarting failed container checkout-server in pod checkout-api-7f9c8d6b4-xk9p2",
				"SystemOOM: Memory cgroup out of memory: Killed process 1842 (checkout-server), rss=262144kB, limit=262144kB",
			},
		},
		rawLogs: []string{
			"2026-11-25T12:58:10Z INFO starting checkout-server version=v2.5.0 batch_buffer_mb=320 memory_limit=256Mi",
			"2026-11-25T12:58:14Z WARN cart_hydration customer_email=maria.gonzalez@example.org client_ip=10.42.18.99 phone=+1-415-555-0199",
			"2026-11-25T12:58:15Z DEBUG upstream_auth header=\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfOTk4MSIsImVtYWlsIjoibWFyaWEuZ29uemFsZXpAZXhhbXBsZS5vcmcifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"",
			"2026-11-25T12:58:16Z ERROR fatal runtime: out of memory allocating 67108864-byte ledger buffer (total allocated 264Mi > cgroup limit 256Mi)",
		},
		revisions: []RevisionEntry{
			{
				Revision:      3,
				Image:         "us-docker.pkg.dev/acme-prod/payments/checkout-api:v2.4.1",
				MemoryLimit:   "256Mi",
				EnvSummary:    map[string]string{"LEDGER_BATCH_BUFFER_MB": "64", "LOG_LEVEL": "info"},
				ChangeSummary: "Stable production release v2.4.1 (p99 latency 42ms, 0 restarts)",
				Healthy:       true,
				DeployedAt:    now.Add(-48 * time.Hour),
			},
			{
				Revision:      4,
				Image:         "us-docker.pkg.dev/acme-prod/payments/checkout-api:v2.5.0",
				MemoryLimit:   "256Mi",
				EnvSummary:    map[string]string{"LEDGER_BATCH_BUFFER_MB": "320", "LOG_LEVEL": "debug"},
				ChangeSummary: "Increased LEDGER_BATCH_BUFFER_MB from 64 to 320 without raising 256Mi container memory limit",
				Healthy:       false,
				DeployedAt:    now.Add(-18 * time.Minute),
			},
		},
	}

	// Scenario 2: catalog/inventory-sync — CrashLoopBackOff due to invalid env config in rev 7.
	c.workloads["catalog/inventory-sync"] = &simulatedWorkload{
		podName:   "inventory-sync-64d8b5f7c-m2n8q",
		container: "sync-worker",
		health: WorkloadHealth{
			Namespace:         "catalog",
			Deployment:        "inventory-sync",
			DesiredReplicas:   3,
			ReadyReplicas:     0,
			CurrentRevision:   7,
			Image:             "us-docker.pkg.dev/acme-prod/catalog/inventory-sync:v1.9.0-rc2",
			PodStatus:         "CrashLoopBackOff",
			TerminationReason: "Error",
			ExitCode:          1,
			RestartCount:      9,
			CPUUtilizationPct: 12,
			MemoryLimit:       "512Mi",
			RecentWarnings: []string{
				"BackOff: Back-off restarting failed container sync-worker in pod inventory-sync-64d8b5f7c-m2n8q",
			},
		},
		rawLogs: []string{
			"2026-11-25T12:55:01Z INFO initializing inventory-sync version=v1.9.0-rc2",
			"2026-11-25T12:55:02Z ERROR config validation failed: DB_POOL_MAX_IDLE=-5 must be >= 0 (operator contact: oncall-catalog@example.com)",
			"2026-11-25T12:55:02Z FATAL exiting with code 1 due to invalid environment configuration",
		},
		revisions: []RevisionEntry{
			{
				Revision:      6,
				Image:         "us-docker.pkg.dev/acme-prod/catalog/inventory-sync:v1.8.4",
				MemoryLimit:   "512Mi",
				EnvSummary:    map[string]string{"DB_POOL_MAX_IDLE": "10", "SYNC_INTERVAL": "30s"},
				ChangeSummary: "Stable release v1.8.4",
				Healthy:       true,
				DeployedAt:    now.Add(-72 * time.Hour),
			},
			{
				Revision:      7,
				Image:         "us-docker.pkg.dev/acme-prod/catalog/inventory-sync:v1.9.0-rc2",
				MemoryLimit:   "512Mi",
				EnvSummary:    map[string]string{"DB_POOL_MAX_IDLE": "-5", "SYNC_INTERVAL": "10s"},
				ChangeSummary: "Canary config update setting DB_POOL_MAX_IDLE=-5 (invalid negative value)",
				Healthy:       false,
				DeployedAt:    now.Add(-25 * time.Minute),
			},
		},
	}

	// Scenario 3: orders/fulfillment-worker — Healthy code experiencing flash-sale CPU saturation
	// where horizontal scaling (2 -> 6 replicas), NOT rollback, is warranted.
	c.workloads["orders/fulfillment-worker"] = &simulatedWorkload{
		podName:   "fulfillment-worker-59b7d48f9-z4t7w",
		container: "worker",
		health: WorkloadHealth{
			Namespace:         "orders",
			Deployment:        "fulfillment-worker",
			DesiredReplicas:   2,
			ReadyReplicas:     2,
			CurrentRevision:   5,
			Image:             "us-docker.pkg.dev/acme-prod/orders/fulfillment-worker:v3.2.0",
			PodStatus:         "DegradedHighLatency",
			TerminationReason: "",
			ExitCode:          0,
			RestartCount:      0,
			CPUUtilizationPct: 95,
			MemoryLimit:       "1Gi",
			RecentWarnings: []string{
				"CpuThrottlingHigh: Container worker CPU throttled 64% of periods; pubsub backlog=4200 messages",
			},
		},
		rawLogs: []string{
			"2026-11-25T12:59:01Z WARN queue consumer lag high: backlog=4200 avg_processing_ms=890 cpu_pct=95",
			"2026-11-25T12:59:05Z INFO worker healthy; zero errors, bottlenecked on 2 active replicas during flash sale",
		},
		revisions: []RevisionEntry{
			{
				Revision:      5,
				Image:         "us-docker.pkg.dev/acme-prod/orders/fulfillment-worker:v3.2.0",
				MemoryLimit:   "1Gi",
				EnvSummary:    map[string]string{"WORKER_CONCURRENCY": "16"},
				ChangeSummary: "Stable release v3.2.0 running cleanly for 14 days",
				Healthy:       true,
				DeployedAt:    now.Add(-14 * 24 * time.Hour),
			},
		},
	}

	// Scenario 4: kube-system/coredns — Protected control-plane workload for guardrail tests.
	c.workloads["kube-system/coredns"] = &simulatedWorkload{
		podName:   "coredns-787d4945fb-9v2kl",
		container: "coredns",
		health: WorkloadHealth{
			Namespace:         "kube-system",
			Deployment:        "coredns",
			DesiredReplicas:   2,
			ReadyReplicas:     2,
			CurrentRevision:   1,
			Image:             "registry.k8s.io/coredns/coredns:v1.11.3",
			PodStatus:         "Running",
			CPUUtilizationPct: 14,
			MemoryLimit:       "170Mi",
		},
		rawLogs: []string{"2026-11-25T12:00:00Z INFO CoreDNS-1.11.3 serving cluster.local"},
		revisions: []RevisionEntry{
			{
				Revision:      1,
				Image:         "registry.k8s.io/coredns/coredns:v1.11.3",
				MemoryLimit:   "170Mi",
				ChangeSummary: "Cluster bootstrap DNS deployment",
				Healthy:       true,
				DeployedAt:    now.Add(-90 * 24 * time.Hour),
			},
		},
	}

	return c
}

// ListNamespaces returns all monitored namespaces in deterministic order.
func (c *SimulatedCluster) ListNamespaces(_ context.Context) ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := slices.Clone(c.namespaces)
	slices.Sort(out)
	return out, nil
}

// ListUnhealthyWorkloads returns degraded or crashing workloads in namespace (or across all non-system namespaces if empty).
func (c *SimulatedCluster) ListUnhealthyWorkloads(_ context.Context, namespace string) ([]WorkloadHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if namespace != "" {
		if err := ValidateIdentifier(namespace); err != nil {
			return nil, err
		}
		if !slices.Contains(c.namespaces, namespace) {
			return nil, fmt.Errorf("%w: %q", ErrNamespaceNotFound, namespace)
		}
	}

	var out []WorkloadHealth
	for _, w := range c.workloads {
		if namespace != "" && w.health.Namespace != namespace {
			continue
		}
		if w.health.ReadyReplicas < w.health.DesiredReplicas || w.health.RestartCount > 0 || w.health.CPUUtilizationPct >= 85 {
			cloned := w.health
			cloned.RecentWarnings = slices.Clone(w.health.RecentWarnings)
			out = append(out, cloned)
		}
	}
	slices.SortFunc(out, func(a, b WorkloadHealth) int {
		if a.Namespace != b.Namespace {
			return stringsCompare(a.Namespace, b.Namespace)
		}
		return stringsCompare(a.Deployment, b.Deployment)
	})
	return out, nil
}

// FetchPodLogs retrieves recent log lines and warning events for deployment.
func (c *SimulatedCluster) FetchPodLogs(_ context.Context, namespace, deployment string, tailLines int32) (*PodLogSnapshot, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if !slices.Contains(c.namespaces, namespace) {
		return nil, fmt.Errorf("%w: %q", ErrNamespaceNotFound, namespace)
	}
	w, ok := c.workloads[namespace+"/"+deployment]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrDeploymentNotFound, namespace, deployment)
	}

	lines := slices.Clone(w.rawLogs)
	if tailLines > 0 && int(tailLines) < len(lines) {
		lines = lines[len(lines)-int(tailLines):]
	}

	return &PodLogSnapshot{
		Namespace:         namespace,
		Deployment:        deployment,
		PodName:           w.podName,
		ContainerName:     w.container,
		TerminationReason: w.health.TerminationReason,
		ExitCode:          w.health.ExitCode,
		RestartCount:      w.health.RestartCount,
		ScrubbedLogLines:  lines,
		WarningEvents:     slices.Clone(w.health.RecentWarnings),
		CapturedAt:        time.Now().UTC(),
	}, nil
}

// InspectRolloutHistory returns the ReplicaSet revision history for deployment.
func (c *SimulatedCluster) InspectRolloutHistory(_ context.Context, namespace, deployment string) ([]RevisionEntry, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if !slices.Contains(c.namespaces, namespace) {
		return nil, fmt.Errorf("%w: %q", ErrNamespaceNotFound, namespace)
	}
	w, ok := c.workloads[namespace+"/"+deployment]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrDeploymentNotFound, namespace, deployment)
	}

	out := make([]RevisionEntry, len(w.revisions))
	copy(out, w.revisions)
	return out, nil
}

// RollbackDeployment reverts deployment to targetRevision after safety validation.
func (c *SimulatedCluster) RollbackDeployment(_ context.Context, namespace, deployment string, targetRevision int64, _ string) (*RemediationOutcome, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}
	if IsProtectedNamespace(namespace) {
		return nil, fmt.Errorf("%w: %q", ErrProtectedNamespace, namespace)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !slices.Contains(c.namespaces, namespace) {
		return nil, fmt.Errorf("%w: %q", ErrNamespaceNotFound, namespace)
	}
	w, ok := c.workloads[namespace+"/"+deployment]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrDeploymentNotFound, namespace, deployment)
	}

	var target *RevisionEntry
	for i := range w.revisions {
		if w.revisions[i].Revision == targetRevision {
			target = &w.revisions[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("%w: revision %d for %s/%s", ErrRevisionNotFound, targetRevision, namespace, deployment)
	}

	prevRev := w.health.CurrentRevision
	w.health.CurrentRevision = target.Revision
	w.health.Image = target.Image
	w.health.MemoryLimit = target.MemoryLimit
	w.health.ReadyReplicas = w.health.DesiredReplicas
	w.health.PodStatus = "Running"
	w.health.TerminationReason = ""
	w.health.ExitCode = 0
	w.health.RestartCount = 0
	w.health.RecentWarnings = nil

	return &RemediationOutcome{
		Action:           "deployment_rollback",
		Namespace:        namespace,
		Deployment:       deployment,
		PreviousRevision: prevRev,
		AppliedRevision:  target.Revision,
		PreviousReplicas: w.health.DesiredReplicas,
		AppliedReplicas:  w.health.DesiredReplicas,
		AppliedImage:     target.Image,
		CurrentPodStatus: w.health.PodStatus,
		AppliedAt:        time.Now().UTC(),
	}, nil
}

// ScaleDeployment updates desired replicas within policy bounds [1..50].
func (c *SimulatedCluster) ScaleDeployment(_ context.Context, namespace, deployment string, replicas int32, _ string) (*RemediationOutcome, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}
	if IsProtectedNamespace(namespace) {
		return nil, fmt.Errorf("%w: %q", ErrProtectedNamespace, namespace)
	}
	if replicas < 1 || replicas > 50 {
		return nil, fmt.Errorf("replica count %d violates cluster safety bounds [1..50]", replicas)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !slices.Contains(c.namespaces, namespace) {
		return nil, fmt.Errorf("%w: %q", ErrNamespaceNotFound, namespace)
	}
	w, ok := c.workloads[namespace+"/"+deployment]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrDeploymentNotFound, namespace, deployment)
	}

	prev := w.health.DesiredReplicas
	w.health.DesiredReplicas = replicas
	w.health.ReadyReplicas = replicas
	if w.health.PodStatus == "DegradedHighLatency" && replicas > prev {
		w.health.PodStatus = "Running"
		w.health.CPUUtilizationPct = max(25, w.health.CPUUtilizationPct*prev/replicas)
		w.health.RecentWarnings = nil
	}

	return &RemediationOutcome{
		Action:           "scale_deployment",
		Namespace:        namespace,
		Deployment:       deployment,
		PreviousRevision: w.health.CurrentRevision,
		AppliedRevision:  w.health.CurrentRevision,
		PreviousReplicas: prev,
		AppliedReplicas:  replicas,
		AppliedImage:     w.health.Image,
		CurrentPodStatus: w.health.PodStatus,
		AppliedAt:        time.Now().UTC(),
	}, nil
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
