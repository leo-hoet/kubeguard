package tools

import (
	"context"
	"testing"

	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

func TestBuildToolsSchemasAndGuidedErrorRecovery(t *testing.T) {
	ctx := context.Background()
	cluster := k8s.NewSimulatedCluster()
	redactor, err := privacy.NewHybridRedactor(ctx, "", false)
	if err != nil {
		t.Fatalf("creating redactor: %v", err)
	}
	defer func() { _ = redactor.Close() }()

	diagTools, err := BuildDiagnosticTools(cluster, redactor)
	if err != nil {
		t.Fatalf("BuildDiagnosticTools failed: %v", err)
	}
	if len(diagTools) != 4 {
		t.Fatalf("expected 4 diagnostic tools, got %d", len(diagTools))
	}

	remTools, err := BuildRemediationTools(cluster)
	if err != nil {
		t.Fatalf("BuildRemediationTools failed: %v", err)
	}
	if len(remTools) != 2 {
		t.Fatalf("expected 2 remediation tools, got %d", len(remTools))
	}

	// Verify guided error recovery instructions for unknown namespaces and protected namespaces.
	nsRec := BuildK8sGuidedRecovery(k8s.ErrNamespaceNotFound, "paymnts", "checkout-api")
	if nsRec.ErrorCode != "NAMESPACE_NOT_FOUND" || nsRec.RecoveryHint == "" {
		t.Fatalf("expected actionable NAMESPACE_NOT_FOUND recovery hint, got: %+v", nsRec)
	}

	protRec := BuildK8sGuidedRecovery(k8s.ErrProtectedNamespace, "kube-system", "coredns")
	if protRec.ErrorCode != "PROTECTED_NAMESPACE_BLOCKED" || protRec.RecoveryHint == "" {
		t.Fatalf("expected actionable PROTECTED_NAMESPACE_BLOCKED recovery hint, got: %+v", protRec)
	}
}
