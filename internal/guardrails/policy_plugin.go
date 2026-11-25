// Package guardrails implements KubeGuard's ADK v2 policy enforcement and
// output self-evaluation plugin, preventing unauthorized namespace mutations,
// dangerous scaling parameters, prompt-injection bypasses, and unredacted PII leaks.
package guardrails

import (
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/tool"

	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

var mutatingToolNames = map[string]struct{}{
	"execute_deployment_rollback": {},
	"scale_deployment_replicas":   {},
}

var injectionPatterns = []string{
	"ignore all previous instructions",
	"ignore constitutional constraints",
	"bypass kubeguard policy",
	"disable pii redaction",
	"dump all kubernetes secrets",
}

// NewClusterSafetyPolicyPlugin creates an ADK v2 Plugin enforcing:
// 1. Input prompt-injection screening (BeforeModelCallback).
// 2. Hard policy guardrails on mutating Kubernetes tools (BeforeToolCallback) —
//    blocking protected namespaces (kube-system, istio-system, etc.) and unsafe replica bounds
//    even before HITL confirmation prompts can fire.
// 3. Output self-evaluation & PII scrubbing (AfterModelCallback) — guaranteeing no raw
//    JWTs, emails, or secrets escape in model responses.
func NewClusterSafetyPolicyPlugin(logger *slog.Logger, redactor privacy.Redactor) (*plugin.Plugin, error) {
	if logger == nil {
		logger = slog.Default()
	}

	return plugin.New(plugin.Config{
		Name: "kubeguard_cluster_safety_guardrail",

		BeforeModelCallback: func(ctx agent.Context, req *model.LLMRequest) (*model.LLMResponse, error) {
			if req == nil || len(req.Contents) == 0 {
				return nil, nil
			}
			last := req.Contents[len(req.Contents)-1]
			if last == nil || last.Role != string(genai.RoleUser) {
				return nil, nil
			}
			for _, part := range last.Parts {
				if part == nil || part.Text == "" {
					continue
				}
				lower := strings.ToLower(part.Text)
				for _, banned := range injectionPatterns {
					if strings.Contains(lower, banned) {
						logger.WarnContext(ctx, "guardrail blocked adversarial prompt-injection attempt",
							slog.String("agent_name", ctx.AgentName()),
							slog.String("matched_rule", banned))
						return &model.LLMResponse{
							Content: genai.NewContentFromText(
								"Request refused by KubeGuard Security Guardrail: adversarial instruction override or secret-exfiltration requests are prohibited by cluster safety policy.",
								genai.RoleModel,
							),
							TurnComplete: true,
						}, nil
					}
				}
			}
			return nil, nil
		},

		BeforeToolCallback: func(ctx agent.Context, t tool.Tool, args map[string]any) (map[string]any, error) {
			if _, isMutating := mutatingToolNames[t.Name()]; !isMutating {
				return nil, nil
			}

			ns, _ := args["namespace"].(string)
			ns = strings.TrimSpace(ns)
			if k8s.IsProtectedNamespace(ns) {
				logger.WarnContext(ctx, "guardrail blocked mutation against protected namespace",
					slog.String("tool_name", t.Name()),
					slog.String("namespace", ns),
					slog.String("agent_name", ctx.AgentName()))
				return map[string]any{
					"status":  "policy_blocked",
					"message": fmt.Sprintf("Guardrail Policy Violation: automated mutation %q on protected namespace %q is strictly prohibited.", t.Name(), ns),
					"recovery": map[string]any{
						"error_code":    "PROTECTED_NAMESPACE_GUARDRAIL",
						"error_message": fmt.Sprintf("Namespace %q belongs to cluster control-plane/platform infrastructure.", ns),
						"recovery_hint": "Do not retry mutating tools on protected namespaces. Provide read-only findings and manual runbook escalation instructions to the human operator.",
					},
				}, nil
			}

			if t.Name() == "scale_deployment_replicas" {
				if reps, ok := numericArg(args["desired_replicas"]); ok && (reps < 1 || reps > 50) {
					logger.WarnContext(ctx, "guardrail blocked out-of-bounds replica scaling",
						slog.String("namespace", ns),
						slog.Int64("desired_replicas", reps))
					return map[string]any{
						"status":  "policy_blocked",
						"message": fmt.Sprintf("Guardrail Policy Violation: desired_replicas=%d is outside allowed safety bounds [1..50].", reps),
						"recovery": map[string]any{
							"error_code":    "REPLICA_SAFETY_GUARDRAIL",
							"error_message": "Scaling to 0 causes service outage; scaling above 50 risks node-pool exhaustion.",
							"recovery_hint": "Propose a replica count within [1..50] supported by CPU/backlog telemetry.",
						},
					}, nil
				}
			}

			return nil, nil
		},

		AfterModelCallback: func(ctx agent.Context, resp *model.LLMResponse, respErr error) (*model.LLMResponse, error) {
			if respErr != nil || resp == nil || resp.Content == nil || redactor == nil {
				return nil, nil
			}

			modified := false
			clonedParts := make([]*genai.Part, len(resp.Content.Parts))
			for i, p := range resp.Content.Parts {
				if p == nil || p.Text == "" || p.Thought {
					clonedParts[i] = p
					continue
				}
				if privacy.ContainsUnredactedPII(p.Text) {
					scrubbed := redactor.RedactText(ctx, p.Text)
					cp := *p
					cp.Text = scrubbed
					clonedParts[i] = &cp
					modified = true
					logger.WarnContext(ctx, "self-eval guardrail scrubbed residual PII/token from model output",
						slog.String("agent_name", ctx.AgentName()))
				} else {
					clonedParts[i] = p
				}
			}
			if !modified {
				return nil, nil
			}

			replacement := *resp
			contentCopy := *resp.Content
			contentCopy.Parts = clonedParts
			replacement.Content = &contentCopy
			return &replacement, nil
		},
	})
}

func numericArg(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}
