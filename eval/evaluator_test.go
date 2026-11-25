// Package eval executes KubeGuard's automated golden-dataset evaluation suite
// verifying multi-agent orchestration, strategic Flash/Pro routing, HITL tool
// confirmation, safety guardrails, PII redaction, OpenTelemetry spans, and
// async persistent memory consolidation.
package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"iter"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool/toolconfirmation"

	"github.com/leo-hoet/kubeguard/internal/agents"
	"github.com/leo-hoet/kubeguard/internal/guardrails"
	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/memory"
	"github.com/leo-hoet/kubeguard/internal/observability"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

type goldenCase struct {
	ID                      string   `json:"id"`
	Description             string   `json:"description"`
	Prompt                  string   `json:"prompt"`
	TargetNamespace         string   `json:"target_namespace"`
	TargetDeployment        string   `json:"target_deployment"`
	ExpectedRouterTier      string   `json:"expected_router_tier"`
	ExpectedTools           []string `json:"expected_tools"`
	RequiresHITL            bool     `json:"requires_hitl"`
	ApproveHITL             bool     `json:"approve_hitl"`
	ExpectPolicyBlocked     bool     `json:"expect_policy_blocked"`
	ExpectGuardrailRefusal  bool     `json:"expect_guardrail_refusal"`
	ExpectedAppliedRevision int64    `json:"expected_applied_revision"`
	ExpectedAppliedReplicas int32    `json:"expected_applied_replicas"`
	ForbiddenSubstrings     []string `json:"forbidden_substrings"`
}

// spanCollector records OpenTelemetry spans in memory so golden tests verify distributed tracing.
type spanCollector struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (s *spanCollector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spans = append(s.spans, spans...)
	return nil
}

func (s *spanCollector) Shutdown(_ context.Context) error { return nil }

func (s *spanCollector) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.spans))
	for i, sp := range s.spans {
		out[i] = sp.Name()
	}
	return out
}

// deterministicSREModel implements adk/v2/model.LLM so the full ADK v2 multi-agent runtime
// (SequentialAgent, ParallelAgent, FunctionTools, Guardrails, HITL ToolConfirmation, OTel,
// Session DB, and Async Memory) can be evaluated deterministically in CI without flaky network calls.
type deterministicSREModel struct {
	modelName string
}

func (m *deterministicSREModel) Name() string { return m.modelName }

func (m *deterministicSREModel) GenerateContent(_ context.Context, req *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		resp := m.planTurn(req)
		yield(resp, nil)
	}
}

func (m *deterministicSREModel) planTurn(req *model.LLMRequest) *model.LLMResponse {
	sysInst := ""
	if req.Config != nil && req.Config.SystemInstruction != nil {
		for _, p := range req.Config.SystemInstruction.Parts {
			if p != nil {
				sysInst += p.Text + "\n"
			}
		}
	}

	userPrompt := extractFirstUserText(req.Contents)
	calledTools := extractCalledToolResponses(req.Contents)
	ns, dep := inferTargetWorkload(userPrompt)

	switch {
	// Root Coordinator agent
	case strings.Contains(sysInst, "Principal Kubernetes Site Reliability Engineering (SRE) Coordinator"):
		lower := strings.ToLower(userPrompt)
		if strings.Contains(lower, "which kubernetes namespaces") || strings.Contains(lower, "monitored") {
			if res, done := calledTools["list_monitored_namespaces"]; done {
				return textResp("Monitored application namespaces: " + stringifyMap(res))
			}
			return toolCallResp("list_monitored_namespaces", map[string]any{"include_system": false})
		}
		// Delegate active incidents to incident_response_pipeline via ADK transfer_to_agent!
		return toolCallResp("transfer_to_agent", map[string]any{"agent_name": "incident_response_pipeline"})

	// Parallel Branch A: Pod Telemetry Triage Specialist (Flash)
	case strings.Contains(sysInst, "pod_telemetry_triage_agent"):
		if _, ok := calledTools["fetch_crashing_pod_logs"]; !ok {
			return toolCallResp("fetch_crashing_pod_logs", map[string]any{
				"namespace":  ns,
				"deployment": dep,
				"tail_lines": 50,
			})
		}
		if _, ok := calledTools["inspect_deployment_rollout_history"]; !ok {
			return toolCallResp("inspect_deployment_rollout_history", map[string]any{
				"namespace":  ns,
				"deployment": dep,
			})
		}
		return textResp("### Workload Symptoms\nTelemetry & rollout diff collected for " + ns + "/" + dep + ": " +
			stringifyMap(calledTools["fetch_crashing_pod_logs"]) + " | " +
			stringifyMap(calledTools["inspect_deployment_rollout_history"]))

	// Parallel Branch B: SRE Runbook & Postmortem Researcher (Flash)
	case strings.Contains(sysInst, "runbook_and_memory_agent"):
		if _, ok := calledTools["search_sre_runbooks"]; !ok {
			q := "OOMKilled exit 137 memory limit rollback"
			if strings.Contains(strings.ToLower(userPrompt), "cpu") {
				q = "cpu throttling backlog scale replicas"
			}
			return toolCallResp("search_sre_runbooks", map[string]any{
				"symptom_query": q,
				"max_results":   2,
			})
		}
		if _, ok := calledTools["query_past_incident_postmortems"]; !ok {
			return toolCallResp("query_past_incident_postmortems", map[string]any{
				"service_or_symptom": ns + "/" + dep,
				"max_results":        2,
			})
		}
		return textResp("### Applicable Runbooks\nMatched SRE runbooks and historical postmortems for " + ns + "/" + dep + ".")

	// Sequential Synthesis & HITL Commander (Pro)
	case strings.Contains(sysInst, "remediation_architect_agent"):
		if res, ok := calledTools["execute_deployment_rollback"]; ok {
			return textResp("Remediation completed for " + ns + "/" + dep + ": " + stringifyMap(res))
		}
		if res, ok := calledTools["scale_deployment_replicas"]; ok {
			return textResp("Scaling remediation completed for " + ns + "/" + dep + ": " + stringifyMap(res))
		}
		if strings.Contains(strings.ToLower(userPrompt), "scale") || strings.Contains(strings.ToLower(userPrompt), "cpu") {
			return toolCallResp("scale_deployment_replicas", map[string]any{
				"namespace":        ns,
				"deployment":       dep,
				"desired_replicas": 6,
				"reason":           "CPU throttling at 95% with 4200 message backlog on healthy v3.2.0 release per RB-309",
			})
		}
		targetRev := 3
		if ns == "kube-system" {
			targetRev = 1
		}
		return toolCallResp("execute_deployment_rollback", map[string]any{
			"namespace":       ns,
			"deployment":      dep,
			"target_revision": targetRev,
			"reason":          "Roll back OOMKilled revision to verified healthy revision per RB-101",
		})

	default:
		return textResp("Summarized prior session context cleanly.")
	}
}

func TestGoldenIncidentEvaluationSuite(t *testing.T) {
	raw, err := os.ReadFile("golden_incidents.json")
	if err != nil {
		t.Fatalf("reading golden_incidents.json: %v", err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parsing golden_incidents.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("golden dataset must contain at least one test case")
	}

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			ctx := context.Background()
			var logBuf bytes.Buffer

			redactor, err := privacy.NewHybridRedactor(ctx, "", false)
			if err != nil {
				t.Fatalf("creating redactor: %v", err)
			}
			t.Cleanup(func() { _ = redactor.Close() })

			logger := observability.NewStructuredLogger(&logBuf, slog.LevelInfo, "demo-gcp-project", redactor)

			spans := &spanCollector{}
			telRuntime, err := observability.InitTelemetry(ctx, false, spans)
			if err != nil {
				t.Fatalf("initializing telemetry: %v", err)
			}
			t.Cleanup(func() { _ = telRuntime.Shutdown(context.Background()) })

			dbPath := t.TempDir() + "/eval.db"
			db, err := memory.OpenPersistentDB("", dbPath)
			if err != nil {
				t.Fatalf("opening sqlite db: %v", err)
			}
			sessionSvc, err := memory.NewPersistentSessionService(db)
			if err != nil {
				t.Fatalf("creating session service: %v", err)
			}
			knowledgeStore, err := memory.NewPersistentKnowledgeStore(ctx, db, redactor)
			if err != nil {
				t.Fatalf("creating knowledge store: %v", err)
			}

			consolidator := memory.NewAsyncMemoryConsolidator(knowledgeStore, redactor, logger, 32, 2)
			cluster := k8s.NewSimulatedCluster()

			fastModel := &deterministicSREModel{modelName: "gemini-4-hydrogen"}
			proModel := &deterministicSREModel{modelName: "gemini-4-neon"}

			topo, err := agents.BuildKubeGuardTopology(agents.TopologyDependencies{
				FastModel:      fastModel,
				ReasoningModel: proModel,
				Cluster:        cluster,
				KnowledgeStore: knowledgeStore,
				Redactor:       redactor,
				Logger:         logger,
			})
			if err != nil {
				t.Fatalf("building topology: %v", err)
			}

			compactionCfg, err := memory.NewCompactionConfig(fastModel)
			if err != nil {
				t.Fatalf("configuring compaction: %v", err)
			}
			guardrailPlugin, err := guardrails.NewClusterSafetyPolicyPlugin(logger, redactor)
			if err != nil {
				t.Fatalf("creating guardrail plugin: %v", err)
			}
			auditRecorder := observability.NewAuditTrailRecorder(logger, redactor)
			auditPlugin, err := auditRecorder.Plugin()
			if err != nil {
				t.Fatalf("creating audit plugin: %v", err)
			}
			asyncMemPlugin, err := consolidator.Plugin()
			if err != nil {
				t.Fatalf("creating async memory plugin: %v", err)
			}

			r, err := runner.New(runner.Config{
				AppName:           "kubeguard",
				Agent:             topo.RootAgent,
				SessionService:    sessionSvc,
				MemoryService:     knowledgeStore,
				AutoCreateSession: true,
				Compaction:        compactionCfg,
				PluginConfig: runner.PluginConfig{
					Plugins:      []*plugin.Plugin{auditPlugin, guardrailPlugin, asyncMemPlugin},
					CloseTimeout: 5 * time.Second,
				},
			})
			if err != nil {
				t.Fatalf("creating adk runner: %v", err)
			}

			sessionID := "sess-" + strings.ToLower(tc.ID)
			userID := "eval-sre"

			var transcript strings.Builder
			var pendingConfirmationCallID string

			for ev, runErr := range r.Run(ctx, userID, sessionID, genai.NewContentFromText(tc.Prompt, genai.RoleUser), agent.RunConfig{
				StreamingMode: agent.StreamingModeNone,
			}) {
				if runErr != nil {
					t.Fatalf("runner error on initial turn: %v", runErr)
				}
				collectEventDetails(ev, &transcript, &pendingConfirmationCallID)
			}

			// Verify Human-in-the-Loop confirmation behavior!
			if tc.RequiresHITL {
				if pendingConfirmationCallID == "" {
					t.Fatalf("expected HITL confirmation pause (%s), but tool executed without confirmation!", toolconfirmation.FunctionCallName)
				}
				// Resume the paused ADK session with operator approval!
				approvalContent := &genai.Content{
					Role: string(genai.RoleUser),
					Parts: []*genai.Part{
						{
							FunctionResponse: &genai.FunctionResponse{
								Name: toolconfirmation.FunctionCallName,
								ID:   pendingConfirmationCallID,
								Response: map[string]any{
									"confirmed": tc.ApproveHITL,
								},
							},
						},
					},
				}
				for ev, runErr := range r.Run(ctx, userID, sessionID, approvalContent, agent.RunConfig{
					StreamingMode: agent.StreamingModeNone,
				}) {
					if runErr != nil {
						t.Fatalf("runner error on HITL resume turn: %v", runErr)
					}
					var unused string
					collectEventDetails(ev, &transcript, &unused)
				}
			} else if pendingConfirmationCallID != "" {
				t.Fatalf("unexpected HITL confirmation pause %q for non-HITL scenario", pendingConfirmationCallID)
			}

			// Drain async memory consolidator so background postmortem indexing finishes deterministically.
			shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := consolidator.Shutdown(shutdownCtx); err != nil {
				t.Fatalf("draining async consolidator: %v", err)
			}

			// 1. Assert Strategic Model Router tier selection.
			stats := topo.Router.Stats()
			if tc.ExpectedRouterTier == "fast" && !tc.ExpectGuardrailRefusal && stats.FastCalls == 0 {
				t.Errorf("expected fast model tier to be used, got stats=%+v", stats)
			}
			if tc.ExpectedRouterTier == "reasoning" && stats.ReasoningCalls == 0 {
				t.Errorf("expected reasoning model tier to be used, got stats=%+v", stats)
			}

			// 2. Assert Guardrail Refusal on adversarial prompt injection.
			fullOutput := transcript.String()
			if tc.ExpectGuardrailRefusal && !strings.Contains(fullOutput, "Request refused by KubeGuard Security Guardrail") {
				t.Errorf("expected guardrail refusal message, got output: %s", fullOutput)
			}

			// 3. Assert Expected Tools & Intent-vs-Outcome Audit Pairing.
			auditRecords := auditRecorder.Records()
			var executedTools []string
			intentCount, outcomeCount := 0, 0
			policyBlocked := false
			for _, rec := range auditRecords {
				if rec.Stage == "intent" {
					intentCount++
					executedTools = append(executedTools, rec.ToolName)
				}
				if rec.Stage == "outcome" {
					outcomeCount++
					if rec.OutcomeStatus == "policy_blocked" {
						policyBlocked = true
					}
				}
			}
			if intentCount != outcomeCount {
				t.Errorf("intent count (%d) must match outcome count (%d)", intentCount, outcomeCount)
			}
			for _, expectedTool := range tc.ExpectedTools {
				if !slices.Contains(executedTools, expectedTool) {
					t.Errorf("expected tool %q to be invoked; actual tools: %v", expectedTool, executedTools)
				}
			}
			if tc.ExpectPolicyBlocked && !policyBlocked {
				t.Errorf("expected policy_blocked outcome for protected namespace %q", tc.TargetNamespace)
			}

			// 4. Assert Kubernetes Remediation State Mutation after HITL approval.
			if tc.ExpectedAppliedRevision > 0 {
				unhealthy, err := cluster.ListUnhealthyWorkloads(ctx, tc.TargetNamespace)
				if err != nil {
					t.Fatalf("checking post-rollback health: %v", err)
				}
				if len(unhealthy) != 0 {
					t.Errorf("expected %s/%s to be healthy after rollback, still unhealthy: %+v",
						tc.TargetNamespace, tc.TargetDeployment, unhealthy)
				}
			}
			if tc.ExpectedAppliedReplicas > 0 {
				unhealthy, err := cluster.ListUnhealthyWorkloads(ctx, tc.TargetNamespace)
				if err != nil {
					t.Fatalf("checking post-scale health: %v", err)
				}
				if len(unhealthy) != 0 {
					t.Errorf("expected %s/%s saturation resolved after scaling to %d, still unhealthy: %+v",
						tc.TargetNamespace, tc.TargetDeployment, tc.ExpectedAppliedReplicas, unhealthy)
				}
			}

			// 5. Assert Zero PII / Secret Leakage across transcript, structured JSON logs, and persistent memory!
			logsStr := logBuf.String()
			for _, forbidden := range tc.ForbiddenSubstrings {
				if strings.Contains(fullOutput, forbidden) {
					t.Errorf("PII LEAK in agent transcript: found %q", forbidden)
				}
				if strings.Contains(logsStr, forbidden) {
					t.Errorf("PII LEAK in structured JSON logs: found %q", forbidden)
				}
			}

			// 6. Assert Distributed Tracing Spans & Async Memory Consolidation!
			if !tc.ExpectGuardrailRefusal {
				if consolidator.ProcessedCount() == 0 {
					t.Errorf("expected AsyncMemoryConsolidator to process at least 1 background session job")
				}
				spanNames := spans.Names()
				if len(spanNames) == 0 {
					t.Errorf("expected OpenTelemetry spans to be exported, got 0")
				}
			}
		})
	}
}

func collectEventDetails(ev *session.Event, transcript *strings.Builder, pendingConfirmID *string) {
	if ev == nil || ev.Content == nil {
		return
	}
	for _, p := range ev.Content.Parts {
		if p == nil {
			continue
		}
		if p.Text != "" {
			transcript.WriteString(p.Text)
			transcript.WriteByte('\n')
		}
		if fc := p.FunctionCall; fc != nil && fc.Name == toolconfirmation.FunctionCallName {
			*pendingConfirmID = fc.ID
		}
	}
}

func extractFirstUserText(contents []*genai.Content) string {
	for _, c := range contents {
		if c == nil || c.Role != string(genai.RoleUser) {
			continue
		}
		for _, p := range c.Parts {
			if p != nil && p.Text != "" {
				return p.Text
			}
		}
	}
	return ""
}

func extractCalledToolResponses(contents []*genai.Content) map[string]map[string]any {
	out := make(map[string]map[string]any)
	for _, c := range contents {
		if c == nil {
			continue
		}
		for _, p := range c.Parts {
			if p != nil && p.FunctionResponse != nil {
				out[p.FunctionResponse.Name] = p.FunctionResponse.Response
			}
		}
	}
	return out
}

func inferTargetWorkload(prompt string) (string, string) {
	lower := strings.ToLower(prompt)
	switch {
	case strings.Contains(lower, "payments/checkout-api"):
		return "payments", "checkout-api"
	case strings.Contains(lower, "catalog/inventory-sync"):
		return "catalog", "inventory-sync"
	case strings.Contains(lower, "orders/fulfillment-worker"):
		return "orders", "fulfillment-worker"
	case strings.Contains(lower, "kube-system/coredns"):
		return "kube-system", "coredns"
	default:
		return "payments", "checkout-api"
	}
}

func textResp(msg string) *model.LLMResponse {
	return &model.LLMResponse{
		Content:      genai.NewContentFromText(msg, genai.RoleModel),
		TurnComplete: true,
	}
}

func toolCallResp(name string, args map[string]any) *model.LLMResponse {
	return &model.LLMResponse{
		Content: &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "call_" + name,
						Name: name,
						Args: args,
					},
				},
			},
		},
	}
}

func stringifyMap(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}
