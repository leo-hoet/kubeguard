package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

// OfflineDemoSREModel implements adk/v2/model.LLM for zero-key local Web UI previews
// and deterministic offline smoke testing when neither GOOGLE_API_KEY nor GOOGLE_CLOUD_PROJECT
// is configured in development mode.
type OfflineDemoSREModel struct {
	modelName string
}

var _ model.LLM = (*OfflineDemoSREModel)(nil)

// NewOfflineDemoSREModel constructs a deterministic local SRE model simulator.
func NewOfflineDemoSREModel(modelName string) *OfflineDemoSREModel {
	if modelName == "" {
		modelName = "kubeguard-offline-simulator"
	}
	return &OfflineDemoSREModel{modelName: modelName}
}

// Name returns the configured model tier name so strategic routing metrics work identically.
func (m *OfflineDemoSREModel) Name() string {
	return m.modelName
}

// GenerateContent simulates multi-agent tool calls, HITL proposals, and root-cause synthesis.
func (m *OfflineDemoSREModel) GenerateContent(_ context.Context, req *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		yield(m.planTurn(req), nil)
	}
}

func (m *OfflineDemoSREModel) planTurn(req *model.LLMRequest) *model.LLMResponse {
	sysInst := ""
	if req != nil && req.Config != nil && req.Config.SystemInstruction != nil {
		for _, p := range req.Config.SystemInstruction.Parts {
			if p != nil {
				sysInst += p.Text + "\n"
			}
		}
	}

	userPrompt := latestUserPrompt(req.Contents)
	calledTools := collectedToolOutputs(req.Contents)
	ns, dep := detectTargetWorkload(userPrompt)

	const badge = "_[Offline Demo Mode — set `GOOGLE_API_KEY` or `GOOGLE_CLOUD_PROJECT` in `.env` for live Gemini 4 Hydrogen / Gemini 4 Neon]_\n\n"

	switch {
	case strings.Contains(sysInst, "Principal Kubernetes Site Reliability Engineering (SRE) Coordinator"):
		lower := strings.ToLower(userPrompt)
		if strings.Contains(lower, "namespace") || strings.Contains(lower, "monitored") || strings.Contains(lower, "list") && !strings.Contains(lower, "incident") {
			if res, done := calledTools["list_monitored_namespaces"]; done {
				return offlineText(badge + "**Monitored Application Namespaces:**\n```json\n" + prettyJSON(res) + "\n```")
			}
			return offlineToolCall("list_monitored_namespaces", map[string]any{"include_system": false})
		}
		return offlineToolCall("transfer_to_agent", map[string]any{"agent_name": "incident_response_pipeline"})

	case strings.Contains(sysInst, "pod_telemetry_triage_agent"):
		if _, ok := calledTools["fetch_crashing_pod_logs"]; !ok {
			return offlineToolCall("fetch_crashing_pod_logs", map[string]any{
				"namespace":  ns,
				"deployment": dep,
				"tail_lines": 50,
			})
		}
		if _, ok := calledTools["inspect_deployment_rollout_history"]; !ok {
			return offlineToolCall("inspect_deployment_rollout_history", map[string]any{
				"namespace":  ns,
				"deployment": dep,
			})
		}
		return offlineText(fmt.Sprintf("### Workload Symptoms (`%s/%s`)\n- Pod logs & PII-redacted events captured.\n- Rollout history inspected: `%s`",
			ns, dep, compactJSON(calledTools["inspect_deployment_rollout_history"])))

	case strings.Contains(sysInst, "runbook_and_memory_agent"):
		if _, ok := calledTools["search_sre_runbooks"]; !ok {
			q := "OOMKilled exit 137 memory limit rollback"
			if strings.Contains(strings.ToLower(userPrompt), "cpu") || strings.Contains(strings.ToLower(userPrompt), "scale") {
				q = "cpu throttling backlog scale replicas"
			} else if strings.Contains(strings.ToLower(userPrompt), "config") || ns == "catalog" {
				q = "CrashLoopBackOff config validation rollback"
			}
			return offlineToolCall("search_sre_runbooks", map[string]any{
				"symptom_query": q,
				"max_results":   2,
			})
		}
		if _, ok := calledTools["query_past_incident_postmortems"]; !ok {
			return offlineToolCall("query_past_incident_postmortems", map[string]any{
				"service_or_symptom": ns + "/" + dep,
				"max_results":        2,
			})
		}
		return offlineText(fmt.Sprintf("### Applicable Runbooks & Memory (`%s/%s`)\nMatched SRE playbooks and PII-scrubbed postmortems retrieved.", ns, dep))

	case strings.Contains(sysInst, "remediation_architect_agent"):
		if res, ok := calledTools["execute_deployment_rollback"]; ok {
			return offlineText(badge + fmt.Sprintf("## Remediation Outcome (`%s/%s`)\n```json\n%s\n```", ns, dep, prettyJSON(res)))
		}
		if res, ok := calledTools["scale_deployment_replicas"]; ok {
			return offlineText(badge + fmt.Sprintf("## Scaling Outcome (`%s/%s`)\n```json\n%s\n```", ns, dep, prettyJSON(res)))
		}
		if strings.Contains(strings.ToLower(userPrompt), "scale") || strings.Contains(strings.ToLower(userPrompt), "cpu") || ns == "orders" {
			return offlineToolCall("scale_deployment_replicas", map[string]any{
				"namespace":        ns,
				"deployment":       dep,
				"desired_replicas": 6,
				"reason":           "CPU throttling at 95% with 4200 backlog messages on stable release per RB-309",
			})
		}
		targetRev := 3
		if ns == "catalog" {
			targetRev = 6
		} else if ns == "kube-system" {
			targetRev = 1
		}
		return offlineToolCall("execute_deployment_rollback", map[string]any{
			"namespace":       ns,
			"deployment":      dep,
			"target_revision": targetRev,
			"reason":          fmt.Sprintf("Roll back unhealthy %s/%s rollout to verified healthy revision %d", ns, dep, targetRev),
		})

	default:
		return offlineText("Compacted prior incident turns cleanly.")
	}
}

func latestUserPrompt(contents []*genai.Content) string {
	for i := len(contents) - 1; i >= 0; i-- {
		c := contents[i]
		if c == nil || c.Role != string(genai.RoleUser) {
			continue
		}
		for _, p := range c.Parts {
			if p != nil && strings.TrimSpace(p.Text) != "" {
				return p.Text
			}
		}
	}
	return ""
}

func collectedToolOutputs(contents []*genai.Content) map[string]map[string]any {
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

func detectTargetWorkload(prompt string) (string, string) {
	lower := strings.ToLower(prompt)
	switch {
	case strings.Contains(lower, "catalog") || strings.Contains(lower, "inventory-sync"):
		return "catalog", "inventory-sync"
	case strings.Contains(lower, "orders") || strings.Contains(lower, "fulfillment-worker"):
		return "orders", "fulfillment-worker"
	case strings.Contains(lower, "kube-system") || strings.Contains(lower, "coredns"):
		return "kube-system", "coredns"
	default:
		return "payments", "checkout-api"
	}
}

func offlineText(msg string) *model.LLMResponse {
	return &model.LLMResponse{
		Content:      genai.NewContentFromText(msg, genai.RoleModel),
		TurnComplete: true,
	}
}

func offlineToolCall(name string, args map[string]any) *model.LLMResponse {
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

func prettyJSON(m map[string]any) string {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func compactJSON(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}
