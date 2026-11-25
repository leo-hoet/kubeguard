package agents

import (
	"fmt"
	"log/slog"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agent/workflowagents/parallelagent"
	"google.golang.org/adk/v2/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/loadmemorytool"
	"google.golang.org/adk/v2/tool/preloadmemorytool"

	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/memory"
	"github.com/leo-hoet/kubeguard/internal/privacy"
	"github.com/leo-hoet/kubeguard/internal/tools"
)

// TopologyDependencies bundles models, backends, and stores required to assemble KubeGuard.
type TopologyDependencies struct {
	FastModel      model.LLM
	ReasoningModel model.LLM
	Cluster        k8s.ClusterBackend
	KnowledgeStore *memory.PersistentKnowledgeStore
	Redactor       privacy.Redactor
	Logger         *slog.Logger
}

// BuiltTopology exposes the assembled root agent alongside its strategic router for inspection/testing.
type BuiltTopology struct {
	RootAgent        agent.Agent
	IncidentPipeline agent.Agent
	Router           *StrategicModelRouter
}

// BuildKubeGuardTopology constructs KubeGuard's multi-agent ADK v2 hierarchy:
//   - kubeguard_coordinator (Root LLMAgent backed by StrategicModelRouter: Flash vs. Pro)
//     └── incident_response_pipeline (SequentialAgent)
//         ├── diagnostic_fanout_agent (ParallelAgent)
//         │   ├── pod_telemetry_triage_agent (LLMAgent on Flash -> OutputKey: "telemetry_findings")
//         │   └── runbook_and_memory_agent (LLMAgent on Flash -> OutputKey: "runbook_findings")
//         └── remediation_architect_agent (LLMAgent on Pro + HITL tools)
func BuildKubeGuardTopology(deps TopologyDependencies) (*BuiltTopology, error) {
	if deps.FastModel == nil || deps.ReasoningModel == nil {
		return nil, fmt.Errorf("both FastModel and ReasoningModel are required")
	}
	if deps.Cluster == nil {
		return nil, fmt.Errorf("Cluster backend is required")
	}
	if deps.KnowledgeStore == nil {
		return nil, fmt.Errorf("KnowledgeStore is required")
	}

	diagTools, err := tools.BuildDiagnosticTools(deps.Cluster, deps.Redactor)
	if err != nil {
		return nil, fmt.Errorf("building diagnostic tools: %w", err)
	}
	knowledgeTools, err := tools.BuildKnowledgeTools(deps.KnowledgeStore)
	if err != nil {
		return nil, fmt.Errorf("building knowledge tools: %w", err)
	}
	remediationTools, err := tools.BuildRemediationTools(deps.Cluster)
	if err != nil {
		return nil, fmt.Errorf("building remediation tools: %w", err)
	}

	// 1. Fast Parallel Branch A: Pod & Rollout Telemetry Triage (Gemini Flash)
	telemetryAgent, err := llmagent.New(llmagent.Config{
		Name:            "pod_telemetry_triage_agent",
		Description:     "Fast Kubernetes pod log, warning event, and rollout revision triage specialist.",
		Model:           deps.FastModel,
		Instruction:     TelemetryTriageConstitution,
		Tools:           diagTools,
		OutputKey:       "telemetry_findings",
		IncludeContents: llmagent.IncludeContentsDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("creating pod_telemetry_triage_agent: %w", err)
	}

	// 2. Fast Parallel Branch B: SRE Runbook & Persistent Postmortem Memory Specialist (Gemini Flash)
	memTools := append([]tool.Tool{
		preloadmemorytool.New(),
		loadmemorytool.New(),
	}, knowledgeTools...)
	runbookAgent, err := llmagent.New(llmagent.Config{
		Name:            "runbook_and_memory_agent",
		Description:     "Retrieves matching SRE runbooks and historical incident postmortems from persistent memory.",
		Model:           deps.FastModel,
		Instruction:     RunbookResearcherConstitution,
		Tools:           memTools,
		OutputKey:       "runbook_findings",
		IncludeContents: llmagent.IncludeContentsDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("creating runbook_and_memory_agent: %w", err)
	}

	// 3. Parallel Fan-Out Orchestrator
	fanOutAgent, err := parallelagent.New(parallelagent.Config{
		AgentConfig: agent.Config{
			Name:        "diagnostic_fanout_agent",
			Description: "Concurrently gathers pod/rollout telemetry and SRE runbook/postmortem context.",
			SubAgents:   []agent.Agent{telemetryAgent, runbookAgent},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating diagnostic_fanout_agent: %w", err)
	}

	// 4. Deep-Reasoning Synthesis & HITL Remediation Commander (Gemini 4 Neon with resilient fallback)
	architectTools := append([]tool.Tool{}, remediationTools...)
	architectTools = append(architectTools, diagTools...)
	resilientReasoning := NewResilientReasoningModel(deps.ReasoningModel, deps.FastModel, deps.Logger)
	architectAgent, err := llmagent.New(llmagent.Config{
		Name:            "remediation_architect_agent",
		Description:     "Synthesizes root cause from parallel findings and proposes HITL-gated cluster remediations.",
		Model:           resilientReasoning,
		Instruction:     RemediationArchitectConstitution,
		Tools:           architectTools,
		OutputKey:       "remediation_plan",
		IncludeContents: llmagent.IncludeContentsDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("creating remediation_architect_agent: %w", err)
	}

	// 5. Sequential Incident Response Pipeline: Parallel Fan-Out -> Remediation Architect
	pipelineAgent, err := sequentialagent.New(sequentialagent.Config{
		AgentConfig: agent.Config{
			Name:        "incident_response_pipeline",
			Description: "End-to-end incident triage pipeline running parallel telemetry + runbook research followed by root-cause synthesis and HITL-approved remediation.",
			SubAgents:   []agent.Agent{fanOutAgent, architectAgent},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating incident_response_pipeline: %w", err)
	}

	// 6. Root Coordinator with Strategic Model Router (Flash for quick status, Pro for incident coordination)
	router := NewStrategicModelRouter("kubeguard-strategic-router", deps.FastModel, deps.ReasoningModel, deps.Logger)
	rootCoordinator, err := llmagent.New(llmagent.Config{
		Name:            "kubeguard_coordinator",
		Description:     "Principal Kubernetes SRE Coordinator handling status checks directly and delegating active incidents to incident_response_pipeline.",
		Model:           router,
		Instruction:     CoordinatorConstitution,
		Tools:           diagTools,
		SubAgents:       []agent.Agent{pipelineAgent},
		IncludeContents: llmagent.IncludeContentsDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("creating kubeguard_coordinator: %w", err)
	}

	return &BuiltTopology{
		RootAgent:        rootCoordinator,
		IncidentPipeline: pipelineAgent,
		Router:           router,
	}, nil
}
