// Command kubeguard launches the KubeGuard multi-agent Kubernetes incident
// triage and HITL remediation service built on Google ADK for Go v2.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/cmd/launcher/full"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/server/authn"
	"google.golang.org/adk/v2/server/authz"

	"github.com/leo-hoet/kubeguard/internal/agents"
	"github.com/leo-hoet/kubeguard/internal/config"
	"github.com/leo-hoet/kubeguard/internal/guardrails"
	"github.com/leo-hoet/kubeguard/internal/k8s"
	"github.com/leo-hoet/kubeguard/internal/memory"
	"github.com/leo-hoet/kubeguard/internal/observability"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args[1:]); err != nil {
		bootstrapLog := observability.NewStructuredLogger(os.Stderr, slog.LevelError, "", nil)
		bootstrapLog.ErrorContext(ctx, "kubeguard exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	// 1. Bootstrap temporary structured JSON logger for secret & config resolution.
	bootLogger := observability.NewStructuredLogger(os.Stderr, slog.LevelInfo, "", nil)
	cfg, err := config.Load(ctx, bootLogger, nil)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// 2. Initialize PII redactor (Cloud Sensitive Data Protection / DLP + deterministic regex).
	redactor, err := privacy.NewHybridRedactor(ctx, cfg.GCPProjectID, cfg.EnableCloudDLP)
	if err != nil {
		return fmt.Errorf("initializing pii redactor: %w", err)
	}
	defer func() { _ = redactor.Close() }()

	// 3. Upgrade structured JSON logger with active PII scrubbing + Cloud Logging trace correlation.
	logger := observability.NewStructuredLogger(os.Stderr, slog.LevelInfo, cfg.GCPProjectID, redactor)

	// 4. Initialize OpenTelemetry distributed tracing (ADK v2 GenAI semantic conventions).
	telemetryRuntime, err := observability.InitTelemetry(ctx, cfg.EnableCloudTrace)
	if err != nil {
		return fmt.Errorf("initializing telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetryRuntime.Shutdown(shutdownCtx)
	}()

	// 5. Initialize persistent relational DB for sessions, SRE runbooks, and postmortem memory.
	db, err := memory.OpenPersistentDB(cfg.PostgresDSN, cfg.SQLitePath)
	if err != nil {
		return fmt.Errorf("opening persistent database: %w", err)
	}
	sessionSvc, err := memory.NewPersistentSessionService(db)
	if err != nil {
		return fmt.Errorf("creating persistent session service: %w", err)
	}
	knowledgeStore, err := memory.NewPersistentKnowledgeStore(ctx, db, redactor)
	if err != nil {
		return fmt.Errorf("creating persistent knowledge store: %w", err)
	}

	// 6. Start non-blocking Async Memory Consolidator worker pool.
	consolidator := memory.NewAsyncMemoryConsolidator(knowledgeStore, redactor, logger, 64, 2)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = consolidator.Shutdown(shutdownCtx)
	}()

	// 7. Select Kubernetes cluster backend (SimulatedCluster default or live client-go).
	var cluster k8s.ClusterBackend
	if cfg.ClusterMode == "live" {
		cluster, err = k8s.NewLiveClientGoCluster(cfg.KubeconfigPath)
		if err != nil {
			return fmt.Errorf("initializing live client-go cluster backend: %w", err)
		}
	} else {
		cluster = k8s.NewSimulatedCluster()
	}

	// 8. Initialize Gemini Flash (fast triage/compaction) and Gemini Pro (deep reasoning) models,
	// or fall back cleanly in local development to OfflineDemoSREModel when no API key / project is set.
	var (
		fastLLM      model.LLM
		reasoningLLM model.LLM
	)
	if cfg.UseOfflineDemoLLM {
		logger.WarnContext(ctx, "GOOGLE_API_KEY and GOOGLE_CLOUD_PROJECT are unset; starting with built-in Offline Demo SRE Simulator so Web UI & Console work immediately. Set GOOGLE_API_KEY or GOOGLE_CLOUD_PROJECT (in env or .env) for live Gemini 4 Hydrogen / Gemini 4 Neon.",
			slog.String("fast_simulator", cfg.FastModel),
			slog.String("reasoning_simulator", cfg.ReasoningModel),
		)
		fastLLM = agents.NewOfflineDemoSREModel(cfg.FastModel)
		reasoningLLM = agents.NewOfflineDemoSREModel(cfg.ReasoningModel)
	} else {
		genaiCfg := buildGenAIClientConfig(cfg)
		fastLLM, err = gemini.NewModel(ctx, cfg.FastModel, genaiCfg)
		if err != nil {
			return fmt.Errorf("initializing fast gemini model (%s): %w", cfg.FastModel, err)
		}
		reasoningLLM, err = gemini.NewModel(ctx, cfg.ReasoningModel, genaiCfg)
		if err != nil {
			return fmt.Errorf("initializing reasoning gemini model (%s): %w", cfg.ReasoningModel, err)
		}
	}

	// 9. Assemble Multi-Agent ADK v2 Topology + Strategic Model Router.
	topo, err := agents.BuildKubeGuardTopology(agents.TopologyDependencies{
		FastModel:      fastLLM,
		ReasoningModel: reasoningLLM,
		Cluster:        cluster,
		KnowledgeStore: knowledgeStore,
		Redactor:       redactor,
		Logger:         logger,
	})
	if err != nil {
		return fmt.Errorf("assembling kubeguard agent topology: %w", err)
	}

	// 10. Configure ADK History Compaction (sliding window + token-ceiling tail retention).
	compactionCfg, err := memory.NewCompactionConfig(fastLLM)
	if err != nil {
		return fmt.Errorf("configuring history compaction: %w", err)
	}

	// 11. Register Guardrail Policy, Intent-vs-Outcome Audit, and Async Memory Plugins.
	guardrailPlugin, err := guardrails.NewClusterSafetyPolicyPlugin(logger, redactor)
	if err != nil {
		return fmt.Errorf("creating safety guardrail plugin: %w", err)
	}
	auditRecorder := observability.NewAuditTrailRecorder(logger, redactor)
	auditPlugin, err := auditRecorder.Plugin()
	if err != nil {
		return fmt.Errorf("creating intent-outcome audit plugin: %w", err)
	}
	asyncMemPlugin, err := consolidator.Plugin()
	if err != nil {
		return fmt.Errorf("creating async memory plugin: %w", err)
	}

	if len(args) == 0 {
		args = []string{"console"}
	}

	hasWebUI := slices.Contains(args, "webui")
	if hasWebUI && !cfg.IsProduction() {
		args = ensureLocalDebugAPIFlag(args)
	}

	// Enforce Bearer token authentication + strict per-user authorization in production
	// or headless API mode; when the embedded ADK WebUI SPA is mounted in local development
	// on loopback (127.0.0.1), rely on ADK's loopback/origin guard unless KUBEGUARD_REQUIRE_API_AUTH=true.
	var (
		authenticator authn.Authenticator
		authorizer    authz.Authorizer
	)
	if cfg.RequireAPIAuth || !hasWebUI {
		authenticator = observability.NewBearerTokenAuthenticator(cfg.APIAuthToken, "sre-operator")
		authorizer = observability.StrictUserAuthorizer{}
	}

	launchCfg := &launcher.Config{
		SessionService:   sessionSvc,
		MemoryService:    knowledgeStore,
		AgentLoader:      agent.NewSingleLoader(topo.RootAgent),
		TelemetryOptions: telemetryRuntime.ADKOptions,
		Compaction:       compactionCfg,
		BindHost:         cfg.BindHost,
		AllowedOrigins:   cfg.AllowedOrigins,
		Authenticator:    authenticator,
		Authorizer:       authorizer,
		PluginConfig: runner.PluginConfig{
			// Register auditPlugin before guardrailPlugin so blocked tool intents are
			// captured in the Intent-vs-Outcome audit trail before policy short-circuiting.
			Plugins:      []*plugin.Plugin{auditPlugin, guardrailPlugin, asyncMemPlugin},
			CloseTimeout: 5 * time.Second,
		},
	}
	if err := launchCfg.Validate(); err != nil {
		return fmt.Errorf("validating launcher config: %w", err)
	}

	logger.InfoContext(ctx, "starting kubeguard adk launcher",
		slog.String("environment", cfg.Environment),
		slog.String("cluster_mode", cfg.ClusterMode),
		slog.Bool("offline_demo_llm", cfg.UseOfflineDemoLLM),
		slog.String("fast_model", cfg.FastModel),
		slog.String("reasoning_model", cfg.ReasoningModel),
		slog.String("bind_host", cfg.BindHost),
	)

	l := full.NewLauncher()
	return l.Execute(ctx, launchCfg, args)
}

func ensureLocalDebugAPIFlag(args []string) []string {
	if slices.Contains(args, "-include_debug_api") || slices.Contains(args, "--include_debug_api") {
		return args
	}
	idx := slices.Index(args, "api")
	if idx < 0 {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, args[:idx+1]...)
	out = append(out, "-include_debug_api")
	out = append(out, args[idx+1:]...)
	return out
}

func buildGenAIClientConfig(cfg *config.AppConfig) *genai.ClientConfig {
	timeout := 30 * time.Second
	httpOpts := genai.HTTPOptions{
		Timeout: &timeout,
		RetryOptions: &genai.HTTPRetryOptions{
			Attempts: genai.Ptr(int32(2)),
		},
	}
	if cfg.GeminiAPIKey != "" {
		return &genai.ClientConfig{
			APIKey:      cfg.GeminiAPIKey,
			Backend:     genai.BackendGeminiAPI,
			HTTPOptions: httpOpts,
		}
	}
	if cfg.GCPProjectID != "" {
		return &genai.ClientConfig{
			Project:     cfg.GCPProjectID,
			Location:    cfg.GCPLocation,
			Backend:     genai.BackendVertexAI,
			HTTPOptions: httpOpts,
		}
	}
	return &genai.ClientConfig{HTTPOptions: httpOpts}
}
