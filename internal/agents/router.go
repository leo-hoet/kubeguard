package agents

import (
	"context"
	"iter"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/adk/v2/model"

	"github.com/leo-hoet/kubeguard/internal/observability"
)

var deepReasoningSignals = []string{
	"crashloop",
	"oomkilled",
	"out of memory",
	"exit 137",
	"incident",
	"outage",
	"rollback",
	"roll back",
	"remediate",
	"fix",
	"root cause",
	"triage",
	"latency",
	"throttling",
	"scale",
	"degraded",
	"failing",
}

// RouteStats tracks how many LLM invocations were routed to the fast vs. deep reasoning tiers.
type RouteStats struct {
	FastCalls      int64
	ReasoningCalls int64
}

// StrategicModelRouter implements adk/v2/model.LLM and dynamically dispatches requests
// between a low-latency model (e.g. gemini-4-hydrogen / gemini-3.8-flash) for simple status
// queries and a frontier reasoning model (e.g. gemini-4-neon) for complex incident analysis.
type StrategicModelRouter struct {
	name           string
	fastModel      model.LLM
	reasoningModel model.LLM
	logger         *slog.Logger

	fastCount      atomic.Int64
	reasoningCount atomic.Int64
}

var _ model.LLM = (*StrategicModelRouter)(nil)

// NewStrategicModelRouter creates a complexity-aware model router across Flash and Pro tiers.
func NewStrategicModelRouter(name string, fastModel, reasoningModel model.LLM, logger *slog.Logger) *StrategicModelRouter {
	if name == "" {
		name = "kubeguard-strategic-router"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &StrategicModelRouter{
		name:           name,
		fastModel:      fastModel,
		reasoningModel: reasoningModel,
		logger:         logger,
	}
}

// Name returns the router identifier registered with ADK.
func (r *StrategicModelRouter) Name() string {
	return r.name
}

// Stats returns cumulative routing counters for observability and evaluation assertions.
func (r *StrategicModelRouter) Stats() RouteStats {
	return RouteStats{
		FastCalls:      r.fastCount.Load(),
		ReasoningCalls: r.reasoningCount.Load(),
	}
}

// GenerateContent inspects conversation context, routes to either fastModel or reasoningModel,
// records an OpenTelemetry routing span + structured JSON log, and streams responses.
func (r *StrategicModelRouter) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	target, tier, reason := r.selectModel(req)
	if tier == "reasoning" {
		r.reasoningCount.Add(1)
	} else {
		r.fastCount.Add(1)
	}

	spanCtx, span := observability.Tracer("model_router").Start(ctx, "kubeguard.model_router.dispatch",
		trace.WithAttributes(
			attribute.String("kubeguard.router.tier", tier),
			attribute.String("kubeguard.router.selected_model", target.Name()),
			attribute.String("kubeguard.router.reason", reason),
		),
	)

	r.logger.InfoContext(spanCtx, "strategic_model_routed",
		slog.String("selected_tier", tier),
		slog.String("selected_model", target.Name()),
		slog.String("routing_reason", reason),
	)

	// Ensure LLMRequest.Model matches the chosen underlying model name.
	clonedReq := *req
	clonedReq.Model = target.Name()

	return func(yield func(*model.LLMResponse, error) bool) {
		defer span.End()
		callCtx := spanCtx
		var cancel context.CancelFunc
		if tier == "reasoning" {
			callCtx, cancel = context.WithTimeout(spanCtx, 25*time.Second)
			defer cancel()
		}
		yieldedAny := false
		for resp, err := range target.GenerateContent(callCtx, &clonedReq, stream) {
			if err != nil && !yieldedAny && tier == "reasoning" && ctx.Err() == nil && isTierEntitlementOrQuotaError(err) {
				r.logger.WarnContext(spanCtx, "reasoning model tier timed out or unavailable; falling back to fast model tier",
					slog.String("primary_model", target.Name()),
					slog.String("fallback_model", r.fastModel.Name()),
					slog.String("reason", err.Error()),
				)
				fallbackReq := *req
				fallbackReq.Model = r.fastModel.Name()
				for fbResp, fbErr := range r.fastModel.GenerateContent(spanCtx, &fallbackReq, stream) {
					if fbErr != nil {
						span.RecordError(fbErr)
					}
					if !yield(fbResp, fbErr) {
						return
					}
				}
				return
			}
			if err != nil {
				span.RecordError(err)
			} else {
				yieldedAny = true
			}
			if !yield(resp, err) {
				return
			}
		}
	}
}

// NewResilientReasoningModel wraps a frontier reasoning model (e.g. gemini-4-neon) with
// automatic 25s timeout & fallback to fastFallback (e.g. gemini-4-hydrogen) when a backend
// stalls on prefill (504 DEADLINE_EXCEEDED), hits quota (429), or lacks tier entitlement.
func NewResilientReasoningModel(primary, fastFallback model.LLM, logger *slog.Logger) model.LLM {
	if primary == nil {
		return fastFallback
	}
	if fastFallback == nil || primary.Name() == fastFallback.Name() {
		return primary
	}
	return &resilientTierModel{
		primary:  primary,
		fallback: fastFallback,
		logger:   logger,
	}
}

type resilientTierModel struct {
	primary  model.LLM
	fallback model.LLM
	logger   *slog.Logger
}

func (m *resilientTierModel) Name() string {
	return m.primary.Name()
}

func (m *resilientTierModel) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		attemptCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()

		yieldedAny := false
		for resp, err := range m.primary.GenerateContent(attemptCtx, req, stream) {
			if err != nil && !yieldedAny && ctx.Err() == nil && isTierEntitlementOrQuotaError(err) {
				if m.logger != nil {
					m.logger.WarnContext(ctx, "primary reasoning model timed out or unavailable; retrying with fast model tier",
						slog.String("primary_model", m.primary.Name()),
						slog.String("fallback_model", m.fallback.Name()),
						slog.String("reason", err.Error()),
					)
				}
				fbReq := *req
				fbReq.Model = m.fallback.Name()
				for fbResp, fbErr := range m.fallback.GenerateContent(ctx, &fbReq, stream) {
					if !yield(fbResp, fbErr) {
						return
					}
				}
				return
			}
			if err == nil {
				yieldedAny = true
			}
			if !yield(resp, err) {
				return
			}
		}
	}
}

func isTierEntitlementOrQuotaError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resource_exhausted") ||
		strings.Contains(msg, "permission_denied") ||
		strings.Contains(msg, "deadline_exceeded") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "service unavailable") ||
		strings.Contains(msg, "not_found") ||
		strings.Contains(msg, "429") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "404") ||
		strings.Contains(msg, "503") ||
		strings.Contains(msg, "504") ||
		strings.Contains(msg, "billing") ||
		strings.Contains(msg, "free tier")
}

func (r *StrategicModelRouter) selectModel(req *model.LLMRequest) (selected model.LLM, tier string, reason string) {
	if req == nil || len(req.Contents) == 0 {
		return r.fastModel, "fast", "empty_request_default_fast"
	}

	// Inspect the latest user/tool turn for incident severity or multi-step tool orchestration.
	for i := len(req.Contents) - 1; i >= max(0, len(req.Contents)-3); i-- {
		c := req.Contents[i]
		if c == nil {
			continue
		}
		for _, p := range c.Parts {
			if p == nil {
				continue
			}
			if p.FunctionResponse != nil {
				return r.reasoningModel, "reasoning", "tool_result_synthesis"
			}
			lower := strings.ToLower(p.Text)
			for _, kw := range deepReasoningSignals {
				if strings.Contains(lower, kw) {
					return r.reasoningModel, "reasoning", "incident_signal:" + kw
				}
			}
			if len(lower) > 280 {
				return r.reasoningModel, "reasoning", "complex_long_prompt"
			}
		}
	}
	return r.fastModel, "fast", "lightweight_status_or_discovery_query"
}
