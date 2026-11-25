package observability

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/tool"

	"github.com/leo-hoet/kubeguard/internal/privacy"
)

// AuditRecord captures paired pre-execution Intent and post-execution Outcome telemetry.
type AuditRecord struct {
	Stage          string         `json:"stage"` // "intent" | "outcome"
	InvocationID   string         `json:"invocation_id"`
	SessionID      string         `json:"session_id"`
	AgentName      string         `json:"agent_name"`
	ToolName       string         `json:"tool_name"`
	FunctionCallID string         `json:"function_call_id"`
	IntendedArgs   map[string]any `json:"intended_args,omitempty"`
	ActualOutcome  map[string]any `json:"actual_outcome,omitempty"`
	OutcomeStatus  string         `json:"outcome_status,omitempty"`
	DurationMs     int64          `json:"duration_ms,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

type inflightCall struct {
	startedAt time.Time
	span      trace.Span
}

// AuditTrailRecorder stores structured Intent/Outcome records and emits JSON logs + OTel spans.
type AuditTrailRecorder struct {
	logger   *slog.Logger
	redactor privacy.Redactor

	mu       sync.Mutex
	inflight map[string]inflightCall
	records  []AuditRecord
}

// NewAuditTrailRecorder creates a thread-safe Intent-vs-Outcome recorder.
func NewAuditTrailRecorder(logger *slog.Logger, redactor privacy.Redactor) *AuditTrailRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditTrailRecorder{
		logger:   logger,
		redactor: redactor,
		inflight: make(map[string]inflightCall),
	}
}

// Records returns a snapshot of recorded Intent and Outcome entries (useful for automated evals).
func (r *AuditTrailRecorder) Records() []AuditRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AuditRecord, len(r.records))
	copy(out, r.records)
	return out
}

// Plugin returns an ADK v2 lifecycle Plugin that logs both intended actions before tool
// execution and actual outcomes afterward, correlated by invocation_id and function_call_id.
func (r *AuditTrailRecorder) Plugin() (*plugin.Plugin, error) {
	return plugin.New(plugin.Config{
		Name: "kubeguard_intent_outcome_audit",
		BeforeToolCallback: func(ctx agent.Context, t tool.Tool, args map[string]any) (map[string]any, error) {
			sanitizedArgs := sanitizeMap(ctx, r.redactor, args)
			callKey := fmt.Sprintf("%s:%s:%s", ctx.InvocationID(), ctx.FunctionCallID(), t.Name())

			_, span := Tracer("audit").Start(ctx, "kubeguard.tool."+t.Name(),
				trace.WithAttributes(
					attribute.String("kubeguard.invocation_id", ctx.InvocationID()),
					attribute.String("kubeguard.session_id", ctx.SessionID()),
					attribute.String("kubeguard.agent_name", ctx.AgentName()),
					attribute.String("kubeguard.tool_name", t.Name()),
					attribute.String("kubeguard.function_call_id", ctx.FunctionCallID()),
				),
			)

			now := time.Now().UTC()
			rec := AuditRecord{
				Stage:          "intent",
				InvocationID:   ctx.InvocationID(),
				SessionID:      ctx.SessionID(),
				AgentName:      ctx.AgentName(),
				ToolName:       t.Name(),
				FunctionCallID: ctx.FunctionCallID(),
				IntendedArgs:   sanitizedArgs,
				Timestamp:      now,
			}

			r.mu.Lock()
			r.inflight[callKey] = inflightCall{startedAt: now, span: span}
			r.records = append(r.records, rec)
			r.mu.Unlock()

			r.logger.InfoContext(ctx, "tool_execution_intent",
				slog.String("audit_stage", "intent"),
				slog.String("invocation_id", rec.InvocationID),
				slog.String("session_id", rec.SessionID),
				slog.String("agent_name", rec.AgentName),
				slog.String("tool_name", rec.ToolName),
				slog.String("function_call_id", rec.FunctionCallID),
				slog.Any("intended_action_args", sanitizedArgs),
			)
			return nil, nil
		},
		AfterToolCallback: func(ctx agent.Context, t tool.Tool, args, result map[string]any, toolErr error) (map[string]any, error) {
			sanitizedArgs := sanitizeMap(ctx, r.redactor, args)
			sanitizedResult := sanitizeMap(ctx, r.redactor, result)
			callKey := fmt.Sprintf("%s:%s:%s", ctx.InvocationID(), ctx.FunctionCallID(), t.Name())

			now := time.Now().UTC()
			var durationMs int64
			var span trace.Span

			r.mu.Lock()
			if inf, ok := r.inflight[callKey]; ok {
				durationMs = now.Sub(inf.startedAt).Milliseconds()
				span = inf.span
				delete(r.inflight, callKey)
			}
			status := classifyOutcomeStatus(sanitizedResult, toolErr)
			rec := AuditRecord{
				Stage:          "outcome",
				InvocationID:   ctx.InvocationID(),
				SessionID:      ctx.SessionID(),
				AgentName:      ctx.AgentName(),
				ToolName:       t.Name(),
				FunctionCallID: ctx.FunctionCallID(),
				IntendedArgs:   sanitizedArgs,
				ActualOutcome:  sanitizedResult,
				OutcomeStatus:  status,
				DurationMs:     durationMs,
				Timestamp:      now,
			}
			r.records = append(r.records, rec)
			r.mu.Unlock()

			if span != nil {
				span.SetAttributes(
					attribute.String("kubeguard.outcome_status", status),
					attribute.Int64("kubeguard.duration_ms", durationMs),
				)
				if toolErr != nil {
					span.RecordError(toolErr)
					span.SetStatus(codes.Error, "tool execution error")
				} else {
					span.SetStatus(codes.Ok, status)
				}
				span.End()
			}

			r.logger.InfoContext(ctx, "tool_execution_outcome",
				slog.String("audit_stage", "outcome"),
				slog.String("invocation_id", rec.InvocationID),
				slog.String("session_id", rec.SessionID),
				slog.String("agent_name", rec.AgentName),
				slog.String("tool_name", rec.ToolName),
				slog.String("function_call_id", rec.FunctionCallID),
				slog.String("outcome_status", status),
				slog.Int64("duration_ms", durationMs),
				slog.Any("actual_outcome", sanitizedResult),
			)
			return nil, nil
		},
	})
}

func classifyOutcomeStatus(result map[string]any, err error) string {
	if err != nil {
		return "error"
	}
	if s, ok := result["status"].(string); ok && s != "" {
		return s
	}
	return "succeeded"
}

func sanitizeMap(ctx agent.Context, redactor privacy.Redactor, m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	if redactor == nil {
		return m
	}
	if out, ok := redactor.RedactAny(ctx, m).(map[string]any); ok {
		return out
	}
	return m
}
