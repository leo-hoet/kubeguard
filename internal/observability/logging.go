// Package observability provides structured Cloud Logging JSON output with
// automatic PII scrubbing, OpenTelemetry distributed tracing, Intent-vs-Outcome
// audit plugins, and hardened HTTP security middleware.
package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"go.opentelemetry.io/otel/trace"

	"github.com/leo-hoet/kubeguard/internal/privacy"
)

// NewStructuredLogger builds a JSON slog.Logger compatible with Google Cloud Logging
// that automatically redacts PII/secrets and injects OpenTelemetry trace/span IDs.
func NewStructuredLogger(w io.Writer, level slog.Level, projectID string, redactor privacy.Redactor) *slog.Logger {
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.LevelKey:
				a.Key = "severity"
			case slog.MessageKey:
				a.Key = "message"
			case slog.TimeKey:
				a.Key = "timestamp"
			}
			return a
		},
	})
	return slog.New(&redactingTraceHandler{
		inner:     base,
		projectID: projectID,
		redactor:  redactor,
	})
}

type redactingTraceHandler struct {
	inner     slog.Handler
	projectID string
	redactor  privacy.Redactor
}

func (h *redactingTraceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingTraceHandler) Handle(ctx context.Context, rec slog.Record) error {
	cleanMsg := rec.Message
	if h.redactor != nil {
		cleanMsg = h.redactor.RedactText(ctx, cleanMsg)
	}
	cloned := slog.NewRecord(rec.Time, rec.Level, cleanMsg, rec.PC)

	if spanCtx := trace.SpanContextFromContext(ctx); spanCtx.IsValid() {
		traceVal := spanCtx.TraceID().String()
		if h.projectID != "" {
			traceVal = fmt.Sprintf("projects/%s/traces/%s", h.projectID, traceVal)
		}
		cloned.AddAttrs(
			slog.String("logging.googleapis.com/trace", traceVal),
			slog.String("logging.googleapis.com/spanId", spanCtx.SpanID().String()),
			slog.Bool("logging.googleapis.com/trace_sampled", spanCtx.IsSampled()),
		)
	}

	rec.Attrs(func(a slog.Attr) bool {
		cloned.AddAttrs(h.sanitizeAttr(ctx, a))
		return true
	})

	return h.inner.Handle(ctx, cloned)
}

func (h *redactingTraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = h.sanitizeAttr(context.Background(), a)
	}
	return &redactingTraceHandler{
		inner:     h.inner.WithAttrs(sanitized),
		projectID: h.projectID,
		redactor:  h.redactor,
	}
}

func (h *redactingTraceHandler) WithGroup(name string) slog.Handler {
	return &redactingTraceHandler{
		inner:     h.inner.WithGroup(name),
		projectID: h.projectID,
		redactor:  h.redactor,
	}
}

func (h *redactingTraceHandler) sanitizeAttr(ctx context.Context, a slog.Attr) slog.Attr {
	if h.redactor == nil {
		return a
	}
	val := a.Value.Resolve()
	switch val.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.redactor.RedactText(ctx, val.String()))
	case slog.KindGroup:
		groupAttrs := val.Group()
		cleaned := make([]any, len(groupAttrs))
		for i, ga := range groupAttrs {
			cleaned[i] = h.sanitizeAttr(ctx, ga)
		}
		return slog.Group(a.Key, cleaned...)
	case slog.KindAny:
		return slog.Any(a.Key, h.redactor.RedactAny(ctx, val.Any()))
	default:
		return a
	}
}
