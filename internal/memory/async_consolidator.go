package memory

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/adk/v2/agent"
	adkmemory "google.golang.org/adk/v2/memory"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/session"

	"github.com/leo-hoet/kubeguard/internal/observability"
	"github.com/leo-hoet/kubeguard/internal/privacy"
)

// ConsolidationTask represents a session snapshot queued for background memory persistence.
type ConsolidationTask struct {
	AppName   string
	UserID    string
	SessionID string
	Events    []*session.Event
	TraceCtx  trace.SpanContext
}

// AsyncMemoryConsolidator executes expensive PII redaction and persistent memory
// indexing on a background worker pool so agent turns never block UI responsiveness.
type AsyncMemoryConsolidator struct {
	store     *PersistentKnowledgeStore
	redactor  privacy.Redactor
	logger    *slog.Logger
	queue     chan ConsolidationTask
	wg        sync.WaitGroup
	closeOnce sync.Once
	processed atomic.Int64
	dropped   atomic.Int64
}

// NewAsyncMemoryConsolidator starts workerCount background goroutines draining a buffered queue.
func NewAsyncMemoryConsolidator(store *PersistentKnowledgeStore, redactor privacy.Redactor, logger *slog.Logger, queueSize, workerCount int) *AsyncMemoryConsolidator {
	if logger == nil {
		logger = slog.Default()
	}
	if queueSize <= 0 {
		queueSize = 64
	}
	if workerCount <= 0 {
		workerCount = 2
	}
	c := &AsyncMemoryConsolidator{
		store:    store,
		redactor: redactor,
		logger:   logger,
		queue:    make(chan ConsolidationTask, queueSize),
	}
	for range workerCount {
		c.wg.Add(1)
		go c.worker()
	}
	return c
}

// Enqueue submits a memory consolidation job without blocking the caller's UI/HTTP turn.
func (c *AsyncMemoryConsolidator) Enqueue(task ConsolidationTask) bool {
	if c == nil || c.store == nil {
		return false
	}
	select {
	case c.queue <- task:
		return true
	default:
		c.dropped.Add(1)
		c.logger.Warn("async memory queue full; dropping background consolidation task",
			slog.String("session_id", task.SessionID))
		return false
	}
}

// ProcessedCount returns the total number of completed background memory consolidations.
func (c *AsyncMemoryConsolidator) ProcessedCount() int64 {
	if c == nil {
		return 0
	}
	return c.processed.Load()
}

// Plugin builds an ADK AfterRunCallback plugin that snapshots session events at the end
// of each turn and dispatches consolidation asynchronously off the critical path.
func (c *AsyncMemoryConsolidator) Plugin() (*plugin.Plugin, error) {
	return plugin.New(plugin.Config{
		Name: "kubeguard_async_memory_consolidator",
		AfterRunCallback: func(ctx agent.InvocationContext) {
			sess := ctx.Session()
			if sess == nil {
				return
			}
			var snapshot []*session.Event
			if evs := sess.Events(); evs != nil {
				for ev := range evs.All() {
					if ev != nil {
						snapshot = append(snapshot, ev)
					}
				}
			}
			if len(snapshot) == 0 {
				return
			}
			c.Enqueue(ConsolidationTask{
				AppName:   sess.AppName(),
				UserID:    sess.UserID(),
				SessionID: sess.ID(),
				Events:    snapshot,
				TraceCtx:  trace.SpanContextFromContext(ctx),
			})
		},
		CloseFunc: func() error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return c.Shutdown(shutdownCtx)
		},
	})
}

// Shutdown drains all queued background tasks or exits when ctx expires.
func (c *AsyncMemoryConsolidator) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.queue)
	})
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *AsyncMemoryConsolidator) worker() {
	defer c.wg.Done()
	for task := range c.queue {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if task.TraceCtx.IsValid() {
			bgCtx = trace.ContextWithRemoteSpanContext(bgCtx, task.TraceCtx)
		}
		spanCtx, span := observability.Tracer("async_memory").Start(bgCtx, "kubeguard.memory.async_consolidate",
			trace.WithAttributes(
				attribute.String("kubeguard.session_id", task.SessionID),
				attribute.Int("kubeguard.event_count", len(task.Events)),
			),
		)

		err := c.consolidate(spanCtx, task)
		if err != nil {
			span.RecordError(err)
			c.logger.ErrorContext(spanCtx, "async memory consolidation failed",
				slog.String("session_id", task.SessionID),
				slog.String("error", err.Error()))
		} else {
			c.processed.Add(1)
			c.logger.InfoContext(spanCtx, "async memory consolidation completed",
				slog.String("session_id", task.SessionID),
				slog.Int("events_indexed", len(task.Events)))
		}
		span.End()
		cancel()
	}
}

func (c *AsyncMemoryConsolidator) consolidate(ctx context.Context, task ConsolidationTask) error {
	if err := c.store.AddEventsToMemory(ctx, &adkmemory.AddEventsRequest{
		AppName:   task.AppName,
		UserID:    task.UserID,
		SessionID: task.SessionID,
		Events:    task.Events,
	}); err != nil {
		return err
	}

	// Also synthesize a compact postmortem note when an incident remediation completed in the turn.
	var summaryLines []string
	for _, ev := range task.Events {
		if ev == nil || ev.Content == nil {
			continue
		}
		for _, p := range ev.Content.Parts {
			if p != nil && !p.Thought && strings.TrimSpace(p.Text) != "" {
				text := strings.TrimSpace(p.Text)
				if c.redactor != nil {
					text = c.redactor.RedactText(ctx, text)
				}
				summaryLines = append(summaryLines, text)
			}
		}
	}
	if len(summaryLines) > 0 {
		joined := strings.Join(summaryLines, " | ")
		if len(joined) > 600 {
			joined = joined[:600]
		}
		if strings.Contains(strings.ToLower(joined), "rollback") || strings.Contains(strings.ToLower(joined), "scale") {
			_ = c.store.RecordPostmortem(ctx, task.AppName, task.UserID, task.SessionID, "session:"+task.SessionID, joined)
		}
	}
	return nil
}
