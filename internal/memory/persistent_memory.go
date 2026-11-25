package memory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"google.golang.org/genai"
	"gorm.io/gorm"

	adkmemory "google.golang.org/adk/v2/memory"
	"google.golang.org/adk/v2/session"

	"github.com/leo-hoet/kubeguard/internal/privacy"
)

// SRERunbook represents an authoritative incident response playbook stored in the DB.
type SRERunbook struct {
	ID                string    `gorm:"primaryKey;size:32" json:"id"`
	Title             string    `gorm:"size:200;not null" json:"title"`
	SymptomKeywords   string    `gorm:"size:500;not null" json:"symptom_keywords"`
	PreChecks         string    `gorm:"type:text;not null" json:"pre_checks"`
	RemediationSteps  string    `gorm:"type:text;not null" json:"remediation_steps"`
	RequiresHITL      bool      `gorm:"not null" json:"requires_hitl"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// IncidentPostmortemRecord persists PII-scrubbed historical incident summaries across sessions.
type IncidentPostmortemRecord struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AppName         string    `gorm:"index:idx_mem_scope;size:128;not null" json:"app_name"`
	UserID          string    `gorm:"index:idx_mem_scope;size:128;not null" json:"user_id"`
	SessionID       string    `gorm:"index;size:128;not null" json:"session_id"`
	EventID         string    `gorm:"size:128" json:"event_id"`
	Author          string    `gorm:"size:128" json:"author"`
	ServiceKey      string    `gorm:"index;size:128" json:"service_key"`
	SummaryText     string    `gorm:"type:text;not null" json:"summary_text"`
	RecordedAt      time.Time `gorm:"index" json:"recorded_at"`
}

// PersistentKnowledgeStore implements adk/v2/memory.Service + EventAdder on top of GORM
// using strictly parameterized SQL queries, while also serving SRE runbooks and postmortems.
type PersistentKnowledgeStore struct {
	db       *gorm.DB
	redactor privacy.Redactor
}

var (
	_ adkmemory.Service    = (*PersistentKnowledgeStore)(nil)
	_ adkmemory.EventAdder = (*PersistentKnowledgeStore)(nil)
)

// NewPersistentKnowledgeStore migrates runbook & memory tables and seeds default SRE runbooks.
func NewPersistentKnowledgeStore(ctx context.Context, db *gorm.DB, redactor privacy.Redactor) (*PersistentKnowledgeStore, error) {
	if db == nil {
		return nil, errors.New("db must not be nil")
	}
	if err := db.AutoMigrate(&SRERunbook{}, &IncidentPostmortemRecord{}); err != nil {
		return nil, fmt.Errorf("migrating knowledge store tables: %w", err)
	}
	store := &PersistentKnowledgeStore{
		db:       db,
		redactor: redactor,
	}
	if err := store.seedDefaultKnowledge(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// AddSessionToMemory extracts visible text turns from curSession, scrubs PII, and persists them.
func (s *PersistentKnowledgeStore) AddSessionToMemory(ctx context.Context, curSession session.Session) error {
	if curSession == nil {
		return errors.New("memory: session must not be nil")
	}
	var events []*session.Event
	if evIter := curSession.Events(); evIter != nil {
		for ev := range evIter.All() {
			events = append(events, ev)
		}
	}
	return s.AddEventsToMemory(ctx, &adkmemory.AddEventsRequest{
		AppName:   curSession.AppName(),
		UserID:    curSession.UserID(),
		SessionID: curSession.ID(),
		Events:    events,
	})
}

// AddEventsToMemory scrubs and appends session events into the persistent SQL store.
func (s *PersistentKnowledgeStore) AddEventsToMemory(ctx context.Context, req *adkmemory.AddEventsRequest) error {
	if req == nil {
		return errors.New("memory: AddEventsRequest must not be nil")
	}

	for _, ev := range req.Events {
		if ev == nil || ev.Content == nil {
			continue
		}
		var parts []string
		for _, p := range ev.Content.Parts {
			if p != nil && !p.Thought && strings.TrimSpace(p.Text) != "" {
				parts = append(parts, strings.TrimSpace(p.Text))
			}
		}
		if len(parts) == 0 {
			continue
		}
		text := strings.Join(parts, "\n")
		if s.redactor != nil {
			text = s.redactor.RedactText(ctx, text)
		}

		// Parameterized existence check to guarantee idempotency by event_id.
		if ev.ID != "" {
			var count int64
			if err := s.db.WithContext(ctx).Model(&IncidentPostmortemRecord{}).
				Where("app_name = ? AND user_id = ? AND session_id = ? AND event_id = ?",
					req.AppName, req.UserID, req.SessionID, ev.ID).
				Count(&count).Error; err == nil && count > 0 {
				continue
			}
		}

		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		rec := IncidentPostmortemRecord{
			AppName:     req.AppName,
			UserID:      req.UserID,
			SessionID:   req.SessionID,
			EventID:     ev.ID,
			Author:      ev.Author,
			SummaryText: text,
			RecordedAt:  ts,
		}
		if err := s.db.WithContext(ctx).Create(&rec).Error; err != nil {
			return fmt.Errorf("persisting memory event: %w", err)
		}
	}
	return nil
}

// RecordPostmortem stores an explicit, PII-redacted incident postmortem entry.
func (s *PersistentKnowledgeStore) RecordPostmortem(ctx context.Context, appName, userID, sessionID, serviceKey, summary string) error {
	clean := strings.TrimSpace(summary)
	if clean == "" {
		return nil
	}
	if s.redactor != nil {
		clean = s.redactor.RedactText(ctx, clean)
	}
	rec := IncidentPostmortemRecord{
		AppName:     appName,
		UserID:      userID,
		SessionID:   sessionID,
		Author:      "kubeguard_async_consolidator",
		ServiceKey:  strings.TrimSpace(serviceKey),
		SummaryText: clean,
		RecordedAt:  time.Now().UTC(),
	}
	return s.db.WithContext(ctx).Create(&rec).Error
}

// SearchMemory implements adk/v2/memory.Service using parameterized database lookup + keyword ranking.
func (s *PersistentKnowledgeStore) SearchMemory(ctx context.Context, req *adkmemory.SearchRequest) (*adkmemory.SearchResponse, error) {
	if req == nil {
		return nil, errors.New("memory: SearchRequest must not be nil")
	}
	qTokens := tokenizeQuery(req.Query)
	if len(qTokens) == 0 {
		return &adkmemory.SearchResponse{}, nil
	}

	var rows []IncidentPostmortemRecord
	err := s.db.WithContext(ctx).
		Where("app_name = ? AND (user_id = ? OR user_id = ?)", req.AppName, req.UserID, "global-sre").
		Order("recorded_at DESC").
		Limit(200).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("searching persistent memory: %w", err)
	}

	type scored struct {
		score int
		entry adkmemory.Entry
	}
	var matches []scored
	for _, row := range rows {
		score := scoreText(row.ServiceKey+" "+row.SummaryText, qTokens)
		if score == 0 {
			continue
		}
		matches = append(matches, scored{
			score: score,
			entry: adkmemory.Entry{
				ID:        fmt.Sprintf("mem-%d", row.ID),
				Author:    row.Author,
				Timestamp: row.RecordedAt,
				Content:   genai.NewContentFromText(row.SummaryText, genai.RoleModel),
				CustomMetadata: map[string]any{
					"service_key": row.ServiceKey,
					"session_id":  row.SessionID,
				},
			},
		})
	}

	slices.SortStableFunc(matches, func(a, b scored) int {
		return cmp.Compare(b.score, a.score)
	})
	resp := &adkmemory.SearchResponse{}
	for _, m := range matches[:min(len(matches), 10)] {
		resp.Memories = append(resp.Memories, m.entry)
	}
	return resp, nil
}

// SearchRunbooks queries the persistent SRERunbook catalog and ranks playbooks against symptom keywords.
func (s *PersistentKnowledgeStore) SearchRunbooks(ctx context.Context, query string, maxResults int) ([]SRERunbook, error) {
	if maxResults <= 0 || maxResults > 10 {
		maxResults = 5
	}
	var all []SRERunbook
	if err := s.db.WithContext(ctx).Order("id ASC").Find(&all).Error; err != nil {
		return nil, fmt.Errorf("querying runbooks: %w", err)
	}

	qTokens := tokenizeQuery(query)
	if len(qTokens) == 0 {
		return all[:min(len(all), maxResults)], nil
	}

	type scoredRB struct {
		score int
		rb    SRERunbook
	}
	var ranked []scoredRB
	for _, rb := range all {
		haystack := rb.ID + " " + rb.Title + " " + rb.SymptomKeywords + " " + rb.RemediationSteps
		if sc := scoreText(haystack, qTokens); sc > 0 {
			ranked = append(ranked, scoredRB{score: sc, rb: rb})
		}
	}
	slices.SortStableFunc(ranked, func(a, b scoredRB) int {
		return cmp.Compare(b.score, a.score)
	})

	out := make([]SRERunbook, 0, min(len(ranked), maxResults))
	for _, item := range ranked[:min(len(ranked), maxResults)] {
		out = append(out, item.rb)
	}
	return out, nil
}

// SearchPostmortems queries historical incident postmortems matching serviceKey or symptom keywords.
func (s *PersistentKnowledgeStore) SearchPostmortems(ctx context.Context, query string, maxResults int) ([]IncidentPostmortemRecord, error) {
	if maxResults <= 0 || maxResults > 10 {
		maxResults = 5
	}
	var rows []IncidentPostmortemRecord
	if err := s.db.WithContext(ctx).Order("recorded_at DESC").Limit(100).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("querying postmortems: %w", err)
	}
	qTokens := tokenizeQuery(query)
	if len(qTokens) == 0 {
		return rows[:min(len(rows), maxResults)], nil
	}

	type scoredPM struct {
		score int
		pm    IncidentPostmortemRecord
	}
	var ranked []scoredPM
	for _, r := range rows {
		if sc := scoreText(r.ServiceKey+" "+r.SummaryText, qTokens); sc > 0 {
			ranked = append(ranked, scoredPM{score: sc, pm: r})
		}
	}
	slices.SortStableFunc(ranked, func(a, b scoredPM) int {
		return cmp.Compare(b.score, a.score)
	})
	out := make([]IncidentPostmortemRecord, 0, min(len(ranked), maxResults))
	for _, item := range ranked[:min(len(ranked), maxResults)] {
		out = append(out, item.pm)
	}
	return out, nil
}

func (s *PersistentKnowledgeStore) seedDefaultKnowledge(ctx context.Context) error {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	runbooks := []SRERunbook{
		{
			ID:              "RB-101",
			Title:           "Container OOMKilled (Exit Code 137) After Deployment Rollout",
			SymptomKeywords: "oomkilled exit 137 memory limit crashloopbackoff out of memory cgroup buffer",
			PreChecks:       "1. Confirm pod termination reason is OOMKilled (exit 137). 2. Inspect rollout history to verify whether a recent revision increased buffer/heap usage without raising memory limits.",
			RemediationSteps: "1. Do NOT horizontally scale pods—scaling does not fix per-pod cgroup memory exhaustion. 2. Roll back immediately to the previous healthy revision via execute_deployment_rollback (requires HITL approval). 3. File follow-up PR right-sizing memory limits.",
			RequiresHITL:    true,
			UpdatedAt:       now,
		},
		{
			ID:              "RB-204",
			Title:           "CrashLoopBackOff Due to Invalid Environment / ConfigMap Rollout",
			SymptomKeywords: "crashloopbackoff exit 1 config validation env malformed db_pool_max_idle startup error",
			PreChecks:       "1. Inspect crashing pod logs for fatal config validation errors. 2. Compare current revision env summary with the previous healthy revision.",
			RemediationSteps: "1. Execute deployment rollback to the last verified healthy revision (requires HITL approval). 2. Verify ReadyReplicas == DesiredReplicas post-rollback.",
			RequiresHITL:    true,
			UpdatedAt:       now,
		},
		{
			ID:              "RB-309",
			Title:           "Flash-Sale CPU Throttling & Queue Backlog on Healthy Release",
			SymptomKeywords: "cpu throttling high latency queue lag backlog degradedhighlatency scale replicas",
			PreChecks:       "1. Confirm zero restarts and zero fatal errors in pod logs. 2. Confirm rollout has been stable (>24h) so rollback would not reduce load.",
			RemediationSteps: "1. Scale deployment replicas horizontally within [1..50] safety ceiling using scale_deployment_replicas (requires HITL approval) proportional to CPU/backlog ratio.",
			RequiresHITL:    true,
			UpdatedAt:       now,
		},
		{
			ID:              "RB-412",
			Title:           "Sensitive PII or Bearer Token Leak in Application Crash Logs",
			SymptomKeywords: "pii leak jwt bearer token email secret debug log redaction dlp",
			PreChecks:       "1. Verify KubeGuard DLP redactor masked raw tokens/emails in telemetry and memory. 2. Identify whether LOG_LEVEL=debug caused header/payload dumping.",
			RemediationSteps: "1. Roll back debug-logging revision if newly introduced. 2. Instruct security/service team to rotate exposed signing keys or tokens.",
			RequiresHITL:    true,
			UpdatedAt:       now,
		},
	}

	for _, rb := range runbooks {
		if err := s.db.WithContext(ctx).Save(&rb).Error; err != nil {
			return fmt.Errorf("seeding runbook %s: %w", rb.ID, err)
		}
	}

	var pmCount int64
	if err := s.db.WithContext(ctx).Model(&IncidentPostmortemRecord{}).Count(&pmCount).Error; err == nil && pmCount == 0 {
		seedPM := IncidentPostmortemRecord{
			AppName:    "kubeguard",
			UserID:     "global-sre",
			SessionID:  "postmortem-inc-2026-089",
			EventID:    "seed-pm-1",
			Author:     "sre-postmortem-bot",
			ServiceKey: "payments/checkout-api",
			SummaryText: "INC-2026-089 (payments/checkout-api): Previous OOMKilled incident occurred when batch buffer exceeded 128Mi under a 256Mi container memory limit; rolling back to the prior revision restored 100% availability in 35s, and debug auth logging also required JWT key rotation.",
			RecordedAt: now,
		}
		if err := s.db.WithContext(ctx).Create(&seedPM).Error; err != nil {
			return fmt.Errorf("seeding historical postmortem: %w", err)
		}
	}
	return nil
}

func tokenizeQuery(q string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, tok := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '-' && r != '_' && r != '/'
	}) {
		if len(tok) < 2 {
			continue
		}
		if _, exists := seen[tok]; !exists {
			seen[tok] = struct{}{}
			out = append(out, tok)
		}
	}
	return out
}

func scoreText(haystack string, tokens []string) int {
	lower := strings.ToLower(haystack)
	score := 0
	for _, tok := range tokens {
		if strings.Contains(lower, tok) {
			score++
		}
	}
	return score
}
