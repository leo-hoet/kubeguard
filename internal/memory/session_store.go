// Package memory implements persistent session storage, ADK history compaction,
// SRE runbook/postmortem retrieval, and non-blocking async memory consolidation.
package memory

import (
	"fmt"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/compaction"
	"google.golang.org/adk/v2/session/database"
)

// OpenPersistentDB opens a GORM connection backed by Cloud SQL PostgreSQL (when postgresDSN
// is set) or pure-Go SQLite locally, using silent GORM logging so SQL internals never leak.
func OpenPersistentDB(postgresDSN, sqlitePath string) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	if dsn := strings.TrimSpace(postgresDSN); dsn != "" {
		db, err := gorm.Open(postgres.Open(dsn), gormCfg)
		if err != nil {
			return nil, fmt.Errorf("connecting to postgresql session store: %w", err)
		}
		return db, nil
	}

	path := strings.TrimSpace(sqlitePath)
	if path == "" {
		path = "file::memory:?cache=shared"
	}
	db, err := gorm.Open(sqlite.Open(path), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite session store: %w", err)
	}
	// Serialize SQLite writer connections and enable WAL + busy_timeout so concurrent
	// ParallelAgent branches and AsyncMemoryConsolidator background writes never hit SQLITE_BUSY.
	if sqlDB, sqlErr := db.DB(); sqlErr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	_ = db.Exec("PRAGMA journal_mode=WAL;")
	_ = db.Exec("PRAGMA busy_timeout=5000;")
	return db, nil
}

// NewPersistentSessionService initializes ADK v2's relational database session.Service
// and runs schema AutoMigrate on startup.
func NewPersistentSessionService(db *gorm.DB) (session.Service, error) {
	svc, err := database.NewSessionServiceFromDB(db)
	if err != nil {
		return nil, fmt.Errorf("creating database session service: %w", err)
	}
	if err := database.AutoMigrate(svc); err != nil {
		return nil, fmt.Errorf("migrating adk session tables: %w", err)
	}
	return svc, nil
}

// NewCompactionConfig configures ADK v2 history compaction combining sliding-window
// turn summarization with token-threshold tail retention to prevent context bloat.
func NewCompactionConfig(fastSummarizerModel model.LLM) (*compaction.Config, error) {
	if fastSummarizerModel == nil {
		return nil, fmt.Errorf("fastSummarizerModel is required for history compaction")
	}
	summarizer, err := compaction.NewLLMSummarizer(compaction.LLMSummarizerConfig{
		Model: fastSummarizerModel,
	})
	if err != nil {
		return nil, fmt.Errorf("creating compaction summarizer: %w", err)
	}
	cfg := &compaction.Config{
		Summarizer:         summarizer,
		CompactionInterval: 8,
		OverlapSize:        1,
		TokenThreshold:     24_000,
		EventRetentionSize: 5,
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating compaction config: %w", err)
	}
	return cfg, nil
}
