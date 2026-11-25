// Package config loads runtime configuration and secrets using Google Cloud
// Secret Manager with fail-closed production semantics and zero hardcoded keys.
package config

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// SecretFetcher abstracts Google Cloud Secret Manager so secret loading can be
// verified deterministically in unit tests without live network calls.
type SecretFetcher interface {
	FetchSecret(ctx context.Context, projectID, secretID string) (string, error)
	Close() error
}

// GCPSecretManagerFetcher retrieves secret versions from Google Cloud Secret Manager.
type GCPSecretManagerFetcher struct {
	client *secretmanager.Client
}

// NewGCPSecretManagerFetcher creates a Secret Manager client using Application Default Credentials.
func NewGCPSecretManagerFetcher(ctx context.Context) (*GCPSecretManagerFetcher, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating secret manager client: %w", err)
	}
	return &GCPSecretManagerFetcher{client: client}, nil
}

// FetchSecret accesses the "latest" version of secretID in projectID.
func (f *GCPSecretManagerFetcher) FetchSecret(ctx context.Context, projectID, secretID string) (string, error) {
	if projectID == "" || secretID == "" {
		return "", errors.New("projectID and secretID must be non-empty")
	}
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	resp, err := f.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return "", fmt.Errorf("accessing secret %q: %w", secretID, err)
	}
	if resp.GetPayload() == nil {
		return "", fmt.Errorf("secret %q returned empty payload", secretID)
	}
	return strings.TrimSpace(string(resp.GetPayload().GetData())), nil
}

// Close releases the underlying gRPC connection.
func (f *GCPSecretManagerFetcher) Close() error {
	if f == nil || f.client == nil {
		return nil
	}
	return f.client.Close()
}

// AppConfig holds validated runtime settings and resolved credentials.
type AppConfig struct {
	Environment       string
	GCPProjectID      string
	GCPLocation       string
	FastModel         string
	ReasoningModel    string
	ClusterMode       string
	KubeconfigPath    string
	SQLitePath        string
	PostgresDSN       string
	GeminiAPIKey      string
	APIAuthToken      string
	BindHost          string
	Port              int
	AllowedOrigins    []string
	EnableCloudDLP    bool
	EnableCloudTrace  bool
	UseOfflineDemoLLM bool
	RequireAPIAuth    bool
}

// IsProduction reports whether KubeGuard is running in strict production mode.
func (c AppConfig) IsProduction() bool {
	return strings.EqualFold(c.Environment, "production")
}

// Load resolves configuration from environment variables and Google Cloud Secret Manager.
// In production mode, missing required secrets fail closed immediately.
// In development/test mode, a local .env file is loaded automatically when present, and
// missing API auth tokens fall back to a CSPRNG ephemeral secret.
func Load(ctx context.Context, logger *slog.Logger, fetcher SecretFetcher) (*AppConfig, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if !strings.EqualFold(strings.TrimSpace(os.Getenv("KUBEGUARD_ENV")), "production") {
		loadDotEnvIfPresent(".env")
	}

	env := strings.ToLower(strings.TrimSpace(envOr("KUBEGUARD_ENV", "development")))
	projectID := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT"))

	// Lazily initialize Secret Manager client when running in a GCP project and no test double was injected.
	var ownedFetcher SecretFetcher
	if fetcher == nil && projectID != "" {
		smFetcher, err := NewGCPSecretManagerFetcher(ctx)
		if err != nil {
			if env == "production" {
				return nil, fmt.Errorf("initializing Secret Manager in production: %w", err)
			}
			logger.WarnContext(ctx, "Secret Manager unavailable; falling back to local environment variables",
				slog.String("reason", err.Error()))
		} else {
			fetcher = smFetcher
			ownedFetcher = smFetcher
		}
	}
	if ownedFetcher != nil {
		defer func() { _ = ownedFetcher.Close() }()
	}

	geminiKey, err := resolveSecret(ctx, fetcher, projectID,
		os.Getenv("GEMINI_API_KEY_SECRET_ID"),
		"GOOGLE_API_KEY", "GEMINI_API_KEY")
	if err != nil && env == "production" {
		return nil, fmt.Errorf("resolving Gemini API key: %w", err)
	}

	postgresDSN, err := resolveSecret(ctx, fetcher, projectID,
		os.Getenv("DATABASE_DSN_SECRET_ID"),
		"KUBEGUARD_POSTGRES_DSN")
	if err != nil && env == "production" {
		return nil, fmt.Errorf("resolving database DSN: %w", err)
	}

	apiToken, err := resolveSecret(ctx, fetcher, projectID,
		os.Getenv("API_AUTH_TOKEN_SECRET_ID"),
		"KUBEGUARD_API_TOKEN")
	if err != nil && env == "production" {
		return nil, fmt.Errorf("resolving API auth token: %w", err)
	}

	if env == "production" {
		if geminiKey == "" && projectID == "" {
			return nil, errors.New("production requires GOOGLE_API_KEY via Secret Manager or Vertex AI project configuration")
		}
		if apiToken == "" {
			return nil, errors.New("production requires KUBEGUARD_API_TOKEN from Secret Manager; refusing to start unauthenticated")
		}
	} else if apiToken == "" {
		ephemeral, genErr := generateCSPRNGHex(32)
		if genErr != nil {
			return nil, fmt.Errorf("generating ephemeral auth token: %w", genErr)
		}
		apiToken = ephemeral
		logger.WarnContext(ctx, "generated ephemeral CSPRNG API auth token for non-production instance",
			slog.Bool("instance_isolated", true),
			slog.String("environment", env))
	}

	defaultHost := "127.0.0.1"
	if env == "production" {
		defaultHost = "0.0.0.0"
	}
	bindHost := strings.TrimSpace(envOr("KUBEGUARD_BIND_HOST", defaultHost))
	if env == "test" && (bindHost == "0.0.0.0" || bindHost == "::" || bindHost == "") {
		bindHost = "127.0.0.1"
	}

	port := 8080
	if rawPort := strings.TrimSpace(envOr("PORT", os.Getenv("KUBEGUARD_PORT"))); rawPort != "" {
		parsed, parseErr := strconv.Atoi(rawPort)
		if parseErr != nil || parsed < 1 || parsed > 65535 {
			return nil, fmt.Errorf("invalid port %q", rawPort)
		}
		port = parsed
	}

	originsRaw := envOr("KUBEGUARD_ALLOWED_ORIGINS", fmt.Sprintf("http://127.0.0.1:%d,http://localhost:%d", port, port))
	var origins []string
	for _, part := range strings.Split(originsRaw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || trimmed == "*" {
			// Wildcard CORS origins are strictly rejected by security policy.
			continue
		}
		origins = append(origins, trimmed)
	}

	enableCloud := projectID != "" && envOr("KUBEGUARD_DISABLE_GCP_APIS", "false") != "true"
	useOffline := env != "production" && (strings.EqualFold(os.Getenv("KUBEGUARD_OFFLINE_DEMO"), "true") || (geminiKey == "" && projectID == ""))
	requireAPIAuth := env == "production" || strings.EqualFold(os.Getenv("KUBEGUARD_REQUIRE_API_AUTH"), "true")

	return &AppConfig{
		Environment:       env,
		GCPProjectID:      projectID,
		GCPLocation:       envOr("GOOGLE_CLOUD_LOCATION", "us-central1"),
		FastModel:         envOr("KUBEGUARD_FAST_MODEL", "gemini-4-hydrogen"),
		ReasoningModel:    envOr("KUBEGUARD_REASONING_MODEL", "gemini-4-neon"),
		ClusterMode:       strings.ToLower(envOr("KUBEGUARD_CLUSTER_MODE", "simulated")),
		KubeconfigPath:    strings.TrimSpace(os.Getenv("KUBECONFIG")),
		SQLitePath:        envOr("KUBEGUARD_SQLITE_PATH", "kubeguard_sessions.db"),
		PostgresDSN:       postgresDSN,
		GeminiAPIKey:      geminiKey,
		APIAuthToken:      apiToken,
		BindHost:          bindHost,
		Port:              port,
		AllowedOrigins:    origins,
		EnableCloudDLP:    enableCloud,
		EnableCloudTrace:  enableCloud,
		UseOfflineDemoLLM: useOffline,
		RequireAPIAuth:    requireAPIAuth,
	}, nil
}

// loadDotEnvIfPresent parses simple KEY=VALUE lines from path without overriding
// environment variables already exported in the caller's shell.
func loadDotEnvIfPresent(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		if key != "" && os.Getenv(key) == "" && val != "" {
			_ = os.Setenv(key, val)
		}
	}
}

func resolveSecret(ctx context.Context, fetcher SecretFetcher, projectID, secretID string, envKeys ...string) (string, error) {
	if fetcher != nil && projectID != "" && strings.TrimSpace(secretID) != "" {
		val, err := fetcher.FetchSecret(ctx, projectID, strings.TrimSpace(secretID))
		if err != nil {
			return "", err
		}
		if val != "" {
			return val, nil
		}
	}
	for _, k := range envKeys {
		if val := strings.TrimSpace(os.Getenv(k)); val != "" {
			return val, nil
		}
	}
	return "", nil
}

func generateCSPRNGHex(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
