package config

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

type stubSecretFetcher struct {
	secrets map[string]string
}

func (s *stubSecretFetcher) FetchSecret(_ context.Context, _, secretID string) (string, error) {
	return s.secrets[secretID], nil
}

func (s *stubSecretFetcher) Close() error { return nil }

func TestLoadSecretManagerAndFailClosedProduction(t *testing.T) {
	ctx := context.Background()
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))

	t.Run("production fails closed without auth token", func(t *testing.T) {
		t.Setenv("KUBEGUARD_ENV", "production")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "prod-proj")
		t.Setenv("GEMINI_API_KEY_SECRET_ID", "gemini-sec")
		t.Setenv("API_AUTH_TOKEN_SECRET_ID", "auth-sec")
		t.Setenv("KUBEGUARD_API_TOKEN", "")

		_, err := Load(ctx, silentLog, &stubSecretFetcher{secrets: map[string]string{
			"gemini-sec": "resolved-from-secret-manager",
		}})
		if err == nil {
			t.Fatal("expected production Load to fail closed when API auth token is missing")
		}
	})

	t.Run("production resolves secrets from Secret Manager", func(t *testing.T) {
		t.Setenv("KUBEGUARD_ENV", "production")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "prod-proj")
		t.Setenv("GEMINI_API_KEY_SECRET_ID", "gemini-sec")
		t.Setenv("API_AUTH_TOKEN_SECRET_ID", "auth-sec")

		cfg, err := Load(ctx, silentLog, &stubSecretFetcher{secrets: map[string]string{
			"gemini-sec": "sm-gemini-key",
			"auth-sec":   "sm-bearer-token",
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.GeminiAPIKey != "sm-gemini-key" || cfg.APIAuthToken != "sm-bearer-token" {
			t.Fatalf("unexpected resolved secrets: %+v", cfg)
		}
	})

	t.Run("test mode forces localhost bind and generates ephemeral token", func(t *testing.T) {
		t.Setenv("KUBEGUARD_ENV", "test")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		t.Setenv("KUBEGUARD_BIND_HOST", "0.0.0.0")
		t.Setenv("KUBEGUARD_API_TOKEN", "")

		cfg, err := Load(ctx, silentLog, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.BindHost != "127.0.0.1" {
			t.Fatalf("expected test bind host 127.0.0.1, got %q", cfg.BindHost)
		}
		if len(cfg.APIAuthToken) < 32 {
			t.Fatalf("expected CSPRNG ephemeral token, got length %d", len(cfg.APIAuthToken))
		}
	})
}
