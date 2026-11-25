package observability

import (
	"context"
	"crypto/subtle"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/time/rate"
	"google.golang.org/adk/v2/server/authn"
	"google.golang.org/adk/v2/server/authz"
)

// BearerTokenAuthenticator implements adk/v2/server/authn.Authenticator using
// constant-time token comparison and strictly rejecting credentials passed in URL query strings.
type BearerTokenAuthenticator struct {
	expectedToken []byte
	defaultUserID string
}

// NewBearerTokenAuthenticator constructs an Authenticator backed by a secret token.
func NewBearerTokenAuthenticator(token, defaultUserID string) *BearerTokenAuthenticator {
	if defaultUserID == "" {
		defaultUserID = "sre-operator"
	}
	return &BearerTokenAuthenticator{
		expectedToken: []byte(token),
		defaultUserID: defaultUserID,
	}
}

// Authenticate validates the Authorization: Bearer header in constant time.
func (a *BearerTokenAuthenticator) Authenticate(r *http.Request) (*authn.Caller, error) {
	// Reject credentials leaked via URL query parameters.
	if q := r.URL.Query(); q.Has("token") || q.Has("api_key") || q.Has("access_token") {
		return nil, authn.ErrUnauthenticated
	}
	if len(a.expectedToken) == 0 {
		return nil, authn.ErrUnauthenticated
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return nil, authn.ErrUnauthenticated
	}
	provided := strings.TrimSpace(authHeader[len(prefix):])
	if subtle.ConstantTimeCompare([]byte(provided), a.expectedToken) != 1 {
		return nil, authn.ErrUnauthenticated
	}

	callerID := strings.TrimSpace(r.Header.Get("X-KubeGuard-Caller"))
	if callerID == "" {
		callerID = a.defaultUserID
	}
	return &authn.Caller{
		UserID: callerID,
		Claims: map[string]any{"role": "sre_operator"},
	}, nil
}

// StrictUserAuthorizer implements adk/v2/server/authz.Authorizer, ensuring a caller
// can only access or mutate sessions owned by their own UserID.
type StrictUserAuthorizer struct{}

// CanActAsUser enforces strict resource ownership without echoing PII in error strings.
func (StrictUserAuthorizer) CanActAsUser(ctx context.Context, targetUserID string) error {
	caller, ok := authn.CallerFromContext(ctx)
	if !ok || caller == nil || caller.UserID == "" {
		return authz.ErrUnauthorized
	}
	if caller.UserID != targetUserID {
		return authz.ErrUnauthorized
	}
	return nil
}

// HardenedHTTPMiddleware enforces HTTP method allow-listing, token-bucket rate limiting,
// strict CSP/X-Frame-Options/nosniff/Permissions-Policy headers, Cache-Control: no-store,
// and explicit origin allow-list CORS.
func HardenedHTTPMiddleware(allowedOrigins []string, rps rate.Limit, burst int) func(http.Handler) http.Handler {
	var mu sync.Mutex
	limiters := make(map[string]*rate.Limiter)

	getLimiter := func(clientKey string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()
		lim, exists := limiters[clientKey]
		if !exists {
			lim = rate.NewLimiter(rps, burst)
			limiters[clientKey] = lim
		}
		return lim
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers on every response.
			h := w.Header()
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Cache-Control", "no-store")

			// Explicit CORS allow-list (never wildcard '*').
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
				if !slices.Contains(allowedOrigins, origin) {
					http.Error(w, "origin not allowed", http.StatusForbidden)
					return
				}
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KubeGuard-Caller")
			}

			// Allow-list strictly necessary HTTP methods; block TRACE, PUT, DELETE, etc.
			switch r.Method {
			case http.MethodOptions:
				w.WriteHeader(http.StatusNoContent)
				return
			case http.MethodGet, http.MethodPost:
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Reject credential leakage in query parameters early.
			if q := r.URL.Query(); q.Has("token") || q.Has("api_key") || q.Has("password") {
				http.Error(w, "credentials in URL parameters are forbidden", http.StatusBadRequest)
				return
			}

			if !getLimiter(r.RemoteAddr).Allow() {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
