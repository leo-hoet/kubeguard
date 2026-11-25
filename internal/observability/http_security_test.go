package observability

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
	"google.golang.org/adk/v2/server/authn"
)

func TestHardenedHTTPMiddlewareAndAuthentication(t *testing.T) {
	authenticator := NewBearerTokenAuthenticator("super-secret-ephemeral-token", "alice-sre")
	authorizer := StrictUserAuthorizer{}

	protected := authn.Middleware(authenticator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetUser := r.URL.Query().Get("user_id")
		if err := authorizer.CanActAsUser(r.Context(), targetUser); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	handler := HardenedHTTPMiddleware([]string{"http://127.0.0.1:8080"}, rate.Limit(50), 50)(protected)

	// Strictly bind test listener to 127.0.0.1 (never 0.0.0.0).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding localhost listener: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	client := srv.Client()

	// 1. Unauthenticated request -> 401 + security headers present.
	resp, err := client.Get(srv.URL + "/api?user_id=alice-sre")
	if err != nil {
		t.Fatalf("GET unauthenticated: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %+v", resp.Header)
	}

	// 2. Disallowed HTTP method DELETE -> 405.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api", nil)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE request: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for DELETE, got %d", delResp.StatusCode)
	}

	// 3. Authenticated caller trying to access another user's session -> 403 Forbidden (IDOR defense).
	idorReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api?user_id=bob-sre", nil)
	idorReq.Header.Set("Authorization", "Bearer super-secret-ephemeral-token")
	idorResp, err := client.Do(idorReq)
	if err != nil {
		t.Fatalf("IDOR request: %v", err)
	}
	_ = idorResp.Body.Close()
	if idorResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-user access, got %d", idorResp.StatusCode)
	}

	// 4. Valid authenticated & authorized request -> 200 OK.
	okReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api?user_id=alice-sre", nil)
	okReq.Header.Set("Authorization", "Bearer super-secret-ephemeral-token")
	okReq.Header.Set("Origin", "http://127.0.0.1:8080")
	okResp, err := client.Do(okReq)
	if err != nil {
		t.Fatalf("valid request: %v", err)
	}
	_ = okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", okResp.StatusCode)
	}
}
