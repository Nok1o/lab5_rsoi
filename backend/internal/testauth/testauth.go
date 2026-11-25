// Package testauth contains deterministic unit-test helpers. It is imported
// only by tests; end-to-end JWT checks use real RSA signatures and HTTPS JWKS.
package testauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"libriary_system/shared/auth"
)

type verifier struct{}

func (verifier) Verify(_ context.Context, token, audience string) (auth.Principal, error) {
	if audience == "public" && strings.HasPrefix(token, "user:") && len(token) > len("user:") {
		return auth.Principal{Subject: strings.TrimPrefix(token, "user:")}, nil
	}
	if audience == "internal" && token == "worker" {
		return auth.Principal{Subject: "worker@clients", ClientID: "worker", Scopes: []string{auth.ReturnsCompleteScope}}, nil
	}
	return auth.Principal{}, auth.ErrInvalidToken
}

func middleware(t testing.TB, audience string) *auth.Middleware {
	t.Helper()
	m, err := auth.NewMiddleware(verifier{}, audience)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func User(t testing.TB) *auth.Middleware   { return middleware(t, "public") }
func Worker(t testing.TB) *auth.Middleware { return middleware(t, "internal") }

func Login(request *http.Request, subject string) {
	request.Header.Del("Authorization")
	if subject != "" {
		request.Header.Set("Authorization", "Bearer user:"+subject)
	}
	// Deliberately contradict the token to catch accidental legacy fallbacks.
	request.Header.Set("X-User-Name", "spoofed-user")
}

func NewRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	Login(r, "alice")
	return r
}

// CheckProtected verifies auth runs before handlers, body validation or domain
// calls for every registered method/path. Tokens in query/legacy headers do not
// authorize the request. Use concrete paths (not mux placeholders).
func CheckProtected(t testing.TB, router http.Handler, routes ...string) {
	t.Helper()
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		for _, header := range []string{"", "Bearer invalid-token", "Basic credentials"} {
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("X-User-Name", "alice")
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			result := httptest.NewRecorder()
			router.ServeHTTP(result, req)
			if result.Code != http.StatusUnauthorized {
				t.Fatalf("unprotected %s: status=%d", route, result.Code)
			}
		}
	}
	result := httptest.NewRecorder()
	router.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/manage/health", nil))
	if result.Code != http.StatusOK {
		t.Fatal("health must remain public")
	}
}

func Context(t testing.TB, subject string) context.Context {
	t.Helper()
	var ctx context.Context
	User(t).Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).ServeHTTP(
		httptest.NewRecorder(), NewRequestWithSubject(subject),
	)
	if ctx == nil {
		t.Fatal("unit-test identity was rejected")
	}
	return ctx
}

func NewRequestWithSubject(subject string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	Login(r, subject)
	return r
}
