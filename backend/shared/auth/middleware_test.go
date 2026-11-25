package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

type verifierFunc func(context.Context, string, string) (Principal, error)

func (f verifierFunc) Verify(ctx context.Context, token, audience string) (Principal, error) {
	return f(ctx, token, audience)
}

func newMiddleware(t *testing.T, verifier TokenVerifier, audience string) *Middleware {
	t.Helper()
	m, err := NewMiddleware(verifier, audience)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func assertAuthError(t *testing.T, result *httptest.ResponseRecorder, status int, challenge string) {
	t.Helper()
	if result.Code != status || result.Header().Get("WWW-Authenticate") != challenge {
		t.Fatalf("status/challenge = %d / %q, want %d / %q", result.Code, result.Header().Get("WWW-Authenticate"), status, challenge)
	}
	if result.Header().Get("Content-Type") != "application/json" || result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authentication errors must be non-cacheable JSON")
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil || body.Message == "" {
		t.Fatalf("invalid error response: %v", err)
	}
}

func TestMiddlewareRejectsMissingAndMalformedCredentials(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
	}{
		{"missing", nil},
		{"empty", []string{""}},
		{"basic", []string{"Basic dXNlcjpwYXNz"}},
		{"missing token", []string{"Bearer"}},
		{"empty bearer", []string{"Bearer "}},
		{"spaces only", []string{"Bearer   "}},
		{"tab separator", []string{"Bearer\ttoken"}},
		{"whitespace in token", []string{"Bearer first second"}},
		{"trailing whitespace", []string{"Bearer token "}},
		{"comma-separated", []string{"Bearer first, Bearer second"}},
		{"duplicate headers", []string{"Bearer first", "Bearer second"}},
		{"oversized token", []string{"Bearer " + strings.Repeat("x", maxTokenSize+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := verifierFunc(func(context.Context, string, string) (Principal, error) {
				t.Fatal("malformed credentials must not reach the verifier")
				return Principal{}, nil
			})
			handler := newMiddleware(t, verifier, "public").Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unauthenticated request reached the handler")
			}))
			// Query, cookies and legacy headers are not authentication mechanisms.
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rating?access_token=not-trusted", nil)
			req.Header.Set("X-User-Name", "spoofed-user")
			req.AddCookie(&http.Cookie{Name: "access_token", Value: "not-trusted"})
			for _, header := range tc.headers {
				req.Header.Add("Authorization", header)
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, req)
			challenge := `Bearer error="invalid_token"`
			if len(tc.headers) == 0 {
				challenge = "Bearer"
			}
			assertAuthError(t, result, http.StatusUnauthorized, challenge)
		})
	}
}

func TestMiddlewareStoresVerifiedIdentityAndCredential(t *testing.T) {
	for _, header := range []string{"Bearer test-token", "bearer test-token", "BEARER   test-token"} {
		t.Run(header, func(t *testing.T) {
			type upstreamKey struct{}
			original := Principal{Subject: "auth0|real-user", ClientID: "user-client", Scopes: []string{"openid", "profile"}, ExpiresAt: time.Now().Add(time.Hour)}
			calls := 0
			verifier := verifierFunc(func(ctx context.Context, token, audience string) (Principal, error) {
				calls++
				if token != "test-token" || audience != "public" || ctx.Value(upstreamKey{}) != "preserved" {
					t.Fatal("verifier received wrong credentials, audience or context")
				}
				return original, nil
			})
			handler := newMiddleware(t, verifier, "public").Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal, ok := PrincipalFromContext(r.Context())
				if !ok || principal.Subject != "auth0|real-user" || principal.ClientID != "user-client" || !principal.ExpiresAt.Equal(original.ExpiresAt) {
					t.Fatal("verified principal was not stored")
				}
				principal.Scopes[0] = "changed"
				again, _ := PrincipalFromContext(r.Context())
				if !again.HasScope("openid") || !original.HasScope("openid") {
					t.Fatal("mutable scopes escaped the context")
				}
				token, ok := AccessTokenFromContext(r.Context())
				if !ok || token != "test-token" || r.Context().Value(upstreamKey{}) != "preserved" {
					t.Fatal("verified token or parent context was lost")
				}
				for _, format := range []string{"%v", "%+v", "%#v"} {
					if strings.Contains(fmt.Sprintf(format, r.Context().Value(authenticationKey{})), token) {
						t.Fatalf("context credential leaked with %s", format)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rating", nil)
			req.Header.Set("Authorization", header)
			req.Header.Set("X-User-Name", "spoofed-user")
			req = req.WithContext(context.WithValue(req.Context(), upstreamKey{}, "preserved"))
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, req)
			if result.Code != http.StatusNoContent || calls != 1 {
				t.Fatalf("status=%d, verifier calls=%d", result.Code, calls)
			}
			if _, ok := PrincipalFromContext(req.Context()); ok {
				t.Fatal("authentication mutated the original request context")
			}
		})
	}
}

func TestMiddlewareMapsVerifierErrorsWithoutLeakingCredentials(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		status    int
		challenge string
	}{
		{"invalid token", fmt.Errorf("signature for secret-token: %w", ErrInvalidToken), http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"unavailable provider", fmt.Errorf("provider-private-details: %w", ErrProviderUnavailable), http.StatusServiceUnavailable, ""},
		{"deadline", context.DeadlineExceeded, http.StatusServiceUnavailable, ""},
		{"canceled", context.Canceled, http.StatusServiceUnavailable, ""},
		{"unexpected error", errors.New("provider-private-details"), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := verifierFunc(func(context.Context, string, string) (Principal, error) {
				return Principal{Subject: "must-not-be-used"}, tc.err
			})
			handler := newMiddleware(t, verifier, "public").Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("authentication failure reached the handler")
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rating", nil)
			req.Header.Set("Authorization", "Bearer secret-token")
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, req)
			assertAuthError(t, result, tc.status, tc.challenge)
			if strings.Contains(result.Body.String(), "secret-token") || strings.Contains(result.Body.String(), "provider-private-details") {
				t.Fatal("authentication details leaked in the response")
			}
		})
	}
}

func TestRequireScopes(t *testing.T) {
	cases := []struct {
		name          string
		authenticated bool
		scopes        []string
		required      []string
		status        int
	}{
		{"no identity", false, nil, []string{"returns:complete"}, http.StatusUnauthorized},
		{"no identity even without required scopes", false, nil, nil, http.StatusUnauthorized},
		{"missing scope", true, []string{"openid"}, []string{"returns:complete"}, http.StatusForbidden},
		{"substring is not a permission", true, []string{"returns:complete:all"}, []string{"returns:complete"}, http.StatusForbidden},
		{"all permissions required", true, []string{"returns:complete"}, []string{"returns:complete", "other:permission"}, http.StatusForbidden},
		{"allowed", true, []string{"returns:complete", "other:permission"}, []string{"returns:complete", "other:permission"}, http.StatusNoContent},
		{"identity without scope policy", true, nil, nil, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := RequireScopes(tc.required...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, "/internal/returns", nil)
			if tc.authenticated {
				req = req.WithContext(authenticatedContext(req.Context(), Principal{Subject: "worker@clients", Scopes: tc.scopes}, "test-token"))
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, req)
			if result.Code != tc.status || called != (tc.status == http.StatusNoContent) {
				t.Fatalf("status=%d, handler called=%v", result.Code, called)
			}
			if tc.status == http.StatusUnauthorized {
				assertAuthError(t, result, tc.status, "Bearer")
			}
			if tc.status == http.StatusForbidden {
				assertAuthError(t, result, tc.status, `Bearer error="insufficient_scope"`)
			}
		})
	}
}

func TestMiddlewareConfigurationAndContextIsolation(t *testing.T) {
	valid := verifierFunc(func(context.Context, string, string) (Principal, error) { return Principal{}, nil })
	if _, err := NewMiddleware(nil, "public"); err == nil {
		t.Fatal("expected nil verifier rejection")
	}
	for _, audience := range []string{"", " ", " public "} {
		if _, err := NewMiddleware(valid, audience); err == nil {
			t.Fatal("expected invalid audience rejection")
		}
	}
	ctx := context.WithValue(context.Background(), "principal", Principal{Subject: "unverified"})
	if _, ok := PrincipalFromContext(ctx); ok {
		t.Fatal("unrelated context value was trusted")
	}
	if _, ok := AccessTokenFromContext(ctx); ok {
		t.Fatal("unrelated context contains a verified access token")
	}
	principal := Principal{Subject: "user", Scopes: []string{"original"}}
	ctx = authenticatedContext(ctx, principal, "test-token")
	principal.Scopes[0] = "mutated"
	stored, _ := PrincipalFromContext(ctx)
	if !stored.HasScope("original") {
		t.Fatal("original scope slice must not mutate context identity")
	}
	// The permission policy must not change if its caller later reuses a slice.
	required := []string{"original"}
	handler := RequireScopes(required...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	required[0] = "mutated"
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
	if result.Code != http.StatusNoContent {
		t.Fatal("permission policy changed through a shared slice")
	}
}

func TestClientCredentialsPolicyRequiresVerifiedServiceIdentity(t *testing.T) {
	for _, tc := range []struct {
		principal *Principal
		status    int
	}{
		{nil, http.StatusUnauthorized},
		{&Principal{Subject: "auth0|alice", ClientID: "user-client"}, http.StatusForbidden},
		{&Principal{Subject: "worker@clients"}, http.StatusForbidden},
		{&Principal{Subject: "worker@clients", ClientID: "another-client"}, http.StatusForbidden},
		{&Principal{Subject: "worker@clients", ClientID: "worker"}, http.StatusNoContent},
	} {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/rating", nil)
		if tc.principal != nil {
			req = req.WithContext(authenticatedContext(req.Context(), *tc.principal, "test-token"))
		}
		result := httptest.NewRecorder()
		RequireClientCredentials(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(result, req)
		if result.Code != tc.status {
			t.Fatalf("service identity policy: status=%d want=%d", result.Code, tc.status)
		}
	}
}

func TestMiddlewareWithRealJWTAndExplicitPublicRoutes(t *testing.T) {
	f := newProvider(t)
	v := f.verifier(t)
	user := newMiddleware(t, v, f.config().Audience)
	worker := newMiddleware(t, v, f.config().InternalAudience)
	router := mux.NewRouter()
	// Public exceptions are explicit routes, not broad string-prefix matches.
	for _, path := range []string{"/manage/health", "/api/v1/authorize", "/api/v1/callback"} {
		router.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	protected := router.PathPrefix("/api/").Subrouter()
	protected.Use(user.Authenticate)
	protected.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "auth0|user-test" {
			t.Error("real JWT did not authenticate the expected identity")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	protected.HandleFunc("/v1/authorize-extra", func(http.ResponseWriter, *http.Request) { t.Error("public prefix bypass") })
	protected.HandleFunc("/v1/callback/extra", func(http.ResponseWriter, *http.Request) { t.Error("public prefix bypass") })
	router.Handle("/internal/returns", worker.Authenticate(RequireScopes("returns:complete")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))
	issue := func(edit func(map[string]any)) string {
		claims := f.claims(time.Now())
		if edit != nil {
			edit(claims)
		}
		return signToken(t, f.private, map[string]any{"alg": "RS256", "kid": "key-1"}, claims)
	}
	userToken := issue(nil)
	workerToken := issue(func(c map[string]any) {
		c["aud"], c["sub"], c["azp"], c["scope"] = f.config().InternalAudience, "worker@clients", "worker", "returns:complete"
	})
	noScopeToken := issue(func(c map[string]any) { c["aud"] = f.config().InternalAudience })
	expiredToken := issue(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() })
	cases := []struct {
		path   string
		token  string
		status int
	}{
		{"/manage/health", "", http.StatusOK},
		{"/api/v1/authorize", "", http.StatusOK},
		{"/api/v1/callback", "", http.StatusOK},
		{"/api/v1/authorize-extra", "", http.StatusUnauthorized},
		{"/api/v1/callback/extra", "", http.StatusUnauthorized},
		{"/api/v1/me", "", http.StatusUnauthorized},
		{"/api/v1/me", "bad.token.value", http.StatusUnauthorized},
		{"/api/v1/me", expiredToken, http.StatusUnauthorized},
		{"/api/v1/me", userToken, http.StatusNoContent},
		{"/api/v1/me", workerToken, http.StatusUnauthorized},
		{"/internal/returns", userToken, http.StatusUnauthorized},
		{"/internal/returns", noScopeToken, http.StatusForbidden},
		{"/internal/returns", workerToken, http.StatusNoContent},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			result := httptest.NewRecorder()
			router.ServeHTTP(result, req)
			if result.Code != tc.status {
				t.Fatalf("path=%s, status=%d, want=%d", tc.path, result.Code, tc.status)
			}
		})
	}
	if f.requests.Load() != 1 || f.discovery.Load() != 1 {
		t.Fatal("middleware must use cached public keys, not contact the IdP per request")
	}
}
