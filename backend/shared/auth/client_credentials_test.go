package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func workerJWT(t *testing.T, f *providerFixture, now time.Time, edit func(map[string]any)) string {
	t.Helper()
	claims := f.claims(now)
	claims["aud"], claims["sub"], claims["azp"], claims["scope"] = f.config().InternalAudience, "worker@clients", "worker", ReturnsCompleteScope
	if edit != nil {
		edit(claims)
	}
	return signToken(t, f.private, map[string]any{"alg": "RS256", "kid": "key-1"}, claims)
}

func newWorkerSource(t *testing.T, f *providerFixture) *ClientCredentialsSource {
	t.Helper()
	source, err := NewClientCredentialsSource(WorkerConfig{ClientID: "worker", ClientSecret: "test-only-secret"}, f.verifier(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestClientCredentialsGrantCachingRefreshAndConcurrency(t *testing.T) {
	f := newProvider(t)
	now := time.Now().Truncate(time.Second)
	var calls atomic.Int32
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "worker" || r.Form.Get("client_secret") != "test-only-secret" || r.Form.Get("audience") != f.config().InternalAudience || r.Form.Get("scope") != ReturnsCompleteScope {
			t.Error("incorrect Client Credentials request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": workerJWT(t, f, now, nil), "token_type": "Bearer", "expires_in": 3600})
	}
	source := newWorkerSource(t, f)
	source.now = func() time.Time { return now }
	source.verifier.now = source.now
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if token, err := source.Token(context.Background()); err != nil || token == "" {
				t.Errorf("Token(): %v", err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent callers issued %d grants, want 1", calls.Load())
	}
	previous, _ := source.Token(context.Background())
	now = now.Add(59*time.Minute + 31*time.Second)
	if token, err := source.Token(context.Background()); err != nil || token == previous {
		t.Fatalf("cached token was not refreshed before expiry: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("grant calls = %d, want 2", calls.Load())
	}
	source.Invalidate(previous) // A late 401 for an old token must not evict a new one.
	if _, err := source.Token(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("stale invalidation evicted a newer token")
	}
	current, _ := source.Token(context.Background())
	source.Invalidate(current)
	if _, err := source.Token(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatal("rejected current token was not refreshed")
	}
}

func TestClientCredentialsRejectUnusableTokens(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"public audience", func(c map[string]any) { c["aud"] = "https://library-system" }},
		{"missing scope", func(c map[string]any) { c["scope"] = "openid" }},
		{"wrong client", func(c map[string]any) { c["azp"] = "different-worker" }},
		{"user subject", func(c map[string]any) { c["sub"] = "auth0|user" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvider(t)
			f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": workerJWT(t, f, time.Now(), tc.edit), "token_type": "Bearer", "expires_in": 3600})
			}
			source := newWorkerSource(t, f)
			if token, err := source.Token(context.Background()); token != "" || !errors.Is(err, ErrTokenUnavailable) {
				t.Fatalf("unusable token accepted: %v", err)
			}
		})
	}
}

func TestClientCredentialsProviderFailuresAndRecovery(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newProvider(t)
			var calls atomic.Int32
			responseStatus := status
			f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if responseStatus != http.StatusOK {
					w.WriteHeader(responseStatus)
					_, _ = w.Write([]byte(`{"error_description":"test-only-secret"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": workerJWT(t, f, time.Now(), nil), "token_type": "Bearer", "expires_in": 3600})
			}
			source := newWorkerSource(t, f)
			now := time.Now()
			source.now = func() time.Time { return now }
			for i := 0; i < 5; i++ {
				_, err := source.Token(context.Background())
				if !errors.Is(err, ErrTokenUnavailable) || strings.Contains(err.Error(), "test-only-secret") {
					t.Fatalf("unexpected or sensitive error: %v", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("failed token endpoint must be backoff-limited")
			}
			f.mu.Lock()
			responseStatus = http.StatusOK
			f.mu.Unlock()
			now = now.Add(time.Second)
			if _, err := source.Token(context.Background()); err != nil {
				t.Fatalf("token source did not recover: %v", err)
			}
		})
	}
}

func TestClientCredentialsCancellationAndConfiguration(t *testing.T) {
	f := newProvider(t)
	source := newWorkerSource(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	source.refresh <- struct{}{}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancelWait()
	if _, err := source.Token(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for another refresh must honor context: %v", err)
	}
	<-source.refresh
	if _, err := NewClientCredentialsSource(WorkerConfig{}, source.verifier, nil); err == nil {
		t.Fatal("empty credentials accepted")
	}
	source.verifier.tokenURL = ""
	if _, err := NewClientCredentialsSource(WorkerConfig{ClientID: "worker", ClientSecret: "test-only-secret"}, source.verifier, nil); err == nil {
		t.Fatal("missing token endpoint accepted")
	}
}
