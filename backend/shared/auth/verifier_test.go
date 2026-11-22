package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// The fixture is a real HTTPS discovery/JWKS server, not an Auth0 tenant.
// Keys and signed access tokens are generated locally and never logged.
type providerFixture struct {
	server    *httptest.Server
	private   *rsa.PrivateKey
	mu        sync.RWMutex
	document  map[string]string
	keys      []byte
	status    int
	requests  atomic.Int32
	discovery atomic.Int32
}

func newProvider(t *testing.T) *providerFixture {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &providerFixture{private: private, status: http.StatusOK}
	f.keys = publicJWKS(t, private, "key-1")
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discovery.Add(1)
			_ = json.NewEncoder(w).Encode(f.document)
		case "/keys":
			f.requests.Add(1)
			w.WriteHeader(f.status)
			_, _ = w.Write(f.keys)
		default:
			http.NotFound(w, r)
		}
	}))
	f.document = map[string]string{"issuer": f.server.URL + "/", "jwks_uri": f.server.URL + "/keys"}
	t.Cleanup(f.server.Close)
	return f
}

func publicJWKS(t *testing.T, private *rsa.PrivateKey, id string) []byte {
	t.Helper()
	key, err := jwk.Import(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"kid": id, "alg": jwa.RS256(), "use": "sig"} {
		if err := key.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *providerFixture) config() Config {
	return Config{Issuer: f.server.URL + "/", Audience: "https://library-system", InternalAudience: "https://library-system/internal"}
}

func (f *providerFixture) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), f.config(), f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *providerFixture) claims(now time.Time) map[string]any {
	return map[string]any{
		"iss": f.config().Issuer, "aud": f.config().Audience, "sub": "auth0|user-test",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		"azp": "user-client", "scope": "openid profile",
	}
}

// Sign independently of the verifier's JWT parser to exercise wire-format input.
func signToken(t *testing.T, private *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	input := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	switch header["alg"] {
	case "none":
	case "HS256":
		mac := hmac.New(sha256.New, []byte("not-a-trusted-key"))
		_, _ = mac.Write([]byte(input))
		signature = mac.Sum(nil)
	default:
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyClaimsAndSignature(t *testing.T) {
	f := newProvider(t)
	v := f.verifier(t)
	now := time.Now().Truncate(time.Second)
	v.now = func() time.Time { return now }
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		edit     func(map[string]any, map[string]any)
		internal bool
		wrongKey bool
		valid    bool
	}{
		{name: "user", valid: true},
		{name: "audience array", valid: true, edit: func(_ map[string]any, c map[string]any) {
			c["aud"] = []string{f.config().Audience, f.config().Issuer + "userinfo"}
		}},
		{name: "worker", valid: true, internal: true, edit: func(_ map[string]any, c map[string]any) {
			c["aud"], c["sub"], c["azp"], c["scope"] = f.config().InternalAudience, "worker-client@clients", "worker-client", "returns:complete"
		}},
		{name: "RFC9068 client_id", valid: true, edit: func(_ map[string]any, c map[string]any) { c["client_id"] = c["azp"]; delete(c, "azp") }},
		{name: "unsigned", edit: func(h, _ map[string]any) { h["alg"] = "none" }},
		{name: "HMAC confusion", edit: func(h, _ map[string]any) { h["alg"] = "HS256" }},
		{name: "wrong signature", wrongKey: true},
		{name: "missing kid", edit: func(h, _ map[string]any) { delete(h, "kid") }},
		{name: "missing issuer", edit: func(_ map[string]any, c map[string]any) { delete(c, "iss") }},
		{name: "wrong issuer", edit: func(_ map[string]any, c map[string]any) { c["iss"] = "https://untrusted.example/" }},
		{name: "missing audience", edit: func(_ map[string]any, c map[string]any) { delete(c, "aud") }},
		{name: "wrong audience", edit: func(_ map[string]any, c map[string]any) { c["aud"] = "other-api" }},
		{name: "user cannot use internal route", internal: true},
		{name: "worker cannot use user route", edit: func(_ map[string]any, c map[string]any) { c["aud"] = f.config().InternalAudience }},
		{name: "missing expiry", edit: func(_ map[string]any, c map[string]any) { delete(c, "exp") }},
		{name: "expired", edit: func(_ map[string]any, c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }},
		{name: "expiry boundary", edit: func(_ map[string]any, c map[string]any) { c["exp"] = now.Unix() }},
		{name: "missing subject", edit: func(_ map[string]any, c map[string]any) { delete(c, "sub") }},
		{name: "empty subject", edit: func(_ map[string]any, c map[string]any) { c["sub"] = " " }},
		{name: "numeric subject", edit: func(_ map[string]any, c map[string]any) { c["sub"] = 123 }},
		{name: "future nbf", edit: func(_ map[string]any, c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }},
		{name: "past nbf", valid: true, edit: func(_ map[string]any, c map[string]any) { c["nbf"] = now.Add(-time.Minute).Unix() }},
		{name: "wrong scope type", edit: func(_ map[string]any, c map[string]any) { c["scope"] = []string{"returns:complete"} }},
		{name: "conflicting client claims", edit: func(_ map[string]any, c map[string]any) { c["client_id"] = "another-client" }},
		{name: "untrusted key URL ignored", valid: true, edit: func(h, _ map[string]any) { h["jku"] = "http://not-trusted.invalid/keys" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := map[string]any{"alg": "RS256", "kid": "key-1", "typ": "JWT"}
			claims := f.claims(now)
			if tc.edit != nil {
				tc.edit(header, claims)
			}
			key := f.private
			if tc.wrongKey {
				key = otherKey
			}
			audience := f.config().Audience
			if tc.internal {
				audience = f.config().InternalAudience
			}
			principal, err := v.Verify(context.Background(), signToken(t, key, header, claims), audience)
			if !tc.valid {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("expected invalid token, got %v", err)
				}
				return
			}
			if err != nil || principal.Subject != claims["sub"] || principal.ClientID == "" || !principal.ExpiresAt.Equal(now.Add(time.Hour)) {
				t.Fatalf("unexpected verified identity: %+v, %v", principal, err)
			}
			if tc.internal && !principal.HasScope("returns:complete") {
				t.Fatal("worker scope was not mapped")
			}
		})
	}
	if f.requests.Load() != 1 || f.discovery.Load() != 1 {
		t.Fatal("known keys must be verified locally without further IdP requests")
	}
	for _, raw := range []string{"", "bad-token", "a.b.c", strings.Repeat("x", maxTokenSize+1)} {
		if _, err := v.Verify(context.Background(), raw, f.config().Audience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected rejection of malformed token: %v", err)
		}
	}
}

func TestKeyRotationAndConcurrentUnknownKey(t *testing.T) {
	f := newProvider(t)
	v := f.verifier(t)
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.keys = publicJWKS(t, rotated, "key-2")
	f.mu.Unlock()
	raw := signToken(t, rotated, map[string]any{"alg": "RS256", "kid": "key-2"}, f.claims(time.Now()))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), raw, f.config().Audience); err != nil {
				t.Errorf("rotated key rejected: %v", err)
			}
		}()
	}
	wg.Wait()
	if f.requests.Load() != 2 {
		t.Fatalf("rotation must coalesce into one refresh; requests=%d", f.requests.Load())
	}
	for i := 0; i < 20; i++ {
		raw := signToken(t, f.private, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("unknown-%d", i)}, f.claims(time.Now()))
		if _, err := v.Verify(context.Background(), raw, f.config().Audience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("unknown key accepted: %v", err)
		}
	}
	if f.requests.Load() != 2 {
		t.Fatal("random kids must not trigger a JWKS request flood")
	}
	old := signToken(t, f.private, map[string]any{"alg": "RS256", "kid": "key-1"}, f.claims(time.Now()))
	if _, err := v.Verify(context.Background(), old, f.config().Audience); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("removed key must not remain trusted after refresh")
	}
}

func TestCacheExpiryAndProviderOutage(t *testing.T) {
	f := newProvider(t)
	v := f.verifier(t)
	now := time.Now()
	v.now = func() time.Time { return now }
	raw := signToken(t, f.private, map[string]any{"alg": "RS256", "kid": "key-1"}, f.claims(now))
	f.mu.Lock()
	f.status = http.StatusServiceUnavailable
	f.mu.Unlock()
	if _, err := v.Verify(context.Background(), raw, f.config().Audience); err != nil {
		t.Fatalf("fresh cache should survive outage: %v", err)
	}
	now = now.Add(keyCacheTTL + time.Second)
	for i := 0; i < 10; i++ {
		if _, err := v.Verify(context.Background(), raw, f.config().Audience); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("expired cache must fail closed: %v", err)
		}
	}
	if f.requests.Load() != 2 {
		t.Fatal("failing refreshes must be throttled")
	}
	f.mu.Lock()
	f.status = http.StatusOK
	f.mu.Unlock()
	now = now.Add(refreshInterval)
	if _, err := v.Verify(context.Background(), raw, f.config().Audience); err != nil {
		t.Fatalf("provider recovery did not refresh keys: %v", err)
	}
	if f.requests.Load() != 3 {
		t.Fatal("expected a refresh after provider recovery")
	}
}

func TestDiscoveryAndJWKSRejectUnsafeResponses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*providerFixture)
	}{
		{"issuer mismatch", func(f *providerFixture) { f.document["issuer"] = "https://wrong.example/" }},
		{"insecure JWKS", func(f *providerFixture) {
			f.document["jwks_uri"] = strings.Replace(f.server.URL, "https:", "http:", 1) + "/keys"
		}},
		{"foreign JWKS host", func(f *providerFixture) { f.document["jwks_uri"] = "https://wrong.example/keys" }},
		{"malformed JWKS", func(f *providerFixture) { f.keys = []byte("not-json") }},
		{"empty JWKS", func(f *providerFixture) { f.keys = []byte(`{"keys":[]}`) }},
		{"oversized JWKS", func(f *providerFixture) { f.keys = []byte(strings.Repeat("x", maxResponseSize+1)) }},
		{"unavailable JWKS", func(f *providerFixture) { f.status = http.StatusServiceUnavailable }},
		{"encryption key", func(f *providerFixture) {
			f.keys = []byte(strings.Replace(string(f.keys), `"use":"sig"`, `"use":"enc"`, 1))
		}},
		{"wrong key algorithm", func(f *providerFixture) {
			f.keys = []byte(strings.Replace(string(f.keys), `"alg":"RS256"`, `"alg":"RS512"`, 1))
		}},
		{"duplicate kid", func(f *providerFixture) {
			var set struct {
				Keys []json.RawMessage `json:"keys"`
			}
			_ = json.Unmarshal(f.keys, &set)
			set.Keys = append(set.Keys, set.Keys[0])
			f.keys, _ = json.Marshal(set)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvider(t)
			f.mu.Lock()
			tc.edit(f)
			f.mu.Unlock()
			if _, err := NewVerifier(context.Background(), f.config(), f.server.Client()); err == nil {
				t.Fatal("expected startup rejection")
			}
		})
	}
}

func TestDiscoveryDoesNotFollowRedirects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))
	defer server.Close()
	_, err := NewVerifier(context.Background(), Config{Issuer: server.URL, Audience: "public", InternalAudience: "internal"}, server.Client())
	if err == nil || calls.Load() != 1 {
		t.Fatalf("redirect followed or accepted: calls=%d, error=%v", calls.Load(), err)
	}
}

func TestCanceledContextAndUnconfiguredAudience(t *testing.T) {
	f := newProvider(t)
	v := f.verifier(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(ctx, "anything", f.config().Audience); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if _, err := NewVerifier(ctx, f.config(), f.server.Client()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled discovery, got %v", err)
	}
	if _, err := v.Verify(context.Background(), "anything", "unconfigured"); err == nil {
		t.Fatal("expected unconfigured audience error")
	}
}
