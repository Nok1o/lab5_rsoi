package testauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"libriary_system/shared/auth"
)

// Provider is an isolated HTTPS OIDC stand-in with real RSA-signed tokens.
// It uses fake credentials and never calls or configures a real Auth0 tenant.
type Provider struct {
	Server  *httptest.Server
	Config  auth.Config
	Grants  atomic.Int32
	private *rsa.PrivateKey
}

func NewProvider(t testing.TB) *Provider {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{private: private}
	key, err := jwk.Import(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set("kid", "test-key"); err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.Config.Issuer, "jwks_uri": p.Server.URL + "/keys", "token_endpoint": p.Server.URL + "/oauth/token"})
		case "/keys":
			_, _ = w.Write(keys)
		case "/oauth/token":
			p.Grants.Add(1)
			if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "worker" || r.Form.Get("client_secret") != "fake-secret" || r.Form.Get("audience") != p.Config.InternalAudience || r.Form.Get("scope") != auth.ReturnsCompleteScope {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			token := p.Issue(t, "worker@clients", p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	p.Config = auth.Config{Issuer: p.Server.URL + "/", Audience: "https://library-system", InternalAudience: "https://library-system/internal"}
	t.Cleanup(p.Server.Close)
	return p
}

func (p *Provider) Verifier(t testing.TB) *auth.Verifier {
	t.Helper()
	v, err := auth.NewVerifier(t.Context(), p.Config, p.Server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (p *Provider) Middleware(t testing.TB, audience string) *auth.Middleware {
	t.Helper()
	m, err := auth.NewMiddleware(p.Verifier(t), audience)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (p *Provider) Issue(t testing.TB, subject, audience, scope string, expiresAt time.Time) string {
	t.Helper()
	header := []byte(`{"alg":"RS256","kid":"test-key"}`)
	client := "user-client"
	if subject == "worker@clients" {
		client = "worker"
	}
	payload, err := json.Marshal(map[string]any{"iss": p.Config.Issuer, "sub": subject, "aud": audience, "exp": expiresAt.Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "scope": scope, "azp": client})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
