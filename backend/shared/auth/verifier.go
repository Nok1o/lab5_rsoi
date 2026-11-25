package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	keyCacheTTL     = 5 * time.Minute
	refreshInterval = 30 * time.Second
	requestTimeout  = 5 * time.Second
	maxResponseSize = 1 << 20
	maxTokenSize    = 16 << 10
)

var (
	ErrInvalidToken        = errors.New("invalid access token")
	ErrProviderUnavailable = errors.New("OIDC provider unavailable")
)

// Principal contains verified identity data, not the original bearer token.
// Authorization (user vs worker, required scopes) belongs to the caller.
type Principal struct {
	Subject   string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

func (p Principal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

// Verifier is safe for concurrent use. It refreshes keys lazily: no background
// goroutine or Close method is needed. An expired cache fails closed if refresh
// fails; an unavailable provider does not invalidate still-fresh cached keys.
type Verifier struct {
	cfg      Config
	client   *http.Client
	jwksURL  string
	tokenURL string
	now      func() time.Time

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
	refreshMu   sync.Mutex
}

// NewVerifier discovers and loads keys immediately, so invalid provider
// configuration can be detected at startup. Pass nil for the default HTTP client.
func NewVerifier(ctx context.Context, cfg Config, client *http.Client) (*Verifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	if boundedClient.Timeout <= 0 || boundedClient.Timeout > requestTimeout {
		boundedClient.Timeout = requestTimeout
	}
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	v := &Verifier{cfg: cfg, client: &boundedClient, now: time.Now}

	data, err := v.get(ctx, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	var metadata struct {
		Issuer        string `json:"issuer"`
		JWKSURI       string `json:"jwks_uri"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("OIDC discovery must return the configured issuer")
	}
	issuerURL, _ := httpsURL(cfg.Issuer)
	keysURL, err := httpsURL(metadata.JWKSURI)
	if err != nil || !strings.EqualFold(keysURL.Host, issuerURL.Host) {
		return nil, fmt.Errorf("OIDC jwks_uri must use HTTPS and the configured issuer's host")
	}
	v.jwksURL = keysURL.String()
	if metadata.TokenEndpoint != "" {
		tokenURL, err := httpsURL(metadata.TokenEndpoint)
		if err != nil || !strings.EqualFold(tokenURL.Host, issuerURL.Host) {
			return nil, fmt.Errorf("OIDC token_endpoint must use HTTPS and the configured issuer's host")
		}
		v.tokenURL = tokenURL.String()
	}
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	v.keys, v.fetchedAt = keys, v.now()
	return v, nil
}

// Verify accepts a raw compact JWT, without "Bearer ". The expected audience
// must be chosen explicitly for the route; user/internal audiences are not an OR.
// Neither iss/jku/x5u headers nor unverified claims select a discovery/key URL.
func (v *Verifier) Verify(ctx context.Context, rawToken, audience string) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	if audience != v.cfg.Audience && audience != v.cfg.InternalAudience {
		return Principal{}, fmt.Errorf("expected audience is not configured")
	}
	if len(rawToken) == 0 || len(rawToken) > maxTokenSize {
		return Principal{}, ErrInvalidToken
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return Principal{}, ErrInvalidToken
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(data, &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" || len(header.KeyID) > 256 {
		return Principal{}, ErrInvalidToken
	}
	key, err := v.key(ctx, header.KeyID)
	if err != nil {
		return Principal{}, err
	}
	token, err := jwt.ParseString(rawToken,
		jwt.WithKey(jwa.RS256(), key), jwt.WithValidate(true),
		jwt.WithStrictStringClaims(true),
		jwt.WithIssuer(v.cfg.Issuer), jwt.WithAudience(audience),
		jwt.WithRequiredClaim(jwt.ExpirationKey), jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	subject, _ := token.Subject()
	if strings.TrimSpace(subject) == "" {
		return Principal{}, ErrInvalidToken
	}
	var clientID, scope string
	if token.Has("azp") && token.Get("azp", &clientID) != nil {
		return Principal{}, ErrInvalidToken
	}
	if token.Has("client_id") {
		var alternative string
		if token.Get("client_id", &alternative) != nil || (clientID != "" && clientID != alternative) {
			return Principal{}, ErrInvalidToken
		}
		clientID = alternative
	}
	if token.Has("scope") && token.Get("scope", &scope) != nil {
		return Principal{}, ErrInvalidToken
	}
	expiresAt, _ := token.Expiration()
	return Principal{Subject: subject, ClientID: clientID, Scopes: strings.Fields(scope), ExpiresAt: expiresAt}, nil
}

func (v *Verifier) cachedKey(id string) (*rsa.PublicKey, bool, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	fresh := v.now().Sub(v.fetchedAt) < keyCacheTTL
	throttled := !v.lastAttempt.IsZero() && v.now().Sub(v.lastAttempt) < refreshInterval
	return v.keys[id], fresh, throttled
}

func (v *Verifier) key(ctx context.Context, id string) (*rsa.PublicKey, error) {
	if key, fresh, _ := v.cachedKey(id); fresh && key != nil {
		return key, nil
	}
	// Coalesce concurrent refreshes. Cached, known keys take the fast path above
	// and are not blocked by a refresh for an unknown kid.
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, fresh, throttled := v.cachedKey(id)
	if fresh && key != nil {
		return key, nil
	}
	if throttled {
		if !fresh {
			return nil, ErrProviderUnavailable
		}
		return nil, ErrInvalidToken
	}
	v.mu.Lock()
	v.lastAttempt = v.now()
	v.mu.Unlock()
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, v.now()
	v.mu.Unlock()
	if key := keys[id]; key != nil {
		return key, nil
	}
	return nil, ErrInvalidToken
}

func (v *Verifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	data, err := v.get(ctx, v.jwksURL)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(data, jwk.WithMaxKeys(100), jwk.WithRejectDuplicateKID(true), jwk.WithStrictKeySetParsing(true))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JWKS", ErrProviderUnavailable)
	}
	keys := make(map[string]*rsa.PublicKey)
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		id, _ := key.KeyID()
		if id == "" || key.KeyType() != jwa.RSA() {
			continue
		}
		if private, ok := key.(jwk.AsymmetricKey); ok && private.IsPrivate() {
			continue
		}
		if alg, ok := key.Algorithm(); ok && alg.String() != "RS256" {
			continue
		}
		if use, ok := key.KeyUsage(); ok && use != string(jwk.ForSignature) {
			continue
		}
		if ops, ok := key.KeyOps(); ok && !slices.Contains(ops, jwk.KeyOpVerify) {
			continue
		}
		var publicKey rsa.PublicKey
		if err := jwk.Export(key, &publicKey); err != nil || publicKey.N == nil || publicKey.N.BitLen() < 2048 {
			continue
		}
		keys[id] = &publicKey
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: JWKS contains no usable RS256 public keys", ErrProviderUnavailable)
	}
	return keys, nil
}

func (v *Verifier) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid endpoint", ErrProviderUnavailable)
	}
	res, err := v.client.Do(req)
	if err != nil {
		// Provider bodies and raw tokens must never appear in authentication errors.
		return nil, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrProviderUnavailable, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("%w: cannot read bounded response", ErrProviderUnavailable)
	}
	return data, nil
}
