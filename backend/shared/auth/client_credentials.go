package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const ReturnsCompleteScope = "returns:complete"

var ErrTokenUnavailable = errors.New("worker access token unavailable")

// ClientCredentialsSource belongs only to Gateway. It stores an M2M token in
// process memory, never in Redis, and verifies it before caching/using it.
type ClientCredentialsSource struct {
	worker    WorkerConfig
	verifier  *Verifier
	client    *http.Client
	now       func() time.Time
	refresh   chan struct{}
	mu        sync.RWMutex
	token     string
	refreshAt time.Time
	retryAt   time.Time
}

func (*ClientCredentialsSource) String() string     { return "[worker token source]" }
func (s *ClientCredentialsSource) GoString() string { return s.String() }

func NewClientCredentialsSource(worker WorkerConfig, verifier *Verifier, client *http.Client) (*ClientCredentialsSource, error) {
	if verifier == nil || verifier.tokenURL == "" {
		return nil, fmt.Errorf("worker requires a discovered HTTPS token_endpoint")
	}
	if strings.TrimSpace(worker.ClientID) == "" || strings.TrimSpace(worker.ClientSecret) == "" {
		return nil, fmt.Errorf("worker client credentials are required")
	}
	if client == nil {
		client = verifier.client
	}
	bounded := *client
	if bounded.Timeout <= 0 || bounded.Timeout > requestTimeout {
		bounded.Timeout = requestTimeout
	}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ClientCredentialsSource{worker: worker, verifier: verifier, client: &bounded,
		now: time.Now, refresh: make(chan struct{}, 1)}, nil
}

func (s *ClientCredentialsSource) cached() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token, s.token != "" && s.now().Before(s.refreshAt)
}

func (s *ClientCredentialsSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if token, fresh := s.cached(); fresh {
		return token, nil
	}
	select {
	case s.refresh <- struct{}{}:
		defer func() { <-s.refresh }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if token, fresh := s.cached(); fresh {
		return token, nil
	}
	s.mu.RLock()
	backoff := s.now().Before(s.retryAt)
	s.mu.RUnlock()
	if backoff {
		return "", ErrTokenUnavailable
	}
	token, refreshAt, err := s.fetch(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.retryAt = s.now().Add(time.Second)
		return "", err
	}
	s.token, s.refreshAt, s.retryAt = token, refreshAt, time.Time{}
	return token, nil
}

func (s *ClientCredentialsSource) Invalidate(rejected string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == rejected {
		s.token, s.refreshAt = "", time.Time{}
	}
}

func (s *ClientCredentialsSource) fetch(ctx context.Context) (string, time.Time, error) {
	started := s.now()
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {s.worker.ClientID},
		"client_secret": {s.worker.ClientSecret}, "audience": {s.verifier.cfg.InternalAudience},
		"scope": {ReturnsCompleteScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.verifier.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, ErrTokenUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		// Never include request/response bodies or OAuth credentials in errors.
		if ctx.Err() != nil {
			return "", time.Time{}, fmt.Errorf("%w: %w", ErrTokenUnavailable, ctx.Err())
		}
		return "", time.Time{}, ErrTokenUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("%w: HTTP %d", ErrTokenUnavailable, response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil || len(data) > maxResponseSize || json.Unmarshal(data, &body) != nil || !strings.EqualFold(body.TokenType, "Bearer") || body.ExpiresIn <= 0 || body.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return "", time.Time{}, ErrTokenUnavailable
	}
	principal, err := s.verifier.Verify(ctx, body.AccessToken, s.verifier.cfg.InternalAudience)
	if err != nil || principal.ClientID != s.worker.ClientID || principal.Subject != s.worker.ClientID+"@clients" || !principal.HasScope(ReturnsCompleteScope) {
		return "", time.Time{}, ErrTokenUnavailable
	}
	expiresAt := started.Add(time.Duration(body.ExpiresIn) * time.Second)
	if principal.ExpiresAt.Before(expiresAt) {
		expiresAt = principal.ExpiresAt
	}
	lifetime := expiresAt.Sub(s.now())
	if lifetime <= time.Second {
		return "", time.Time{}, ErrTokenUnavailable
	}
	margin := min(30*time.Second, lifetime/10)
	return body.AccessToken, expiresAt.Add(-margin), nil
}
