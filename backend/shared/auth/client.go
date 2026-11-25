package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

var ErrMissingAccessToken = errors.New("outgoing request has no access token")

type TokenSource interface {
	Token(context.Context) (string, error)
}

// RequestTokenSource forwards only the token accepted by incoming middleware.
type RequestTokenSource struct{}

func (RequestTokenSource) Token(ctx context.Context) (string, error) {
	token, ok := AccessTokenFromContext(ctx)
	if !ok || token == "" {
		return "", ErrMissingAccessToken
	}
	return token, nil
}

// NewHTTPClient makes a private copy; it never modifies the caller's client,
// transport or request. Redirects are disabled to prevent credential leakage
// and accidental replay of writes. The caller decides which service to call.
func NewHTTPClient(base *http.Client, source TokenSource) *http.Client {
	if source == nil {
		panic("outgoing authentication requires a token source")
	}
	if base == nil {
		base = &http.Client{Timeout: 5 * time.Second}
	}
	client := *base
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &bearerTransport{base: transport, source: source}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

type bearerTransport struct {
	base   http.RoundTripper
	source TokenSource
}

func (t *bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	token, err := t.source.Token(request.Context())
	if err != nil {
		return nil, err
	}
	if token == "" || strings.ContainsAny(token, " \t\r\n,") {
		return nil, ErrMissingAccessToken
	}
	copy := request.Clone(request.Context())
	copy.Header.Set("Authorization", "Bearer "+token)
	copy.Header.Del("X-User-Name")
	response, err := t.base.RoundTrip(copy)
	// Do not replay a mutation automatically. On a rejected worker token, the
	// queue's NEXT attempt can acquire a fresh token instead of using it again.
	if err == nil && response.StatusCode == http.StatusUnauthorized {
		if invalidator, ok := t.source.(interface{ Invalidate(string) }); ok {
			invalidator.Invalidate(token)
			response.Body.Close()
			return nil, ErrTokenUnavailable
		}
	}
	return response, err
}
