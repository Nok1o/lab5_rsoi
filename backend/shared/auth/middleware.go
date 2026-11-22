package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// TokenVerifier is implemented by Verifier. HTTP authorization does not depend
// on its discovery, key caching or cryptographic implementation details.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken, audience string) (Principal, error)
}

type Middleware struct {
	verifier TokenVerifier
	audience string
}

// NewMiddleware binds authentication to one explicit audience. Use separate
// instances for public/user routes and internal/worker routes, never an OR.
func NewMiddleware(verifier TokenVerifier, audience string) (*Middleware, error) {
	if verifier == nil {
		return nil, fmt.Errorf("authentication middleware requires a token verifier")
	}
	if strings.TrimSpace(audience) == "" || audience != strings.TrimSpace(audience) {
		return nil, fmt.Errorf("authentication middleware requires a non-empty audience without surrounding whitespace")
	}
	return &Middleware{verifier: verifier, audience: audience}, nil
}

// Authenticate protects every request reaching it. Public health/authorize/
// callback routes must be registered outside the protected router; this layer
// has no path-prefix bypasses. Only Authorization: Bearer is accepted.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) == 0 {
			writeAuthError(w, http.StatusUnauthorized, "authentication required", "Bearer")
			return
		}
		if len(values) != 1 {
			writeAuthError(w, http.StatusUnauthorized, "invalid access token", `Bearer error="invalid_token"`)
			return
		}
		scheme, token, found := strings.Cut(values[0], " ")
		// RFC 6750 allows one or more SP characters, not tabs or multiple tokens.
		token = strings.TrimLeft(token, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenSize || strings.ContainsAny(token, " \t\r\n,") {
			writeAuthError(w, http.StatusUnauthorized, "invalid access token", `Bearer error="invalid_token"`)
			return
		}
		principal, err := m.verifier.Verify(r.Context(), token, m.audience)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidToken):
				writeAuthError(w, http.StatusUnauthorized, "invalid access token", `Bearer error="invalid_token"`)
			case errors.Is(err, ErrProviderUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
				// Failure to fetch trusted keys is not evidence of bad credentials.
				writeAuthError(w, http.StatusServiceUnavailable, "authentication service unavailable", "")
			default:
				writeAuthError(w, http.StatusInternalServerError, "authentication failed", "")
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(authenticatedContext(r.Context(), principal, token)))
	})
}

// RequireScopes must run after Authenticate. All listed permissions are
// required; scopes are compared as complete values, not string substrings.
// Without an authenticated context, it fails closed with 401 (not 403).
func RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	required := slices.Clone(scopes)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "authentication required", "Bearer")
				return
			}
			for _, scope := range required {
				if !principal.HasScope(scope) {
					writeAuthError(w, http.StatusForbidden, "insufficient permissions", `Bearer error="insufficient_scope"`)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// This is an HTTP error DTO, not a domain entity. Never send verification
// details, provider response bodies or bearer credentials to the caller.
func writeAuthError(w http.ResponseWriter, status int, message, challenge string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{Message: message})
}
