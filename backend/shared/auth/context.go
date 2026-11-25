package auth

import (
	"context"
	"slices"
)

type authenticationKey struct{}

// SubjectFromContext is for delivery handlers behind Authenticate. No legacy
// header or request field is used as a fallback when identity is absent.
func SubjectFromContext(ctx context.Context) string {
	value, _ := ctx.Value(authenticationKey{}).(authentication)
	return value.principal.Subject
}

// The raw token lives only in the synchronous request context, not in Principal,
// domain models or queued jobs. HTTP clients can forward it at the next step.
type authentication struct {
	principal Principal
	token     string
}

// Avoid revealing the bearer credential if the context value is formatted.
func (authentication) String() string     { return "[authenticated request]" }
func (a authentication) GoString() string { return a.String() }

func authenticatedContext(ctx context.Context, principal Principal, token string) context.Context {
	principal.Scopes = slices.Clone(principal.Scopes)
	return context.WithValue(ctx, authenticationKey{}, authentication{principal: principal, token: token})
}

// PrincipalFromContext returns an identity only after Authenticate succeeds.
// A copy of Scopes prevents callers from modifying the verified context value.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	value, ok := ctx.Value(authenticationKey{}).(authentication)
	if !ok {
		return Principal{}, false
	}
	principal := value.principal
	principal.Scopes = slices.Clone(principal.Scopes)
	return principal, true
}

// AccessTokenFromContext is intended for synchronous downstream HTTP calls.
// Never log the returned credential or persist it in a background task.
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(authenticationKey{}).(authentication)
	return value.token, ok
}
