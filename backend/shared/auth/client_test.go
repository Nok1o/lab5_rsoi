package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutgoingClientForwardsCredentialAndPreservesRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer accepted-token" || r.Header.Get("X-User-Name") != "" {
			t.Error("outgoing authorization was not sanitized")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewHTTPClient(nil, RequestTokenSource{})
	req, _ := http.NewRequestWithContext(authenticatedContext(context.Background(), Principal{Subject: "alice"}, "accepted-token"), http.MethodGet, server.URL, nil)
	req.Header.Set("Authorization", "Bearer must-not-be-used")
	req.Header.Set("X-User-Name", "spoofed")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if calls.Load() != 1 || req.Header.Get("Authorization") != "Bearer must-not-be-used" || req.Header.Get("X-User-Name") != "spoofed" {
		t.Fatal("client mutated the original request")
	}
	missing, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	missing.Header.Set("Authorization", "Bearer not-verified")
	if _, err := client.Do(missing); !errors.Is(err, ErrMissingAccessToken) || calls.Load() != 1 {
		t.Fatal("unverified Authorization header was forwarded")
	}
}

func TestOutgoingClientNeverFollowsRedirects(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	base := &http.Client{}
	client := NewHTTPClient(base, RequestTokenSource{})
	req, _ := http.NewRequestWithContext(authenticatedContext(context.Background(), Principal{Subject: "alice"}, "accepted-token"), http.MethodPost, redirect.URL, strings.NewReader("write"))
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || leaked.Load() || base.Transport != nil || base.CheckRedirect != nil {
		t.Fatal("redirect followed or caller's client was modified")
	}
}

func TestRejectedWorkerCredentialIsInvalidatedWithoutReplayingWrite(t *testing.T) {
	f := newProvider(t)
	var grants atomic.Int32
	f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		grants.Add(1)
		_, _ = io.WriteString(w, `{"access_token":"`+workerJWT(t, f, time.Now(), nil)+`","token_type":"Bearer","expires_in":3600}`)
	}
	source := newWorkerSource(t, f)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writes.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	client := NewHTTPClient(nil, source)
	for attempt := 1; attempt <= 2; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("mutation"))
		if _, err := client.Do(req); !errors.Is(err, ErrTokenUnavailable) {
			t.Fatalf("unexpected error: %v", err)
		}
		if writes.Load() != int32(attempt) || grants.Load() != int32(attempt) {
			t.Fatal("write replayed or next attempt reused the rejected token")
		}
	}
}
