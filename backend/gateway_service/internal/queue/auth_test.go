package queue

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	libraryclient "libriary_system/gateway_service/internal/client/library"
	ratingclient "libriary_system/gateway_service/internal/client/rating"
	"libriary_system/gateway_service/internal/usecase"
	"libriary_system/internal/testauth"
	"libriary_system/shared/auth"
)

func TestDeferredReturnUsesWorkerIdentityWithoutUserToken(t *testing.T) {
	p := testauth.NewProvider(t)
	tokens, err := auth.NewClientCredentialsSource(auth.WorkerConfig{ClientID: "worker", ClientSecret: "fake-secret"}, p.Verifier(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	job := testJob("auth0|alice")
	job.Stage = usecase.ReturnStageRestoreBook
	job.OriginalCondition = ""
	initial := job
	targetUser, bookUID := job.Username, job.BookUID
	// The initiating user's JWT is expired. It is not available to the worker.
	expired := p.Issue(t, job.Username, p.Config.Audience, "openid profile", time.Now().Add(-time.Hour))
	var calls atomic.Int32
	var failRating atomic.Bool
	var failedRating atomic.Bool
	middleware := p.Middleware(t, p.Config.InternalAudience)
	server := httptest.NewServer(middleware.Authenticate(auth.RequireScopes(auth.ReturnsCompleteScope)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		principal, _ := auth.PrincipalFromContext(r.Context())
		if principal.Subject != "worker@clients" || r.Header.Get("Authorization") == "Bearer "+expired || r.Header.Get("X-User-Name") != "" {
			t.Error("worker reused user credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/internal/v1/libraries/"):
			_, _ = w.Write([]byte(`{"bookUid":"` + bookUID.String() + `","condition":"EXCELLENT","availableCount":0}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/return"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && r.URL.Path == "/internal/v1/rating":
			var body struct {
				Username string `json:"username"`
				Delta    int    `json:"delta"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Username != targetUser || body.Delta != 1 {
				t.Error("worker did not preserve target user/rating delta")
			}
			if failRating.CompareAndSwap(true, false) {
				failedRating.Store(true)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"stars":76}`))
		default:
			t.Errorf("unexpected worker operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))))
	defer server.Close()
	libraries, err := libraryclient.NewWorkerClient(server.URL, nil, nil, tokens)
	if err != nil {
		t.Fatal(err)
	}
	ratings, err := ratingclient.NewWorkerClient(server.URL, nil, nil, tokens)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewReturnQueue(nil, Config{}, libraries, ratings)
	done := false
	for i := 0; i < 3; i++ {
		job, done, err = queue.processOnce(context.Background(), job)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := encodeJob(job)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, expired) || strings.Contains(payload, "access_token") || strings.Contains(payload, "Authorization") {
			t.Fatal("queued payload contains credentials")
		}
	}
	if !done || calls.Load() != 3 || p.Grants.Load() != 1 {
		t.Fatalf("return unfinished or token cache not used: done=%t calls=%d grants=%d", done, calls.Load(), p.Grants.Load())
	}

	t.Run("Redis pending delivery retries with service credentials", func(t *testing.T) {
		rawURL := os.Getenv("REDIS_TEST_URL")
		if rawURL == "" {
			t.Skip("set REDIS_TEST_URL to run Redis integration test")
		}
		opts, err := redis.ParseURL(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		opts.ContextTimeoutEnabled = true
		client := redis.NewClient(opts)
		stream := "test:{" + uuid.NewString() + "}:auth-returns"
		q := NewReturnQueue(client, Config{Stream: stream, Workers: 1, RetryDelay: 50 * time.Millisecond, AttemptTimeout: 100 * time.Millisecond}, libraries, ratings)
		t.Cleanup(func() { client.Del(context.Background(), stream); client.Close() })
		if err := q.Init(context.Background()); err != nil {
			t.Fatal(err)
		}
		failRating.Store(true)
		if err := q.Enqueue(context.Background(), initial); err != nil {
			t.Fatal(err)
		}
		runQueue(t, q)
		eventually(t, func() bool {
			return failedRating.Load() && client.XPending(context.Background(), stream, q.config.Group).Val().Count == 1
		})
		entries, err := client.XRange(context.Background(), stream, "-", "+").Result()
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			payload := entry.Values["payload"].(string)
			if strings.Contains(payload, expired) || strings.Contains(payload, "access_token") {
				t.Fatal("Redis contains user credentials")
			}
		}
		eventually(t, func() bool { return client.XLen(context.Background(), stream).Val() == 0 })
		if calls.Load() != 7 || p.Grants.Load() != 1 {
			t.Fatalf("unexpected worker attempts or grant count: calls=%d grants=%d", calls.Load(), p.Grants.Load())
		}
	})
}
