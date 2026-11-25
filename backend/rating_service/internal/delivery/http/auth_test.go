package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"libriary_system/internal/testauth"
	ratinghttp "libriary_system/rating_service/internal/delivery/http"
	"libriary_system/rating_service/internal/domain"
	"libriary_system/rating_service/internal/usecase"
	"libriary_system/shared/auth"
)

func TestRatingJWTIdentityAndWorkerTarget(t *testing.T) {
	p := testauth.NewProvider(t)
	repo := &memoryRepo{ratings: map[string]domain.Rating{"auth0|alice": {Username: "auth0|alice", StarsCount: 50}, "bob": {Username: "bob", StarsCount: 20}}}
	router := ratinghttp.NewRouter(ratinghttp.NewHandler(usecase.NewRatingUseCase(repo)), p.Middleware(t, p.Config.Audience), p.Middleware(t, p.Config.InternalAudience))
	testauth.CheckProtected(t, router, "GET /api/v1/rating", "POST /api/v1/rating", "PUT /api/v1/rating", "PATCH /api/v1/rating", "PATCH /internal/v1/rating")
	user := p.Issue(t, "auth0|alice", p.Config.Audience, "openid profile", time.Now().Add(time.Hour))
	worker := p.Issue(t, "worker@clients", p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour))
	internalUser := p.Issue(t, "auth0|alice", p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour))
	for _, tc := range []struct {
		method, path, token, body string
		status                    int
	}{
		{http.MethodGet, "/api/v1/rating", user, "", 200},
		{http.MethodPatch, "/api/v1/rating", user, `{"delta":1}`, 200},
		{http.MethodPatch, "/api/v1/rating", user, `{"username":"bob","delta":1}`, 400},
		{http.MethodPatch, "/internal/v1/rating", user, `{"username":"bob","delta":1}`, 401},
		{http.MethodPatch, "/api/v1/rating", worker, `{"delta":1}`, 401},
		{http.MethodPatch, "/internal/v1/rating", internalUser, `{"username":"bob","delta":1}`, 403},
		{http.MethodPatch, "/internal/v1/rating", worker, `{"username":"bob","delta":1}`, 200},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("X-User-Name", "bob")
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != tc.status {
			t.Fatalf("%s %s: status=%d body=%s", tc.method, tc.path, res.Code, res.Body.String())
		}
	}
	if repo.ratings["auth0|alice"].StarsCount != 51 || repo.ratings["bob"].StarsCount != 21 {
		t.Fatal("user/worker identities were confused")
	}
	if _, ok := repo.ratings["worker@clients"]; ok {
		t.Fatal("worker identity must not replace the target user")
	}
}
