package http_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	libraryclient "libriary_system/gateway_service/internal/client/library"
	ratingclient "libriary_system/gateway_service/internal/client/rating"
	reservationclient "libriary_system/gateway_service/internal/client/reservation"
	gatewayhttp "libriary_system/gateway_service/internal/delivery/http"
	"libriary_system/gateway_service/internal/usecase"
	"libriary_system/internal/testauth"
	"libriary_system/shared/auth"
)

func TestGatewayJWTForwardedToAllDependencies(t *testing.T) {
	p := testauth.NewProvider(t)
	userToken := p.Issue(t, "auth0|alice", p.Config.Audience, "openid profile", time.Now().Add(time.Hour))
	var downstreamCalls atomic.Int32
	dependency := func(body string) *httptest.Server {
		server := httptest.NewServer(p.Middleware(t, p.Config.Audience).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			downstreamCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+userToken || r.Header.Get("X-User-Name") != "" || auth.SubjectFromContext(r.Context()) != "auth0|alice" {
				t.Error("Gateway did not forward the accepted identity/token")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})))
		t.Cleanup(server.Close)
		return server
	}
	libraries, err := libraryclient.NewClient(dependency(`{"items":[],"total":0}`).URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ratings, err := ratingclient.NewClient(dependency(`{"stars":75}`).URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := reservationclient.NewClient(dependency(`[]`).URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gatewayhttp.NewRouter(gatewayhttp.NewHandler(usecase.NewGatewayUseCase(libraries, ratings, reservations, nil)), p.Middleware(t, p.Config.Audience))
	testauth.CheckProtected(t, router, "GET /api/v1/libraries", "GET /api/v1/libraries/"+uuid.NewString()+"/books", "GET /api/v1/rating", "GET /api/v1/reservations", "POST /api/v1/reservations", "POST /api/v1/reservations/"+uuid.NewString()+"/return")
	for _, path := range []string{"/api/v1/libraries?city=Москва", "/api/v1/rating", "/api/v1/reservations"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("X-User-Name", "spoofed")
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", path, res.Code, res.Body.String())
		}
	}
	for _, token := range []string{
		p.Issue(t, "auth0|alice", p.Config.Audience, "openid", time.Now().Add(-time.Minute)),
		p.Issue(t, "worker@clients", p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour)),
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rating", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("wrong/expired credential status=%d", res.Code)
		}
	}
	if downstreamCalls.Load() != 3 {
		t.Fatal("unauthenticated requests reached dependencies")
	}
}
