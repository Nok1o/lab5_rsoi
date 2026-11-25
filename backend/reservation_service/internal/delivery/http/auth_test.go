package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"libriary_system/internal/testauth"
	reservationhttp "libriary_system/reservation_service/internal/delivery/http"
	"libriary_system/reservation_service/internal/domain"
	"libriary_system/reservation_service/internal/usecase"
)

func TestReservationJWTProtectionAndOwnership(t *testing.T) {
	p := testauth.NewProvider(t)
	uid := uuid.New()
	repo := &memoryRepo{items: map[uuid.UUID]domain.Reservation{uid: {Id: uid, Username: "auth0|alice", Status: domain.StatusRented}}}
	router := reservationhttp.NewRouter(reservationhttp.NewHandler(usecase.NewReservationUseCase(repo)), p.Middleware(t, p.Config.Audience))
	path := "/api/v1/reservations/" + uid.String()
	testauth.CheckProtected(t, router, "GET /api/v1/reservations", "POST /api/v1/reservations", "GET /api/v1/reservations/count", "GET "+path, "DELETE "+path, "POST "+path+"/return")
	for _, tc := range []struct {
		subject string
		status  int
	}{{"auth0|alice", 200}, {"auth0|bob", 404}} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+p.Issue(t, tc.subject, p.Config.Audience, "openid profile", time.Now().Add(time.Hour)))
		req.Header.Set("X-User-Name", "auth0|alice")
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != tc.status {
			t.Fatalf("subject=%s status=%d", tc.subject, res.Code)
		}
	}
}
