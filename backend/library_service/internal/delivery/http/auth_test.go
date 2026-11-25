package http

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"libriary_system/internal/testauth"
	"libriary_system/library_service/internal/domain"
	"libriary_system/shared/auth"
)

type workerLibraryStub struct {
	LibraryUseCase
	returns int
}

func (*workerLibraryStub) GetBookByUID(context.Context, uuid.UUID, uuid.UUID) (domain.LibraryBook, error) {
	return domain.LibraryBook{}, nil
}
func (s *workerLibraryStub) ReturnBook(context.Context, uuid.UUID, uuid.UUID, domain.BookCondition) error {
	s.returns++
	return nil
}

func TestLibraryJWTProtectionAndNarrowWorkerAccess(t *testing.T) {
	p := testauth.NewProvider(t)
	stub := &workerLibraryStub{}
	router := NewRouter(NewHandler(stub), p.Middleware(t, p.Config.Audience), p.Middleware(t, p.Config.InternalAudience))
	book := "/libraries/" + uuid.NewString() + "/books/" + uuid.NewString()
	testauth.CheckProtected(t, router, "GET /api/v1/libraries", "GET /api/v1/libraries/"+uuid.NewString(), "GET /api/v1/libraries/"+uuid.NewString()+"/books", "GET /api/v1"+book, "POST /api/v1"+book+"/reserve", "POST /api/v1"+book+"/return", "GET /internal/v1"+book, "POST /internal/v1"+book+"/return")
	issue := func(audience, scope string, expiration time.Time) string {
		return p.Issue(t, "worker@clients", audience, scope, expiration)
	}
	for _, tc := range []struct {
		token, path string
		status      int
	}{
		{issue(p.Config.Audience, "openid", time.Now().Add(time.Hour)), "/internal/v1" + book + "/return", 401},
		{issue(p.Config.InternalAudience, "openid", time.Now().Add(time.Hour)), "/internal/v1" + book + "/return", 403},
		{issue(p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(-time.Minute)), "/internal/v1" + book + "/return", 401},
		{issue(p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour)), "/api/v1" + book + "/reserve", 401},
		{issue(p.Config.InternalAudience, auth.ReturnsCompleteScope, time.Now().Add(time.Hour)), "/internal/v1" + book + "/return", 204},
	} {
		req := httptest.NewRequest(stdhttp.MethodPost, tc.path, strings.NewReader(`{"condition":"EXCELLENT"}`))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != tc.status {
			t.Fatalf("%s: status=%d want=%d", tc.path, res.Code, tc.status)
		}
	}
	if stub.returns != 1 {
		t.Fatal("unauthorized worker operation changed a book")
	}
}
