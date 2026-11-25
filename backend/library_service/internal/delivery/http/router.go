package http

import (
	stdhttp "net/http"

	"github.com/gorilla/mux"
	"libriary_system/shared/auth"
)

func NewRouter(handler *Handler, userAuth, workerAuth *auth.Middleware) stdhttp.Handler {
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(userAuth.Authenticate)

	internal := router.PathPrefix("/internal/v1").Subrouter()
	internal.Use(workerAuth.Authenticate, auth.RequireClientCredentials, auth.RequireScopes(auth.ReturnsCompleteScope))
	internal.HandleFunc("/libraries/{libraryUid}/books/{bookUid}", handler.GetBook).Methods(stdhttp.MethodGet)
	internal.HandleFunc("/libraries/{libraryUid}/books/{bookUid}/return", handler.ReturnBook).Methods(stdhttp.MethodPost)

	api.HandleFunc("/libraries", handler.ListLibraries).Methods(stdhttp.MethodGet)
	api.HandleFunc("/libraries/{libraryUid}", handler.GetLibrary).Methods(stdhttp.MethodGet)
	api.HandleFunc("/libraries/{libraryUid}/books", handler.ListBooks).Methods(stdhttp.MethodGet)
	api.HandleFunc(
		"/libraries/{libraryUid}/books/{bookUid}",
		handler.GetBook,
	).Methods(stdhttp.MethodGet)
	api.HandleFunc(
		"/libraries/{libraryUid}/books/{bookUid}/reserve",
		handler.ReserveBook,
	).Methods(stdhttp.MethodPost)
	api.HandleFunc(
		"/libraries/{libraryUid}/books/{bookUid}/return",
		handler.ReturnBook,
	).Methods(stdhttp.MethodPost)

	router.HandleFunc("/manage/health", func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writeJSON(w, stdhttp.StatusOK, map[string]string{"status": "ok"})
	}).Methods(stdhttp.MethodGet)

	return router
}
