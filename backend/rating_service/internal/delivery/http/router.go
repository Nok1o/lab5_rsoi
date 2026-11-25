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
	api.HandleFunc("/rating", handler.GetRating).Methods(stdhttp.MethodGet)
	api.HandleFunc("/rating", handler.CreateRating).Methods(stdhttp.MethodPost)
	api.HandleFunc("/rating", handler.UpdateRating).Methods(stdhttp.MethodPut)
	api.HandleFunc("/rating", handler.AddStars).Methods(stdhttp.MethodPatch)
	internal := router.PathPrefix("/internal/v1").Subrouter()
	internal.Use(workerAuth.Authenticate, auth.RequireClientCredentials, auth.RequireScopes(auth.ReturnsCompleteScope))
	internal.HandleFunc("/rating", handler.AddStarsForUser).Methods(stdhttp.MethodPatch)
	router.HandleFunc("/manage/health", func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writeJSON(w, stdhttp.StatusOK, map[string]string{"status": "ok"})
	}).Methods(stdhttp.MethodGet)
	return router
}
