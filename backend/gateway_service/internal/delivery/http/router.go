package http

import (
	stdhttp "net/http"

	"github.com/gorilla/mux"
	"libriary_system/shared/auth"
)

func NewRouter(handler *Handler, userAuth *auth.Middleware) stdhttp.Handler {
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(userAuth.Authenticate)
	api.HandleFunc("/libraries", handler.ListLibrariesByCity).Methods(stdhttp.MethodGet)
	api.HandleFunc("/libraries/{libraryUid}/books", handler.ListBooksByLibrary).Methods(stdhttp.MethodGet)
	api.HandleFunc("/reservations", handler.ListReservations).Methods(stdhttp.MethodGet)
	api.HandleFunc("/reservations", handler.TakeBook).Methods(stdhttp.MethodPost)
	api.HandleFunc("/reservations/{reservationUid}/return", handler.ReturnBook).Methods(stdhttp.MethodPost)
	api.HandleFunc("/rating", handler.GetRating).Methods(stdhttp.MethodGet)
	router.HandleFunc("/manage/health", func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writeJSON(w, stdhttp.StatusOK, map[string]string{"status": "ok"})
	}).Methods(stdhttp.MethodGet)
	return router
}
