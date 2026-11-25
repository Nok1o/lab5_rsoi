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
	api.HandleFunc("/reservations", handler.ListReservations).Methods(stdhttp.MethodGet)
	api.HandleFunc("/reservations", handler.Rent).Methods(stdhttp.MethodPost)
	api.HandleFunc("/reservations/count", handler.CountReservations).Methods(stdhttp.MethodGet)
	api.HandleFunc("/reservations/{reservationUid}", handler.GetReservation).Methods(stdhttp.MethodGet)
	api.HandleFunc("/reservations/{reservationUid}", handler.Cancel).Methods(stdhttp.MethodDelete)
	api.HandleFunc("/reservations/{reservationUid}/return", handler.Return).Methods(stdhttp.MethodPost)
	router.HandleFunc("/manage/health", func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writeJSON(w, stdhttp.StatusOK, map[string]string{"status": "ok"})
	}).Methods(stdhttp.MethodGet)
	return router
}
