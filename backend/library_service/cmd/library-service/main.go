package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"libriary_system/library_service/internal/config"
	libraryhttp "libriary_system/library_service/internal/delivery/http"
	"libriary_system/library_service/internal/repository/postgres"
	"libriary_system/library_service/internal/usecase"
	"libriary_system/shared/auth"
	"libriary_system/shared/log"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Error("load configuration", "error", err)
		os.Exit(1)
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()

	verifier, err := auth.NewVerifier(startupCtx, cfg.OIDC, nil)
	if err != nil {
		log.Error("initialize OIDC verifier", "error", err)
		os.Exit(1)
	}
	userAuth, err := auth.NewMiddleware(verifier, cfg.OIDC.Audience)
	if err != nil {
		log.Error("configure user authentication", "error", err)
		os.Exit(1)
	}
	workerAuth, err := auth.NewMiddleware(verifier, cfg.OIDC.InternalAudience)
	if err != nil {
		log.Error("configure worker authentication", "error", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(startupCtx, cfg.DatabaseURL)
	if err != nil {
		log.Error("create database pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(startupCtx); err != nil {
		log.Error("connect to database", "error", err)
		os.Exit(1)
	}

	repository := postgres.NewLibraryPGRepo(pool)
	libraryUseCase := usecase.NewLibraryUseCase(repository)
	handler := libraryhttp.NewHandler(libraryUseCase)
	server := &http.Server{
		Addr:              cfg.HTTPAddress,
		Handler:           libraryhttp.NewRouter(handler, userAuth, workerAuth),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Info("library service started", "address", cfg.HTTPAddress)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case signal := <-signals:
		log.Info("shutdown signal received", "signal", signal.String())
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown", "error", err)
		os.Exit(1)
	}

	log.Info("library service stopped")
}
