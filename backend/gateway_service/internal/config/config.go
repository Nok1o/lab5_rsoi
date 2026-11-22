package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"libriary_system/shared/auth"
)

type Config struct {
	HTTPAddress           string
	LibraryServiceURL     string
	RatingServiceURL      string
	ReservationServiceURL string
	RedisURL              string
	OIDC                  auth.Config
	Worker                auth.WorkerConfig
}

func Load() (Config, error) {
	port := envOrDefault("PORT", "8080")
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("PORT must be an integer between 1 and 65535")
	}
	oidc, err := auth.LoadConfig()
	if err != nil {
		return Config{}, err
	}
	worker, err := auth.LoadWorkerConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{
		HTTPAddress:           ":" + port,
		LibraryServiceURL:     envOrDefault("LIBRARY_SERVICE_URL", "http://localhost:8060"),
		RatingServiceURL:      envOrDefault("RATING_SERVICE_URL", "http://localhost:8050"),
		ReservationServiceURL: envOrDefault("RESERVATION_SERVICE_URL", "http://localhost:8070"),
		RedisURL:              envOrDefault("REDIS_URL", "redis://localhost:6379/0"),
		OIDC:                  oidc,
		Worker:                worker,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
