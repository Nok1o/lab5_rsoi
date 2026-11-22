package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	setAuthEnv(t)
	for _, key := range []string{"PORT", "LIBRARY_SERVICE_URL", "RATING_SERVICE_URL", "RESERVATION_SERVICE_URL", "REDIS_URL"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddress != ":8080" || cfg.LibraryServiceURL != "http://localhost:8060" || cfg.RatingServiceURL != "http://localhost:8050" || cfg.ReservationServiceURL != "http://localhost:8070" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Fatalf("RedisURL = %q", cfg.RedisURL)
	}
	if cfg.OIDC.Issuer != "https://tenant.example/" || cfg.Worker.ClientID != "worker-test" {
		t.Fatalf("unexpected auth configuration: %+v", cfg.OIDC)
	}
}

func setAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER", "https://tenant.example/")
	t.Setenv("OIDC_AUDIENCE", "https://library-system")
	t.Setenv("OIDC_INTERNAL_AUDIENCE", "https://library-system/internal")
	t.Setenv("OIDC_WORKER_CLIENT_ID", "worker-test")
	t.Setenv("OIDC_WORKER_CLIENT_SECRET", "test-only")
}

func TestLoadRejectsMissingAuth(t *testing.T) {
	for _, key := range []string{"OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_INTERNAL_AUDIENCE", "OIDC_WORKER_CLIENT_ID", "OIDC_WORKER_CLIENT_SECRET"} {
		t.Run(key, func(t *testing.T) {
			setAuthEnv(t)
			t.Setenv("PORT", "8080")
			t.Setenv(key, "")
			if _, err := Load(); err == nil {
				t.Fatalf("expected error for missing %s", key)
			}
		})
	}
}

func TestLoadRejectsInvalidPort(t *testing.T) {
	t.Setenv("PORT", "70000")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid port error")
	}
}
