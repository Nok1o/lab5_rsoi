package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	setAuthEnv(t)
	for _, key := range []string{"PORT", "DATABASE_URL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_SSLMODE"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddress != ":8070" || !strings.Contains(cfg.DatabaseURL, "/reservations?") {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.OIDC.Issuer != "https://tenant.example/" {
		t.Fatalf("unexpected auth configuration: %+v", cfg.OIDC)
	}
}

func setAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER", "https://tenant.example/")
	t.Setenv("OIDC_AUDIENCE", "https://library-system")
	t.Setenv("OIDC_INTERNAL_AUDIENCE", "https://library-system/internal")
	t.Setenv("OIDC_WORKER_CLIENT_ID", "")
	t.Setenv("OIDC_WORKER_CLIENT_SECRET", "")
}

func TestLoadRejectsMissingAuth(t *testing.T) {
	setAuthEnv(t)
	t.Setenv("PORT", "8070")
	t.Setenv("DATABASE_URL", "postgres://localhost/reservations")
	t.Setenv("OIDC_ISSUER", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing issuer error")
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	t.Setenv("PORT", "70000")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid port error")
	}
	t.Setenv("PORT", "8070")
	t.Setenv("DATABASE_URL", "postgres://localhost")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid database URL error")
	}
}
