package auth

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("OIDC_ISSUER", " https://tenant.example/ ")
	t.Setenv("OIDC_AUDIENCE", " https://library-system ")
	t.Setenv("OIDC_INTERNAL_AUDIENCE", " https://library-system/internal ")
	cfg, err := LoadConfig()
	if err != nil || cfg.Issuer != "https://tenant.example/" || cfg.Audience != "https://library-system" || cfg.InternalAudience != "https://library-system/internal" {
		t.Fatalf("LoadConfig() = %+v, %v", cfg, err)
	}
}

func TestConfigRejectsInvalidSettings(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"http issuer", func(c *Config) { c.Issuer = "http://tenant.example/" }},
		{"relative issuer", func(c *Config) { c.Issuer = "/tenant" }},
		{"issuer credentials", func(c *Config) { c.Issuer = "https://user:secret@tenant.example/" }},
		{"issuer query", func(c *Config) { c.Issuer = "https://tenant.example/?query=true" }},
		{"issuer fragment", func(c *Config) { c.Issuer = "https://tenant.example/#fragment" }},
		{"missing audience", func(c *Config) { c.Audience = "" }},
		{"missing internal audience", func(c *Config) { c.InternalAudience = "" }},
		{"equal audiences", func(c *Config) { c.InternalAudience = c.Audience }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Issuer: "https://tenant.example/", Audience: "public", InternalAudience: "internal"}
			tc.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestWorkerConfig(t *testing.T) {
	t.Setenv("OIDC_WORKER_CLIENT_ID", " worker-test ")
	t.Setenv("OIDC_WORKER_CLIENT_SECRET", "test-secret")
	cfg, err := LoadWorkerConfig()
	if err != nil || cfg.ClientID != "worker-test" || cfg.ClientSecret != "test-secret" {
		t.Fatalf("unexpected worker config: %v", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, cfg), "test-secret") {
			t.Fatalf("secret leaked with format %s", format)
		}
	}
	for _, key := range []string{"OIDC_WORKER_CLIENT_ID", "OIDC_WORKER_CLIENT_SECRET"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "")
			if _, err := LoadWorkerConfig(); err == nil {
				t.Fatal("expected missing worker credentials error")
			}
		})
	}
}
