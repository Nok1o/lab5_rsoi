// Package auth contains OIDC infrastructure, independent of service domain models.
package auth

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config contains public resource-server settings, not OAuth client secrets.
type Config struct {
	Issuer           string
	Audience         string
	InternalAudience string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Issuer:           strings.TrimSpace(os.Getenv("OIDC_ISSUER")),
		Audience:         strings.TrimSpace(os.Getenv("OIDC_AUDIENCE")),
		InternalAudience: strings.TrimSpace(os.Getenv("OIDC_INTERNAL_AUDIENCE")),
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if _, err := httpsURL(c.Issuer); err != nil {
		return fmt.Errorf("OIDC_ISSUER must be an absolute HTTPS URL without credentials, query or fragment")
	}
	if strings.TrimSpace(c.Audience) == "" || c.Audience != strings.TrimSpace(c.Audience) {
		return fmt.Errorf("OIDC_AUDIENCE must be non-empty and have no surrounding whitespace")
	}
	if strings.TrimSpace(c.InternalAudience) == "" || c.InternalAudience != strings.TrimSpace(c.InternalAudience) {
		return fmt.Errorf("OIDC_INTERNAL_AUDIENCE must be non-empty and have no surrounding whitespace")
	}
	if c.Audience == c.InternalAudience {
		return fmt.Errorf("OIDC_AUDIENCE and OIDC_INTERNAL_AUDIENCE must differ")
	}
	return nil
}

func httpsURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.Contains(value, "#") {
		return nil, fmt.Errorf("invalid HTTPS URL")
	}
	return u, nil
}

// WorkerConfig belongs only to Gateway. Resource servers need public keys only.
type WorkerConfig struct {
	ClientID     string
	ClientSecret string
}

func LoadWorkerConfig() (WorkerConfig, error) {
	cfg := WorkerConfig{
		ClientID:     strings.TrimSpace(os.Getenv("OIDC_WORKER_CLIENT_ID")),
		ClientSecret: os.Getenv("OIDC_WORKER_CLIENT_SECRET"),
	}
	if cfg.ClientID == "" || strings.TrimSpace(cfg.ClientSecret) == "" {
		return WorkerConfig{}, fmt.Errorf("OIDC_WORKER_CLIENT_ID and OIDC_WORKER_CLIENT_SECRET are required for Gateway")
	}
	return cfg, nil
}

func (c WorkerConfig) String() string {
	return fmt.Sprintf("{ClientID:%s ClientSecret:[REDACTED]}", c.ClientID)
}

func (c WorkerConfig) GoString() string { return c.String() }
