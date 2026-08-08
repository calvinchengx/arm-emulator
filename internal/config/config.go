// Package config resolves runtime configuration from ARM_* environment
// variables with flag overrides applied by cmd. The docker-compose contract
// (ARM_ENTRA_ISSUER, ARM_ENTRA_TLS_INSECURE) is the canonical wiring to
// entra-emulator, matching the sibling emulators.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is the resolved emulator configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8445".
	Addr string
	// DataDir holds SQLite and TLS state. Empty means in-memory DB and
	// ephemeral TLS keys.
	DataDir string

	// EntraIssuer is the exact iss expected in bearer tokens. A
	// comma-separated list trusts several issuers, each against its own JWKS.
	EntraIssuer string
	// EntraJWKSURL is where signing keys are fetched; derived from the
	// issuer when unset.
	EntraJWKSURL string
	// EntraTLSInsecure skips TLS verification when fetching JWKS.
	EntraTLSInsecure bool

	// SubscriptionID is the seeded subscription every resource lives under.
	SubscriptionID string
	// TenantID is reported by /tenants and on subscription resources.
	TenantID string
	// DisableTLS serves plain HTTP.
	DisableTLS bool
}

// Defaults shared with the family's compose file and docs.
const (
	DefaultSubscription = "6082bfda-63d0-46f4-8272-ae9195139feb"
	DefaultTenant       = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
)

// FromEnvPartial reads the environment without validating — cmd applies flag
// overrides first, then calls Finish.
func FromEnvPartial() *Config {
	return &Config{
		Addr:             envOr("ARM_ADDR", ":8445"),
		DataDir:          os.Getenv("ARM_DATA_DIR"),
		EntraIssuer:      os.Getenv("ARM_ENTRA_ISSUER"),
		EntraJWKSURL:     os.Getenv("ARM_ENTRA_JWKS_URL"),
		EntraTLSInsecure: boolEnv("ARM_ENTRA_TLS_INSECURE"),
		SubscriptionID:   envOr("ARM_SUBSCRIPTION_ID", DefaultSubscription),
		TenantID:         envOr("ARM_TENANT_ID", DefaultTenant),
		DisableTLS:       boolEnv("ARM_DISABLE_TLS"),
	}
}

// FromEnv builds a validated Config.
func FromEnv() (*Config, error) {
	c := FromEnvPartial()
	return c, c.Finish()
}

// Issuers returns the trusted issuers in order.
func (c *Config) Issuers() []string {
	var out []string
	for _, s := range strings.Split(c.EntraIssuer, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// IssuerJWKS returns ordered {issuer, jwksURL} pairs. An explicit
// ARM_ENTRA_JWKS_URL applies to the first issuer only.
func (c *Config) IssuerJWKS() [][2]string {
	var out [][2]string
	for i, iss := range c.Issuers() {
		base := strings.TrimSuffix(strings.TrimSuffix(iss, "/"), "/v2.0")
		jwks := base + "/discovery/v2.0/keys"
		if i == 0 && c.EntraJWKSURL != "" {
			jwks = c.EntraJWKSURL
		}
		out = append(out, [2]string{iss, jwks})
	}
	return out
}

// Finish validates and derives dependent fields. Call after flag overrides.
func (c *Config) Finish() error {
	issuers := c.Issuers()
	if len(issuers) == 0 {
		return fmt.Errorf("ARM_ENTRA_ISSUER is required: the issuer bearer tokens must carry (an entra-emulator or real Entra v2.0 issuer URL)")
	}
	if c.EntraJWKSURL == "" {
		base := strings.TrimSuffix(strings.TrimSuffix(issuers[0], "/"), "/v2.0")
		c.EntraJWKSURL = base + "/discovery/v2.0/keys"
	}
	for _, iss := range issuers {
		if u, err := url.Parse(iss); err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("ARM_ENTRA_ISSUER %q is not a URL", iss)
		}
	}
	if c.SubscriptionID == "" {
		return fmt.Errorf("ARM_SUBSCRIPTION_ID must not be empty")
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolEnv(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
