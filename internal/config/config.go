// Package config resolves runtime configuration from ARM_* environment
// variables with flag overrides applied by cmd. The docker-compose contract
// (ARM_ENTRA_ISSUER, ARM_ENTRA_TLS_INSECURE) is the canonical wiring to
// entra-emulator, matching the sibling emulators.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is the resolved emulator configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8445".
	Addr string
	// DataDir holds SQLite and TLS state. Defaults to ./data, so a plain
	// `arm-emulator` keeps its role assignments and vaults across restarts —
	// the same posture as entra-emulator, and what people expect of a local
	// control plane they are building against.
	//
	// Setting ARM_DATA_DIR to the EMPTY string opts back into in-memory,
	// which is distinct from leaving it unset. The compose files rely on that
	// distinction to keep a throwaway stack from accumulating a SQLite file in
	// a container layer that is about to be deleted.
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

	// LRODelaySeconds is the virtual time an asynchronous operation stays
	// InProgress. Zero means it is terminal on its first poll — real
	// pollers still walk the full protocol, but CI never waits. Raise it
	// (or freeze the clock) to hold a poller in flight.
	LRODelaySeconds int64
	// RetryAfterSeconds is advertised on 202s and in-progress polls.
	RetryAfterSeconds int
	// VaultRetentionDays is how long a soft-deleted vault stays
	// recoverable. Real Key Vault allows 7-90; the default matches.
	VaultRetentionDays int
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
		Addr:               envOr("ARM_ADDR", ":8445"),
		DataDir:            envDefault("ARM_DATA_DIR", DefaultDataDir),
		EntraIssuer:        os.Getenv("ARM_ENTRA_ISSUER"),
		EntraJWKSURL:       os.Getenv("ARM_ENTRA_JWKS_URL"),
		EntraTLSInsecure:   boolEnv("ARM_ENTRA_TLS_INSECURE"),
		SubscriptionID:     envOr("ARM_SUBSCRIPTION_ID", DefaultSubscription),
		TenantID:           envOr("ARM_TENANT_ID", DefaultTenant),
		DisableTLS:         boolEnv("ARM_DISABLE_TLS"),
		LRODelaySeconds:    int64(intEnv("ARM_LRO_DELAY_SECONDS", 0)),
		RetryAfterSeconds:  intEnv("ARM_RETRY_AFTER_SECONDS", 1),
		VaultRetentionDays: intEnv("ARM_VAULT_RETENTION_DAYS", 90),
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
	if c.RetryAfterSeconds <= 0 {
		c.RetryAfterSeconds = 1
	}
	// Real Key Vault accepts a 7-90 day retention window; anything outside
	// it falls back to the default rather than inventing a policy.
	if c.VaultRetentionDays < 7 || c.VaultRetentionDays > 90 {
		c.VaultRetentionDays = 90
	}
	return nil
}

// DefaultDataDir is where state lands when ARM_DATA_DIR is not set at all.
const DefaultDataDir = "./data"

// envDefault distinguishes UNSET from SET-EMPTY, which envOr cannot: unset
// takes the default, while an explicit empty value is honoured as empty. For
// DataDir that difference is the difference between persisting and not.
func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
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

// intEnv reads an integer environment variable, falling back to def when
// unset or unparseable.
func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
