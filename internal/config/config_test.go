package config

import (
	"strings"
	"testing"
)

func TestFromEnvDefaultsAndOverrides(t *testing.T) {
	// Defaults when nothing is set (beyond the required issuer).
	t.Setenv("ARM_ENTRA_ISSUER", "https://localhost:8443/tid/v2.0")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":8445" || c.SubscriptionID != DefaultSubscription || c.TenantID != DefaultTenant {
		t.Fatalf("defaults = %+v", c)
	}
	if c.EntraJWKSURL != "https://localhost:8443/tid/discovery/v2.0/keys" {
		t.Fatalf("derived JWKS = %q", c.EntraJWKSURL)
	}
	if c.DisableTLS || c.EntraTLSInsecure {
		t.Fatal("boolean defaults should be off")
	}

	// Every override reads through, and the bool forms all count as true.
	t.Setenv("ARM_ADDR", ":9000")
	t.Setenv("ARM_DATA_DIR", "/tmp/armstate")
	t.Setenv("ARM_SUBSCRIPTION_ID", "sub-1")
	t.Setenv("ARM_TENANT_ID", "tenant-1")
	t.Setenv("ARM_ENTRA_JWKS_URL", "https://elsewhere/keys")
	t.Setenv("ARM_ENTRA_TLS_INSECURE", "TRUE")
	t.Setenv("ARM_DISABLE_TLS", "yes")
	c, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":9000" || c.DataDir != "/tmp/armstate" || c.SubscriptionID != "sub-1" ||
		c.TenantID != "tenant-1" || c.EntraJWKSURL != "https://elsewhere/keys" ||
		!c.EntraTLSInsecure || !c.DisableTLS {
		t.Fatalf("overrides = %+v", c)
	}
}

func TestFinishValidation(t *testing.T) {
	// The issuer is required and must be a URL.
	c := &Config{SubscriptionID: "s"}
	if err := c.Finish(); err == nil || !strings.Contains(err.Error(), "ARM_ENTRA_ISSUER is required") {
		t.Fatalf("missing issuer = %v", err)
	}
	c = &Config{EntraIssuer: "not-a-url", SubscriptionID: "s"}
	if err := c.Finish(); err == nil || !strings.Contains(err.Error(), "is not a URL") {
		t.Fatalf("bad issuer = %v", err)
	}
	// An empty subscription is refused.
	c = &Config{EntraIssuer: "https://e/t/v2.0"}
	if err := c.Finish(); err == nil || !strings.Contains(err.Error(), "ARM_SUBSCRIPTION_ID") {
		t.Fatalf("empty subscription = %v", err)
	}
}

func TestMultiIssuerConfig(t *testing.T) {
	c := &Config{
		EntraIssuer:    " https://a/t1/v2.0 , https://b/t2/v2.0 ,, ",
		SubscriptionID: "s",
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if got := c.Issuers(); len(got) != 2 || got[0] != "https://a/t1/v2.0" || got[1] != "https://b/t2/v2.0" {
		t.Fatalf("Issuers = %v", got)
	}
	pairs := c.IssuerJWKS()
	if len(pairs) != 2 {
		t.Fatalf("pairs = %v", pairs)
	}
	// Each issuer derives its own JWKS; the first honours an explicit override.
	if pairs[1][1] != "https://b/t2/discovery/v2.0/keys" {
		t.Fatalf("second JWKS = %q", pairs[1][1])
	}
	c.EntraJWKSURL = "https://explicit/keys"
	if got := c.IssuerJWKS(); got[0][1] != "https://explicit/keys" ||
		got[1][1] != "https://b/t2/discovery/v2.0/keys" {
		t.Fatalf("explicit override = %v", got)
	}
	// A second issuer that is not a URL fails validation.
	bad := &Config{EntraIssuer: "https://a/t/v2.0,nope", SubscriptionID: "s"}
	if err := bad.Finish(); err == nil {
		t.Fatal("invalid second issuer accepted")
	}
}

// TestLRODelayEnv: the async knobs come from the environment like every
// other setting, and a value that is not a number falls back rather than
// failing a boot.
func TestLRODelayEnv(t *testing.T) {
	t.Setenv("ARM_ENTRA_ISSUER", "https://e/t/v2.0")
	t.Setenv("ARM_LRO_DELAY_SECONDS", "300")
	t.Setenv("ARM_RETRY_AFTER_SECONDS", "7")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.LRODelaySeconds != 300 || c.RetryAfterSeconds != 7 {
		t.Fatalf("lro knobs = %d / %d", c.LRODelaySeconds, c.RetryAfterSeconds)
	}

	t.Setenv("ARM_LRO_DELAY_SECONDS", "not-a-number")
	t.Setenv("ARM_RETRY_AFTER_SECONDS", "0")
	c, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// Unparseable falls back to the default, and Finish floors Retry-After
	// at one second so a poller is never told to retry immediately.
	if c.LRODelaySeconds != 0 || c.RetryAfterSeconds != 1 {
		t.Fatalf("fallback knobs = %d / %d", c.LRODelaySeconds, c.RetryAfterSeconds)
	}
}
