package auth

// Multi-issuer validation: tokens from any trusted issuer validate against
// that issuer's own JWKS, and the verifying key is bound to the iss claim.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func jwksServer(t *testing.T, kid string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func TestMultiIssuer(t *testing.T) {
	srvA, keyA := jwksServer(t, "kid-a")
	srvB, keyB := jwksServer(t, "kid-b")
	now := int64(1_700_000_000)
	v := NewMulti([][2]string{
		{"https://issuer-a/t/v2.0", srvA.URL},
		{"https://issuer-b/t/v2.0", srvB.URL},
	}, false, func() int64 { return now }, srvA.Client())

	// A token from each issuer validates.
	for _, c := range []struct {
		iss string
		key *rsa.PrivateKey
		kid string
	}{
		{"https://issuer-a/t/v2.0", keyA, "kid-a"},
		{"https://issuer-b/t/v2.0", keyB, "kid-b"},
	} {
		tok := mint(t, c.key, mintOpts{iss: c.iss, aud: "https://management.azure.com",
			exp: now + 600, oid: "user-1", kid: c.kid})
		if _, err := v.Validate(tok); err != nil {
			t.Fatalf("token from %s rejected: %v", c.iss, err)
		}
	}

	// Cross-wiring is refused: issuer A's iss claim signed by B's key. The
	// signature verifies under B's key, but the key is bound to issuer B.
	tok := mint(t, keyB, mintOpts{iss: "https://issuer-a/t/v2.0",
		aud: "https://management.azure.com", exp: now + 600, oid: "user-1", kid: "kid-b"})
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("issuer-a claim signed by issuer-b's key was accepted")
	}
	// An unknown issuer's token is refused even with a known key id shape.
	tok = mint(t, keyA, mintOpts{iss: "https://issuer-c/t/v2.0",
		aud: "https://management.azure.com", exp: now + 600, oid: "user-1", kid: "kid-a"})
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("unknown issuer accepted")
	}
}

// TestValidatePayloadFailures: the signature covers the header and payload
// strings, so a token can verify cryptographically yet carry a payload that
// is not base64url or not JSON — both must be refused after the signature
// check, never before it.
func TestValidatePayloadFailures(t *testing.T) {
	srv, key := jwksServer(t, "kid-p")
	now := int64(1_700_000_000)
	v := NewMulti([][2]string{{"https://iss/t/v2.0", srv.URL}}, false, func() int64 { return now }, srv.Client())

	head := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "kid-p"})
	for name, payload := range map[string]string{
		"not base64url": "!!!not-base64!!!",
		"not JSON":      base64.RawURLEncoding.EncodeToString([]byte("plain text, not json")),
	} {
		signing := head + "." + payload
		digest := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		token := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := v.Validate(token); err == nil {
			t.Fatalf("%s payload accepted", name)
		}
	}
}

// TestRefreshSkipsUnusableKeys: a JWKS entry whose modulus or exponent is not
// base64url is skipped rather than poisoning the cache.
func TestRefreshSkipsUnusableKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[
			{"kty":"RSA","kid":"bad-n","n":"!!!","e":"AQAB"},
			{"kty":"RSA","kid":"bad-e","n":"AQAB","e":"!!!"},
			{"kty":"oct","kid":"not-rsa","n":"AQAB","e":"AQAB"},
			{"kty":"RSA","kid":"good","n":"AQAB","e":"AQAB"}]}`))
	}))
	defer srv.Close()
	v := NewMulti([][2]string{{"https://iss/t/v2.0", srv.URL}}, false, func() int64 { return 0 }, srv.Client())
	if err := v.refresh(v.issuers[0]); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, _, err := v.key("good"); err != nil {
		t.Fatalf("usable key not cached: %v", err)
	}
	for _, kid := range []string{"bad-n", "bad-e", "not-rsa"} {
		if _, _, err := v.key(kid); err == nil {
			t.Fatalf("unusable key %q was cached", kid)
		}
	}
}
