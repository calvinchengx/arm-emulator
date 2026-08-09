// Package tlscert generates the emulator's self-signed TLS certificate
// (localhost + the Key Vault wildcard), persisted under dataDir/tls when a
// data directory is configured so the fingerprint stays stable across runs.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Hosts the certificate covers — local addressing plus the ARM hostname so
// DNS-pinned SDK use (management.azure.com -> 127.0.0.1) verifies.
var Hosts = []string{
	"localhost", "arm-emulator", "management.azure.com", "management.core.windows.net",
}

// Load returns a certificate, generating (and persisting when dataDir is
// non-empty) one if needed.
func Load(dataDir string) (tls.Certificate, error) {
	if dataDir != "" {
		certPath := filepath.Join(dataDir, "tls", "cert.pem")
		keyPath := filepath.Join(dataDir, "tls", "key.pem")
		if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			return c, nil
		}
		certPEM, keyPEM, err := generate()
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	certPEM, keyPEM, err := generate()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generate() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "arm-emulator"},
		NotBefore:    time.Now().Add(-time.Hour),
		// 397 days, not the ten years this used to be. Apple refuses to
		// trust a TLS server certificate valid for more than 825 days, so a
		// long-lived one cannot be verified by ANY client on macOS built on
		// the platform trust stack — .NET included — even when the developer
		// deliberately trusts the file. 397 is the CA/Browser Forum maximum
		// for public TLS, and sibling entra-emulator is already inside the
		// limit. Regenerating is a delete of tls/ in the data directory.
		NotAfter:              time.Now().AddDate(0, 0, 397),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              Hosts,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Pool returns a CertPool holding the emulator's own persisted certificate.
//
// A self-signed certificate is its own certificate authority, so pinning it
// lets a local probe VERIFY the connection rather than skip verification —
// the same move the e2e harnesses make when they hand the `az` CLI a CA
// bundle instead of turning checking off. It fails when there is nothing to
// pin (an ephemeral instance keeps its key only in memory).
func Pool(dataDir string) (*x509.CertPool, error) {
	if dataDir == "" {
		return nil, errors.New("no data directory: this instance's certificate is ephemeral and cannot be pinned")
	}
	path := filepath.Join(dataDir, "tls", "cert.pem")
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}
	return pool, nil
}
