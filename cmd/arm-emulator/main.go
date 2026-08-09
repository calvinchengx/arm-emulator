// Command arm-emulator runs the Azure Resource Manager control-plane
// emulator: subscriptions, resource groups, and Microsoft.Authorization role
// definitions and assignments, with ARM-audience bearer tokens validated
// against an Entra issuer (entra-emulator or a real tenant).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/server"
	"github.com/calvinchengx/arm-emulator/internal/tlscert"
)

// version is stamped by GoReleaser via -ldflags "-X main.version=…".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cfg := config.FromEnvPartial()
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println("arm-emulator", version)
			return nil
		case "healthcheck":
			return healthcheck(cfg.Addr, cfg.DataDir)
		}
	}
	fs := flag.NewFlagSet("arm-emulator", flag.ContinueOnError)
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "state directory (empty = in-memory)")
	fs.StringVar(&cfg.EntraIssuer, "entra-issuer", cfg.EntraIssuer, "trusted Entra issuer URL (required)")
	fs.StringVar(&cfg.EntraJWKSURL, "entra-jwks-url", cfg.EntraJWKSURL, "JWKS URL (derived from issuer when empty)")
	fs.BoolVar(&cfg.EntraTLSInsecure, "entra-tls-insecure", cfg.EntraTLSInsecure, "skip TLS verification fetching JWKS")
	fs.StringVar(&cfg.SubscriptionID, "subscription-id", cfg.SubscriptionID, "the seeded subscription id")
	fs.StringVar(&cfg.TenantID, "tenant-id", cfg.TenantID, "the tenant id reported by /tenants")
	fs.BoolVar(&cfg.DisableTLS, "disable-tls", cfg.DisableTLS, "serve plain HTTP")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cfg.Finish(); err != nil {
		return err
	}

	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
			return err
		}
	}
	srv, err := server.New(cfg, nil)
	if err != nil {
		return err
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	scheme := "https"
	if cfg.DisableTLS {
		scheme = "http"
	} else {
		cert, err := tlscert.Load(cfg.DataDir)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	fmt.Printf("arm-emulator listening on %s://%s (issuer: %s, subscription: %s)\n",
		scheme, ln.Addr(), cfg.EntraIssuer, cfg.SubscriptionID)
	return http.Serve(ln, srv.Handler())
}

// healthcheck probes /health locally and exits 0 when healthy — distroless
// images have no shell, so container HEALTHCHECKs exec this binary.
//
// The probe VERIFIES TLS. The emulator's certificate is self-signed, which
// makes it its own certificate authority, so pinning it as the only trusted
// root authenticates this connection against exactly one server — rather
// than disabling verification, which would accept any certificate at all.
// The container image sets ARM_DATA_DIR, so the certificate is on disk where
// this probe can read it. With TLS switched off the plain probe answers; with
// TLS on and no certificate to pin, the error says exactly that rather than
// quietly trusting whatever answered.
func healthcheck(addr, dataDir string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	if pool, err := tlscert.Pool(dataDir); err == nil {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	resp, err := client.Get("https://" + net.JoinHostPort(host, port) + "/health")
	if err != nil {
		// A certificate failure is its own diagnosis: the server is there
		// and speaking TLS, we just have no certificate to trust it by.
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return fmt.Errorf("cannot verify this instance's certificate (%w) — run the healthcheck with "+
				"the same ARM_DATA_DIR as the server, so its self-signed certificate can be pinned", err)
		}
		// Not a certificate problem: TLS is probably off, so probe plainly.
		if resp, err = client.Get("http://" + net.JoinHostPort(host, port) + "/health"); err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: %s", resp.Status)
	}
	return nil
}
