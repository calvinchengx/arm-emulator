package tlscert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadEphemeral(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"localhost", "management.azure.com", "management.core.windows.net"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("cert does not cover %s: %v", h, err)
		}
	}
}

func TestLoadPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	c1, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	l1, _ := x509.ParseCertificate(c1.Certificate[0])
	l2, _ := x509.ParseCertificate(c2.Certificate[0])
	if l1.SerialNumber.Cmp(l2.SerialNumber) != 0 {
		t.Fatal("second Load generated a new cert; want the persisted one (stable fingerprint)")
	}
}

func TestLoadFailureModes(t *testing.T) {
	// dataDir/tls exists as a FILE → MkdirAll fails.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/tls", []byte("in the way"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load with tls-path-is-a-file succeeded; want error")
	}

	// Corrupt persisted PEMs: LoadX509KeyPair fails, so Load regenerates
	// fresh ones over them rather than erroring.
	dir2 := t.TempDir()
	if err := os.MkdirAll(dir2+"/tls", 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir2+"/tls/cert.pem", []byte("garbage"), 0o644)
	os.WriteFile(dir2+"/tls/key.pem", []byte("garbage"), 0o600)
	if _, err := Load(dir2); err != nil {
		t.Fatalf("Load over corrupt PEMs = %v; want regeneration", err)
	}
}

// TestLoadWriteFailures: with the tls directory unwritable, persisting a
// freshly generated certificate must surface the error rather than serving
// an unpersisted one. POSIX only — chmod does not write-protect a directory
// on Windows.
func TestLoadWriteFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod cannot write-protect a directory on Windows")
	}
	// The tls/ directory exists but is read-only: the cert write fails.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "tls"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "tls"), 0o700) })
	if _, err := Load(dir); err == nil {
		t.Fatal("Load with an unwritable tls dir succeeded")
	}
	_ = os.Chmod(filepath.Join(dir, "tls"), 0o700)

	// The key path is a directory: the cert write succeeds, the key fails.
	dir2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir2, "tls", "key.pem"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir2); err == nil {
		t.Fatal("Load with key.pem as a directory succeeded")
	}

	// The data dir itself is a file: MkdirAll fails.
	dir3 := t.TempDir()
	f := filepath.Join(dir3, "notadir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err == nil {
		t.Fatal("Load under a regular file succeeded")
	}
}

// TestPool: pinning the emulator's own certificate is what lets a local
// probe verify instead of skipping verification, so every way it can fail
// has to be legible.
func TestPool(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	pool, err := Pool(dir)
	if err != nil {
		t.Fatalf("Pool of a persisted certificate: %v", err)
	}
	// The pool must actually verify the certificate it was built from.
	cert, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err != nil {
		t.Fatalf("the pinned certificate does not verify against its own pool: %v", err)
	}

	// An ephemeral instance has nothing on disk to pin.
	if _, err := Pool(""); err == nil {
		t.Fatal("Pool accepted an empty data directory")
	}
	// A data directory with no certificate yet.
	if _, err := Pool(t.TempDir()); err == nil {
		t.Fatal("Pool accepted a directory with no certificate")
	}
	// A file that exists but holds no certificate.
	junk := t.TempDir()
	if err := os.MkdirAll(filepath.Join(junk, "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(junk, "tls", "cert.pem"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pool(junk); err == nil {
		t.Fatal("Pool accepted a file with no PEM certificate in it")
	}
}
