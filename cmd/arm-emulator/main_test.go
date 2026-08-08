package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// serverDataDir is t.TempDir() minus the strict cleanup, for tests that start a
// server and leave it running. run() blocks until process exit and has no
// shutdown hook, so the SQLite file stays open for the life of the test binary
// — and Windows refuses to unlink an open file, so t.TempDir()'s own RemoveAll
// fails the test after it has already passed. POSIX unlinks open files happily,
// which is why this only ever surfaced off Linux (CI here is ubuntu-only).
// Cleanup is best-effort; the OS reclaims the temp directory regardless.
func serverDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kv-emulator-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ARM_ADDR", "ARM_DATA_DIR", "ARM_ENTRA_ISSUER",
		"ARM_ENTRA_JWKS_URL", "ARM_ENTRA_TLS_INSECURE", "ARM_DISABLE_TLS"} {
		t.Setenv(k, "")
	}
}

func TestRunErrors(t *testing.T) {
	clearEnv(t)
	if err := run([]string{"-bogus-flag"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run(nil); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "999.999.999.999:1"}); err == nil {
		t.Fatal("unlistenable addr accepted")
	}
}

// poll waits for the health endpoint to answer.
func poll(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("health never came up at %s", url)
}

func TestRunServesTLS(t *testing.T) {
	clearEnv(t)
	port := freePort(t)
	dir := serverDataDir(t)
	go func() {
		// Serve blocks until process exit; the goroutine dies with the test.
		_ = run([]string{
			"-entra-issuer", "https://127.0.0.1:1/t/v2.0", // JWKS unreachable is fine: /health needs no token
			"-addr", fmt.Sprintf("127.0.0.1:%d", port),
			"-data-dir", dir,
		})
	}()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	poll(t, client, fmt.Sprintf("https://127.0.0.1:%d/health", port))
	// An authenticated route without a token is a Fabric-shaped 401.
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/secrets?api-version=7.5", port))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /secrets = %d; want 401", resp.StatusCode)
	}
}

func TestRunServesPlainHTTP(t *testing.T) {
	clearEnv(t)
	port := freePort(t)
	go func() {
		_ = run([]string{
			"-entra-issuer", "https://127.0.0.1:1/t/v2.0",
			"-addr", fmt.Sprintf("127.0.0.1:%d", port),
			"-disable-tls",
		})
	}()
	poll(t, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/health", port))
}

func TestRunDataDirAndTLSFailures(t *testing.T) {
	clearEnv(t)
	// -data-dir pointing at an existing FILE: MkdirAll fails.
	dir := t.TempDir()
	file := dir + "/occupied"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "127.0.0.1:0", "-data-dir", file})
	if err == nil {
		t.Fatal("data-dir-is-a-file accepted")
	}
	// tls subpath blocked: data dir ok, cert persistence fails.
	dir3 := t.TempDir()
	if err := os.WriteFile(dir3+"/tls", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "127.0.0.1:0", "-data-dir", dir3}); err == nil {
		t.Fatal("broken tls dir accepted")
	}
}

func TestSubcommands(t *testing.T) {
	clearEnv(t)
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	// healthcheck against a live TLS instance succeeds; against a dead port fails.
	port := freePort(t)
	go func() {
		_ = run([]string{"-entra-issuer", "https://127.0.0.1:1/t/v2.0",
			"-addr", fmt.Sprintf("127.0.0.1:%d", port)})
	}()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	poll(t, client, fmt.Sprintf("https://127.0.0.1:%d/health", port))
	t.Setenv("ARM_ADDR", fmt.Sprintf("127.0.0.1:%d", port))
	if err := run([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	t.Setenv("ARM_ADDR", fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	if err := run([]string{"healthcheck"}); err == nil {
		t.Fatal("healthcheck against dead port succeeded")
	}
	t.Setenv("ARM_ADDR", "not-an-addr")
	if err := run([]string{"healthcheck"}); err == nil {
		t.Fatal("healthcheck with bad addr succeeded")
	}
}

// TestMainFunc covers func main itself by re-executing this test binary as a
// subprocess: the child runs main with a bad configuration and must exit
// non-zero via log.Fatal, the one path main has.
func TestMainFunc(t *testing.T) {
	if os.Getenv("ARM_MAIN_CHILD") == "1" {
		// No issuer configured, so run() errors and main log.Fatal()s.
		os.Args = []string{"arm-emulator"}
		main()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestMainFunc")
	cmd.Env = append(os.Environ(), "ARM_MAIN_CHILD=1", "ARM_ENTRA_ISSUER=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("main with no issuer exited 0: %s", out)
	}
	if !strings.Contains(string(out), "ARM_ENTRA_ISSUER is required") {
		t.Fatalf("unexpected child output: %s", out)
	}

	// And the success path: `version` prints and returns cleanly.
	cmd = exec.Command(exe, "-test.run=TestMainVersionChild")
	cmd.Env = append(os.Environ(), "ARM_MAIN_VERSION_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("main version child failed: %v %s", err, out)
	} else if !strings.Contains(string(out), "arm-emulator") {
		t.Fatalf("version output = %s", out)
	}
}

func TestMainVersionChild(t *testing.T) {
	if os.Getenv("ARM_MAIN_VERSION_CHILD") != "1" {
		t.Skip("child-only")
	}
	os.Args = []string{"arm-emulator", "version"}
	main()
}

// TestHealthcheckStatuses covers the fallback and non-200 branches.
func TestHealthcheckStatuses(t *testing.T) {
	// A plain-HTTP server: the https attempt fails, the http fallback wins.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := healthcheck(strings.TrimPrefix(ok.URL, "http://")); err != nil {
		t.Fatalf("healthcheck against a plain-HTTP server: %v", err)
	}

	// A server answering 503 is unhealthy.
	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer sick.Close()
	if err := healthcheck(strings.TrimPrefix(sick.URL, "http://")); err == nil {
		t.Fatal("healthcheck accepted a 503")
	}

	// Nothing listening: both schemes fail.
	if err := healthcheck(fmt.Sprintf("127.0.0.1:%d", freePort(t))); err == nil {
		t.Fatal("healthcheck against a dead port succeeded")
	}
	// A malformed address fails at parsing.
	if err := healthcheck("not-an-address"); err == nil {
		t.Fatal("healthcheck accepted a malformed address")
	}
	// A host-less address (the container form, ":8445") probes loopback.
	if err := healthcheck(fmt.Sprintf(":%d", freePort(t))); err == nil {
		t.Fatal("healthcheck against a dead loopback port succeeded")
	}
}

// TestRunServerNewFailure: the data dir is creatable but the database path
// inside it is a directory, so store.Open fails after MkdirAll succeeds —
// run's server.New error branch.
func TestRunServerNewFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "arm-emulator.db"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := run([]string{
		"-entra-issuer", "https://localhost:8443/tid/v2.0",
		"-data-dir", dir,
		"-addr", fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	if err == nil {
		t.Fatal("run with an unusable database path succeeded")
	}
}
