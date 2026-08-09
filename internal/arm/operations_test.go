package arm

// The asynchronous-operation protocol at the handler level: the branches a
// happy-path SDK poller never reaches — an operation still running, one that
// failed, one that belongs to another subscription, and one that never
// existed.

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// poll drives one poll of either shape and returns the recorder.
func poll(s *Service, kind, sub, id string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := req("GET", "/subscriptions/"+sub+"/"+kind+"/"+id+"?api-version=2022-04-01", "")
	if kind == "operationresults" {
		s.operationResults(w, r, sub, id)
	} else {
		s.operationStatuses(w, r, sub, id)
	}
	return w
}

func TestOperationPollingBranches(t *testing.T) {
	s, st := newService(t, "")
	st.Clock.Freeze()

	// An operation still running: Location-style answers 202 and keeps
	// pointing at itself; AsyncOperation-style reports InProgress.
	running := &store.Operation{Kind: "DeleteResourceGroup", Subscription: testSub}
	running.CompleteAt = st.Now() + 300
	if err := st.CreateOperation(running); err != nil {
		t.Fatal(err)
	}
	w := poll(s, "operationresults", testSub, running.ID)
	if w.Code != http.StatusAccepted {
		t.Fatalf("in-flight operationresults = %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, running.ID) {
		t.Fatalf("in-flight Location = %q", loc)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("in-flight poll carried no Retry-After")
	}
	w = poll(s, "operationstatuses", testSub, running.ID)
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["status"] != store.OpInProgress || doc["endTime"] != nil {
		t.Fatalf("in-flight status document = %v", doc)
	}

	// Advancing the clock past completeAt is what finishes it — no worker,
	// no sleep.
	st.Clock.Advance(301)
	if w := poll(s, "operationresults", testSub, running.ID); w.Code != http.StatusOK {
		t.Fatalf("completed operationresults = %d", w.Code)
	}
	w = poll(s, "operationstatuses", testSub, running.ID)
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["status"] != store.OpSucceeded || doc["endTime"] == nil {
		t.Fatalf("completed status document = %v", doc)
	}

	// A failed operation surfaces the error in both shapes.
	failed := &store.Operation{Kind: "CreateVault", Subscription: testSub, FailWith: "VaultCreateFailed"}
	if err := st.CreateOperation(failed); err != nil {
		t.Fatal(err)
	}
	if w := poll(s, "operationresults", testSub, failed.ID); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "VaultCreateFailed") {
		t.Fatalf("failed operationresults = %d %s", w.Code, w.Body.Bytes())
	}
	w = poll(s, "operationstatuses", testSub, failed.ID)
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["status"] != store.OpFailed || doc["error"] == nil {
		t.Fatalf("failed status document = %v", doc)
	}

	// Unknown ids, and an operation read through the wrong subscription,
	// are both OperationNotFound — an operation is scoped to its own
	// subscription like every other ARM resource.
	for _, tc := range []struct{ sub, id string }{
		{testSub, "no-such-operation"},
		{"11111111-2222-3333-4444-555555555555", running.ID},
	} {
		for _, kind := range []string{"operationresults", "operationstatuses"} {
			if w := poll(s, kind, tc.sub, tc.id); w.Code != http.StatusNotFound ||
				!strings.Contains(w.Body.String(), "OperationNotFound") {
				t.Fatalf("%s %v = %d %s", kind, tc, w.Code, w.Body.Bytes())
			}
		}
	}
}

// TestOperationPollURLScheme: the poll URL a client is handed must match the
// scheme it reached us on, or the poller leaves TLS behind.
func TestOperationPollURLScheme(t *testing.T) {
	s, _ := newService(t, "")
	plain := req("GET", "/x?api-version=2022-04-01", "")
	if got := s.pollURL(plain, testSub, "operationresults", "abc"); !strings.HasPrefix(got, "http://") {
		t.Fatalf("plain-HTTP poll URL = %q", got)
	}
	if !strings.Contains(s.pollURL(plain, testSub, "operationresults", "abc"), "api-version=2022-04-01") {
		t.Fatal("poll URL dropped the caller's api-version")
	}
	tls := req("GET", "/x?api-version=2022-04-01", "")
	tls.TLS = &connState
	if got := s.pollURL(tls, testSub, "operationstatuses", "abc"); !strings.HasPrefix(got, "https://") {
		t.Fatalf("TLS poll URL = %q", got)
	}
}

// connState is a minimal non-nil TLS state: the handler only checks whether
// the request arrived over TLS, not what was negotiated.
var connState = tls.ConnectionState{}

// TestOperationStorageFailures drops the operations table under live
// handlers: an emulator that cannot record an operation must say so rather
// than hand a client a poll URL that will never resolve.
func TestOperationStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	// A group and a vault to act on, created while the table still exists.
	for _, rg := range []string{"rg-op", "rg-op2"} {
		w := httptest.NewRecorder()
		s.resourceGroup(w, req("PUT", "/x", `{"location":"westeurope"}`), testSub, rg)
		if w.Code != http.StatusCreated {
			t.Fatalf("seed %s = %d %s", rg, w.Code, w.Body.Bytes())
		}
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE operations`); err != nil {
		t.Fatal(err)
	}

	// The delete cannot record its operation.
	w := httptest.NewRecorder()
	s.resourceGroup(w, req("DELETE", "/x", ""), testSub, "rg-op")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the operations table dropped = %d %s", w.Code, w.Body.Bytes())
	}
	// So does the vault create.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"location":"westeurope","properties":{}}`),
		"/subscriptions/"+testSub+"/resourceGroups/rg-op2", []string{"vaults", "vop"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("vault create with the operations table dropped = %d %s", w.Code, w.Body.Bytes())
	}
}
