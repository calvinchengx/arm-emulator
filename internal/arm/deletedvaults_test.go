package arm

// Deleted-vault recovery: delete holds the name, recover brings the vault
// back with its configuration, purge destroys it, and the retention window
// closes on the controllable clock rather than after ninety real days.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

func kvPath(s *Service, rest ...string) (string, []string) {
	return "/subscriptions/" + testSub, rest
}

// deleted drives the deletedVaults surface at subscription scope.
func deleted(s *Service, method string, rest ...string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	scope, r := kvPath(s, rest...)
	s.deletedVaults(w, req(method, "/x?api-version=2022-07-01", ""), scope, r)
	return w
}

func TestVaultSoftDeleteRecoverPurge(t *testing.T) {
	s, st := newService(t, "")
	st.Clock.Freeze()
	seedVault(t, s, "recoverable", `{"enableRbacAuthorization":true}`)
	scope := vaultScopeFor("recoverable")

	// DELETE does not destroy: the vault leaves the live list…
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d", w.Code)
	}
	// …and appears among the deleted, carrying its purge deadline.
	w = deleted(s, "GET", "deletedVaults")
	var list struct {
		Value []struct {
			Name       string
			Properties struct{ DeletionDate, ScheduledPurgeDate, VaultID string }
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Value) != 1 || list.Value[0].Name != "recoverable" ||
		list.Value[0].Properties.ScheduledPurgeDate == "" || list.Value[0].Properties.VaultID == "" {
		t.Fatalf("deleted list = %+v", list.Value)
	}
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "recoverable"); w.Code != http.StatusOK {
		t.Fatalf("get deleted = %d %s", w.Code, w.Body.Bytes())
	}

	// The name is still held: a plain create is a conflict, which is what
	// makes an accidental delete recoverable rather than silently replaced.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01", `{"location":"westeurope","properties":{}}`),
		scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "VaultAlreadyExists") {
		t.Fatalf("create over a soft-deleted name = %d %s", w.Code, w.Body.Bytes())
	}

	// createMode "recover" brings it back with its configuration intact.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01",
		`{"location":"westeurope","properties":{"createMode":"recover"}}`),
		scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusOK {
		t.Fatalf("recover = %d %s", w.Code, w.Body.Bytes())
	}
	var back struct {
		Properties struct{ EnableRbacAuthorization bool }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &back)
	if !back.Properties.EnableRbacAuthorization {
		t.Fatal("the recovered vault lost its configuration")
	}
	if w := deleted(s, "GET", "deletedVaults"); !strings.Contains(w.Body.String(), `"value":[]`) {
		t.Fatalf("still listed as deleted after recovery: %s", w.Body.Bytes())
	}

	// Delete it again, then purge: gone for good, and the purge is the
	// asynchronous operation ARM makes it.
	w = httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusOK {
		t.Fatalf("second delete = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("POST", "/x?api-version=2022-07-01", ""), "/subscriptions/"+testSub,
		[]string{"locations", "westeurope", "deletedVaults", "recoverable", "purge"})
	if w.Code != http.StatusAccepted || w.Header().Get("Location") == "" {
		t.Fatalf("purge = %d loc=%q", w.Code, w.Header().Get("Location"))
	}
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "recoverable"); w.Code != http.StatusNotFound {
		t.Fatalf("get after purge = %d", w.Code)
	}
	// A purged name is free again.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01", `{"location":"westeurope","properties":{}}`),
		scope, []string{"vaults", "recoverable"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create after purge = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestVaultRetentionWindowOnTheClock(t *testing.T) {
	s, st := newService(t, "")
	st.Clock.Freeze()
	seedVault(t, s, "expiring", `{}`)
	scope := vaultScopeFor("expiring")

	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "expiring"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "expiring"); w.Code != http.StatusOK {
		t.Fatalf("inside the window = %d", w.Code)
	}
	// Ninety days later the window has closed: the vault is gone as if
	// purged, and its name is free.
	st.Clock.Advance(91 * 86400)
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "expiring"); w.Code != http.StatusNotFound {
		t.Fatalf("after the window = %d", w.Code)
	}
	if w := deleted(s, "GET", "deletedVaults"); !strings.Contains(w.Body.String(), `"value":[]`) {
		t.Fatalf("lapsed vault still listed: %s", w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01", `{"location":"westeurope","properties":{}}`),
		scope, []string{"vaults", "expiring"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create after the window lapsed = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestDeletedVaultErrors(t *testing.T) {
	s, _ := newService(t, "")
	subScope := "/subscriptions/" + testSub

	// Unknown deleted vault, and recovering one that never existed.
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "ghost"); w.Code != http.StatusNotFound {
		t.Fatalf("get of an unknown deleted vault = %d", w.Code)
	}
	w := httptest.NewRecorder()
	s.deletedVaults(w, req("POST", "/x?api-version=2022-07-01", ""), subScope,
		[]string{"locations", "westeurope", "deletedVaults", "ghost", "purge"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("purge of an unknown deleted vault = %d", w.Code)
	}
	if err := s.Store.PutResourceGroup(&store.ResourceGroup{Subscription: testSub, Name: "rg1"}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01",
		`{"location":"westeurope","properties":{"createMode":"recover"}}`),
		vaultScopeFor("ghost"), []string{"vaults", "ghost"})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "VaultNotFound") {
		t.Fatalf("recover of a vault that never existed = %d %s", w.Code, w.Body.Bytes())
	}

	// Wrong methods and malformed paths.
	if w := deleted(s, "POST", "deletedVaults"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on the collection = %d", w.Code)
	}
	if w := deleted(s, "DELETE", "locations", "westeurope", "deletedVaults", "x"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE on a deleted vault = %d", w.Code)
	}
	if w := deleted(s, "GET", "locations", "westeurope"); w.Code != http.StatusBadRequest {
		t.Fatalf("truncated path = %d", w.Code)
	}
	// An unknown subscription is refused before the provider is reached.
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("GET", "/x?api-version=2022-07-01", ""),
		"/subscriptions/11111111-2222-3333-4444-555555555555", []string{"deletedVaults"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown subscription = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("GET", "/x?api-version=2022-07-01", ""), "/", []string{"deletedVaults"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("tenant scope = %d", w.Code)
	}
}

func TestDeletedVaultStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "doomed", `{}`)
	scope := vaultScopeFor("doomed")

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE deleted_vaults`); err != nil {
		t.Fatal(err)
	}
	// The delete cannot record the soft-deleted copy, so it must not destroy
	// the live one silently.
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "doomed"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the table dropped = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "doomed"})
	if w.Code != http.StatusOK {
		t.Fatalf("the vault was destroyed despite the failed soft delete: %d", w.Code)
	}
	if w := deleted(s, "GET", "deletedVaults"); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with the table dropped = %d", w.Code)
	}
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "doomed"); w.Code != http.StatusInternalServerError {
		t.Fatalf("get with the table dropped = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("POST", "/x?api-version=2022-07-01", ""), "/subscriptions/"+testSub,
		[]string{"locations", "westeurope", "deletedVaults", "doomed", "purge"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("purge with the table dropped = %d", w.Code)
	}
}

// TestDeletedVaultBlockedWrites: storage refuses the write half of a
// recovery or a purge, and the handler reports it rather than claiming
// success it did not achieve.
func TestDeletedVaultBlockedWrites(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "blocked", `{}`)
	scope := vaultScopeFor("blocked")
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "blocked"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`CREATE TRIGGER no_purge BEFORE DELETE ON deleted_vaults
		 BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	// Recovery cannot clear the tombstone…
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01",
		`{"location":"westeurope","properties":{"createMode":"recover"}}`),
		scope, []string{"vaults", "blocked"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("blocked recovery = %d %s", w.Code, w.Body.Bytes())
	}
	// …and neither can a purge.
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("POST", "/x?api-version=2022-07-01", ""), "/subscriptions/"+testSub,
		[]string{"locations", "westeurope", "deletedVaults", "blocked", "purge"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("blocked purge = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestSoftDeleteIsAtomic: the tombstone and the removal are one transaction,
// so a vault can never end up listed as both live and deleted.
func TestSoftDeleteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "atomic", `{}`)
	scope := vaultScopeFor("atomic")

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The tombstone will insert; removing the live row will not.
	if _, err := db.Exec(
		`CREATE TRIGGER no_vault_delete BEFORE DELETE ON vaults
		 BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "atomic"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("half-completed soft delete = %d %s", w.Code, w.Body.Bytes())
	}
	// Rolled back: still live, and not also sitting in the deleted list.
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "atomic"})
	if w.Code != http.StatusOK {
		t.Fatalf("the vault vanished despite the rollback: %d", w.Code)
	}
	if w := deleted(s, "GET", "deletedVaults"); !strings.Contains(w.Body.String(), `"value":[]`) {
		t.Fatalf("a tombstone survived the rollback: %s", w.Body.Bytes())
	}
}

// TestPurgeOperationFailure: the purge cannot be recorded as an operation,
// so the caller is told rather than handed a poll URL that resolves to
// nothing.
func TestPurgeOperationFailure(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "opless", `{}`)
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), vaultScopeFor("opless"),
		[]string{"vaults", "opless"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE operations`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.deletedVaults(w, req("POST", "/x?api-version=2022-07-01", ""), "/subscriptions/"+testSub,
		[]string{"locations", "westeurope", "deletedVaults", "opless", "purge"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("purge with no operations table = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestRecoveryIsAtomic: the restore and the tombstone removal are one
// transaction too, so a failed recovery leaves the vault recoverable rather
// than lost.
func TestRecoveryIsAtomic(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "halfway", `{}`)
	scope := vaultScopeFor("halfway")
	w := httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x?api-version=2022-07-01", ""), scope, []string{"vaults", "halfway"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The vault cannot be written back.
	if _, err := db.Exec(
		`CREATE TRIGGER no_vault_insert BEFORE INSERT ON vaults
		 BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x?api-version=2022-07-01",
		`{"location":"westeurope","properties":{"createMode":"recover"}}`),
		scope, []string{"vaults", "halfway"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("blocked recovery = %d %s", w.Code, w.Body.Bytes())
	}
	// Still recoverable: the tombstone survived the rollback.
	if w := deleted(s, "GET", "locations", "westeurope", "deletedVaults", "halfway"); w.Code != http.StatusOK {
		t.Fatalf("the vault became unrecoverable after a failed recovery: %d", w.Code)
	}
}

// TestListResources: the subscription-wide resource list, which the CLI
// consults whenever a command names a resource without its group.
func TestListResources(t *testing.T) {
	s, _ := newService(t, "")
	seedVault(t, s, "findable", `{}`)
	list := func(filter string) []map[string]any {
		w := httptest.NewRecorder()
		url := "/x?api-version=2022-09-01"
		if filter != "" {
			url += "&$filter=" + filter
		}
		s.listResources(w, req("GET", url, ""), testSub)
		if w.Code != http.StatusOK {
			t.Fatalf("list %q = %d %s", filter, w.Code, w.Body.Bytes())
		}
		var out struct{ Value []map[string]any }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out.Value
	}
	if got := list(""); len(got) != 1 || got[0]["name"] != "findable" ||
		got[0]["type"] != "Microsoft.KeyVault/vaults" {
		t.Fatalf("unfiltered = %+v", got)
	}
	// The two clauses the CLI sends.
	if got := list("resourceType%20eq%20'Microsoft.KeyVault/vaults'"); len(got) != 1 {
		t.Fatalf("resourceType filter = %+v", got)
	}
	if got := list("name%20eq%20'findable'"); len(got) != 1 {
		t.Fatalf("name filter = %+v", got)
	}
	if got := list("name%20eq%20'other'"); len(got) != 0 {
		t.Fatalf("non-matching name filter = %+v", got)
	}
	if got := list("resourceType%20eq%20'Microsoft.Compute/virtualMachines'"); len(got) != 0 {
		t.Fatalf("non-matching type filter = %+v", got)
	}
	// Malformed filters are ignored rather than failing the call.
	if got := list("resourceType%20eq%20unquoted"); len(got) != 1 {
		t.Fatalf("unquoted filter = %+v", got)
	}
	if got := list("resourceType%20eq%20'unterminated"); len(got) != 1 {
		t.Fatalf("unterminated filter = %+v", got)
	}

	// Wrong method, and an unknown subscription.
	w := httptest.NewRecorder()
	s.listResources(w, req("POST", "/x?api-version=2022-09-01", ""), testSub)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /resources = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.listResources(w, req("GET", "/x?api-version=2022-09-01", ""), "11111111-2222-3333-4444-555555555555")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown subscription = %d", w.Code)
	}
}

// TestRouteReachesNewSurfaces: the paths a client actually sends, parsed by
// the router rather than handed straight to a handler.
func TestRouteReachesNewSurfaces(t *testing.T) {
	s, _ := newService(t, "")
	seedVault(t, s, "routed", `{}`)
	route := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.route(w, req(method, path+"?api-version=2022-07-01", ""), caller)
		return w
	}
	sub := "/subscriptions/" + testSub
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", sub + "/resources", http.StatusOK},
		{"GET", sub + "/providers/Microsoft.KeyVault/deletedVaults", http.StatusOK},
		{"GET", sub + "/providers/Microsoft.KeyVault/locations/westeurope/deletedVaults/routed",
			http.StatusNotFound}, // live, not deleted
	} {
		if w := route(tc.method, tc.path); w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d (%s)", tc.method, tc.path, w.Code, tc.want, w.Body.Bytes())
		}
	}
}

// TestListResourcesStorageFailure: the list cannot be built, so it reports a
// failure rather than an empty subscription.
func TestListResourcesStorageFailure(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "gone", `{}`)
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE vaults`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.listResources(w, req("GET", "/x?api-version=2022-09-01", ""), testSub)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("list with the vaults table dropped = %d", w.Code)
	}
}
