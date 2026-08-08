package arm

// Microsoft.KeyVault/vaults: the branches the typed SDK does not reach —
// policy-operation kinds, RBAC mode, storage failures and scope parsing.

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

func vaultScopeFor(name string) string {
	return "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/" + name
}

// seedVault creates the group and a vault through the handlers.
func seedVault(t *testing.T, s *Service, name, props string) {
	t.Helper()
	if err := s.Store.PutResourceGroup(&store.ResourceGroup{Subscription: testSub, Name: "rg1"}); err != nil {
		t.Fatal(err)
	}
	body := `{"location":"westeurope","properties":` + props + `}`
	w := httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", body), vaultScopeFor(name), []string{"vaults", name})
	if w.Code != http.StatusOK {
		t.Fatalf("seed vault = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestVaultLifecycleBranches(t *testing.T) {
	s, _ := newService(t, "")

	// A vault outside a resource group is refused.
	w := httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"location":"westeurope"}`),
		"/subscriptions/"+testSub, []string{"vaults", "v"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("vault without a group = %d %s", w.Code, w.Body.Bytes())
	}
	// A malformed body and a missing location are refused.
	scope := vaultScopeFor("v1")
	for body, want := range map[string]string{
		"{nope": "InvalidRequestContent",
		"{}":    "LocationRequired",
	} {
		w := httptest.NewRecorder()
		s.vaults(w, req("PUT", "/x", body), scope, []string{"vaults", "v1"})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("PUT %q = %d %s", body, w.Code, w.Body.Bytes())
		}
	}
	// A group that does not exist is refused.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"location":"westeurope"}`), scope, []string{"vaults", "v1"})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "ResourceGroupNotFound") {
		t.Fatalf("vault in a missing group = %d %s", w.Code, w.Body.Bytes())
	}

	seedVault(t, s, "v1", `{"tenantId":"tid","accessPolicies":[]}`)

	// GET fills in the vault URI and provisioning state.
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), scope, []string{"vaults", "v1"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://v1.vault.azure.net/") {
		t.Fatalf("GET vault = %d %s", w.Code, w.Body.Bytes())
	}
	// An absent vault 404s; a DELETE of one is 204; a real DELETE is 200.
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), vaultScopeFor("nope"), []string{"vaults", "nope"})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "ResourceNotFound") {
		t.Fatalf("absent vault = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x", ""), vaultScopeFor("nope"), []string{"vaults", "nope"})
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete absent vault = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("DELETE", "/x", ""), scope, []string{"vaults", "v1"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete vault = %d %s", w.Code, w.Body.Bytes())
	}

	// Unsupported methods and unknown sub-resources are refused.
	w = httptest.NewRecorder()
	s.vaults(w, req("PATCH", "/x", "{}"), scope, []string{"vaults", "v1"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH vault = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), scope, []string{"vaults", "v1", "privateEndpointConnections"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown sub-resource = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("POST", "/x", "{}"), scope, []string{"vaults"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the vault collection = %d", w.Code)
	}
	// A scope with no subscription is refused.
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), "/", []string{"vaults"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("vaults at the tenant root = %d %s", w.Code, w.Body.Bytes())
	}
	// An unknown subscription is refused too.
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), "/subscriptions/99999999-0000-0000-0000-000000000000", []string{"vaults"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("vaults under an unknown subscription = %d", w.Code)
	}
}

func TestAccessPolicyOperations(t *testing.T) {
	s, _ := newService(t, "")
	seedVault(t, s, "v2", `{"accessPolicies":[{"objectId":"p1","permissions":{"secrets":["get"]}}]}`)
	scope := vaultScopeFor("v2")
	rest := func(kind string) []string { return []string{"vaults", "v2", "accessPolicies", kind} }

	policies := func(w *httptest.ResponseRecorder) []AccessPolicyEntry {
		var out struct {
			Properties struct {
				AccessPolicies []AccessPolicyEntry `json:"accessPolicies"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Properties.AccessPolicies
	}

	// add: a new principal joins, an existing objectId is replaced in place.
	w := httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"properties":{"accessPolicies":[
		{"objectId":"p2","permissions":{"keys":["sign"]}},
		{"objectId":"P1","permissions":{"secrets":["get","list"]}}]}}`), scope, rest("add"))
	if w.Code != http.StatusOK {
		t.Fatalf("add = %d %s", w.Code, w.Body.Bytes())
	}
	got := policies(w)
	if len(got) != 2 {
		t.Fatalf("after add = %+v", got)
	}
	for _, e := range got {
		if strings.EqualFold(e.ObjectID, "p1") && len(e.Permissions.Secrets) != 2 {
			t.Fatalf("existing objectId not replaced: %+v", e)
		}
	}

	// remove drops by objectId, case-insensitively.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"properties":{"accessPolicies":[{"objectId":"P2"}]}}`), scope, rest("remove"))
	if got := policies(w); len(got) != 1 || !strings.EqualFold(got[0].ObjectID, "p1") {
		t.Fatalf("after remove = %+v", got)
	}

	// replace swaps the whole list; a null list clears it.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"properties":{"accessPolicies":[{"objectId":"p9"}]}}`), scope, rest("replace"))
	if got := policies(w); len(got) != 1 || got[0].ObjectID != "p9" {
		t.Fatalf("after replace = %+v", got)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"properties":{}}`), scope, rest("replace"))
	if got := policies(w); len(got) != 0 {
		t.Fatalf("after clearing replace = %+v", got)
	}

	// Refusals: unknown kind, missing kind, wrong method, bad body, no vault.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", "{}"), scope, rest("frobnicate"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", "{}"), scope, []string{"vaults", "v2", "accessPolicies"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing kind = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("GET", "/x", ""), scope, rest("add"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET access policies = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", "{nope"), scope, rest("add"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed policy body = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", "{}"), vaultScopeFor("gone"), []string{"vaults", "gone", "accessPolicies", "add"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("policies on a missing vault = %d", w.Code)
	}
}

func TestVaultConfigAtForFeed(t *testing.T) {
	s, _ := newService(t, "")
	// Not a vault scope, and a vault that does not exist: Exists=false, so the
	// data plane keeps its own defaults instead of being reconfigured by an
	// absent resource. The policy list is empty rather than nil either way.
	for _, scope := range []string{"/subscriptions/" + testSub, vaultScopeFor("absent"), "/"} {
		cfg, err := s.VaultConfigAt(scope)
		if err != nil || cfg.Exists || cfg.AccessPolicies == nil || len(cfg.AccessPolicies) != 0 ||
			cfg.EnableRbacAuthorization {
			t.Fatalf("VaultConfigAt(%q) = %+v %v", scope, cfg, err)
		}
		// Nothing to apply: every optional property stays unset.
		if cfg.EnablePurgeProtection != nil || cfg.EnableSoftDelete != nil ||
			cfg.SoftDeleteRetentionDays != nil {
			t.Fatalf("absent vault carried configuration: %+v", cfg)
		}
	}

	// A vault in RBAC mode reports its policies and the flag.
	seedVault(t, s, "v3", `{"enableRbacAuthorization":true,
		"accessPolicies":[{"objectId":"p1","permissions":{"secrets":["get"]}}]}`)
	cfg, err := s.VaultConfigAt(vaultScopeFor("v3"))
	if err != nil || !cfg.Exists || len(cfg.AccessPolicies) != 1 || !cfg.EnableRbacAuthorization {
		t.Fatalf("RBAC vault = %+v %v", cfg, err)
	}

	// The vault resource's own settings ride along, so a data plane learns
	// purge protection and the soft-delete window from ARM rather than from
	// its own flags.
	seedVault(t, s, "v3p", `{"enablePurgeProtection":true,"enableSoftDelete":true,
		"softDeleteRetentionInDays":7}`)
	cfg, err = s.VaultConfigAt(vaultScopeFor("v3p"))
	if err != nil || !cfg.Exists {
		t.Fatalf("configured vault = %+v %v", cfg, err)
	}
	if cfg.EnablePurgeProtection == nil || !*cfg.EnablePurgeProtection ||
		cfg.EnableSoftDelete == nil || !*cfg.EnableSoftDelete ||
		cfg.SoftDeleteRetentionDays == nil || *cfg.SoftDeleteRetentionDays != 7 {
		t.Fatalf("vault settings not carried: %+v", cfg)
	}
	// Unset is distinguishable from false — the data plane must be able to
	// tell "the resource says no" from "the resource does not say".
	seedVault(t, s, "v3q", `{}`)
	cfg, err = s.VaultConfigAt(vaultScopeFor("v3q"))
	if err != nil || !cfg.Exists || cfg.EnablePurgeProtection != nil ||
		cfg.SoftDeleteRetentionDays != nil {
		t.Fatalf("unset properties did not stay nil: %+v %v", cfg, err)
	}

	// vaultNameOf only matches a Microsoft.KeyVault vaults segment.
	if got := vaultNameOf("/subscriptions/s/providers/Microsoft.Other/vaults/x"); got != "" {
		t.Fatalf("foreign provider vault name = %q", got)
	}
	if got := vaultNameOf(vaultScopeFor("v9")); got != "v9" {
		t.Fatalf("vaultNameOf = %q", got)
	}
}

// TestVaultStorageFailures drops the vaults table under live handlers.
func TestVaultStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "v4", `{}`)
	scope := vaultScopeFor("v4")

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE vaults`); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(w http.ResponseWriter){
		"list":   func(w http.ResponseWriter) { s.vaults(w, req("GET", "/x", ""), scope, []string{"vaults"}) },
		"get":    func(w http.ResponseWriter) { s.vaults(w, req("GET", "/x", ""), scope, []string{"vaults", "v4"}) },
		"delete": func(w http.ResponseWriter) { s.vaults(w, req("DELETE", "/x", ""), scope, []string{"vaults", "v4"}) },
		"put": func(w http.ResponseWriter) {
			s.vaults(w, req("PUT", "/x", `{"location":"westeurope"}`), scope, []string{"vaults", "v4"})
		},
		"policies": func(w http.ResponseWriter) {
			s.vaults(w, req("PUT", "/x", `{"properties":{"accessPolicies":[]}}`), scope,
				[]string{"vaults", "v4", "accessPolicies", "add"})
		},
		"feed": func(w http.ResponseWriter) {
			s.ServeFeed(w, req("GET", "/_family/authorization?scope="+scope, ""))
		},
	}
	for name, call := range cases {
		w := httptest.NewRecorder()
		call(w)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with the vaults table dropped = %d %s", name, w.Code, w.Body.Bytes())
		}
	}
	if _, err := s.VaultConfigAt(scope); err == nil {
		t.Fatal("VaultConfigAt ignored the storage failure")
	}
}

func TestVaultBodyDefaults(t *testing.T) {
	s, _ := newService(t, "")
	// A vault stored with an unreadable properties document still renders:
	// the body fills in the defaults rather than failing the read.
	body := s.vaultBody(&store.Vault{
		Subscription: testSub, ResourceGroup: "rg", Name: "v",
		TagsJSON: "not-json", PropertiesJSON: "not-json",
	})
	props := body["properties"].(vaultProperties)
	if props.VaultURI != "https://v.vault.azure.net/" || props.ProvisioningState != "Succeeded" ||
		props.TenantID != s.Cfg.TenantID || props.AccessPolicies == nil {
		t.Fatalf("defaults = %+v", props)
	}
}

func TestApplyPolicyOpNilCurrent(t *testing.T) {
	// A vault with no policy list yet still accepts an add.
	got := applyPolicyOp(nil, []AccessPolicyEntry{{ObjectID: "p1"}}, "add")
	if len(got) != 1 || got[0].ObjectID != "p1" {
		t.Fatalf("add to a nil list = %+v", got)
	}
	if got := applyPolicyOp(nil, nil, "remove"); len(got) != 0 {
		t.Fatalf("remove from a nil list = %+v", got)
	}
}

func TestVaultPropertiesEdgeCases(t *testing.T) {
	s, st := newService(t, "")
	// Properties that are not JSON surface as an error to the feed rather
	// than being silently read as empty.
	if err := st.PutVault(&store.Vault{
		Subscription: testSub, ResourceGroup: "rg1", Name: "broken",
		PropertiesJSON: "not-json",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VaultConfigAt(vaultScopeFor("broken")); err == nil {
		t.Fatal("unreadable vault properties did not error")
	}
	// A vault with no accessPolicies member reports an empty list, not nil.
	if err := st.PutVault(&store.Vault{
		Subscription: testSub, ResourceGroup: "rg1", Name: "bare", PropertiesJSON: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.VaultConfigAt(vaultScopeFor("bare"))
	if err != nil || cfg.AccessPolicies == nil || len(cfg.AccessPolicies) != 0 ||
		cfg.EnableRbacAuthorization {
		t.Fatalf("bare vault = %+v %v", cfg, err)
	}
}

// TestVaultWriteFailures: reads succeed but writes abort, reaching the
// handlers' 500 branches after a successful lookup.
func TestVaultWriteFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedVault(t, s, "v5", `{}`)
	scope := vaultScopeFor("v5")

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_vault_write BEFORE INSERT ON vaults
BEGIN SELECT RAISE(ABORT, 'write refused'); END`); err != nil {
		t.Fatal(err)
	}
	// The policy operation reads the vault, then fails to persist it.
	w := httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"properties":{"accessPolicies":[{"objectId":"p1"}]}}`),
		scope, []string{"vaults", "v5", "accessPolicies", "add"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("policy write with a refusing trigger = %d %s", w.Code, w.Body.Bytes())
	}
	// So does a create, after its resource-group check passes.
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"location":"westeurope","tags":{"a":"b"}}`),
		scope, []string{"vaults", "v6"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("vault write with a refusing trigger = %d %s", w.Code, w.Body.Bytes())
	}

	// With the resource_groups table gone, the create's group lookup errors.
	if _, err := db.Exec(`DROP TABLE resource_groups`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.vaults(w, req("PUT", "/x", `{"location":"westeurope"}`), scope, []string{"vaults", "v7"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("vault create with no resource_groups table = %d %s", w.Code, w.Body.Bytes())
	}
}
