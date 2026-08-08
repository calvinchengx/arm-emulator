package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/clock"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenFailsOnBadDir(t *testing.T) {
	if _, err := Open("/nonexistent-path-xyz", clock.New()); err == nil {
		t.Fatal("Open with an unusable data dir succeeded")
	}
}

func TestNewGUIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		g := NewGUID()
		if len(g) != 36 || strings.Count(g, "-") != 4 {
			t.Fatalf("not a UUID: %q", g)
		}
		// Version 4, RFC 4122 variant.
		if g[14] != '4' || !strings.ContainsRune("89ab", rune(g[19])) {
			t.Fatalf("not a v4 UUID: %q", g)
		}
		if seen[g] {
			t.Fatalf("duplicate GUID %q", g)
		}
		seen[g] = true
	}
}

func TestResourceGroupCRUD(t *testing.T) {
	s := newStore(t)
	g := &ResourceGroup{Subscription: "sub", Name: "rg1"}
	if err := s.PutResourceGroup(g); err != nil {
		t.Fatal(err)
	}
	// Defaults filled in.
	if g.Location == "" || g.TagsJSON != "{}" {
		t.Fatalf("defaults not applied: %+v", g)
	}
	// PUT is an upsert, as ARM's is.
	g2 := &ResourceGroup{Subscription: "sub", Name: "rg1", Location: "eastus", TagsJSON: `{"a":"b"}`}
	if err := s.PutResourceGroup(g2); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetResourceGroup("sub", "RG1") // case-insensitive
	if err != nil || got.Location != "eastus" || got.TagsJSON != `{"a":"b"}` {
		t.Fatalf("upsert = %+v %v", got, err)
	}
	list, err := s.ListResourceGroups("sub")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v %v", list, err)
	}
	if l, _ := s.ListResourceGroups("other-sub"); len(l) != 0 {
		t.Fatalf("cross-subscription leak: %v", l)
	}
	if err := s.DeleteResourceGroup("sub", "rg1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetResourceGroup("sub", "rg1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	if err := s.DeleteResourceGroup("sub", "rg1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete = %v", err)
	}
}

func TestRoleAssignmentCRUD(t *testing.T) {
	s := newStore(t)
	a := &RoleAssignment{
		Name: "a1", ScopeDisplay: "/subscriptions/S/resourceGroups/RG",
		RoleDefinitionID: "/def/1", PrincipalID: "p1",
	}
	if err := s.CreateRoleAssignment(a); err != nil {
		t.Fatal(err)
	}
	// Scope is canonicalized for matching; the display form is preserved.
	if a.Scope != "/subscriptions/s/resourcegroups/rg" || a.ScopeDisplay != "/subscriptions/S/resourceGroups/RG" {
		t.Fatalf("scope handling: %+v", a)
	}
	if a.PrincipalType != "User" {
		t.Fatalf("default principalType = %q", a.PrincipalType)
	}

	// The same role to the same principal at the same scope conflicts, even
	// when the caller spells the scope differently.
	dup := &RoleAssignment{Name: "a2", ScopeDisplay: "/SUBSCRIPTIONS/s/RESOURCEGROUPS/rg",
		RoleDefinitionID: "/def/1", PrincipalID: "p1"}
	if err := s.CreateRoleAssignment(dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	// A different principal or role at the same scope is fine.
	if err := s.CreateRoleAssignment(&RoleAssignment{Name: "a3",
		ScopeDisplay: "/subscriptions/S/resourceGroups/RG", RoleDefinitionID: "/def/1",
		PrincipalID: "p2"}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetRoleAssignment("/subscriptions/s/resourcegroups/rg", "a1"); err != nil {
		t.Fatalf("get by scope+name: %v", err)
	}
	if _, err := s.GetRoleAssignment("/subscriptions/s/other", "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get at the wrong scope = %v", err)
	}
	if _, err := s.GetRoleAssignmentByName("a1"); err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if _, err := s.GetRoleAssignmentByName("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get absent = %v", err)
	}
	all, err := s.ListRoleAssignments()
	if err != nil || len(all) != 2 {
		t.Fatalf("list = %d %v", len(all), err)
	}
	deleted, err := s.DeleteRoleAssignment("a1")
	if err != nil || deleted.Name != "a1" {
		t.Fatalf("delete = %+v %v", deleted, err)
	}
	if _, err := s.DeleteRoleAssignment("a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete = %v", err)
	}
}

// TestClosedDBErrors: with the database closed every query fails, so each
// method must surface the error rather than silently reporting empty.
func TestClosedDBErrors(t *testing.T) {
	s, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.PutResourceGroup(&ResourceGroup{Subscription: "s", Name: "g"}); err == nil {
		t.Fatal("PutResourceGroup on a closed DB succeeded")
	}
	if _, err := s.GetResourceGroup("s", "g"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("GetResourceGroup on a closed DB = %v", err)
	}
	if _, err := s.ListResourceGroups("s"); err == nil {
		t.Fatal("ListResourceGroups on a closed DB succeeded")
	}
	if err := s.DeleteResourceGroup("s", "g"); err == nil {
		t.Fatal("DeleteResourceGroup on a closed DB succeeded")
	}
	if err := s.CreateRoleAssignment(&RoleAssignment{Name: "a", ScopeDisplay: "/"}); err == nil {
		t.Fatal("CreateRoleAssignment on a closed DB succeeded")
	}
	if _, err := s.ListRoleAssignments(); err == nil {
		t.Fatal("ListRoleAssignments on a closed DB succeeded")
	}
	if _, err := s.DeleteRoleAssignment("a"); err == nil {
		t.Fatal("DeleteRoleAssignment on a closed DB succeeded")
	}
}

// TestScanErrors: SQLite stores whatever you insert regardless of column
// affinity, so a text value in an INTEGER column makes Scan fail — the row
// error path every list must surface rather than silently skip.
func TestScanErrors(t *testing.T) {
	s := newStore(t)
	if _, err := s.db.Exec(`INSERT INTO resource_groups
(subscription, name, location, tags_json, created_at) VALUES ('sub','rg','loc','{}','not-a-number')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListResourceGroups("sub"); err == nil {
		t.Fatal("ListResourceGroups ignored an unscannable row")
	}
	if _, err := s.GetResourceGroup("sub", "rg"); err == nil {
		t.Fatal("GetResourceGroup ignored an unscannable row")
	}

	if _, err := s.db.Exec(`INSERT INTO role_assignments
(name, scope, scope_display, role_definition_id, principal_id, principal_type,
 description, condition, condition_version, created_at, updated_at, created_by)
VALUES ('a','/s','/s','/d','p','User','','','','not-a-number',0,'')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListRoleAssignments(); err == nil {
		t.Fatal("ListRoleAssignments ignored an unscannable row")
	}
	if _, err := s.GetRoleAssignmentByName("a"); err == nil {
		t.Fatal("GetRoleAssignmentByName ignored an unscannable row")
	}
	if _, err := s.DeleteRoleAssignment("a"); err == nil {
		t.Fatal("DeleteRoleAssignment ignored an unscannable row")
	}
}

// TestDeleteExecError: the row is found, then a BEFORE DELETE trigger aborts
// the delete — the branch between a successful lookup and a failed write.
func TestDeleteExecError(t *testing.T) {
	s := newStore(t)
	if err := s.CreateRoleAssignment(&RoleAssignment{
		Name: "a1", ScopeDisplay: "/s", RoleDefinitionID: "/d", PrincipalID: "p",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER no_delete BEFORE DELETE ON role_assignments
BEGIN SELECT RAISE(ABORT, 'delete refused'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteRoleAssignment("a1"); err == nil {
		t.Fatal("DeleteRoleAssignment ignored the aborted delete")
	}
}

func TestVaultCRUD(t *testing.T) {
	s := newStore(t)
	v := &Vault{Subscription: "sub", ResourceGroup: "rg", Name: "v1"}
	if err := s.PutVault(v); err != nil {
		t.Fatal(err)
	}
	// Defaults filled in.
	if v.Location == "" || v.TagsJSON != "{}" || v.PropertiesJSON != "{}" {
		t.Fatalf("defaults not applied: %+v", v)
	}
	// PUT is an upsert, and the name matches case-insensitively.
	if err := s.PutVault(&Vault{Subscription: "sub", ResourceGroup: "rg2", Name: "v1",
		Location: "eastus", TagsJSON: `{"a":"b"}`, PropertiesJSON: `{"x":1}`}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVault("sub", "V1")
	if err != nil || got.Location != "eastus" || got.ResourceGroup != "rg2" {
		t.Fatalf("upsert = %+v %v", got, err)
	}
	if _, err := s.GetVault("sub", "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent vault = %v", err)
	}

	// Listing by subscription, then narrowed to a resource group.
	if err := s.PutVault(&Vault{Subscription: "sub", ResourceGroup: "other", Name: "v2"}); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListVaults("sub", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all = %d %v", len(all), err)
	}
	narrowed, err := s.ListVaults("sub", "OTHER")
	if err != nil || len(narrowed) != 1 || narrowed[0].Name != "v2" {
		t.Fatalf("list by group = %+v %v", narrowed, err)
	}
	if l, _ := s.ListVaults("other-sub", ""); len(l) != 0 {
		t.Fatalf("cross-subscription leak: %v", l)
	}

	if err := s.DeleteVault("sub", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteVault("sub", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete = %v", err)
	}

	// An unscannable row surfaces as an error from both the get and the list.
	if _, err := s.db.Exec(`INSERT INTO vaults
(subscription, resource_group, name, location, tags_json, properties_json, created_at)
VALUES ('sub','rg','bad','loc','{}','{}','not-a-number')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListVaults("sub", ""); err == nil {
		t.Fatal("ListVaults ignored an unscannable row")
	}
	if _, err := s.GetVault("sub", "bad"); err == nil {
		t.Fatal("GetVault ignored an unscannable row")
	}
}

func TestVaultClosedDBErrors(t *testing.T) {
	s, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.PutVault(&Vault{Subscription: "s", Name: "v"}); err == nil {
		t.Fatal("PutVault on a closed DB succeeded")
	}
	if _, err := s.ListVaults("s", ""); err == nil {
		t.Fatal("ListVaults on a closed DB succeeded")
	}
	if err := s.DeleteVault("s", "v"); err == nil {
		t.Fatal("DeleteVault on a closed DB succeeded")
	}
	// migrateVaults surfaces its own DDL failure.
	if err := s.migrateVaults(); err == nil {
		t.Fatal("migrateVaults on a closed DB succeeded")
	}
}
