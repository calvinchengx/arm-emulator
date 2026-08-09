package arm

// Custom role definitions: the create/update/delete path, the rules that
// make them safe (built-ins immutable, names unique, assignableScopes
// enforced), and the payoff — a role a caller invented reaches the family
// feed, so its dataActions genuinely grant access in a sibling data plane.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const customGUID = "11111111-2222-4333-8444-555555555555"

func putRole(s *Service, guid, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.roleDefinitions(w, req("PUT", "/x?api-version=2022-04-01", body),
		"/subscriptions/"+testSub, []string{guid})
	return w
}

func roleBody(name, scope string) string {
	return fmt.Sprintf(`{"properties":{"roleName":%q,"description":"a custom role",
		"permissions":[{"actions":["Microsoft.KeyVault/vaults/read"],
		"dataActions":["Microsoft.KeyVault/vaults/secrets/getSecret/action"]}],
		"assignableScopes":[%q]}}`, name, scope)
}

func TestCustomRoleLifecycle(t *testing.T) {
	s, _ := newService(t, "")
	subScope := "/subscriptions/" + testSub

	// Create → 201, reported as a CustomRole carrying its assignable scopes.
	w := putRole(s, customGUID, roleBody("Vault Secret Peeker", subScope))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	var got struct {
		Name       string
		Properties struct {
			RoleName         string
			Type             string
			AssignableScopes []string
			CreatedOn        string
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Name != customGUID || got.Properties.Type != "CustomRole" ||
		len(got.Properties.AssignableScopes) != 1 || got.Properties.CreatedOn == "" {
		t.Fatalf("created role = %+v", got)
	}

	// Update the same GUID → 200, not a second definition.
	if w := putRole(s, customGUID, roleBody("Vault Secret Peeker", subScope)); w.Code != http.StatusOK {
		t.Fatalf("update = %d %s", w.Code, w.Body.Bytes())
	}

	// It reads back by GUID and appears in the list beside the built-ins.
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusOK {
		t.Fatalf("get = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01", ""), subScope, nil)
	var list struct{ Value []struct{ Name string } }
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Value) != len(BuiltInRoles())+1 {
		t.Fatalf("list = %d entries, want built-ins + 1", len(list.Value))
	}
	// The $filter the CLI sends finds it by name.
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01&$filter=roleName%20eq%20'Vault%20Secret%20Peeker'", ""),
		subScope, nil)
	list.Value = nil
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Value) != 1 || list.Value[0].Name != customGUID {
		t.Fatalf("filtered list = %+v", list.Value)
	}

	// Delete → 200 and it is gone; deleting again is a no-op.
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusNoContent {
		t.Fatalf("second delete = %d", w.Code)
	}
}

func TestCustomRoleRules(t *testing.T) {
	s, _ := newService(t, "")
	subScope := "/subscriptions/" + testSub
	// A real built-in GUID: Reader.
	const builtIn = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

	// Built-ins are Microsoft's: neither writable nor deletable.
	if w := putRole(s, builtIn, roleBody("Hijacked Reader", subScope)); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "RoleDefinitionUpdateNotPermitted") {
		t.Fatalf("overwriting a built-in = %d %s", w.Code, w.Body.Bytes())
	}
	w := httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{builtIn})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "RoleDefinitionDeleteNotPermitted") {
		t.Fatalf("deleting a built-in = %d %s", w.Code, w.Body.Bytes())
	}

	// The required properties are required.
	for _, tc := range []struct{ body, code string }{
		{`{`, "InvalidRequestContent"},
		{`{"properties":{"permissions":[{}],"assignableScopes":["/"]}}`, "MissingRoleName"},
		{`{"properties":{"roleName":"R","assignableScopes":["/"]}}`, "MissingPermissions"},
		{`{"properties":{"roleName":"R","permissions":[{}]}}`, "MissingAssignableScopes"},
		{`{"properties":{"roleName":"R","permissions":[{}],"assignableScopes":["not-a-scope"]}}`, "InvalidAssignableScope"},
	} {
		if w := putRole(s, customGUID, tc.body); w.Code != http.StatusBadRequest ||
			!strings.Contains(w.Body.String(), tc.code) {
			t.Errorf("%s = %d %s", tc.code, w.Code, w.Body.Bytes())
		}
	}

	// Two definitions cannot share a display name.
	if w := putRole(s, customGUID, roleBody("Shared Name", subScope)); w.Code != http.StatusCreated {
		t.Fatalf("first create = %d %s", w.Code, w.Body.Bytes())
	}
	other := "99999999-2222-4333-8444-555555555555"
	if w := putRole(s, other, roleBody("Shared Name", subScope)); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "RoleDefinitionWithSameNameExists") {
		t.Fatalf("duplicate name = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCustomRoleAssignableScopes(t *testing.T) {
	s, st := newService(t, "")
	subScope := "/subscriptions/" + testSub
	rgScope := subScope + "/resourceGroups/rg-scoped"

	// A role assignable only inside one resource group.
	if w := putRole(s, customGUID, roleBody("Group Only", rgScope)); w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	assign := func(scope string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"properties":{"roleDefinitionId":%q,"principalId":"p-1"}}`,
			s.roleDefinitionID(subScope, customGUID))
		s.roleAssignments(w, req("PUT", "/x?api-version=2022-04-01", body), scope,
			[]string{"aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"}, caller)
		return w
	}
	// Above the assignable scope: refused, because that is what
	// assignableScopes means.
	if w := assign(subScope); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "ScopeNotAssignable") {
		t.Fatalf("assignment above assignableScopes = %d %s", w.Code, w.Body.Bytes())
	}
	// At the scope itself: allowed.
	if w := assign(rgScope); w.Code != http.StatusCreated {
		t.Fatalf("assignment at the assignable scope = %d %s", w.Code, w.Body.Bytes())
	}
	// A built-in is assignable anywhere.
	w := httptest.NewRecorder()
	body := `{"properties":{"roleDefinitionId":"acdd72a7-3385-48ef-bd42-f606fba81ae7","principalId":"p-2"}}`
	s.roleAssignments(w, req("PUT", "/x?api-version=2022-04-01", body), subScope,
		[]string{"bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"}, caller)
	if w.Code != http.StatusCreated {
		t.Fatalf("built-in assignment = %d %s", w.Code, w.Body.Bytes())
	}

	// A definition carrying assignments cannot be deleted out from under them.
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "RoleDefinitionHasAssignments") {
		t.Fatalf("delete with assignments = %d %s", w.Code, w.Body.Bytes())
	}

	// THE PAYOFF: the custom role's dataActions reach the family feed, which
	// is what a sibling data plane reads to authorize a request. A role a
	// caller invented genuinely grants access.
	eff, err := s.EffectiveAt(rgScope)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range eff {
		if e.PrincipalID == "p-1" && e.RoleName == "Group Only" {
			found = true
			if len(e.DataActions) != 1 ||
				e.DataActions[0] != "Microsoft.KeyVault/vaults/secrets/getSecret/action" {
				t.Fatalf("custom dataActions in the feed = %v", e.DataActions)
			}
		}
	}
	if !found {
		t.Fatalf("the custom role never reached the feed: %+v", eff)
	}
	_ = st
}

// TestCustomRoleStorageFailures drops the table under live handlers, and
// corrupts a stored definition, so every branch that reports a failure
// rather than silently granting nothing is exercised.
func TestCustomRoleStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	subScope := "/subscriptions/" + testSub
	if w := putRole(s, customGUID, roleBody("Doomed", subScope)); w.Code != http.StatusCreated {
		t.Fatalf("seed = %d %s", w.Code, w.Body.Bytes())
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A definition whose stored JSON cannot be decoded must not be served as
	// if it were valid.
	if _, err := db.Exec(`UPDATE role_definitions SET permissions_json = 'not json' WHERE guid = ?`,
		customGUID); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusNotFound {
		t.Fatalf("get of an undecodable definition = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01", ""), subScope, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("list with an undecodable definition = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete of an undecodable definition = %d", w.Code)
	}

	// Assignments cannot be counted: the delete refuses rather than guessing.
	if _, err := db.Exec(`UPDATE role_definitions SET permissions_json = '[]' WHERE guid = ?`,
		customGUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE role_assignments`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the assignments table dropped = %d", w.Code)
	}

	// The table itself is gone: writes, reads and deletes all say so.
	if _, err := db.Exec(`DROP TABLE role_definitions`); err != nil {
		t.Fatal(err)
	}
	if w := putRole(s, customGUID, roleBody("Gone", subScope)); w.Code != http.StatusInternalServerError {
		t.Fatalf("put with the table dropped = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("GET", "/x?api-version=2022-04-01", ""), subScope, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("list with the table dropped = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the table dropped = %d", w.Code)
	}
}

// TestCustomRoleUndecodableScopes: assignableScopes is the field that
// decides where a role may be used, so a definition whose scopes cannot be
// read must not resolve at all.
func TestCustomRoleUndecodableScopes(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	subScope := "/subscriptions/" + testSub
	if w := putRole(s, customGUID, roleBody("Scope Broken", subScope)); w.Code != http.StatusCreated {
		t.Fatalf("seed = %d", w.Code)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE role_definitions SET scopes_json = '{' WHERE guid = ?`, customGUID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.resolveRole(customGUID); ok {
		t.Fatal("a definition with unreadable assignableScopes resolved")
	}
	// And an assignment naming it is refused rather than silently granted.
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"properties":{"roleDefinitionId":%q,"principalId":"p-9"}}`,
		s.roleDefinitionID(subScope, customGUID))
	s.roleAssignments(w, req("PUT", "/x?api-version=2022-04-01", body), subScope,
		[]string{"cccccccc-1111-4111-8111-cccccccccccc"}, caller)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "RoleDefinitionDoesNotExist") {
		t.Fatalf("assignment to an unreadable definition = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestCustomRoleDeleteBlocked: the row survives every check and then the
// delete itself is refused by storage. The definition must not be reported
// as deleted when it is still there.
func TestCustomRoleDeleteBlocked(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	subScope := "/subscriptions/" + testSub
	if w := putRole(s, customGUID, roleBody("Undeletable", subScope)); w.Code != http.StatusCreated {
		t.Fatalf("seed = %d", w.Code)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`CREATE TRIGGER no_roledef_delete BEFORE DELETE ON role_definitions
		 BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.roleDefinitions(w, req("DELETE", "/x?api-version=2022-04-01", ""), subScope, []string{customGUID})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("blocked delete = %d %s", w.Code, w.Body.Bytes())
	}
}
