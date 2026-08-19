package arm

// White-box handler tests: the branches the typed SDKs cannot reach —
// storage failures (tables dropped under a live handler, the family's
// established injection pattern), and the response/filter branches that need
// specific inputs.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/auth"
	"github.com/calvinchengx/arm-emulator/internal/clock"
	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/store"
)

const testSub = "6082bfda-63d0-46f4-8272-ae9195139feb"

func newService(t *testing.T, dataDir string) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(dataDir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{
		EntraIssuer: "https://e/t/v2.0", SubscriptionID: testSub, TenantID: "tid",
	}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	return New(cfg, st, nil), st
}

var caller = &auth.Principal{ID: "caller-oid", Type: "ServicePrincipal"}

// req runs a handler directly with a body and query.
func req(method, target, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	return r
}

func TestAssignmentBodyOptionalFields(t *testing.T) {
	s, _ := newService(t, "")
	// description, condition and conditionVersion appear only when set —
	// ARM omits them rather than emitting empty strings.
	full := s.assignmentBody(&store.RoleAssignment{
		Name: "a", ScopeDisplay: "/subscriptions/s", Description: "why",
		Condition: "@Resource[x] StringEquals 'y'", ConditionVersion: "2.0",
	})
	props := full["properties"].(map[string]any)
	if props["description"] != "why" || props["condition"] == nil || props["conditionVersion"] != "2.0" {
		t.Fatalf("optional fields missing: %+v", props)
	}
	bare := s.assignmentBody(&store.RoleAssignment{Name: "b", ScopeDisplay: "/"})
	bareProps := bare["properties"].(map[string]any)
	if _, ok := bareProps["description"]; ok {
		t.Fatal("empty description emitted")
	}
	if _, ok := bareProps["condition"]; ok {
		t.Fatal("empty condition emitted")
	}
	// A root-scoped assignment's id has no doubled slash.
	if id := bare["id"].(string); strings.Contains(id, "//providers") {
		t.Fatalf("root scope id = %q", id)
	}
}

func TestRoleByNameMiss(t *testing.T) {
	if _, ok := RoleByName("Duke of Vaults"); ok {
		t.Fatal("unknown role name resolved")
	}
}

func TestFilterPrincipalIDTrailing(t *testing.T) {
	// A principal filter followed by another clause stops at the separator.
	if got := filterPrincipalID("principalId eq 'abc' and atScope()"); got != "abc" {
		t.Fatalf("trailing clause = %q", got)
	}
	if got := filterPrincipalID("principalId eq abc&extra=1"); got != "abc" {
		t.Fatalf("ampersand-separated = %q", got)
	}
}

func TestRootScopeAssignmentAndPrincipalFilter(t *testing.T) {
	s, _ := newService(t, "")
	const role = "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"

	// An empty scope means the tenant root; the stored assignment reads "/".
	w := httptest.NewRecorder()
	s.createAssignment(w, req("PUT", "/x", `{"properties":{"roleDefinitionId":"`+role+`","principalId":"p1"}}`),
		"", "root-1", caller)
	if w.Code != http.StatusCreated {
		t.Fatalf("root-scope create = %d %s", w.Code, w.Body.Bytes())
	}
	got, err := s.Store.GetRoleAssignmentByName("root-1")
	if err != nil || got.ScopeDisplay != "/" {
		t.Fatalf("root scope stored as %+v %v", got, err)
	}

	// A second principal, then the principalId filter narrows the listing.
	w = httptest.NewRecorder()
	s.createAssignment(w, req("PUT", "/x", `{"properties":{"roleDefinitionId":"`+role+`","principalId":"p2"}}`),
		"/subscriptions/"+testSub, "sub-1", caller)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.listAssignments(w, req("GET", "/x?$filter=principalId+eq+'p2'", ""), "/subscriptions/"+testSub)
	var list struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Value) != 1 || list.Value[0].Name != "sub-1" {
		t.Fatalf("principal filter = %+v", list.Value)
	}
}

func TestFeedSkipsDanglingRole(t *testing.T) {
	s, st := newService(t, "")
	// An assignment whose role definition no longer resolves grants nothing;
	// the feed skips it rather than reporting an empty-permission entry.
	if err := st.CreateRoleAssignment(&store.RoleAssignment{
		Name: "d1", ScopeDisplay: "/subscriptions/" + testSub,
		RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/8bce0edd-d70c-43ae-8d40-1b502457ef7d",
		PrincipalID:      "p1",
	}); err != nil {
		t.Fatal(err)
	}
	eff, err := s.EffectiveAt("/subscriptions/" + testSub)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff) != 0 {
		t.Fatalf("dangling role surfaced: %+v", eff)
	}
}

func TestAssignmentScopeSubscriptionCheck(t *testing.T) {
	s, _ := newService(t, "")
	// A scope naming an unknown subscription is refused before the provider
	// is consulted.
	w := httptest.NewRecorder()
	s.roleAssignments(w, req("GET", "/x", ""),
		"/subscriptions/470cdf39-a19d-4440-a4c2-55568885427d/resourceGroups/g", nil, caller)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "SubscriptionNotFound") {
		t.Fatalf("unknown subscription scope = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestStorageFailures drops each table under a live handler so every
// InternalServerError branch is exercised with a real driver error.
func TestStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	const role = "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"

	// Seed one of each so the handlers get past their lookups.
	if err := st.PutResourceGroup(&store.ResourceGroup{Subscription: testSub, Name: "rg"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateRoleAssignment(&store.RoleAssignment{
		Name: "a1", ScopeDisplay: "/subscriptions/" + testSub,
		RoleDefinitionID: role, PrincipalID: "p1",
	}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE resource_groups`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE role_assignments`); err != nil {
		t.Fatal(err)
	}

	scope := "/subscriptions/" + testSub
	cases := map[string]func(w http.ResponseWriter){
		"list groups": func(w http.ResponseWriter) {
			s.listResourceGroups(w, req("GET", "/x", ""), testSub)
		},
		"put group": func(w http.ResponseWriter) {
			s.resourceGroup(w, req("PUT", "/x", `{"location":"westeurope"}`), testSub, "rg2")
		},
		"get group": func(w http.ResponseWriter) {
			s.resourceGroup(w, req("GET", "/x", ""), testSub, "rg")
		},
		"delete group": func(w http.ResponseWriter) {
			s.resourceGroup(w, req("DELETE", "/x", ""), testSub, "rg")
		},
		"create assignment": func(w http.ResponseWriter) {
			s.createAssignment(w, req("PUT", "/x", `{"properties":{"roleDefinitionId":"`+role+`","principalId":"p9"}}`),
				scope, "a9", caller)
		},
		"get assignment": func(w http.ResponseWriter) {
			s.roleAssignments(w, req("GET", "/x", ""), scope, []string{"a1"}, caller)
		},
		"delete assignment": func(w http.ResponseWriter) {
			s.roleAssignments(w, req("DELETE", "/x", ""), scope, []string{"a1"}, caller)
		},
		"list assignments": func(w http.ResponseWriter) {
			s.listAssignments(w, req("GET", "/x", ""), scope)
		},
		"feed": func(w http.ResponseWriter) {
			s.ServeFeed(w, req("GET", "/_family/authorization?scope="+scope, ""))
		},
	}
	for name, call := range cases {
		w := httptest.NewRecorder()
		call(w)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with dropped tables = %d %s", name, w.Code, w.Body.Bytes())
		}
	}

	// EffectiveAt surfaces the storage error to its caller rather than
	// reporting "no assignments".
	if _, err := s.EffectiveAt(scope); err == nil {
		t.Fatal("EffectiveAt with dropped tables returned no error")
	}
}

func TestListAssignmentsScopeSkips(t *testing.T) {
	s, st := newService(t, "")
	const role = "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
	sub := "/subscriptions/" + testSub
	rg := sub + "/resourceGroups/rg1"
	for i, sc := range []string{sub, rg} {
		if err := st.CreateRoleAssignment(&store.RoleAssignment{
			Name: string(rune('a' + i)), ScopeDisplay: sc, RoleDefinitionID: role,
			PrincipalID: "p" + string(rune('1'+i)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(target, filter string) int {
		w := httptest.NewRecorder()
		s.listAssignments(w, req("GET", "/x?$filter="+filter, ""), target)
		var out struct {
			Value []map[string]any `json:"value"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return len(out.Value)
	}
	// Unfiltered at the group: its own assignment plus the inherited one.
	if got := count(rg, ""); got != 2 {
		t.Fatalf("inherited listing = %d", got)
	}
	// atScope() skips the subscription-level assignment.
	if got := count(rg, "atScope()"); got != 1 {
		t.Fatalf("atScope listing = %d", got)
	}
	// A sibling group sees only the inherited subscription assignment.
	if got := count(sub+"/resourceGroups/other", ""); got != 1 {
		t.Fatalf("sibling listing = %d", got)
	}
}

func TestResourceGroupUnknownSubscription(t *testing.T) {
	s, _ := newService(t, "")
	w := httptest.NewRecorder()
	s.resourceGroup(w, req("GET", "/x", ""), "470cdf39-a19d-4440-a4c2-55568885427d", "rg")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "SubscriptionNotFound") {
		t.Fatalf("unknown subscription = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestResourceGroupDeleteError: a BEFORE DELETE trigger makes the delete fail
// after the row is found, reaching the handler's 500 branch.
func TestResourceGroupDeleteError(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	if err := st.PutResourceGroup(&store.ResourceGroup{Subscription: testSub, Name: "rg"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_rg_delete BEFORE DELETE ON resource_groups
BEGIN SELECT RAISE(ABORT, 'delete refused'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.resourceGroup(w, req("DELETE", "/x", ""), testSub, "rg")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with a refusing trigger = %d %s", w.Code, w.Body.Bytes())
	}
}
