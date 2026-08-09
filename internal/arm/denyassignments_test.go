package arm

// Deny assignments: the read-only ARM surface, the seeding seam, and — the
// part that is a real feature rather than a shape — the evaluation. A deny
// beats the role assignment that grants the same action, and these tests
// pin every rule that decides it.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// mustAssign grants Key Vault Secrets User at the subscription, so a deny
// has a real grant to override.
func mustAssign(t *testing.T, s *Service, st *store.Store, principal string) {
	t.Helper()
	if err := st.CreateRoleAssignment(&store.RoleAssignment{
		Name: "grant-" + principal, ScopeDisplay: denyScope,
		RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/" +
			"4633458b-17de-408a-b874-0445c86b69e6",
		PrincipalID: principal, PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
}

const (
	denyScope   = "/subscriptions/" + testSub
	getSecret   = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	setSecret   = "Microsoft.KeyVault/vaults/secrets/setSecret/action"
	deniedName  = "22222222-3333-4444-8555-666666666666"
	principalID = "aaaaaaaa-1111-4222-8333-444444444444"
)

// seedDeny posts a deny assignment through the control surface, as an
// operator or a test harness would.
func seedDeny(t *testing.T, s *Service, name, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	path := "/_emulator/denyassignments"
	if name != "" {
		path += "/" + name
	}
	s.ServeDenyControl(w, req("POST", path, body))
	return w
}

func denyBodyJSON(scope, principal string, extra string) string {
	return fmt.Sprintf(`{"scope":%q,"denyAssignmentName":"No secret reads",
		"description":"seeded by a deployment stack",
		"permissions":[{"dataActions":[%q]}],
		"principals":[{"id":%q,"type":"ServicePrincipal"}]%s}`,
		scope, getSecret, principal, extra)
}

// getDeny reads through the ARM surface.
func getDeny(s *Service, scope string, rest ...string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.denyAssignments(w, req("GET", "/x?api-version=2022-04-01", ""), scope, rest)
	return w
}

func TestDenyAssignmentReadSurface(t *testing.T) {
	s, _ := newService(t, "")
	if w := seedDeny(t, s, deniedName, denyBodyJSON(denyScope, principalID, "")); w.Code != http.StatusCreated {
		t.Fatalf("seed = %d %s", w.Code, w.Body.Bytes())
	}

	// Get by name returns ARM's shape, including the properties that only
	// deny assignments have.
	w := getDeny(s, denyScope, deniedName)
	if w.Code != http.StatusOK {
		t.Fatalf("get = %d %s", w.Code, w.Body.Bytes())
	}
	var got struct {
		ID, Name, Type string
		Properties     struct {
			DenyAssignmentName      string
			Description             string
			Scope                   string
			IsSystemProtected       bool
			DoNotApplyToChildScopes bool
			Principals              []struct{ ID, Type string }
			ExcludePrincipals       []struct{ ID string }
			Permissions             []struct {
				DataActions, NotDataActions, Actions, NotActions []string
			}
			CreatedOn, UpdatedOn string
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	p := got.Properties
	switch {
	case got.Type != "Microsoft.Authorization/denyAssignments":
		t.Fatalf("type = %q", got.Type)
	case got.ID != denyScope+"/providers/Microsoft.Authorization/denyAssignments/"+deniedName:
		t.Fatalf("id = %q", got.ID)
	case p.DenyAssignmentName != "No secret reads" || p.Description == "":
		t.Fatalf("properties = %+v", p)
	case !p.IsSystemProtected:
		// Azure's own deny assignments are system-protected; so are these.
		t.Fatal("isSystemProtected should be true")
	case len(p.Principals) != 1 || p.Principals[0].ID != principalID:
		t.Fatalf("principals = %+v", p.Principals)
	case p.ExcludePrincipals == nil || p.Permissions == nil:
		t.Fatal("empty lists must be emitted, not omitted")
	case len(p.Permissions[0].DataActions) != 1 || p.Permissions[0].Actions == nil:
		t.Fatalf("permissions = %+v", p.Permissions)
	case p.CreatedOn == "" || p.UpdatedOn == "":
		t.Fatalf("timestamps = %+v", p)
	}

	// The collection: visible at its own scope and inherited downward.
	for _, scope := range []string{denyScope, denyScope + "/resourceGroups/rg"} {
		if n := denyCount(t, getDeny(s, scope)); n != 1 {
			t.Fatalf("list at %s = %d", scope, n)
		}
	}
	// Not visible above it.
	if n := denyCount(t, getDeny(s, "/")); n != 0 {
		t.Fatalf("list at tenant root = %d", n)
	}

	// A name that does not exist is a 404, not an empty document.
	if w := getDeny(s, denyScope, "no-such-deny"); w.Code != http.StatusNotFound {
		t.Fatalf("get unknown = %d", w.Code)
	}
	// An unknown subscription is refused before the provider is reached.
	if w := getDeny(s, "/subscriptions/00000000-0000-0000-0000-000000000001"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown subscription = %d", w.Code)
	}
}

func denyCount(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d %s", w.Code, w.Body.Bytes())
	}
	var got struct{ Value []json.RawMessage }
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return len(got.Value)
}

// TestDenyAssignmentsAreReadOnly pins the rule that keeps this surface
// honest: no client may create or delete one over ARM, because Azure will
// not let it either.
func TestDenyAssignmentsAreReadOnly(t *testing.T) {
	s, _ := newService(t, "")
	for _, method := range []string{"PUT", "DELETE", "PATCH", "POST"} {
		w := httptest.NewRecorder()
		s.denyAssignments(w, req(method, "/x?api-version=2022-04-01", "{}"),
			denyScope, []string{deniedName})
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d, want 405", method, w.Code)
		}
		// The refusal must say where they do come from, or it reads as a
		// missing feature rather than a faithful one.
		if body := w.Body.String(); !strings.Contains(body, "read-only") || !strings.Contains(body, "_emulator") {
			t.Fatalf("%s refusal is unhelpful: %s", method, body)
		}
	}
}

func TestDenyAssignmentFilters(t *testing.T) {
	s, _ := newService(t, "")
	rg := denyScope + "/resourceGroups/rg"
	seedDeny(t, s, deniedName, denyBodyJSON(denyScope, principalID, ""))
	seedDeny(t, s, "33333333-4444-4555-8666-777777777777",
		fmt.Sprintf(`{"scope":%q,"denyAssignmentName":"Group lockout",
			"permissions":[{"dataActions":["*"]}],
			"principals":[{"id":"bbbbbbbb-1111-4222-8333-444444444444","type":"Group"}]}`, rg))

	// Default: everything reaching the scope, inherited included.
	if n := denyCount(t, getDeny(s, rg)); n != 2 {
		t.Fatalf("default list at the group = %d, want both", n)
	}
	// atScope(): only the one made here.
	w := httptest.NewRecorder()
	s.denyAssignments(w, req("GET", "/x?api-version=2022-04-01&$filter=atScope()", ""), rg, nil)
	if n := denyCount(t, w); n != 1 {
		t.Fatalf("atScope() = %d", n)
	}
	// principalId eq
	w = httptest.NewRecorder()
	s.denyAssignments(w, req("GET",
		"/x?api-version=2022-04-01&$filter=principalId+eq+'"+principalID+"'", ""), rg, nil)
	if n := denyCount(t, w); n != 1 {
		t.Fatalf("principalId filter = %d", n)
	}
	// denyAssignmentName eq
	w = httptest.NewRecorder()
	s.denyAssignments(w, req("GET",
		"/x?api-version=2022-04-01&$filter=denyAssignmentName%20eq%20'Group%20lockout'", ""), rg, nil)
	if n := denyCount(t, w); n != 1 {
		t.Fatalf("denyAssignmentName filter = %d", n)
	}
	// A filter matching nothing yields an empty list, not everything.
	w = httptest.NewRecorder()
	s.denyAssignments(w, req("GET",
		"/x?api-version=2022-04-01&$filter=denyAssignmentName%20eq%20'nope'", ""), rg, nil)
	if n := denyCount(t, w); n != 0 {
		t.Fatalf("non-matching filter = %d", n)
	}
}

// TestDenyBeatsGrant is the point of the feature: the same principal holds a
// role granting getSecret, and the deny takes it away.
func TestDenyBeatsGrant(t *testing.T) {
	s, _ := newService(t, "")
	scope := denyScope

	if denied, err := s.Denies(scope, []string{principalID}, getSecret); err != nil || denied {
		t.Fatalf("denied before any deny existed: %v %v", denied, err)
	}
	seedDeny(t, s, deniedName, denyBodyJSON(scope, principalID, ""))

	denied, err := s.Denies(scope, []string{principalID}, getSecret)
	if err != nil || !denied {
		t.Fatalf("getSecret should be denied: %v %v", denied, err)
	}
	// Only what the deny names: a different action is untouched.
	if denied, _ := s.Denies(scope, []string{principalID}, setSecret); denied {
		t.Fatal("setSecret should not be denied")
	}
	// Only who it names.
	if denied, _ := s.Denies(scope, []string{"someone-else"}, getSecret); denied {
		t.Fatal("another principal should not be denied")
	}
	// It inherits downward, like every other ARM assignment.
	if denied, _ := s.Denies(scope+"/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v",
		[]string{principalID}, getSecret); !denied {
		t.Fatal("a deny at the subscription must reach a vault beneath it")
	}
	// And not upward.
	if denied, _ := s.Denies("/", []string{principalID}, getSecret); denied {
		t.Fatal("a deny at the subscription must not reach the tenant root")
	}
}

func TestDenyEvaluationRules(t *testing.T) {
	scope := denyScope
	me := []string{principalID}

	cases := []struct {
		name  string
		deny  DenyAssignment
		who   []string
		what  string
		where string
		want  bool
	}{{
		name: "the all-principals GUID denies everyone, named or not",
		deny: DenyAssignment{Scope: scope,
			Principals:  []DenyPrincipal{{ID: AllPrincipals, Type: "SystemDefined"}},
			Permissions: []DenyPermission{{DataActions: []string{"*"}}}},
		who: []string{"anybody-at-all"}, what: getSecret, where: scope, want: true,
	}, {
		name: "an excluded principal escapes even a deny-everyone",
		deny: DenyAssignment{Scope: scope,
			Principals:        []DenyPrincipal{{ID: AllPrincipals, Type: "SystemDefined"}},
			ExcludePrincipals: []DenyPrincipal{{ID: principalID}},
			Permissions:       []DenyPermission{{DataActions: []string{"*"}}}},
		who: me, what: getSecret, where: scope, want: false,
	}, {
		name: "notDataActions carve an action back out of the deny",
		deny: DenyAssignment{Scope: scope,
			Principals: []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{
				DataActions: []string{"Microsoft.KeyVault/*"}, NotDataActions: []string{getSecret}}}},
		who: me, what: getSecret, where: scope, want: false,
	}, {
		name: "the same deny still catches what was not carved out",
		deny: DenyAssignment{Scope: scope,
			Principals: []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{
				DataActions: []string{"Microsoft.KeyVault/*"}, NotDataActions: []string{getSecret}}}},
		who: me, what: setSecret, where: scope, want: true,
	}, {
		name: "a wildcard spans segment boundaries, as Azure's does",
		deny: DenyAssignment{Scope: scope,
			Principals:  []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{DataActions: []string{"Microsoft.KeyVault/vaults/secrets/*"}}}},
		who: me, what: getSecret, where: scope, want: true,
	}, {
		name: "a group the caller belongs to carries the deny",
		deny: DenyAssignment{Scope: scope,
			Principals:  []DenyPrincipal{{ID: "group-oid", Type: "Group"}},
			Permissions: []DenyPermission{{DataActions: []string{getSecret}}}},
		who: []string{principalID, "group-oid"}, what: getSecret, where: scope, want: true,
	}, {
		name: "doNotApplyToChildScopes pins the deny to its own scope",
		deny: DenyAssignment{Scope: scope, DoNotApplyToChildScopes: true,
			Principals:  []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{DataActions: []string{getSecret}}}},
		who: me, what: getSecret, where: scope + "/resourceGroups/rg", want: false,
	}, {
		name: "and still applies exactly there",
		deny: DenyAssignment{Scope: scope, DoNotApplyToChildScopes: true,
			Principals:  []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{DataActions: []string{getSecret}}}},
		who: me, what: getSecret, where: scope, want: true,
	}, {
		name: "a control-plane deny does not silently deny a data action",
		deny: DenyAssignment{Scope: scope,
			Principals:  []DenyPrincipal{{ID: principalID}},
			Permissions: []DenyPermission{{Actions: []string{"*"}}}},
		who: me, what: getSecret, where: scope, want: false,
	}, {
		name: "an empty principal id matches nothing",
		deny: DenyAssignment{Scope: scope,
			Principals:  []DenyPrincipal{{ID: ""}},
			Permissions: []DenyPermission{{DataActions: []string{"*"}}}},
		who: []string{""}, what: getSecret, where: scope, want: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.deny.appliesAt(tc.where) && tc.deny.DeniesAction(tc.who, tc.what, true)
			if got != tc.want {
				t.Fatalf("denied = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestActionMatches(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", getSecret, true},
		{getSecret, getSecret, true},
		{"MICROSOFT.KEYVAULT/VAULTS/SECRETS/GETSECRET/ACTION", getSecret, true},
		{getSecret, setSecret, false},
		{"Microsoft.KeyVault/*", getSecret, true},
		{"Microsoft.Storage/*", getSecret, false},
		{"Microsoft.KeyVault/*/getSecret/action", getSecret, true},
		{"Microsoft.KeyVault/*/setSecret/action", getSecret, false},
		{"*/action", getSecret, true},
		{"*/read", getSecret, false},
		{"Microsoft.KeyVault/vaults/secrets/get*", getSecret, true},
		// Two wildcards: the middle literal has to be found between them.
		{"Microsoft.*/secrets/*", getSecret, true},
		{"Microsoft.*/certificates/*", getSecret, false},
		{"*/vaults/*/action", getSecret, true},
		// A wildcard cannot match a prefix that is not there.
		{"vaults/*", getSecret, false},
	}
	for _, tc := range cases {
		if got := actionMatches(tc.pattern, tc.action); got != tc.want {
			t.Fatalf("actionMatches(%q, %q) = %v, want %v", tc.pattern, tc.action, got, tc.want)
		}
	}
}

// TestDenyReachesTheFamilyFeed is the end of the chain: a data plane reading
// the feed learns both the grant and the deny that overrides it.
func TestDenyReachesTheFamilyFeed(t *testing.T) {
	s, st := newService(t, "")
	scope := denyScope
	mustAssign(t, s, st, principalID)
	seedDeny(t, s, deniedName, denyBodyJSON(scope, principalID, ""))

	w := httptest.NewRecorder()
	s.ServeFeed(w, req("GET", "/_family/authorization?scope="+scope, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("feed = %d %s", w.Code, w.Body.Bytes())
	}
	var feed struct {
		Assignments []struct {
			PrincipalID string
			DataActions []string
			Denied      []struct{ DataActions []string }
		}
		DenyAssignments []struct {
			Name       string
			Scope      string
			Principals []struct{ ID string }
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Assignments) != 1 || len(feed.Assignments[0].DataActions) == 0 {
		t.Fatalf("assignments = %+v", feed.Assignments)
	}
	// The grant is still reported — a deny does not erase the assignment,
	// it overrides it, and the data plane must be able to see both.
	if d := feed.Assignments[0].Denied; len(d) != 1 || len(d[0].DataActions) != 1 ||
		d[0].DataActions[0] != getSecret {
		t.Fatalf("denied riding with the assignment = %+v", d)
	}
	// And the standalone block, which is what a data plane consults when the
	// caller reaches the deny through a group.
	if len(feed.DenyAssignments) != 1 || feed.DenyAssignments[0].Name != deniedName ||
		len(feed.DenyAssignments[0].Principals) != 1 {
		t.Fatalf("feed denyAssignments = %+v", feed.DenyAssignments)
	}

	// A deny naming somebody else rides with nobody.
	if err := st.DeleteDenyAssignment(deniedName); err != nil {
		t.Fatal(err)
	}
	seedDeny(t, s, deniedName, denyBodyJSON(scope, "unrelated-principal", ""))
	eff, err := s.EffectiveAt(scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff) != 1 || len(eff[0].Denied) != 0 {
		t.Fatalf("a deny for another principal attached anyway: %+v", eff)
	}
}

func TestDenyControlSurface(t *testing.T) {
	s, _ := newService(t, "")

	// A seed with no name gets a generated GUID, as ARM would give it.
	w := seedDeny(t, s, "", denyBodyJSON(denyScope, principalID, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("unnamed seed = %d %s", w.Code, w.Body.Bytes())
	}
	var made struct{ Name string }
	_ = json.Unmarshal(w.Body.Bytes(), &made)
	if len(made.Name) != 36 {
		t.Fatalf("generated name = %q", made.Name)
	}

	// A name in the body is honoured when the path has none.
	w = seedDeny(t, s, "", fmt.Sprintf(`{"name":%q,"scope":%q,
		"permissions":[{"dataActions":["*"]}],"principals":[{"id":%q}],
		"doNotApplyToChildScopes":true}`, deniedName, denyScope, principalID))
	if w.Code != http.StatusCreated {
		t.Fatalf("named-in-body seed = %d %s", w.Code, w.Body.Bytes())
	}

	// Re-seeding the same name replaces it rather than duplicating.
	if w := seedDeny(t, s, deniedName, denyBodyJSON(denyScope, principalID, "")); w.Code != http.StatusCreated {
		t.Fatalf("re-seed = %d", w.Code)
	}
	if n := denyCount(t, getDeny(s, denyScope)); n != 2 {
		t.Fatalf("after re-seeding one of two = %d", n)
	}

	// A principal's display name and email ride through when Azure supplies
	// them, and a seed with no permissions at all is still well-formed.
	w = seedDeny(t, s, "", fmt.Sprintf(`{"scope":%q,
		"principals":[{"id":%q,"type":"User","displayName":"Ada","email":"ada@example.test"}],
		"excludePrincipals":[{"id":"other","type":"User"}]}`, denyScope, principalID))
	if w.Code != http.StatusCreated {
		t.Fatalf("seed with named principals = %d %s", w.Code, w.Body.Bytes())
	}
	var named struct {
		Properties struct {
			Permissions []json.RawMessage
			Principals  []struct{ ID, Type, DisplayName, Email string }
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &named)
	if p := named.Properties.Principals; len(p) != 1 || p[0].DisplayName != "Ada" ||
		p[0].Email != "ada@example.test" {
		t.Fatalf("principals = %+v", named.Properties.Principals)
	}
	if named.Properties.Permissions == nil {
		t.Fatal("a permission-less deny must read back as [], not null")
	}

	// Malformed and incomplete seeds are refused with a reason.
	for _, tc := range []struct{ name, body string }{
		{"malformed", "{nope"},
		{"no scope", `{"principals":[{"id":"x"}]}`},
		{"no principals", fmt.Sprintf(`{"scope":%q}`, denyScope)},
	} {
		if w := seedDeny(t, s, "", tc.body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s seed = %d", tc.name, w.Code)
		}
	}

	// A root-scoped deny keeps the root scope rather than an empty string.
	w = seedDeny(t, s, "", `{"scope":"/","permissions":[],"principals":[{"id":"x"}]}`)
	var root struct {
		Properties struct{ Scope string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &root)
	if root.Properties.Scope != "/" {
		t.Fatalf("root scope = %q", root.Properties.Scope)
	}

	// Delete: gone, then idempotent, and a nameless delete is refused.
	del := func(name string) int {
		w := httptest.NewRecorder()
		s.ServeDenyControl(w, req("DELETE", "/_emulator/denyassignments/"+name, ""))
		return w.Code
	}
	if code := del(deniedName); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if code := del(deniedName); code != http.StatusNoContent {
		t.Fatalf("second delete = %d, ARM answers 204 for something already gone", code)
	}
	if code := del(""); code != http.StatusBadRequest {
		t.Fatalf("nameless delete = %d", code)
	}
	w = httptest.NewRecorder()
	s.ServeDenyControl(w, req("GET", "/_emulator/denyassignments", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the control surface = %d", w.Code)
	}
}

// TestDenyStorageFailures: every path that reads deny assignments must fail
// loudly rather than quietly reporting "nothing is denied", which would turn
// a storage fault into an authorization bypass.
func TestDenyStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	mustAssign(t, s, st, principalID)
	seedDeny(t, s, deniedName, denyBodyJSON(denyScope, principalID, ""))

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// First: stored JSON that no longer decodes. The row is readable, its
	// contents are not.
	if _, err := db.Exec(`UPDATE deny_assignments SET permissions_json = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if w := getDeny(s, denyScope, deniedName); w.Code != http.StatusInternalServerError {
		t.Fatalf("get with corrupt permissions = %d", w.Code)
	}
	if w := getDeny(s, denyScope); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with corrupt permissions = %d", w.Code)
	}
	if _, err := s.Denies(denyScope, []string{principalID}, getSecret); err == nil {
		t.Fatal("the evaluator must not report 'not denied' when it cannot read the deny")
	}
	if _, err := s.EffectiveAt(denyScope); err == nil {
		t.Fatal("the feed must not silently drop denies it cannot decode")
	}
	w := httptest.NewRecorder()
	s.ServeFeed(w, req("GET", "/_family/authorization?scope="+denyScope, ""))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("feed with corrupt permissions = %d", w.Code)
	}
	for _, col := range []string{"principals_json", "exclude_principals_json"} {
		if _, err := db.Exec(`UPDATE deny_assignments SET permissions_json = '[]', ` +
			col + ` = 'not json'`); err != nil {
			t.Fatal(err)
		}
		if w := getDeny(s, denyScope, deniedName); w.Code != http.StatusInternalServerError {
			t.Fatalf("get with corrupt %s = %d", col, w.Code)
		}
		if _, err := db.Exec(`UPDATE deny_assignments SET ` + col + ` = '[]'`); err != nil {
			t.Fatal(err)
		}
	}

	// Then: the table itself gone.
	if _, err := db.Exec(`DROP TABLE deny_assignments`); err != nil {
		t.Fatal(err)
	}
	if w := getDeny(s, denyScope, deniedName); w.Code != http.StatusInternalServerError {
		t.Fatalf("get with the table dropped = %d", w.Code)
	}
	if w := getDeny(s, denyScope); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with the table dropped = %d", w.Code)
	}
	if _, err := s.Denies(denyScope, []string{principalID}, getSecret); err == nil {
		t.Fatal("the evaluator must fail when the table is gone")
	}
	w = httptest.NewRecorder()
	s.ServeFeed(w, req("GET", "/_family/authorization?scope="+denyScope, ""))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("feed with the table dropped = %d", w.Code)
	}
	if w := seedDeny(t, s, "x", denyBodyJSON(denyScope, principalID, "")); w.Code != http.StatusInternalServerError {
		t.Fatalf("seed with the table dropped = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.ServeDenyControl(w, req("DELETE", "/_emulator/denyassignments/"+deniedName, ""))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the table dropped = %d", w.Code)
	}
}
