package arm

// ABAC conditions where they matter: refused at write time when they cannot
// be parsed, and actually deciding an outcome when they can. The point of
// these tests is that a condition CHANGES an answer — an assignment that
// grants the action still refuses the request when its condition is not
// satisfied.

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

const (
	secretsUserID = "/providers/Microsoft.Authorization/roleDefinitions/" +
		"4633458b-17de-408a-b874-0445c86b69e6"
	getSecretAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	secretNameAttr  = "@Resource[Microsoft.KeyVault/vaults/secrets:name]"
	// The shape Azure's documentation uses: the guard lets every other
	// action through, so only secret reads are narrowed.
	appOnly = `((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) ` +
		`OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))`
)

func putAssignment(s *Service, name, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.roleAssignments(w, req("PUT", "/x?api-version=2022-04-01", body),
		denyScope, []string{name}, caller)
	return w
}

func assignmentJSON(condition, version string) string {
	extra := ""
	if condition != "" {
		extra = fmt.Sprintf(`,"condition":%q,"conditionVersion":%q`, condition, version)
	}
	return fmt.Sprintf(`{"properties":{"roleDefinitionId":%q,"principalId":%q,
		"principalType":"ServicePrincipal"%s}}`, secretsUserID, principalID, extra)
}

func TestConditionValidatedAtWriteTime(t *testing.T) {
	s, _ := newService(t, "")

	// A condition ARM would reject must not be stored: an assignment that
	// looks constrained but is not is worse than no assignment at all.
	w := putAssignment(s, "a1", assignmentJSON("@Resource[x] Frobnicates 'y'", "2.0"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidCondition") {
		t.Fatalf("malformed condition = %d %s", w.Code, w.Body.Bytes())
	}
	// And the message points at the offending text rather than just failing.
	if !strings.Contains(w.Body.String(), "at position") {
		t.Fatalf("rejection without a position: %s", w.Body.Bytes())
	}

	// Only version 2.0 exists.
	w = putAssignment(s, "a1", assignmentJSON(appOnly, "1.0"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidConditionVersion") {
		t.Fatalf("bad version = %d %s", w.Code, w.Body.Bytes())
	}
	// A version with no condition is meaningless.
	w = putAssignment(s, "a1", `{"properties":{"roleDefinitionId":"`+secretsUserID+
		`","principalId":"`+principalID+`","conditionVersion":"2.0"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("version without condition = %d %s", w.Code, w.Body.Bytes())
	}

	// A valid one round-trips, and the version defaults to 2.0 when omitted.
	w = putAssignment(s, "a1", assignmentJSON(appOnly, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("valid condition = %d %s", w.Code, w.Body.Bytes())
	}
	var got struct {
		Properties struct{ Condition, ConditionVersion string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Properties.Condition != appOnly || got.Properties.ConditionVersion != "2.0" {
		t.Fatalf("condition round-trip = %+v", got.Properties)
	}
}

func TestConditionDecidesTheOutcome(t *testing.T) {
	s, _ := newService(t, "")
	if w := putAssignment(s, "a1", assignmentJSON(appOnly, "2.0")); w.Code != http.StatusCreated {
		t.Fatalf("setup = %d %s", w.Code, w.Body.Bytes())
	}
	ask := func(secret string) EvaluateResult {
		attrs := map[string]any{}
		if secret != "" {
			attrs[secretNameAttr] = secret
		}
		res, err := s.Evaluate(EvaluateRequest{
			Scope: denyScope, PrincipalIDs: []string{principalID},
			Action: getSecretAction, Attributes: attrs,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if r := ask("app-db-password"); !r.Allowed || r.GrantedBy == nil ||
		r.GrantedBy.RoleName != "Key Vault Secrets User" {
		t.Fatalf("a secret the condition allows = %+v", r)
	}
	// The same principal, the same role, a different secret: refused, and
	// the reason distinguishes "no role" from "the condition said no".
	r := ask("prod-db-password")
	switch {
	case r.Allowed:
		t.Fatal("a secret outside the condition was allowed")
	case len(r.ConditionFailed) != 1:
		t.Fatalf("conditionFailed = %+v", r)
	case !strings.Contains(r.Reason, "condition"):
		t.Fatalf("reason = %q", r.Reason)
	}
	// An attribute the condition needs but nobody supplied fails closed.
	if r := ask(""); r.Allowed {
		t.Fatal("a missing attribute allowed the request")
	}
	// An action the guard lets through is decided by the role alone.
	res, err := s.Evaluate(EvaluateRequest{
		Scope: denyScope, PrincipalIDs: []string{principalID},
		Action: "Microsoft.KeyVault/vaults/secrets/setSecret/action",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Key Vault Secrets User does not grant writes, so this is refused by
	// the ROLE, not the condition — a different answer with a different
	// reason, which is the distinction the endpoint exists to make.
	if res.Allowed || len(res.ConditionFailed) != 0 ||
		!strings.Contains(res.Reason, "no role assignment") {
		t.Fatalf("setSecret = %+v", res)
	}
}

func TestEvaluateOrdering(t *testing.T) {
	s, _ := newService(t, "")
	putAssignment(s, "a1", assignmentJSON("", ""))

	ask := func(principals ...string) EvaluateResult {
		res, err := s.Evaluate(EvaluateRequest{
			Scope: denyScope, PrincipalIDs: principals, Action: getSecretAction,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if r := ask(principalID); !r.Allowed {
		t.Fatalf("an unconditional grant = %+v", r)
	}
	// Another principal holds nothing.
	if r := ask("someone-else"); r.Allowed || !strings.Contains(r.Reason, "no role assignment") {
		t.Fatalf("stranger = %+v", r)
	}
	// A deny overrides the grant, and says so.
	seedDeny(t, s, deniedName, denyBodyJSON(denyScope, principalID, ""))
	r := ask(principalID)
	if r.Allowed || r.DeniedBy != deniedName || !strings.Contains(r.Reason, "deny assignment") {
		t.Fatalf("deny should win: %+v", r)
	}
	// It overrides for a group member too, since membership arrives with
	// the request rather than being resolved here.
	if err := s.Store.DeleteDenyAssignment(deniedName); err != nil {
		t.Fatal(err)
	}
	seedDeny(t, s, deniedName, denyBodyJSON(denyScope, "group-oid", ""))
	if r := ask(principalID, "group-oid"); r.Allowed {
		t.Fatal("a deny on a group the caller is in should still win")
	}
}

// TestNotDataActionsCarveOut: the role's own arithmetic, applied before any
// condition is consulted.
func TestGrantsActionArithmetic(t *testing.T) {
	cases := []struct {
		data, notData []string
		want          bool
	}{
		{[]string{getSecretAction}, nil, true},
		{[]string{"Microsoft.KeyVault/*"}, nil, true},
		{[]string{"Microsoft.Storage/*"}, nil, false},
		{nil, nil, false},
		{[]string{"*"}, []string{getSecretAction}, false},
		{[]string{"*"}, []string{"Microsoft.Storage/*"}, true},
	}
	for _, tc := range cases {
		a := EffectiveAssignment{DataActions: tc.data, NotDataActions: tc.notData}
		if got := grantsAction(a, getSecretAction); got != tc.want {
			t.Fatalf("grantsAction(%v, not %v) = %v", tc.data, tc.notData, got)
		}
	}
}

func TestEvaluateEndpoint(t *testing.T) {
	s, _ := newService(t, "")
	putAssignment(s, "a1", assignmentJSON(appOnly, "2.0"))

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeEvaluate(w, req("POST", "/_family/authorization/evaluate", body))
		return w
	}
	body := fmt.Sprintf(`{"scope":%q,"principalIds":[%q],"action":%q,
		"attributes":{%q:"app-secret"}}`, denyScope, principalID, getSecretAction, secretNameAttr)
	w := post(body)
	if w.Code != http.StatusOK {
		t.Fatalf("evaluate = %d %s", w.Code, w.Body.Bytes())
	}
	var res EvaluateResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.GrantedBy == nil {
		t.Fatalf("result = %+v", res)
	}

	// Malformed, incomplete and wrong-method requests are refused.
	if w := post("{nope"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	if w := post(`{"action":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("no scope = %d", w.Code)
	}
	if w := post(fmt.Sprintf(`{"scope":%q}`, denyScope)); w.Code != http.StatusBadRequest {
		t.Fatalf("no action = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.ServeEvaluate(w, req("GET", "/_family/authorization/evaluate", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", w.Code)
	}
}

// TestConditionOnTheFeed: a consumer that reads the feed rather than asking
// for a decision still learns the condition and what it needs.
func TestConditionOnTheFeed(t *testing.T) {
	s, _ := newService(t, "")
	putAssignment(s, "a1", assignmentJSON(appOnly, "2.0"))

	eff, err := s.EffectiveAt(denyScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff) != 1 {
		t.Fatalf("assignments = %+v", eff)
	}
	e := eff[0]
	if e.Condition != appOnly || e.ConditionVersion != "2.0" {
		t.Fatalf("condition = %q %q", e.Condition, e.ConditionVersion)
	}
	if len(e.ConditionAttributes) != 1 || e.ConditionAttributes[0] != secretNameAttr {
		t.Fatalf("conditionAttributes = %v", e.ConditionAttributes)
	}
}

// TestUnparsableStoredConditionGrantsNothing: the stored text is validated on
// the way in, so this can only happen if the database was edited underneath
// the emulator. It must fail closed — honouring the assignment without its
// condition would widen exactly the grant its author narrowed.
func TestUnparsableStoredConditionGrantsNothing(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	putAssignment(s, "a1", assignmentJSON(appOnly, "2.0"))

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE role_assignments SET condition = 'garbage ((('`); err != nil {
		t.Fatal(err)
	}
	eff, err := s.EffectiveAt(denyScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff) != 0 {
		t.Fatalf("a corrupted condition still granted: %+v", eff)
	}
	res, err := s.Evaluate(EvaluateRequest{
		Scope: denyScope, PrincipalIDs: []string{principalID}, Action: getSecretAction,
		Attributes: map[string]any{secretNameAttr: "app-secret"},
	})
	if err != nil || res.Allowed {
		t.Fatalf("evaluate with a corrupted condition = %+v %v", res, err)
	}
}

func TestEvaluateStorageFailures(t *testing.T) {
	// Each table is dropped in its own fixture: the evaluator reads denies
	// first and assignments second, so one fixture could only ever reach
	// the first failure.
	for _, table := range []string{"deny_assignments", "role_assignments"} {
		t.Run(table, func(t *testing.T) {
			dir := t.TempDir()
			s, _ := newService(t, dir)
			putAssignment(s, "a1", assignmentJSON("", ""))

			db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`DROP TABLE ` + table); err != nil {
				t.Fatal(err)
			}
			// Failing to read either table must be an error, never a quiet
			// "nothing applies" — that would be an authorization bypass in
			// one direction and a silent lockout in the other.
			if _, err := s.Evaluate(EvaluateRequest{Scope: denyScope,
				PrincipalIDs: []string{principalID}, Action: getSecretAction}); err == nil {
				t.Fatalf("evaluate succeeded with %s dropped", table)
			}
			w := httptest.NewRecorder()
			s.ServeEvaluate(w, req("POST", "/_family/authorization/evaluate",
				fmt.Sprintf(`{"scope":%q,"action":%q}`, denyScope, getSecretAction)))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("endpoint with %s dropped = %d", table, w.Code)
			}
			// The feed reads the same two tables in the same order.
			w = httptest.NewRecorder()
			s.ServeFeed(w, req("GET", "/_family/authorization?scope="+denyScope, ""))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("feed with %s dropped = %d", table, w.Code)
			}
		})
	}
}
