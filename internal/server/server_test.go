package server_test

// Envelope, control-surface and feed tests driven over plain HTTP with
// entra-minted tokens — the paths the typed SDKs do not reach (bad
// api-versions, unauthenticated calls, fault injection, the family feed).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/server"
	entra "github.com/calvinchengx/entra-emulator/emulator"
)

// raw is a fixture that speaks HTTP directly, with a real ARM-audience token.
type raw struct {
	srv   *httptest.Server
	token string
	c     *http.Client
}

func newRaw(t *testing.T) *raw {
	t.Helper()
	f := newFixture(t)
	tok, err := f.cred.GetToken(context.Background(),
		policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		t.Fatal(err)
	}
	return &raw{srv: f.srv, token: tok.Token, c: f.srv.Client()}
}

func (r *raw) do(t *testing.T, method, path, body string, withToken bool) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, r.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if withToken {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestEnvelope(t *testing.T) {
	r := newRaw(t)
	const v = "?api-version=2022-04-01"

	// Unauthenticated: 401 with the ARM error code and a bearer challenge.
	code, body := r.do(t, "GET", "/subscriptions"+v, "", false)
	if code != http.StatusUnauthorized || !strings.Contains(body, "AuthenticationFailed") {
		t.Fatalf("unauthenticated = %d %s", code, body)
	}
	// A forged token is refused the same way.
	req, _ := http.NewRequest("GET", r.srv.URL+"/subscriptions"+v, nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	resp, err := r.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged token = %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" || resp.Header.Get("x-ms-request-id") == "" {
		t.Fatal("challenge or request-id header missing")
	}

	// api-version is required and validated.
	if code, body := r.do(t, "GET", "/subscriptions", "", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "MissingApiVersionParameter") {
		t.Fatalf("missing api-version = %d %s", code, body)
	}
	if code, body := r.do(t, "GET", "/subscriptions?api-version=7.5", "", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "InvalidApiVersionParameter") {
		t.Fatalf("bad api-version = %d %s", code, body)
	}
	if code, _ := r.do(t, "GET", "/subscriptions?api-version=2022-04-01-preview", "", true); code != http.StatusOK {
		t.Fatalf("preview api-version = %d", code)
	}

	// Discovery surfaces.
	if code, body := r.do(t, "GET", "/tenants"+v, "", true); code != http.StatusOK ||
		!strings.Contains(body, "tenantId") {
		t.Fatalf("tenants = %d %s", code, body)
	}
	if code, body := r.do(t, "GET", "/subscriptions/"+subID+v, "", true); code != http.StatusOK ||
		!strings.Contains(body, "Enabled") {
		t.Fatalf("get subscription = %d %s", code, body)
	}
	// An unknown subscription 404s, both directly and under a resource path.
	if code, body := r.do(t, "GET", "/subscriptions/99999999-0000-0000-0000-000000000000"+v, "", true); code != http.StatusNotFound ||
		!strings.Contains(body, "SubscriptionNotFound") {
		t.Fatalf("unknown subscription = %d %s", code, body)
	}
	if code, _ := r.do(t, "GET", "/subscriptions/99999999-0000-0000-0000-000000000000/resourcegroups"+v, "", true); code != http.StatusNotFound {
		t.Fatalf("unknown subscription rg list = %d", code)
	}

	// Unknown providers and malformed ids are refused with ARM codes.
	if code, body := r.do(t, "GET", "/subscriptions/"+subID+"/providers/Microsoft.Nope/things"+v, "", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "NoRegisteredProviderFound") {
		t.Fatalf("unknown provider = %d %s", code, body)
	}
	if code, body := r.do(t, "GET", "/nonsense"+v, "", true); code != http.StatusNotFound ||
		!strings.Contains(body, "InvalidResourceId") {
		t.Fatalf("bad path = %d %s", code, body)
	}
	if code, _ := r.do(t, "GET", "/subscriptions/"+subID+"/resourcegroups/a/b/c"+v, "", true); code != http.StatusNotFound {
		t.Fatalf("over-long rg path = %d", code)
	}

	// Method policing.
	if code, body := r.do(t, "POST", "/subscriptions/"+subID+"/resourcegroups"+v, "{}", true); code != http.StatusMethodNotAllowed ||
		!strings.Contains(body, "MethodNotAllowed") {
		t.Fatalf("POST to rg collection = %d %s", code, body)
	}
	if code, _ := r.do(t, "PATCH", "/subscriptions/"+subID+"/resourcegroups/x"+v, "{}", true); code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH rg = %d", code)
	}
	if code, _ := r.do(t, "POST", "/subscriptions/"+subID+"/providers/Microsoft.Authorization/roleDefinitions"+v, "{}", true); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST role definitions = %d", code)
	}
	if code, _ := r.do(t, "POST", "/subscriptions/"+subID+"/providers/Microsoft.Authorization/roleAssignments"+v, "{}", true); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST assignment collection = %d", code)
	}
	if code, _ := r.do(t, "PATCH", "/subscriptions/"+subID+"/providers/Microsoft.Authorization/roleAssignments/x"+v, "{}", true); code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH assignment = %d", code)
	}
}

func TestResourceGroupAndAssignmentErrors(t *testing.T) {
	r := newRaw(t)
	const v = "?api-version=2022-04-01"
	rgPath := "/subscriptions/" + subID + "/resourcegroups/rg-err" + v

	// Malformed body and a missing location.
	if code, body := r.do(t, "PUT", rgPath, "{nope", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "InvalidRequestContent") {
		t.Fatalf("malformed rg body = %d %s", code, body)
	}
	if code, body := r.do(t, "PUT", rgPath, "{}", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "LocationRequired") {
		t.Fatalf("rg without location = %d %s", code, body)
	}
	// Absent group: GET 404s, DELETE is 204 (ARM's idempotent delete).
	if code, body := r.do(t, "GET", rgPath, "", true); code != http.StatusNotFound ||
		!strings.Contains(body, "ResourceGroupNotFound") {
		t.Fatalf("absent rg get = %d %s", code, body)
	}
	if code, _ := r.do(t, "DELETE", rgPath, "", true); code != http.StatusNoContent {
		t.Fatalf("absent rg delete = %d", code)
	}
	// Create, then a case-insensitive get finds it, then delete is 200.
	if code, _ := r.do(t, "PUT", rgPath, `{"location":"westeurope"}`, true); code != http.StatusCreated {
		t.Fatalf("create rg = %d", code)
	}
	if code, _ := r.do(t, "GET", "/subscriptions/"+subID+"/resourcegroups/RG-ERR"+v, "", true); code != http.StatusOK {
		t.Fatalf("case-insensitive rg get = %d", code)
	}
	if code, _ := r.do(t, "DELETE", rgPath, "", true); code != http.StatusOK {
		t.Fatalf("delete rg = %d", code)
	}

	// Role definitions: unknown GUID 404s.
	if code, body := r.do(t, "GET",
		"/subscriptions/"+subID+"/providers/Microsoft.Authorization/roleDefinitions/deadbeef"+v, "", true); code != http.StatusNotFound ||
		!strings.Contains(body, "RoleDefinitionDoesNotExist") {
		t.Fatalf("unknown role definition = %d %s", code, body)
	}

	// Role assignments: malformed body, missing properties, unknown role.
	aPath := "/subscriptions/" + subID + "/providers/Microsoft.Authorization/roleAssignments/a1" + v
	if code, body := r.do(t, "PUT", aPath, "{nope", true); code != http.StatusBadRequest ||
		!strings.Contains(body, "InvalidRequestContent") {
		t.Fatalf("malformed assignment = %d %s", code, body)
	}
	if code, _ := r.do(t, "PUT", aPath, `{"properties":{}}`, true); code != http.StatusBadRequest {
		t.Fatalf("assignment without properties = %d", code)
	}
	if code, body := r.do(t, "PUT", aPath,
		`{"properties":{"roleDefinitionId":"/x/y/nope","principalId":"p1"}}`, true); code != http.StatusBadRequest ||
		!strings.Contains(body, "RoleDefinitionDoesNotExist") {
		t.Fatalf("assignment to unknown role = %d %s", code, body)
	}
	// Absent assignment: GET 404s, DELETE 204s.
	if code, body := r.do(t, "GET", aPath, "", true); code != http.StatusNotFound ||
		!strings.Contains(body, "RoleAssignmentNotFound") {
		t.Fatalf("absent assignment get = %d %s", code, body)
	}
	if code, _ := r.do(t, "DELETE", aPath, "", true); code != http.StatusNoContent {
		t.Fatalf("absent assignment delete = %d", code)
	}
}

// TestFamilyFeed: the feed a sibling data plane consumes — assignments that
// apply at a scope, with the role's dataActions, inherited from ancestors.
func TestFamilyFeed(t *testing.T) {
	r := newRaw(t)
	const v = "?api-version=2022-04-01"
	const secretsUser = "4633458b-17de-408a-b874-0445c86b69e6"
	roleID := "/subscriptions/" + subID + "/providers/Microsoft.Authorization/roleDefinitions/" + secretsUser
	vaultScope := "/subscriptions/" + subID + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/v1"

	// Assign at the resource group; the vault beneath it inherits.
	rgScope := "/subscriptions/" + subID + "/resourceGroups/rg1"
	body := fmt.Sprintf(`{"properties":{"roleDefinitionId":%q,"principalId":"p-user","principalType":"ServicePrincipal"}}`, roleID)
	if code, out := r.do(t, "PUT",
		rgScope+"/providers/Microsoft.Authorization/roleAssignments/f1"+v, body, true); code != http.StatusCreated {
		t.Fatalf("create assignment = %d %s", code, out)
	}

	code, out := r.do(t, "GET", "/_family/authorization?scope="+vaultScope, "", false)
	if code != http.StatusOK {
		t.Fatalf("feed = %d %s", code, out)
	}
	var feed struct {
		Scope       string `json:"scope"`
		Assignments []struct {
			PrincipalID string   `json:"principalId"`
			RoleName    string   `json:"roleName"`
			DataActions []string `json:"dataActions"`
		} `json:"assignments"`
	}
	if err := json.Unmarshal([]byte(out), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Assignments) != 1 {
		t.Fatalf("feed assignments = %d: %s", len(feed.Assignments), out)
	}
	a := feed.Assignments[0]
	if a.PrincipalID != "p-user" || a.RoleName != "Key Vault Secrets User" || len(a.DataActions) == 0 {
		t.Fatalf("feed entry = %+v", a)
	}
	// A sibling scope inherits nothing from rg1.
	other := "/subscriptions/" + subID + "/resourceGroups/rg2/providers/Microsoft.KeyVault/vaults/v2"
	_, out = r.do(t, "GET", "/_family/authorization?scope="+other, "", false)
	_ = json.Unmarshal([]byte(out), &feed)
	if len(feed.Assignments) != 0 {
		t.Fatalf("sibling scope inherited: %s", out)
	}
	// The scope parameter is required.
	if code, _ := r.do(t, "GET", "/_family/authorization", "", false); code != http.StatusBadRequest {
		t.Fatalf("feed without scope = %d", code)
	}
}

func TestControlSurface(t *testing.T) {
	r := newRaw(t)
	const v = "?api-version=2022-04-01"

	if code, _ := r.do(t, "GET", "/health", "", false); code != http.StatusOK {
		t.Fatalf("health = %d", code)
	}
	if code, body := r.do(t, "GET", "/_emulator/clock", "", false); code != http.StatusOK ||
		!strings.Contains(body, "frozen") {
		t.Fatalf("clock get = %d %s", code, body)
	}
	if code, body := r.do(t, "POST", "/_emulator/clock", `{"offset":100,"freeze":true,"advance":5}`, false); code != http.StatusOK ||
		!strings.Contains(body, `"frozen":true`) {
		t.Fatalf("clock post = %d %s", code, body)
	}
	if code, body := r.do(t, "POST", "/_emulator/clock", `{"freeze":false}`, false); code != http.StatusOK ||
		!strings.Contains(body, `"frozen":false`) {
		t.Fatalf("unfreeze = %d %s", code, body)
	}
	if code, _ := r.do(t, "POST", "/_emulator/clock", "{nope", false); code != http.StatusBadRequest {
		t.Fatalf("bad clock body = %d", code)
	}
	if code, _ := r.do(t, "POST", "/_emulator/faults", "{nope", false); code != http.StatusBadRequest {
		t.Fatalf("bad faults body = %d", code)
	}
	// Injected throttling and rejection fire on the next ARM calls.
	if code, _ := r.do(t, "POST", "/_emulator/faults", `{"throttleNextRequests":1}`, false); code != http.StatusOK {
		t.Fatalf("faults = %d", code)
	}
	if code, _ := r.do(t, "GET", "/subscriptions"+v, "", true); code != http.StatusTooManyRequests {
		t.Fatalf("throttled = %d", code)
	}
	if code, _ := r.do(t, "POST", "/_emulator/faults", `{"rejectNextRequests":1}`, false); code != http.StatusOK {
		t.Fatalf("faults reject = %d", code)
	}
	if code, _ := r.do(t, "GET", "/subscriptions"+v, "", true); code != http.StatusInternalServerError {
		t.Fatalf("rejected = %d", code)
	}
}

func TestServerNewFailure(t *testing.T) {
	cfg := &config.Config{EntraIssuer: "https://e/t/v2.0", SubscriptionID: subID, DataDir: "/nonexistent-path-xyz"}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(cfg, nil); err == nil {
		t.Fatal("server.New with an unusable data dir succeeded")
	}
}

var _ = entra.DaemonClientID
