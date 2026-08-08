package arm

import (
	"strings"
	"testing"
)

const (
	subScope   = "/subscriptions/00000000-0000-0000-0000-000000000001"
	rgScope    = subScope + "/resourceGroups/rg1"
	vaultScope = rgScope + "/providers/Microsoft.KeyVault/vaults/myvault"
)

func TestScopeApplies(t *testing.T) {
	cases := []struct {
		assignment, target string
		want               bool
	}{
		// Inheritance downward.
		{"/", vaultScope, true},
		{subScope, vaultScope, true},
		{rgScope, vaultScope, true},
		{vaultScope, vaultScope, true},
		// Case-insensitive, as ARM treats resource IDs.
		{strings.ToUpper(rgScope), vaultScope, true},
		{rgScope + "/", vaultScope, true},
		// No inheritance upward, and no sibling leakage.
		{vaultScope, rgScope, false},
		{rgScope, subScope, false},
		{subScope + "/resourceGroups/rg2", vaultScope, false},
		// Prefix must land on a segment boundary: rg1 must not match rg10.
		{subScope + "/resourceGroups/rg1", subScope + "/resourceGroups/rg10/providers/x/y/z", false},
		{"/subscriptions/00000000-0000-0000-0000-00000000000", subScope, false},
	}
	for _, c := range cases {
		if got := ScopeApplies(c.assignment, c.target); got != c.want {
			t.Errorf("ScopeApplies(%q, %q) = %v; want %v", c.assignment, c.target, got, c.want)
		}
	}
}

func TestScopeChainAndParts(t *testing.T) {
	chain := ScopeChain(vaultScope)
	// Nearest first, tenant root last, every ancestor present.
	if chain[0] != strings.ToLower(vaultScope) || chain[len(chain)-1] != "/" {
		t.Fatalf("chain ends wrong: %v", chain)
	}
	var sawRG, sawSub bool
	for _, s := range chain {
		sawRG = sawRG || s == strings.ToLower(rgScope)
		sawSub = sawSub || s == strings.ToLower(subScope)
	}
	if !sawRG || !sawSub {
		t.Fatalf("chain missing ancestors: %v", chain)
	}
	if got := ScopeChain("/"); len(got) != 1 || got[0] != "/" {
		t.Fatalf("root chain = %v", got)
	}

	if got := SubscriptionOf(vaultScope); got != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("SubscriptionOf = %q", got)
	}
	if got := ResourceGroupOf(vaultScope); got != "rg1" {
		t.Fatalf("ResourceGroupOf = %q", got)
	}
	if SubscriptionOf("/") != "" || ResourceGroupOf(subScope) != "" {
		t.Fatal("scope parts found where none exist")
	}
	if got := CanonicalScope(""); got != "/" {
		t.Fatalf("CanonicalScope(empty) = %q", got)
	}
	if got := CanonicalScope("subscriptions/x"); got != "/subscriptions/x" {
		t.Fatalf("CanonicalScope(relative) = %q", got)
	}
}

func TestRoleLookup(t *testing.T) {
	// By GUID, by name, and via a full roleDefinitionId — the three forms
	// real clients use.
	const secretsUser = "4633458b-17de-408a-b874-0445c86b69e6"
	if r, ok := RoleByGUID(secretsUser); !ok || r.RoleName != "Key Vault Secrets User" {
		t.Fatalf("RoleByGUID = %+v %v", r, ok)
	}
	if r, ok := RoleByName("key vault secrets user"); !ok || r.GUID != secretsUser {
		t.Fatalf("RoleByName = %+v %v", r, ok)
	}
	full := subScope + "/providers/Microsoft.Authorization/roleDefinitions/" + secretsUser
	if r, ok := RoleFromDefinitionID(full); !ok || r.GUID != secretsUser {
		t.Fatalf("RoleFromDefinitionID = %+v %v", r, ok)
	}
	if _, ok := RoleFromDefinitionID("not-a-role"); ok {
		t.Fatal("unknown role resolved")
	}
	// Every seeded role has a GUID, a name, and at least one permission set.
	for _, r := range BuiltInRoles() {
		if r.GUID == "" || r.RoleName == "" || len(r.Permissions) == 0 {
			t.Fatalf("incomplete built-in role: %+v", r)
		}
	}
}

func TestSplitProvider(t *testing.T) {
	// The LAST providers segment wins, so a resource-scoped assignment
	// resolves against the resource, not the provider inside its own scope.
	segs := segments(vaultScope + "/providers/Microsoft.Authorization/roleAssignments/abc")
	scope, rest, ok := splitProvider(segs)
	if !ok || !strings.EqualFold(scope, vaultScope) {
		t.Fatalf("scope = %q ok=%v", scope, ok)
	}
	if len(rest) != 3 || rest[2] != "abc" {
		t.Fatalf("rest = %v", rest)
	}
	if _, _, ok := splitProvider(segments(rgScope)); ok {
		t.Fatal("provider found in a plain resource-group scope")
	}
	if _, _, ok := splitProvider(segments("/subscriptions/s/providers")); ok {
		t.Fatal("trailing providers with no namespace accepted")
	}
}

func TestFilterParsing(t *testing.T) {
	if got := filterRoleName("roleName eq 'Key Vault Secrets User'"); got != "Key Vault Secrets User" {
		t.Fatalf("filterRoleName = %q", got)
	}
	if got := filterRoleName("atScope()"); got != "" {
		t.Fatalf("filterRoleName on unrelated filter = %q", got)
	}
	if got := filterPrincipalID("principalId eq '11112222'"); got != "11112222" {
		t.Fatalf("filterPrincipalID = %q", got)
	}
	if got := filterPrincipalID("atScope() and principalId eq 'abc'"); got != "abc" {
		t.Fatalf("filterPrincipalID combined = %q", got)
	}
	if got := filterPrincipalID(""); got != "" {
		t.Fatalf("filterPrincipalID empty = %q", got)
	}
}
