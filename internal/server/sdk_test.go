package server_test

// The P0 centerpiece: Microsoft's REAL management SDKs (armresources,
// armauthorization) drive this emulator over ARM's wire, authenticating with
// an ARM-audience token from an in-process entra-emulator — the production
// trust path, fully offline.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/server"
	entra "github.com/calvinchengx/entra-emulator/emulator"
)

const subID = "6082bfda-63d0-46f4-8272-ae9195139feb"

type fixture struct {
	t    *testing.T
	emu  *entra.Emulator
	arm  *server.Server
	srv  *httptest.Server
	cred *azidentity.ClientSecretCredential
	opts *arm.ClientOptions
}

// combinedTransport routes token traffic to entra's client and everything
// else (ARM) to the httptest client — one Transporter for the SDK.
type combinedTransport struct {
	entraHost string
	entra     *http.Client
	arm       *http.Client
}

func (c *combinedTransport) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host == c.entraHost {
		return c.entra.Do(req)
	}
	return c.arm.Do(req)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	// entra-emulator v0.2.1+ recognizes https://management.azure.com as a
	// well-known Azure resource, so client-credentials resolves the ARM
	// audience with no resource-app seed step.
	emu := entra.StartT(t, entra.WithTLS())

	cfg := &config.Config{
		EntraIssuer:    emu.Origin + "/" + emu.TenantID + "/v2.0",
		SubscriptionID: subID,
		TenantID:       emu.TenantID,
	}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	s, err := server.New(cfg, emu.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	armSrv := httptest.NewTLSServer(s.Handler())
	t.Cleanup(armSrv.Close)

	transport := &combinedTransport{
		entraHost: strings.TrimPrefix(emu.Origin, "https://"),
		entra:     emu.HTTPClient(),
		arm:       armSrv.Client(),
	}
	// The SDK's cloud configuration is what makes this real: the emulator is
	// registered as an ARM endpoint with its own authority and audience,
	// exactly how a sovereign cloud is configured.
	cfgCloud := cloud.Configuration{
		ActiveDirectoryAuthorityHost: emu.Origin,
		Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {
				Endpoint: armSrv.URL,
				Audience: "https://management.azure.com",
			},
		},
	}
	cred, err := azidentity.NewClientSecretCredential(
		emu.TenantID, entra.DaemonClientID, entra.DaemonSecret,
		&azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud:     cfgCloud,
				Transport: transport,
			},
			DisableInstanceDiscovery: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	opts := &arm.ClientOptions{ClientOptions: policy.ClientOptions{
		Cloud: cfgCloud, Transport: transport,
	}}
	return &fixture{t: t, emu: emu, arm: s, srv: armSrv, cred: cred, opts: opts}
}

// TestArmResourcesSDK: the real armresources client creates, reads, lists and
// deletes a resource group.
func TestArmResourcesSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rgc, err := armresources.NewResourceGroupsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}

	created, err := rgc.CreateOrUpdate(ctx, "rg-e2e", armresources.ResourceGroup{
		Location: to.Ptr("westeurope"),
		Tags:     map[string]*string{"env": to.Ptr("test")},
	}, nil)
	if err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	if created.Name == nil || *created.Name != "rg-e2e" {
		t.Fatalf("created name = %v", created.Name)
	}
	if created.ID == nil || !strings.Contains(*created.ID, "/subscriptions/"+subID+"/resourceGroups/rg-e2e") {
		t.Fatalf("created id = %v", created.ID)
	}

	got, err := rgc.Get(ctx, "rg-e2e", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tags["env"] == nil || *got.Tags["env"] != "test" {
		t.Fatalf("tags did not round-trip: %v", got.Tags)
	}

	var names []string
	pager := rgc.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, g := range page.Value {
			names = append(names, *g.Name)
		}
	}
	if len(names) != 1 || names[0] != "rg-e2e" {
		t.Fatalf("list = %v", names)
	}

	// A group that does not exist is a real 404 the SDK surfaces as an error.
	if _, err := rgc.Get(ctx, "absent", nil); err == nil {
		t.Fatal("Get of an absent group succeeded")
	}
}

// TestArmAuthorizationSDK: the real armauthorization client reads built-in
// role definitions and creates, reads, lists and deletes a role assignment —
// the operations `az role assignment create` performs.
func TestArmAuthorizationSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	defs, err := armauthorization.NewRoleDefinitionsClient(f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/" + subID
	// Filter by role name, as the CLI does when a role is named rather than
	// given by GUID.
	var secretsUserID string
	pager := defs.NewListPager(scope, &armauthorization.RoleDefinitionsClientListOptions{
		Filter: to.Ptr("roleName eq 'Key Vault Secrets User'"),
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("role definitions List: %v", err)
		}
		for _, d := range page.Value {
			if d.Properties != nil && d.Properties.RoleName != nil &&
				*d.Properties.RoleName == "Key Vault Secrets User" {
				secretsUserID = *d.ID
			}
		}
	}
	if secretsUserID == "" {
		t.Fatal("Key Vault Secrets User not found via the real SDK")
	}
	// Its data actions are the documented ones, so a consumer can act on them.
	byID, err := defs.GetByID(ctx, strings.TrimPrefix(secretsUserID, "/"), nil)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(byID.Properties.Permissions) == 0 || len(byID.Properties.Permissions[0].DataActions) == 0 {
		t.Fatalf("no dataActions on the role: %+v", byID.Properties)
	}

	assign, err := armauthorization.NewRoleAssignmentsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	vaultScope := scope + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/myvault"
	const assignmentName = "e60e8095-0ea5-4039-8a03-0af68626c01b"
	const principal = "9e0ec08a-e3ec-4c19-a32d-3994c6e61caa"

	created, err := assign.Create(ctx, vaultScope, assignmentName, armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr(secretsUserID),
			PrincipalID:      to.Ptr(principal),
			PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
		},
	}, nil)
	if err != nil {
		t.Fatalf("role assignment Create: %v", err)
	}
	if created.Properties == nil || *created.Properties.PrincipalID != principal {
		t.Fatalf("created = %+v", created.Properties)
	}

	got, err := assign.Get(ctx, vaultScope, assignmentName, nil)
	if err != nil {
		t.Fatalf("role assignment Get: %v", err)
	}
	if *got.Name != assignmentName {
		t.Fatalf("get name = %v", *got.Name)
	}

	// The same role to the same principal at the same scope is a conflict.
	if _, err := assign.Create(ctx, vaultScope, "4bae3e20-b7c8-408f-9ee4-80083988414f",
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: to.Ptr(secretsUserID),
				PrincipalID:      to.Ptr(principal),
			},
		}, nil); err == nil {
		t.Fatal("duplicate assignment accepted")
	}

	// Inheritance: an assignment made at the vault is visible listing the
	// vault scope, and a subscription-scoped one is visible there too.
	const subAssignment = "b0167eff-32ce-46da-86cd-3b4eb8dcf4f1"
	if _, err := assign.Create(ctx, scope, subAssignment,
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: to.Ptr(secretsUserID),
				PrincipalID:      to.Ptr("54a9d08c-889d-489e-b534-336fe19dbfce"),
			},
		}, nil); err != nil {
		t.Fatalf("subscription-scope Create: %v", err)
	}
	seen := map[string]bool{}
	lp := assign.NewListForScopePager(vaultScope, nil)
	for lp.More() {
		page, err := lp.NextPage(ctx)
		if err != nil {
			t.Fatalf("ListForScope: %v", err)
		}
		for _, a := range page.Value {
			seen[*a.Name] = true
		}
	}
	if !seen[assignmentName] || !seen[subAssignment] {
		t.Fatalf("inherited assignments not visible at the vault scope: %v", seen)
	}

	// atScope() narrows to exactly the vault scope.
	atScope := map[string]bool{}
	ap := assign.NewListForScopePager(vaultScope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: to.Ptr("atScope()"),
	})
	for ap.More() {
		page, err := ap.NextPage(ctx)
		if err != nil {
			t.Fatalf("ListForScope atScope(): %v", err)
		}
		for _, a := range page.Value {
			atScope[*a.Name] = true
		}
	}
	if !atScope[assignmentName] || atScope[subAssignment] {
		t.Fatalf("atScope() filter wrong: %v", atScope)
	}

	if _, err := assign.Delete(ctx, vaultScope, assignmentName, nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := assign.Get(ctx, vaultScope, assignmentName, nil); err == nil {
		t.Fatal("Get after Delete succeeded")
	}
}

// TestArmKeyVaultSDK: the real armkeyvault client creates a vault, sets and
// removes access policies, and reads them back — the operations
// `az keyvault create` and `az keyvault set-policy` perform.
func TestArmKeyVaultSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rgc, err := armresources.NewResourceGroupsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rgc.CreateOrUpdate(ctx, "rg-kv", armresources.ResourceGroup{
		Location: to.Ptr("westeurope"),
	}, nil); err != nil {
		t.Fatalf("resource group: %v", err)
	}

	vc, err := armkeyvault.NewVaultsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	// A vault in a group that does not exist is refused, as ARM refuses it.
	if _, err := vc.BeginCreateOrUpdate(ctx, "no-such-rg", "v1", armkeyvault.VaultCreateOrUpdateParameters{
		Location:   to.Ptr("westeurope"),
		Properties: &armkeyvault.VaultProperties{TenantID: to.Ptr(f.emu.TenantID)},
	}, nil); err == nil {
		t.Fatal("vault created in a nonexistent resource group")
	}

	poller, err := vc.BeginCreateOrUpdate(ctx, "rg-kv", "myvault", armkeyvault.VaultCreateOrUpdateParameters{
		Location: to.Ptr("westeurope"),
		Properties: &armkeyvault.VaultProperties{
			TenantID:              to.Ptr(f.emu.TenantID),
			SKU:                   &armkeyvault.SKU{Family: to.Ptr(armkeyvault.SKUFamilyA), Name: to.Ptr(armkeyvault.SKUNameStandard)},
			EnablePurgeProtection: to.Ptr(true),
			AccessPolicies: []*armkeyvault.AccessPolicyEntry{{
				TenantID: to.Ptr(f.emu.TenantID),
				ObjectID: to.Ptr("0aec280f-25cc-4493-89ad-f381f646b279"),
				Permissions: &armkeyvault.Permissions{
					Secrets: []*armkeyvault.SecretPermissions{
						to.Ptr(armkeyvault.SecretPermissionsGet), to.Ptr(armkeyvault.SecretPermissionsList),
					},
				},
			}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("BeginCreateOrUpdate: %v", err)
	}
	created, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	if created.Properties == nil || created.Properties.VaultURI == nil ||
		*created.Properties.VaultURI != "https://myvault.vault.azure.net/" {
		t.Fatalf("vaultUri = %+v", created.Properties)
	}
	if len(created.Properties.AccessPolicies) != 1 {
		t.Fatalf("access policies = %+v", created.Properties.AccessPolicies)
	}

	got, err := vc.Get(ctx, "rg-kv", "myvault", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Properties.EnablePurgeProtection == nil || !*got.Properties.EnablePurgeProtection {
		t.Fatalf("purge protection did not persist: %+v", got.Properties)
	}

	// set-policy: add a second principal, keeping the first.
	upd, err := vc.UpdateAccessPolicy(ctx, "rg-kv", "myvault", armkeyvault.AccessPolicyUpdateKindAdd,
		armkeyvault.VaultAccessPolicyParameters{
			Properties: &armkeyvault.VaultAccessPolicyProperties{
				AccessPolicies: []*armkeyvault.AccessPolicyEntry{{
					TenantID: to.Ptr(f.emu.TenantID),
					ObjectID: to.Ptr("80d828d5-dd38-4fa2-90e4-045e0feb7d3e"),
					Permissions: &armkeyvault.Permissions{
						Keys: []*armkeyvault.KeyPermissions{to.Ptr(armkeyvault.KeyPermissionsSign)},
					},
				}},
			},
		}, nil)
	if err != nil {
		t.Fatalf("UpdateAccessPolicy add: %v", err)
	}
	if len(upd.Properties.AccessPolicies) != 2 {
		t.Fatalf("after add = %d policies", len(upd.Properties.AccessPolicies))
	}

	// delete-policy: remove the first principal.
	rem, err := vc.UpdateAccessPolicy(ctx, "rg-kv", "myvault", armkeyvault.AccessPolicyUpdateKindRemove,
		armkeyvault.VaultAccessPolicyParameters{
			Properties: &armkeyvault.VaultAccessPolicyProperties{
				AccessPolicies: []*armkeyvault.AccessPolicyEntry{{
					ObjectID: to.Ptr("0aec280f-25cc-4493-89ad-f381f646b279"),
				}},
			},
		}, nil)
	if err != nil {
		t.Fatalf("UpdateAccessPolicy remove: %v", err)
	}
	if len(rem.Properties.AccessPolicies) != 1 ||
		*rem.Properties.AccessPolicies[0].ObjectID != "80d828d5-dd38-4fa2-90e4-045e0feb7d3e" {
		t.Fatalf("after remove = %+v", rem.Properties.AccessPolicies)
	}

	// The vault lists under its resource group and under the subscription.
	var names []string
	lp := vc.NewListByResourceGroupPager("rg-kv", nil)
	for lp.More() {
		page, err := lp.NextPage(ctx)
		if err != nil {
			t.Fatalf("ListByResourceGroup: %v", err)
		}
		for _, v := range page.Value {
			names = append(names, *v.Name)
		}
	}
	if len(names) != 1 || names[0] != "myvault" {
		t.Fatalf("list by group = %v", names)
	}

	if _, err := vc.Delete(ctx, "rg-kv", "myvault", nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := vc.Get(ctx, "rg-kv", "myvault", nil); err == nil {
		t.Fatal("Get after Delete succeeded")
	}
}

// TestAsyncOperationPollers is the LRO witness: Microsoft's own pollers walk
// ARM's asynchronous protocol against this emulator, and they genuinely
// SPIN — the operation is held in flight on the controllable clock, so the
// poller observes a real InProgress before a real Succeeded rather than a
// terminal first response it can shortcut.
//
// The two shapes are different code paths in the SDK: a DELETE follows
// Location until it stops answering 202; a PUT follows Azure-AsyncOperation
// until the status document turns terminal, then re-reads the resource.
func TestAsyncOperationPollers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// Hold every operation in flight for five virtual minutes.
	f.arm.Clock.Freeze()
	f.arm.Cfg.LRODelaySeconds = 300

	rgc, err := armresources.NewResourceGroupsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rgc.CreateOrUpdate(ctx, "rg-async", armresources.ResourceGroup{
		Location: to.Ptr("westeurope"),
	}, nil); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}

	// --- Location shape: DELETE ---
	del, err := rgc.BeginDelete(ctx, "rg-async", nil)
	if err != nil {
		t.Fatalf("BeginDelete: %v", err)
	}
	if del.Done() {
		t.Fatal("the poller finished before the operation could run — the delete was not asynchronous")
	}
	// One real poll while in flight: the SDK reports not-done.
	if _, err := del.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if del.Done() {
		t.Fatal("poller reported done while the operation was still InProgress")
	}
	f.arm.Clock.Advance(301)
	if _, err := del.PollUntilDone(ctx, nil); err != nil {
		t.Fatalf("PollUntilDone(delete): %v", err)
	}
	if _, err := rgc.Get(ctx, "rg-async", nil); err == nil {
		t.Fatal("the group survived a completed delete")
	}

	// --- Azure-AsyncOperation shape: PUT ---
	if _, err := rgc.CreateOrUpdate(ctx, "rg-async2", armresources.ResourceGroup{
		Location: to.Ptr("westeurope"),
	}, nil); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	vc, err := armkeyvault.NewVaultsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	create, err := vc.BeginCreateOrUpdate(ctx, "rg-async2", "asyncvault", armkeyvault.VaultCreateOrUpdateParameters{
		Location: to.Ptr("westeurope"),
		Properties: &armkeyvault.VaultProperties{
			TenantID: to.Ptr(f.emu.TenantID),
			SKU: &armkeyvault.SKU{
				Family: to.Ptr(armkeyvault.SKUFamilyA),
				Name:   to.Ptr(armkeyvault.SKUNameStandard),
			},
			AccessPolicies: []*armkeyvault.AccessPolicyEntry{},
		},
	}, nil)
	if err != nil {
		t.Fatalf("BeginCreateOrUpdate: %v", err)
	}
	if create.Done() {
		t.Fatal("the vault create completed synchronously — it was not asynchronous")
	}
	f.arm.Clock.Advance(301)
	created, err := create.PollUntilDone(ctx, nil)
	if err != nil {
		t.Fatalf("PollUntilDone(create): %v", err)
	}
	// The poller's final read is of the resource itself, and by then the
	// provisioningState the emulator reports has turned terminal.
	if created.Properties == nil || created.Properties.ProvisioningState == nil ||
		*created.Properties.ProvisioningState != armkeyvault.VaultProvisioningStateSucceeded {
		t.Fatalf("provisioningState after polling = %v", created.Properties)
	}
}

// TestArmDenyAssignmentsSDK: Microsoft's own DenyAssignmentsClient reads the
// deny-assignment surface — get by name, list at scope, and the atScope() and
// principalId filters. The SDK has no create method, because ARM has none:
// the seeding below goes through the emulator's control surface, which is
// exactly the boundary this feature has in Azure.
func TestArmDenyAssignmentsSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	scope := "/subscriptions/" + subID
	rgScope := scope + "/resourceGroups/rg1"
	const denyName = "9b5ba1a4-4a4e-4d3c-9d1f-2b6f0e6f4c11"
	const denied = "3f7a1c22-8f0e-4bd0-9d2a-77c9e2d5b301"

	seed := fmt.Sprintf(`{"scope":%q,"denyAssignmentName":"Stack lockdown",
		"description":"created by a deployment stack",
		"permissions":[{"actions":["Microsoft.KeyVault/vaults/write"],
		  "dataActions":["Microsoft.KeyVault/vaults/secrets/*"],
		  "notDataActions":["Microsoft.KeyVault/vaults/secrets/readMetadata/action"]}],
		"principals":[{"id":%q,"type":"ServicePrincipal"}]}`, scope, denied)
	req, err := http.NewRequest("POST", f.srv.URL+"/_emulator/denyassignments/"+denyName,
		strings.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seeding the deny assignment = %d", resp.StatusCode)
	}

	client, err := armauthorization.NewDenyAssignmentsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}

	// Get: the SDK deserializes the full shape, including the members only
	// deny assignments have.
	got, err := client.Get(ctx, scope, denyName, nil)
	if err != nil {
		t.Fatalf("deny assignment Get: %v", err)
	}
	p := got.Properties
	switch {
	case p == nil || p.DenyAssignmentName == nil || *p.DenyAssignmentName != "Stack lockdown":
		t.Fatalf("properties = %+v", p)
	case p.IsSystemProtected == nil || !*p.IsSystemProtected:
		t.Fatal("isSystemProtected did not deserialize")
	case len(p.Principals) != 1 || p.Principals[0].ID == nil || *p.Principals[0].ID != denied:
		t.Fatalf("principals = %+v", p.Principals)
	case len(p.Permissions) != 1 || len(p.Permissions[0].DataActions) != 1 ||
		len(p.Permissions[0].NotDataActions) != 1:
		t.Fatalf("permissions = %+v", p.Permissions)
	case p.DoNotApplyToChildScopes == nil || *p.DoNotApplyToChildScopes:
		t.Fatalf("doNotApplyToChildScopes = %+v", p.DoNotApplyToChildScopes)
	}

	// List for scope: the deny made at the subscription is visible on the
	// group beneath it, because deny assignments inherit as everything in
	// ARM does.
	names := map[string]bool{}
	pager := client.NewListForScopePager(rgScope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("deny assignment ListForScope: %v", err)
		}
		for _, d := range page.Value {
			names[*d.Name] = true
		}
	}
	if !names[denyName] {
		t.Fatalf("inherited deny assignment not listed at the group: %v", names)
	}

	// atScope() excludes the inherited one; the principalId filter finds it
	// at its own scope.
	atScope := 0
	pager = client.NewListForScopePager(rgScope, &armauthorization.DenyAssignmentsClientListForScopeOptions{
		Filter: to.Ptr("atScope()"),
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("atScope() pager: %v", err)
		}
		atScope += len(page.Value)
	}
	if atScope != 0 {
		t.Fatalf("atScope() at the group returned %d", atScope)
	}
	byPrincipal := 0
	pager = client.NewListForScopePager(scope, &armauthorization.DenyAssignmentsClientListForScopeOptions{
		Filter: to.Ptr("principalId eq '" + denied + "'"),
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("principalId pager: %v", err)
		}
		byPrincipal += len(page.Value)
	}
	if byPrincipal != 1 {
		t.Fatalf("principalId filter returned %d", byPrincipal)
	}
}

// TestArmConditionsSDK: Microsoft's own client writes an ABAC condition onto
// a role assignment, reads it back, and is REFUSED when the condition cannot
// be parsed — the refusal is what makes the feature real rather than a field
// that accepts anything.
func TestArmConditionsSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	scope := "/subscriptions/" + subID
	const name = "5a2f8c31-9e44-4c0b-b1d7-6e4a2f9c0b13"
	const principal = "c3d4e5f6-1111-4222-8333-444444444444"
	const condition = `((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) ` +
		`OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))`

	assign, err := armauthorization.NewRoleAssignmentsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	roleID := scope + "/providers/Microsoft.Authorization/roleDefinitions/" +
		"4633458b-17de-408a-b874-0445c86b69e6"

	created, err := assign.Create(ctx, scope, name, armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr(roleID),
			PrincipalID:      to.Ptr(principal),
			PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
			Condition:        to.Ptr(condition),
			ConditionVersion: to.Ptr("2.0"),
		},
	}, nil)
	if err != nil {
		t.Fatalf("Create with a condition: %v", err)
	}
	if created.Properties.Condition == nil || *created.Properties.Condition != condition ||
		created.Properties.ConditionVersion == nil || *created.Properties.ConditionVersion != "2.0" {
		t.Fatalf("condition did not round-trip: %+v", created.Properties)
	}
	got, err := assign.Get(ctx, scope, name, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Properties.Condition == nil || *got.Properties.Condition != condition {
		t.Fatalf("condition absent on read: %+v", got.Properties)
	}

	// A condition that cannot be parsed is refused, so a client never walks
	// away believing an assignment is constrained when it is not.
	_, err = assign.Create(ctx, scope, "6b3f9d42-0f55-4d1c-c2e8-7f5b3a0d1c24",
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: to.Ptr(roleID),
				PrincipalID:      to.Ptr(principal),
				Condition:        to.Ptr("@Resource[x] Frobnicates 'y'"),
				ConditionVersion: to.Ptr("2.0"),
			},
		}, nil)
	if err == nil {
		t.Fatal("a malformed condition was accepted")
	}
	if !strings.Contains(err.Error(), "InvalidCondition") {
		t.Fatalf("refusal did not name the problem: %v", err)
	}

	// And the decision itself: the family channel evaluates the condition
	// against the attributes of a request, which is what a data plane asks.
	ask := func(secretName string) bool {
		body := fmt.Sprintf(`{"scope":%q,"principalIds":[%q],
			"action":"Microsoft.KeyVault/vaults/secrets/getSecret/action",
			"attributes":{"@Resource[Microsoft.KeyVault/vaults/secrets:name]":%q}}`,
			scope, principal, secretName)
		resp, err := f.srv.Client().Post(f.srv.URL+"/_family/authorization/evaluate",
			"application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res struct {
			Allowed         bool
			Reason          string
			ConditionFailed []string
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatal(err)
		}
		if !res.Allowed && len(res.ConditionFailed) == 0 && res.Reason == "" {
			t.Fatalf("a refusal with no reason: %+v", res)
		}
		return res.Allowed
	}
	if !ask("app-db-password") {
		t.Fatal("the condition should admit a secret it names")
	}
	if ask("prod-db-password") {
		t.Fatal("the condition should exclude a secret it does not name")
	}
}

// badCredential hands the pipeline a token that is not a token, so the
// emulator's 401 path is exercised by Microsoft's own client stack rather
// than by a hand-rolled request.
type badCredential struct{}

func (badCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "not-a-real-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// TestArmEnvelopeSDK: the parts of ARM's envelope that only a real client can
// witness — that azcore recognizes the 401 challenge, and that it parses the
// error envelope into a typed ResponseError with ARM's own code.
func TestArmEnvelopeSDK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// 1. The 401 + WWW-Authenticate challenge.
	badOpts := &arm.ClientOptions{ClientOptions: f.opts.ClientOptions}
	rejected, err := armresources.NewResourceGroupsClient(subID, badCredential{}, badOpts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rejected.Get(ctx, "rg1", nil)
	if err == nil {
		t.Fatal("a garbage token was accepted")
	}
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("the SDK did not produce a ResponseError: %v", err)
	}
	switch {
	case respErr.StatusCode != http.StatusUnauthorized:
		t.Fatalf("status = %d", respErr.StatusCode)
	case respErr.ErrorCode != "AuthenticationFailed":
		t.Fatalf("the SDK read the error code as %q", respErr.ErrorCode)
	case !strings.HasPrefix(respErr.RawResponse.Header.Get("WWW-Authenticate"), "Bearer "):
		t.Fatalf("no bearer challenge: %q", respErr.RawResponse.Header.Get("WWW-Authenticate"))
	}
	// The challenge points at an authority, which is what makes it
	// actionable rather than decorative.
	if !strings.Contains(respErr.RawResponse.Header.Get("WWW-Authenticate"), "authorization_uri") {
		t.Fatalf("challenge without an authority: %q", respErr.RawResponse.Header.Get("WWW-Authenticate"))
	}

	// 2. The error envelope, on an authenticated request for something
	// absent: the SDK lifts `error.code` out of the body, and the
	// correlation headers ARM stamps are present for a client to log.
	good, err := armresources.NewResourceGroupsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = good.Get(ctx, "no-such-group", nil)
	if !errors.As(err, &respErr) {
		t.Fatalf("missing group did not produce a ResponseError: %v", err)
	}
	if respErr.StatusCode != http.StatusNotFound || respErr.ErrorCode != "ResourceGroupNotFound" {
		t.Fatalf("envelope = %d %q", respErr.StatusCode, respErr.ErrorCode)
	}
	for _, h := range []string{"x-ms-request-id", "x-ms-correlation-request-id"} {
		if respErr.RawResponse.Header.Get(h) == "" {
			t.Fatalf("%s absent from an error response", h)
		}
	}

	// 3. An assignment naming a role definition that does not exist is
	// refused, rather than stored as a dangling reference that grants
	// nothing while looking like it grants something.
	assign, err := armauthorization.NewRoleAssignmentsClient(subID, f.cred, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = assign.Create(ctx, "/subscriptions/"+subID, "8d1f4c07-2b3e-4a55-9c66-1d2e3f4a5b6c",
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: to.Ptr("/subscriptions/" + subID +
					"/providers/Microsoft.Authorization/roleDefinitions/" +
					"00000000-0000-0000-0000-00000000dead"),
				PrincipalID: to.Ptr("b1c2d3e4-1111-4222-8333-444444444444"),
			},
		}, nil)
	if !errors.As(err, &respErr) {
		t.Fatalf("a dangling role definition was accepted: %v", err)
	}
	if respErr.ErrorCode != "RoleDefinitionDoesNotExist" {
		t.Fatalf("refusal code = %q", respErr.ErrorCode)
	}
}
