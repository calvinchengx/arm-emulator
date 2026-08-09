package server_test

// The P0 centerpiece: Microsoft's REAL management SDKs (armresources,
// armauthorization) drive this emulator over ARM's wire, authenticating with
// an ARM-audience token from an in-process entra-emulator — the production
// trust path, fully offline.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
