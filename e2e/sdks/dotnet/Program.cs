// Microsoft's .NET management SDKs driving arm-emulator.
//
// The third vendor stack, for the same reason as the other two: an emulator
// that only ever meets one SDK ends up shaped by that SDK's habits. This one
// brings its own HTTP stack, its own token cache and its own serializer, and
// it models ARM differently again — Azure.ResourceManager is resource-graph
// shaped (a subscription hands you collections) rather than a flat client.
//
// Everything configured here is configuration real Azure supports:
// ArmEnvironment is how a client targets a sovereign or disconnected cloud,
// and AuthorityHost + DisableInstanceDiscovery are how Azure.Identity is
// pointed at a login endpoint that is not the public one.
//
// TLS: .NET reads no CA-bundle environment variable, so rather than switching
// validation off, the harness PINS the emulator's certificate as a custom
// root — the same choice the emulator's own healthcheck makes.

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.Fabric;
using Azure.ResourceManager.Fabric.Models;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Resources.Models;

const string Reader = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
const string SecretsUser = "4633458b-17de-408a-b874-0445c86b69e6";
const string Condition =
    "((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) " +
    "OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))";
const string ResourceGroupName = "dotnet-sdk-rg";

string Env(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } v
        ? v
        : Fail($"{name} is not set");

string Fail(string message)
{
    Console.Error.WriteLine($"FAIL (dotnet): {message}");
    Environment.Exit(1);
    return string.Empty;
}

var armUrl = Env("ARM_URL");
var entraUrl = Env("ENTRA_URL");
var tenantId = Env("ARM_TENANT_ID");
var subscriptionId = Env("ARM_SUBSCRIPTION_ID");
var clientId = Env("ARM_CLIENT_ID");
var clientSecret = Env("ARM_CLIENT_SECRET");
var caBundle = Env("ARM_CA_BUNDLE");

// ---- TLS: trust exactly the emulator's certificate, and nothing else ----

var pinned = new X509Certificate2Collection();
pinned.ImportFromPemFile(caBundle);

bool ValidateAgainstPinned(HttpRequestMessage _, X509Certificate2? certificate,
    X509Chain? __, SslPolicyErrors errors)
{
    if (certificate is null)
    {
        return false;
    }
    // A wrong hostname is never acceptable, pinned root or not.
    if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
    {
        return false;
    }
    if (errors == SslPolicyErrors.None)
    {
        return true;
    }
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.CustomTrustStore.AddRange(pinned);
    return chain.Build(certificate);
}

HttpPipelineTransport PinnedTransport() =>
    new HttpClientTransport(new HttpClient(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = ValidateAgainstPinned,
    }));

// ---- the custom cloud ----

var environment = new ArmEnvironment(new Uri(armUrl), "https://management.azure.com");
var armOptions = new ArmClientOptions { Environment = environment, Transport = PinnedTransport() };
var credential = new ClientSecretCredential(tenantId, clientId, clientSecret,
    new ClientSecretCredentialOptions
    {
        AuthorityHost = new Uri(entraUrl),
        // MSAL otherwise asks login.microsoftonline.com whether this authority
        // is real — the switch every private-cloud deployment sets.
        DisableInstanceDiscovery = true,
        Transport = PinnedTransport(),
    });

Console.WriteLine("-- 1. a real ARM-audience token from entra-emulator");
var token = await credential.GetTokenAsync(
    new TokenRequestContext(new[] { "https://management.azure.com/.default" }));
if (string.IsNullOrEmpty(token.Token))
{
    Fail("no token");
}
Console.WriteLine("   acquired");

var arm = new ArmClient(credential, subscriptionId, armOptions);
var subscription = await arm.GetDefaultSubscriptionAsync();
var scope = new ResourceIdentifier($"/subscriptions/{subscriptionId}");

Console.WriteLine("-- 2. resource groups: create, get, list");
var groups = subscription.GetResourceGroups();
var data = new ResourceGroupData(new AzureLocation("westeurope"));
data.Tags.Add("harness", "dotnet");
var created = await groups.CreateOrUpdateAsync(WaitUntil.Completed, ResourceGroupName, data);
if (created.Value.Data.Name != ResourceGroupName ||
    !created.Value.Data.Tags.TryGetValue("harness", out var tag) || tag != "dotnet")
{
    Fail($"CreateOrUpdate returned {created.Value.Data.Name}");
}
var fetched = await groups.GetAsync(ResourceGroupName);
if (fetched.Value.Data.Location != new AzureLocation("westeurope"))
{
    Fail($"Get returned {fetched.Value.Data.Location}");
}
var seen = false;
await foreach (var g in groups.GetAllAsync())
{
    if (g.Data.Name == ResourceGroupName)
    {
        seen = true;
    }
}
if (!seen)
{
    Fail("the group is missing from the list");
}
Console.WriteLine($"   {created.Value.Data.Id}");

Console.WriteLine("-- 3. the ARM error envelope, as this SDK parses it");
try
{
    await groups.GetAsync("no-such-group-here");
    Fail("a missing group was not an error");
}
catch (RequestFailedException e)
{
    if (e.Status != 404 || e.ErrorCode != "ResourceGroupNotFound")
    {
        Fail($"error envelope = {e.Status} {e.ErrorCode}");
    }
}
Console.WriteLine("   ResourceGroupNotFound, typed");

Console.WriteLine("-- 4. role definitions: list with $filter, by real GUID");
var definitions = arm.GetAuthorizationRoleDefinitions(scope);
var matched = new List<AuthorizationRoleDefinitionResource>();
await foreach (var d in definitions.GetAllAsync(filter: "roleName eq 'Key Vault Secrets User'"))
{
    matched.Add(d);
}
if (matched.Count != 1 || matched[0].Data.Name != SecretsUser)
{
    Fail($"$filter returned {matched.Count} definitions");
}
if (matched[0].Data.Permissions.Count == 0 || matched[0].Data.Permissions[0].DataActions.Count == 0)
{
    Fail("the role arrived with no dataActions");
}
Console.WriteLine($"   {matched[0].Data.RoleName} = {matched[0].Data.Name}");

Console.WriteLine("-- 5. role assignments: create, read back, delete");
var assignments = arm.GetRoleAssignments(scope);
const string assignmentName = "6d7e8f90-1234-4c56-b7c8-d9e0f1a2b3c4";
var content = new RoleAssignmentCreateOrUpdateContent(
    new ResourceIdentifier($"{scope}/providers/Microsoft.Authorization/roleDefinitions/{Reader}"),
    Guid.Parse(clientId))
{
    PrincipalType = RoleManagementPrincipalType.ServicePrincipal,
};
var assignment = await assignments.CreateOrUpdateAsync(WaitUntil.Completed, assignmentName, content);
if (assignment.Value.Data.Name != assignmentName)
{
    Fail($"CreateOrUpdate returned {assignment.Value.Data.Name}");
}
var readBack = await assignments.GetAsync(assignmentName);
if (!string.Equals(readBack.Value.Data.PrincipalId.ToString(), clientId,
        StringComparison.OrdinalIgnoreCase))
{
    Fail("the assignment did not read back");
}
Console.WriteLine($"   {assignment.Value.Data.Id}");

Console.WriteLine("-- 6. an ABAC condition, written and refused");
const string conditionalName = "7e8f9012-3456-4d78-c9d0-e1f2a3b4c5d6";
var conditional = new RoleAssignmentCreateOrUpdateContent(
    new ResourceIdentifier(
        $"{scope}/providers/Microsoft.Authorization/roleDefinitions/{SecretsUser}"),
    Guid.Parse(clientId))
{
    PrincipalType = RoleManagementPrincipalType.ServicePrincipal,
    Condition = Condition,
    ConditionVersion = "2.0",
};
var withCondition =
    await assignments.CreateOrUpdateAsync(WaitUntil.Completed, conditionalName, conditional);
if (withCondition.Value.Data.Condition != Condition)
{
    Fail($"the condition did not round-trip: {withCondition.Value.Data.Condition}");
}
try
{
    var malformed = new RoleAssignmentCreateOrUpdateContent(
        new ResourceIdentifier(
            $"{scope}/providers/Microsoft.Authorization/roleDefinitions/{SecretsUser}"),
        Guid.Parse(clientId))
    {
        Condition = "@Resource[x] Frobnicates 'y'",
        ConditionVersion = "2.0",
    };
    await assignments.CreateOrUpdateAsync(WaitUntil.Completed,
        "8f901234-5678-4e90-d1e2-f3a4b5c6d7e8", malformed);
    Fail("a malformed condition was accepted");
}
catch (RequestFailedException e)
{
    if (e.ErrorCode != "InvalidCondition")
    {
        Fail($"malformed condition refused as {e.ErrorCode}");
    }
}
Console.WriteLine("   round-tripped, and a malformed one refused with InvalidCondition");

Console.WriteLine("-- 7. a garbage token is challenged");
var rejected = new ArmClient(new BadCredential(), subscriptionId, armOptions);
try
{
    var strangerGroups = rejected.GetSubscriptionResource(scope).GetResourceGroups();
    await strangerGroups.GetAsync(ResourceGroupName);
    Fail("a garbage token was accepted");
}
catch (RequestFailedException e)
{
    if (e.Status != 401)
    {
        Fail($"garbage token produced {e.Status}");
    }
}
Console.WriteLine("   401, as ARM challenges");

Console.WriteLine("-- 8. Microsoft.Fabric/capacities via Azure.ResourceManager.Fabric");
// 1.0.0 speaks api-version 2023-11-01: create/get/list/delete and check-name,
// but not list_usages or properties.overage (those arrived later, and Python
// already covers them).
const string capName = "dotnetsdkcap";
var nameCheck = new FabricNameAvailabilityContent
{
    Name = capName,
    ResourceType = "Microsoft.Fabric/capacities",
};
var avail = await subscription.CheckFabricCapacityNameAvailabilityAsync(
    new AzureLocation("westeurope"), nameCheck);
if (avail.Value.IsNameAvailable != true)
{
    Fail($"CheckFabricCapacityNameAvailability = {avail.Value.IsNameAvailable}");
}
var rg = created.Value;
var capacities = rg.GetFabricCapacities();
var capData = new FabricCapacityData(
    new AzureLocation("westeurope"),
    new FabricCapacityProperties(new FabricCapacityAdministration(new[] { "dotnet-sdk@example.com" })),
    new FabricSku("F2", FabricSkuTier.Fabric));
var cap = await capacities.CreateOrUpdateAsync(WaitUntil.Completed, capName, capData);
if (cap.Value.Data.Name != capName)
{
    Fail($"CreateOrUpdate capacity returned {cap.Value.Data.Name}");
}
var gotCap = await capacities.GetAsync(capName);
if (gotCap.Value.Data.Sku.Name != "F2" ||
    gotCap.Value.Data.Properties.State != FabricResourceState.Active)
{
    Fail($"Get capacity = {gotCap.Value.Data.Sku.Name} {gotCap.Value.Data.Properties.State}");
}
var capListed = false;
await foreach (var c in capacities.GetAllAsync())
{
    if (c.Data.Name == capName)
    {
        capListed = true;
    }
}
if (!capListed)
{
    Fail("the capacity is missing from the list");
}
await cap.Value.DeleteAsync(WaitUntil.Completed);
Console.WriteLine($"   {cap.Value.Data.Id}");

Console.WriteLine("-- 9. cleanup: delete the assignments and the group");
await (await assignments.GetAsync(assignmentName)).Value.DeleteAsync(WaitUntil.Completed);
await (await assignments.GetAsync(conditionalName)).Value.DeleteAsync(WaitUntil.Completed);
await (await groups.GetAsync(ResourceGroupName)).Value.DeleteAsync(WaitUntil.Completed);
try
{
    await groups.GetAsync(ResourceGroupName);
    Fail("the group survived its delete");
}
catch (RequestFailedException)
{
    // expected
}
Console.WriteLine("   gone");

Console.WriteLine();
Console.WriteLine(".NET SDK E2E: PASS — Azure.ResourceManager.Resources, "
    + "Azure.ResourceManager.Authorization and Azure.ResourceManager.Fabric "
    + "drive arm-emulator");

// A credential that hands the pipeline nonsense, so the 401 and its
// WWW-Authenticate challenge are exercised by this stack too.
file sealed class BadCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
        new("not-a-real-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context,
        CancellationToken token) => new(GetToken(context, token));
}
