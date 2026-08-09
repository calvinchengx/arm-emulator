// Microsoft's JavaScript management SDKs driving arm-emulator.
//
// Same work as the Python and .NET harnesses, in this stack's idiom, for the
// same reason: three unrelated vendor implementations re-deriving the same
// wire is the check that an emulator has not been shaped by one client's
// habits. This one brings its own transport (undici), its own token cache
// (@azure/msal-node) and its own deserializer.
//
// Everything configured below is configuration real Azure supports:
// `endpoint` and `credentialScopes` are how these clients target a sovereign
// or disconnected cloud, and `authorityHost` + `disableInstanceDiscovery` are
// how @azure/identity is pointed at a login endpoint that is not the public
// one. TLS is verified — NODE_EXTRA_CA_CERTS carries the emulator's
// certificate, set by the runner.

import { ClientSecretCredential } from '@azure/identity';
import { ResourceManagementClient } from '@azure/arm-resources';
import { AuthorizationManagementClient } from '@azure/arm-authorization';

const ARM = env('ARM_URL');
const ENTRA = env('ENTRA_URL');
const TENANT = env('ARM_TENANT_ID');
const SUB = env('ARM_SUBSCRIPTION_ID');
const CLIENT_ID = env('ARM_CLIENT_ID');
const CLIENT_SECRET = env('ARM_CLIENT_SECRET');

const SCOPES = ['https://management.azure.com/.default'];
const RG = 'js-sdk-rg';
const READER = 'acdd72a7-3385-48ef-bd42-f606fba81ae7';
const SECRETS_USER = '4633458b-17de-408a-b874-0445c86b69e6';
const CONDITION =
  "((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) " +
  "OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))";

function env(name) {
  const v = process.env[name];
  if (!v) fail(`${name} is not set`);
  return v;
}

function fail(msg) {
  console.error(`FAIL (js): ${msg}`);
  process.exit(1);
}

const credential = new ClientSecretCredential(TENANT, CLIENT_ID, CLIENT_SECRET, {
  authorityHost: ENTRA,
  // MSAL otherwise asks login.microsoftonline.com whether this authority is
  // real — the switch every private-cloud deployment sets.
  disableInstanceDiscovery: true,
});

const clientOptions = { endpoint: ARM, credentialScopes: SCOPES };
const resources = new ResourceManagementClient(credential, SUB, clientOptions);
const authorization = new AuthorizationManagementClient(credential, SUB, clientOptions);
const scope = `/subscriptions/${SUB}`;

console.log('-- 1. a real ARM-audience token from entra-emulator');
const token = await credential.getToken(SCOPES);
if (!token?.token) fail('no token');
console.log('   acquired');

console.log('-- 2. resource groups: create, get, list');
const made = await resources.resourceGroups.createOrUpdate(RG, {
  location: 'westeurope',
  tags: { harness: 'js' },
});
if (made.name !== RG || made.tags?.harness !== 'js') fail(`createOrUpdate returned ${JSON.stringify(made)}`);
const got = await resources.resourceGroups.get(RG);
if (got.location !== 'westeurope') fail(`get returned ${JSON.stringify(got)}`);
let listed = false;
for await (const g of resources.resourceGroups.list()) {
  if (g.name === RG) listed = true;
}
if (!listed) fail('the group is missing from the list');
console.log(`   ${made.id}`);

console.log('-- 3. the ARM error envelope, as this SDK parses it');
try {
  await resources.resourceGroups.get('no-such-group-here');
  fail('a missing group was not an error');
} catch (e) {
  if (e.statusCode !== 404 || e.code !== 'ResourceGroupNotFound') {
    fail(`error envelope = ${e.statusCode} ${e.code}`);
  }
}
console.log('   ResourceGroupNotFound, typed');

console.log('-- 4. role definitions: list with $filter, by real GUID');
const defs = [];
for await (const d of authorization.roleDefinitions.list(scope, {
  filter: "roleName eq 'Key Vault Secrets User'",
})) {
  defs.push(d);
}
if (defs.length !== 1 || defs[0].name !== SECRETS_USER) {
  fail(`$filter returned ${JSON.stringify(defs.map((d) => d.roleName))}`);
}
if (!defs[0].permissions?.[0]?.dataActions?.length) fail('the role arrived with no dataActions');
console.log(`   ${defs[0].roleName} = ${defs[0].name}`);

console.log('-- 5. role assignments: create, read back, delete');
const name = '3a4b5c6d-7e8f-4901-a2b3-c4d5e6f70819';
const created = await authorization.roleAssignments.create(scope, name, {
  roleDefinitionId: `${scope}/providers/Microsoft.Authorization/roleDefinitions/${READER}`,
  principalId: CLIENT_ID,
  principalType: 'ServicePrincipal',
});
if (created.name !== name) fail(`create returned ${JSON.stringify(created)}`);
const readBack = await authorization.roleAssignments.get(scope, name);
if (readBack.principalId?.toLowerCase() !== CLIENT_ID.toLowerCase()) {
  fail('the assignment did not read back');
}
console.log(`   ${created.id}`);

console.log('-- 6. an ABAC condition, written and refused');
const conditionalName = '4b5c6d7e-8f90-4a12-b3c4-d5e6f708192a';
const conditional = await authorization.roleAssignments.create(scope, conditionalName, {
  roleDefinitionId: `${scope}/providers/Microsoft.Authorization/roleDefinitions/${SECRETS_USER}`,
  principalId: CLIENT_ID,
  principalType: 'ServicePrincipal',
  condition: CONDITION,
  conditionVersion: '2.0',
});
if (conditional.condition !== CONDITION) {
  fail(`the condition did not round-trip: ${conditional.condition}`);
}
try {
  await authorization.roleAssignments.create(scope, '5c6d7e8f-9012-4b23-c4d5-e6f708192a3b', {
    roleDefinitionId: `${scope}/providers/Microsoft.Authorization/roleDefinitions/${SECRETS_USER}`,
    principalId: CLIENT_ID,
    condition: "@Resource[x] Frobnicates 'y'",
    conditionVersion: '2.0',
  });
  fail('a malformed condition was accepted');
} catch (e) {
  if (e.code !== 'InvalidCondition') fail(`malformed condition refused as ${e.code}`);
}
console.log('   round-tripped, and a malformed one refused with InvalidCondition');

console.log('-- 7. a garbage token is challenged');
// A credential handing over nonsense: the 401 and its WWW-Authenticate
// challenge have to be recognised by this stack too.
const badCredential = {
  getToken: async () => ({ token: 'not-a-real-token', expiresOnTimestamp: Date.now() + 3_600_000 }),
};
const rejected = new ResourceManagementClient(badCredential, SUB, clientOptions);
try {
  await rejected.resourceGroups.get(RG);
  fail('a garbage token was accepted');
} catch (e) {
  if (e.statusCode !== 401) fail(`garbage token produced ${e.statusCode}: ${e.message}`);
}
console.log('   401, as ARM challenges');

console.log('-- 8. cleanup: delete the assignments and the group');
await authorization.roleAssignments.delete(scope, name);
await authorization.roleAssignments.delete(scope, conditionalName);
await resources.resourceGroups.beginDeleteAndWait(RG);
try {
  await resources.resourceGroups.get(RG);
  fail('the group survived its delete');
} catch {
  // expected
}
console.log('   gone');

console.log('\nJAVASCRIPT SDK E2E: PASS — @azure/arm-resources and ' +
  '@azure/arm-authorization drive arm-emulator');
