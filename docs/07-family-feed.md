# 07 — The family feed

How a sibling data plane learns which principals hold which permissions at its
scope.

```
GET /_family/authorization?scope={resource-id}
```

## Why this endpoint is different from everything else here

Every other surface in this emulator is ARM's real, public wire. This one is
not, deliberately — and it is the **only** one.

Azure's own propagation from ARM to a data plane is internal: there is no
public protocol by which Key Vault learns about a role assignment. So there is
no wire to copy, and inventing one is the honest option. What we can be
faithful about is the **division of authority**, and this endpoint preserves
it exactly: ARM owns roles, assignments and access policies; the data plane
owns its operation vocabulary and decides what a `dataAction` permits.

The feed is therefore thin on purpose. It reports the assignments that apply
and the roles' `dataActions` verbatim, and stops.

## The document

```json
{
  "scope": "/subscriptions/…/providers/Microsoft.KeyVault/vaults/myvault",
  "generated": 1786000000,
  "assignments": [
    {
      "principalId": "9e0ec08a-…",
      "principalType": "ServicePrincipal",
      "roleName": "Key Vault Secrets User",
      "roleDefinitionId": "/subscriptions/…/roleDefinitions/4633458b-…",
      "scope": "/subscriptions/…/resourceGroups/rg1",
      "dataActions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action", "…"],
      "notDataActions": [],
      "condition": "((!(ActionMatches{'…getSecret/action'})) OR (@Resource[…:name] StringStartsWith 'app-'))",
      "conditionVersion": "2.0",
      "conditionAttributes": ["@Resource[Microsoft.KeyVault/vaults/secrets:name]"],
      "denied": [
        { "dataActions": ["Microsoft.KeyVault/vaults/secrets/*"], "notDataActions": [] }
      ]
    }
  ],
  "denyAssignments": [
    {
      "name": "7c9d2a41-…",
      "scope": "/subscriptions/…",
      "denyAssignmentName": "No secret reads",
      "permissions": [{ "dataActions": ["Microsoft.KeyVault/vaults/secrets/*"] }],
      "principals": [{ "id": "9e0ec08a-…", "type": "ServicePrincipal" }],
      "excludePrincipals": [],
      "doNotApplyToChildScopes": false,
      "isSystemProtected": true
    }
  ],
  "accessPolicies": [
    { "objectId": "…", "permissions": { "secrets": ["get", "list"] } }
  ],
  "enableRbacAuthorization": true
}
```

- **assignments** — everything applying at the scope, inherited entries
  included. An assignment whose role definition no longer resolves is skipped:
  it grants nothing, so reporting it would be misleading.
- **assignments[].condition** and **conditionAttributes** — the ABAC condition
  narrowing this assignment, and the attributes it reads. A condition asking
  about an attribute nobody supplies is false, so the requirement is listed
  rather than left to be discovered as a silent denial. A consumer that would
  rather not implement the language can ask for the decision instead (below).
- **assignments[].denied** — the deny-assignment permissions reaching this
  assignment's own principal. A deny **beats** the grant beside it, so the
  consumer must check these first: an action matching a `denied` entry's
  `dataActions`, and none of its `notDataActions`, is refused even though the
  role grants it. It is in the same shape as the grant, so the matcher a data
  plane already has applies unchanged.
- **denyAssignments** — every deny reaching the scope, verbatim. This is what
  a consumer consults when the caller reaches a deny through a **group**:
  membership is resolved in the data plane, not here, so a deny naming a group
  cannot be attached to a user's assignment upstream. Consult both.
- **accessPolicies** and **enableRbacAuthorization** — present when the scope
  names a vault, so the consumer can honour Key Vault's either/or.
- Unauthenticated, like the `/_emulator` control surfaces: it is a localhost
  coordination channel, not a customer-facing API.

## Asking for the decision instead

```
POST /_family/authorization/evaluate
```

The feed is propagation: it hands over the raw material and leaves the
matching to the consumer. That works for actions and dataActions, which are
string matching. It does not work for **ABAC conditions**, which are a
language — evaluating them where they cannot be parsed means every data plane
reimplementing it. So the decision is available in one call:

```json
{
  "scope": "…/vaults/myvault",
  "principalIds": ["{objectId}", "{groupObjectId}"],
  "action": "Microsoft.KeyVault/vaults/secrets/getSecret/action",
  "attributes": { "@Resource[Microsoft.KeyVault/vaults/secrets:name]": "app-db-password" }
}
```

→ `{"allowed": …, "reason": "…", "grantedBy": {…}, "deniedBy": "…", "conditionFailed": ["…"]}`

Deny assignments override, then a role must grant the action, then its
condition must hold. `principalIds` carries the caller's object id **and its
groups**, because membership is resolved where the token is read.

## The consumer's half

azure-keyvault-emulator polls this (default every 5s) and compiles it onto the
per-principal allowlist its authorization already used. Two behaviours are
worth knowing, and both are visible in that repo's
`internal/vault/armfeed.go`:

- **`dataAction` → operation mapping is the data plane's decision**, including
  the wildcard forms (`Microsoft.KeyVault/vaults/keys/*`) and subtracting
  `notDataActions`. That is where the knowledge of what "sign" means belongs.
- **Under ARM governance, no assignment means no access.** An empty feed
  denies, where an unconfigured emulator would allow — real Azure's posture,
  and the opposite of the convenient local default.

A transient ARM outage leaves the last-known grants in force rather than
locking the vault out.

## Capacities

```
GET /_family/capacities
```

The same localhost exception, for a different document: every
`Microsoft.Fabric/capacities` resource, with the Fabric REST GUID ARM
assigned at create, the ARM resource id, SKU, region, state and admins.
fabric-emulator polls this and upserts those rows into `GET /v1/capacities`.
There is no public ARM→Fabric sync wire to copy; inventing this one is the
honest option, as it was for authorization.

## Proven end to end

`e2e/arm-chain/run.py` and `e2e/az-cli/run.py` (both in
azure-keyvault-emulator, both in CI) assert the whole loop: an assignment
written over ARM flips a data-plane call from `403` to authorized, revocation
flips it back, an access policy grants it again, and a group assignment
reaches a member who is never named.
