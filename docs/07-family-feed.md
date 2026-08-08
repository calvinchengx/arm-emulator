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
      "notDataActions": []
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
- **accessPolicies** and **enableRbacAuthorization** — present when the scope
  names a vault, so the consumer can honour Key Vault's either/or.
- Unauthenticated, like the `/_emulator` control surfaces: it is a localhost
  coordination channel, not a customer-facing API.

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

## Proven end to end

`e2e/arm-chain/run.py` and `e2e/az-cli/run.py` (both in
azure-keyvault-emulator, both in CI) assert the whole loop: an assignment
written over ARM flips a data-plane call from `403` to authorized, revocation
flips it back, an access policy grants it again, and a group assignment
reaches a member who is never named.
