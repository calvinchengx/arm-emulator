# 05 — Authorization: roles, assignments and scope

`Microsoft.Authorization` is why this emulator exists. In Azure, role
assignments are ARM resources — not something a data plane owns — so making
authorization *real* for the emulator family meant serving them on ARM's
actual wire.

## Role definitions

The built-in roles are seeded with their **real definition GUIDs**, because
that is how real code names them:

| Role | GUID |
|---|---|
| Key Vault Administrator | `00482a5a-887f-4fb3-b363-3b7fe8e74483` |
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` |
| Key Vault Secrets Officer | `b86a8fe4-44ce-4948-aee5-eccb2c155cd7` |
| Key Vault Crypto User | `12338af0-0e69-4776-bea7-57ae8d297424` |
| Key Vault Crypto Officer | `14b46e9e-c2b7-41b4-b07b-48a6ebf60603` |
| Key Vault Crypto Service Encryption User | `e147488a-f6f5-4113-8e2d-b22465e65bf6` |
| Key Vault Certificate User | `db79e9a7-68ee-4b58-9aeb-b90e7c24fcba` |
| Key Vault Certificates Officer | `a4417e6f-fecd-4de8-b567-7b0420556985` |
| Key Vault Reader | `21090545-7ca7-4776-b22c-e363652d74d2` |
| Owner / Contributor / Reader | `8e3af657-…` / `b24988ac-…` / `acdd72a7-…` |

Each carries the documented `dataActions`, which is what a data plane reads to
decide what an assignment permits.

```
GET  {scope}/providers/Microsoft.Authorization/roleDefinitions
GET  {scope}/providers/Microsoft.Authorization/roleDefinitions/{guid}
     ?$filter=roleName eq 'Key Vault Secrets User'
```

Custom role definitions are not implemented — see [parity](parity.md).

## Role assignments

```
PUT    {scope}/providers/Microsoft.Authorization/roleAssignments/{guid}
GET    {scope}/providers/Microsoft.Authorization/roleAssignments/{guid}
DELETE {scope}/providers/Microsoft.Authorization/roleAssignments/{guid}
GET    {scope}/providers/Microsoft.Authorization/roleAssignments
       ?$filter=atScope() | principalId eq '{oid}'
```

Real behaviours, not just shapes:

- **Duplicates are refused.** The same role, to the same principal, at the
  same scope returns `RoleAssignmentExists` — enforced by a storage
  constraint, so it holds however the scope was spelled.
- **A dangling role is refused.** Assigning a definition that does not exist
  returns `RoleDefinitionDoesNotExist` rather than storing a broken reference.
- **Delete is idempotent** (`204` when already gone), as ARM's is.

## Scope and inheritance

A scope is a resource ID, and assignments inherit **downward**:

```
/                                                          tenant root
/subscriptions/{sub}
/subscriptions/{sub}/resourceGroups/{rg}
/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}
```

An assignment at the resource group applies to every vault beneath it. Matching
is case-insensitive (as ARM treats resource IDs) and lands on segment
boundaries — `…/resourceGroups/rg1` never matches `…/resourceGroups/rg10`.

`$filter=atScope()` narrows a listing to exactly the scope asked for, dropping
inherited entries — the filter the CLI sends.

## Group principals

An assignment can name a **group** (`principalType: Group`). A caller whose
token carries that group in its `groups` claim is authorized through it,
without ever being named. entra-emulator emits the claim when the app's
`groupMembershipClaims` asks for it; its seeded *Engineering* group has Alice
and Bob in it, which is what the family's CI exercises.

## What is NOT here

Authorization *decisions on ARM's own surface*. This emulator authenticates
every request (a valid ARM-audience token is required) but does not then check
whether that caller may write the assignment. Emulating ARM's self-governance
would mean a bootstrap problem — someone has to make the first assignment —
and it is not what the family needs. The data planes' enforcement is the real
thing here; see [The family feed](07-family-feed.md).
