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

## ABAC conditions

A `condition` narrows a role assignment: the role says what may be done, the
condition says under which attributes. It is written in Azure's version 2.0
language, and here it is **parsed and evaluated** rather than stored and
handed back.

```
((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'}))
 OR
 (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))
```

That is the shape Azure's own documentation uses, and the guard is the reason
why: an attribute nobody supplied makes its comparison **false**, negative
operators included, so without `!(ActionMatches{…}) OR …` the condition would
refuse every unrelated operation too.

Supported: `ActionMatches` / `SubOperationMatches`; `@Resource`, `@Request`,
`@Principal` and `@Environment` attributes; the string operators
(`StringEquals`, `…IgnoreCase`, `StringStartsWith`, `StringLike` and their
negations), numeric, datetime, bool and GUID comparisons; `Exists`; the four
quantifiers (`ForAnyOfAnyValues:`, `ForAllOfAnyValues:`, `ForAnyOfAllValues:`,
`ForAllOfAllValues:`) over `{'a','b'}` value sets; and `AND` / `OR` / `!()`
with parentheses. A multi-valued attribute compared without a quantifier is
false: the author has not said whether they meant any or all, and guessing
would invent an answer.

**Malformed conditions are refused at write time.** `InvalidCondition`, with
the position of the offending text, and `InvalidConditionVersion` for anything
but `2.0`. Storing one that cannot be evaluated would be the worst outcome
available: the caller believes their assignment is constrained, and it is not.

### Asking for a decision

Conditions can only be evaluated where they can be parsed, so the family
channel answers the question directly rather than making each data plane
reimplement the language:

```
POST /_family/authorization/evaluate
{
  "scope": "/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v",
  "principalIds": ["{objectId}", "{groupObjectId}"],
  "action": "Microsoft.KeyVault/vaults/secrets/getSecret/action",
  "attributes": { "@Resource[Microsoft.KeyVault/vaults/secrets:name]": "app-db-password" }
}
```

```json
{ "allowed": true, "reason": "granted by Key Vault Secrets User at /subscriptions/…" }
```

It applies ARM's order: a **deny assignment** overrides everything, then a
role assignment must grant the action, then its condition must be satisfied.
A refusal says which of those it was — `conditionFailed` names the assignments
that would have granted the action but for their condition, which is the
difference between "you have no role" and "your role did not apply to this
resource", and the thing hardest to work out without being told.

## Deny assignments

The one part of the model that takes access away. They behave differently
from role assignments in two ways, and both are real here.

**They are read-only over ARM.** No customer creates one: Azure Blueprints,
managed applications and deployment stacks do. So `GET` and list work, and
every other method is refused with a message saying where they come from — an
emulator that let you `PUT` one would teach a habit Azure will not honour.
Seeding therefore goes through the control surface, which is the honest place
for something with no public wire to copy:

```
POST   /_emulator/denyassignments/{name}
DELETE /_emulator/denyassignments/{name}
```

```json
{
  "scope": "/subscriptions/{sub}",
  "denyAssignmentName": "No secret reads",
  "permissions": [{ "dataActions": ["Microsoft.KeyVault/vaults/secrets/*"],
                    "notDataActions": ["…/readMetadata/action"] }],
  "principals": [{ "id": "{objectId}", "type": "ServicePrincipal" }],
  "excludePrincipals": [],
  "doNotApplyToChildScopes": false
}
```

**They win.** A deny beats every role assignment granting the same action, and
the evaluation is the feature — not the shape:

- `*` matches any run of characters, segment boundaries included, so
  `Microsoft.KeyVault/*` covers a vault's data actions.
- `notDataActions` carve back out of what the deny takes: "deny everything
  except reads" is expressible and honoured.
- The all-principals GUID `00000000-0000-0000-0000-000000000000` denies
  everyone; `excludePrincipals` exempts a named identity from it, which is how
  a managed application locks a resource against everybody but itself.
- A deny naming a **group** reaches its members, resolved as assignments are.
- They inherit downward like everything in ARM, unless
  `doNotApplyToChildScopes` pins one to its own scope.

The data planes see this through the feed: each assignment carries the denies
reaching its principal, and the whole set rides alongside for the group case.
See [The family feed](07-family-feed.md).

## What is NOT here

Authorization *decisions on ARM's own surface*. This emulator authenticates
every request (a valid ARM-audience token is required) but does not then check
whether that caller may write the assignment. Emulating ARM's self-governance
would mean a bootstrap problem — someone has to make the first assignment —
and it is not what the family needs. The data planes' enforcement is the real
thing here; see [The family feed](07-family-feed.md).
