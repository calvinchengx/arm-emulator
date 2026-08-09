# Feature parity: arm-emulator vs. real Azure Resource Manager

How the emulator's surface maps to real ARM (as specified in
[`Azure/azure-rest-api-specs`](https://github.com/Azure/azure-rest-api-specs)
and documented at
[learn.microsoft.com/rest/api/resources](https://learn.microsoft.com/en-us/rest/api/resources/)),
and — the point of this table — **whether real work happens or just the API
shape**.

This emulator exists to make the family's *authorization* real: role
assignments written over ARM's wire by real clients, enforced by the sibling
data planes. It implements the slice of ARM that serves that goal, and says
plainly what it leaves alone.

## Legend

| | Meaning |
|---|---|
| 🟢 **Real** | Genuine work over ARM's real wire: real tokens verified, real resource-ID semantics, real inheritance — an unmodified Microsoft client cannot tell the difference. |
| 🟡 **Emulated** | Faithful contract + persisted state, but simplified behind it. |
| 🔴 **Not implemented** | Absent (404 / NoRegisteredProviderFound). |

## Envelope & identity

| ARM feature | Emulator | Type |
|---|---|---|
| ARM-audience bearer tokens (RS256 / JWKS / issuer / expiry) | Signature verified **before any claim is read**; `https://management.azure.com` audience, `exp`/`nbf` on the emulator's controllable clock; multiple trusted issuers | 🟢 Real |
| `401` + `WWW-Authenticate` challenge with `AuthenticationFailed` | The real shape; unmodified `azidentity` walks it | 🟢 Real |
| Resource-ID grammar (`/subscriptions/{s}/resourceGroups/{g}/providers/{ns}/{type}/{n}`) | Parsed as ARM parses it, including a provider path appended to a scope that itself contains one | 🟢 Real |
| `api-version` required and validated (date-based, `-preview`) | Missing → `MissingApiVersionParameter`; malformed → `InvalidApiVersionParameter` | 🟢 Real |
| ARM error envelope + `x-ms-request-id` / `x-ms-correlation-request-id` | On every response | 🟢 Real |
| Cloud discovery (`GET /metadata/endpoints`, anonymous) | The real document, served without a token as ARM does — it is what `az cloud register` and SDK cloud-discovery fetch first, and it points them at entra-emulator | 🟢 Real |

## Microsoft.Resources

| ARM feature | Emulator | Type |
|---|---|---|
| Tenants + subscriptions discovery (`/tenants`, `/subscriptions`) | Served as real ARM serves it, unknown ids `SubscriptionNotFound`. The tenant holds one subscription — a declared boundary below, not a simplification of the surface | 🟢 Real |
| Resource groups CRUD + tags (case-insensitive names, PUT-as-upsert) | Real semantics, persisted | 🟢 Real |
| Asynchronous group delete (`202` + `Location` polling) | `202` naming a `Location` to poll, `Retry-After`, `202` while it runs and `200` when done — an `armresources` poller genuinely spins, observing `InProgress` before `Succeeded`; `204` when there was nothing to delete | 🟢 Real |

## Microsoft.Authorization

| ARM feature | Emulator | Type |
|---|---|---|
| Built-in role definitions with their **real GUIDs** and documented data actions | Seeded: the Key Vault data-plane roles plus Owner/Contributor/Reader; get by GUID, list, `$filter=roleName eq '…'` | 🟢 Real |
| Role assignments: PUT / GET / DELETE at any scope | Real CRUD, persisted, ARM's status codes (`201`, `200`, idempotent `204`) | 🟢 Real |
| Duplicate (scope, role, principal) → `RoleAssignmentExists` | Enforced at the storage layer | 🟢 Real |
| Assignment to a nonexistent role definition refused | `RoleDefinitionDoesNotExist` rather than a dangling reference | 🟢 Real |
| **Scope inheritance** on read (an assignment applies to every scope beneath it) | Real, on segment boundaries and case-insensitively | 🟢 Real |
| `$filter=atScope()` and `principalId eq '…'` | Honoured, as the CLI sends them | 🟢 Real |
| Assignments to a **group** principal (`principalType: Group`) | Stored and served like any other; a member's token carries the group in its `groups` claim (entra-emulator ≥ v0.3.1) and the data plane resolves membership — a user never named in the assignment is authorized through it | 🟢 Real |
| Custom role definitions (create/update/delete) | Real CRUD at `PUT`/`DELETE .../roleDefinitions/{guid}`, listed and `$filter`ed beside the built-ins. **`assignableScopes` is enforced**, not just stored — an assignment outside them is refused; built-ins cannot be overwritten or deleted, display names are unique, and a definition still carrying assignments cannot be removed. Its `dataActions` flow through the family feed, so a role a caller invented genuinely grants data-plane access | 🟢 Real |
| Deny assignments | — (PIM eligibility is declared out of scope below) | 🔴 Not implemented |
| ABAC `condition` evaluation | Stored and returned verbatim; **not evaluated** | 🟡 Emulated |

## Microsoft.KeyVault

| ARM feature | Emulator | Type |
|---|---|---|
| Vault CRUD (`Microsoft.KeyVault/vaults`) with tags, SKU, `vaultUri` | Real semantics, persisted; creation requires an existing resource group, as ARM requires | 🟢 Real |
| `accessPolicies` + the `add`/`replace`/`remove` operation | Real: `add` merges by objectId, `replace` swaps the list, `remove` drops by objectId — what `az keyvault set-policy` / `delete-policy` call | 🟢 Real |
| `enableRbacAuthorization`, `enablePurgeProtection`, soft-delete settings | Stored, returned, and **fed to the data plane** — RBAC mode makes the vault ignore access policies, as real Key Vault does | 🟢 Real |
| Asynchronous vault create (`202` + polling) | `201`/`200` naming an `Azure-AsyncOperation` status document, with a non-terminal `provisioningState` of `Creating` until it completes; the `armkeyvault` poller walks the status document then re-reads the resource | 🟢 Real |
| Deleted-vault recovery (vault-level soft delete + purge) | — ; would compose with azure-keyvault-emulator's object-level soft delete | 🔴 Not implemented |

## Emulator-only (no ARM equivalent — these exist for testing)

| Feature | Purpose |
|---|---|
| Clock control (`/_emulator/clock`) | Freeze/advance/offset — makes token expiry deterministic |
| Fault injection (`/_emulator/faults`) | Force `429` + `Retry-After` or `500`, to exercise SDK retry paths |
| The family feed (`GET /_family/authorization?scope=…`) | Effective assignments plus their dataActions, for the sibling data planes. Azure's internal ARM→data-plane propagation is not public wire, so there is no ARM behaviour to grade this against — it is ours by necessity, and deliberately thin: assignments and role dataActions verbatim, each data plane mapping them onto its own operations |

## Ecosystem conformance: real clients as witnesses

| Real client (pinned) | Surface exercised | Status |
|---|---|---|
| `armresources` (Azure Go SDK) | Resource groups: create/get/list/delete, tags, 404s | 🟢 CI `test` |
| `armauthorization` (Azure Go SDK) | Role definitions (list + `$filter` + get-by-id), role assignments (create/get/list/delete), duplicate conflict, inheritance, `atScope()` | 🟢 CI `test` |
| `armkeyvault` (Azure Go SDK) | Vault create/get/list/delete, access-policy add and remove | 🟢 CI `test` |
| `azidentity` (`ClientSecretCredential`, custom cloud) | The ARM-audience token path against an in-process real **entra-emulator** | 🟢 CI `test` |
| **The authorization chain** (entra → ARM assignment → Key Vault data plane) | A role assignment written over ARM flips the vault from `403` to authorized, revocation flips it back, and an access policy grants it again — three real processes | 🟢 CI `arm-chain` (in azure-keyvault-emulator) |
| **`az` CLI** via `az cloud register` | The family registered as a cloud: login, group/vault create, **custom role definition create/list/delete**, role assignment create+delete, set-policy — asserted against the Key Vault data plane | 🟢 CI `az-cli` (in azure-keyvault-emulator) |
| Python / JS / .NET management SDKs | Planned (P2) | 🔴 Not wired yet |

Every 🟢 claim names its witness in [`witnesses.json`](witnesses.json),
enforced by `scripts/check_witnesses.py --strict` in CI — the same discipline
as the sibling emulators.

## Scope boundary: the authorization slice, not all of ARM

Everything below is **out of scope on purpose**, and therefore not graded
above: a row appears in exactly one of the two places, never both. Declaring
a boundary is not the same as scoring a gap — the tables above measure how
faithfully the emulator does what it set out to do, and this section says
what it did not set out to do, and why.

| Azure feature | Why out of scope |
|---|---|
| **Arbitrary resource providers** (compute, network, storage, …) | This emulator serves the family's data planes; providers arrive when a sibling needs one |
| **Template/Bicep deployments** (`Microsoft.Resources/deployments`) | A large engine of its own; a later phase if the family needs it |
| **Management groups, multiple subscriptions, cross-tenant** | Directory topology, not authorization behaviour |
| **Azure Policy, Activity Log, Resource Graph, locks** | Separate services layered on ARM |
| **Behaviour differentiated by `api-version`** | Every version is accepted and validated, and all behave alike. Varying shapes by version means maintaining one per version, and the consumers here pin a single version |
| **Private endpoints, network ACLs** | Network-path enforcement, which no localhost process can honour — a firewall an emulator pretends to apply is worse than none |
| **PIM / just-in-time elevation** | Requires an approval workflow and directory state no localhost process holds |

## Test coverage

**98.9%**, with a CI floor at 98%. Every reachable statement is covered,
including the ARM error branches (tables dropped or `BEFORE DELETE` triggers
fired under live handlers), the row-scan failures (SQLite's dynamic typing
lets a text value sit in an INTEGER column), the TLS persistence failures,
`func main` itself (re-executed as a subprocess), and the token paths where a
signature verifies but the payload does not decode.

What remains uncovered is only what cannot run unless the standard library
fails: `crypto/rand` erroring (inside `NewGUID` and certificate generation)
and `sql.Open` rejecting a driver name compiled into the binary. Reaching
those would mean adding mutable global seams to production crypto code, so
they stay honestly uncovered rather than faked.
