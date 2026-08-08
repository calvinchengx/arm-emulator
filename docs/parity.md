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
| Behaviour differentiated **by** api-version | Any valid version behaves identically | 🔴 Not implemented |

## Microsoft.Resources

| ARM feature | Emulator | Type |
|---|---|---|
| Tenants + subscriptions discovery (`/tenants`, `/subscriptions`) | Served as real ARM does; one seeded subscription, unknown ids `SubscriptionNotFound` | 🟡 Emulated |
| Resource groups CRUD + tags (case-insensitive names, PUT-as-upsert) | Real semantics, persisted | 🟢 Real |
| Asynchronous group delete (`202` + `Location` polling) | Completes synchronously (`200`/`204`) — terminal shapes SDK pollers accept | 🟡 Emulated |
| Tracked resources of arbitrary providers, `Microsoft.Resources/deployments` | — | 🔴 Not implemented |

## Microsoft.Authorization

| ARM feature | Emulator | Type |
|---|---|---|
| Built-in role definitions with their **real GUIDs** and documented data actions | Seeded: the Key Vault data-plane roles plus Owner/Contributor/Reader; get by GUID, list, `$filter=roleName eq '…'` | 🟢 Real |
| Role assignments: PUT / GET / DELETE at any scope | Real CRUD, persisted, ARM's status codes (`201`, `200`, idempotent `204`) | 🟢 Real |
| Duplicate (scope, role, principal) → `RoleAssignmentExists` | Enforced at the storage layer | 🟢 Real |
| Assignment to a nonexistent role definition refused | `RoleDefinitionDoesNotExist` rather than a dangling reference | 🟢 Real |
| **Scope inheritance** on read (an assignment applies to every scope beneath it) | Real, on segment boundaries and case-insensitively | 🟢 Real |
| `$filter=atScope()` and `principalId eq '…'` | Honoured, as the CLI sends them | 🟢 Real |
| Custom role definitions (create/update) | Built-ins only | 🔴 Not implemented |
| Deny assignments, PIM eligibility | — | 🔴 Not implemented |
| ABAC `condition` evaluation | Stored and returned verbatim; **not evaluated** | 🟡 Emulated |

## The family feed

| Feature | Emulator | Type |
|---|---|---|
| `GET /_family/authorization?scope=…` — effective assignments + their dataActions | The **only non-ARM surface here**, deliberately: Azure's internal ARM→data-plane propagation is not public wire, so its shape is ours. Thin by design — it reports assignments and role dataActions verbatim, leaving each data plane to map them onto its own operations | 🟡 Emulated (by necessity) |

## Emulator-only (no ARM equivalent — these exist for testing)

| Feature | Purpose |
|---|---|
| Clock control (`/_emulator/clock`) | Freeze/advance/offset — makes token expiry deterministic |
| Fault injection (`/_emulator/faults`) | Force `429` + `Retry-After` or `500`, to exercise SDK retry paths |

## Ecosystem conformance: real clients as witnesses

| Real client (pinned) | Surface exercised | Status |
|---|---|---|
| `armresources` (Azure Go SDK) | Resource groups: create/get/list/delete, tags, 404s | 🟢 CI `test` |
| `armauthorization` (Azure Go SDK) | Role definitions (list + `$filter` + get-by-id), role assignments (create/get/list/delete), duplicate conflict, inheritance, `atScope()` | 🟢 CI `test` |
| `azidentity` (`ClientSecretCredential`, custom cloud) | The ARM-audience token path against an in-process real **entra-emulator** | 🟢 CI `test` |
| **`az` CLI** via `az cloud register` | Planned (P3) — the flagship witness | 🔴 Not wired yet |
| Python / JS / .NET management SDKs | Planned (P2) | 🔴 Not wired yet |

Every 🟢 claim names its witness in [`witnesses.json`](witnesses.json),
enforced by `scripts/check_witnesses.py --strict` in CI — the same discipline
as the sibling emulators.

## Scope boundary: the authorization slice, not all of ARM

| Azure feature | Why out of scope |
|---|---|
| **Arbitrary resource providers** (compute, network, storage, …) | This emulator serves the family's data planes; providers arrive when a sibling needs one |
| **Template/Bicep deployments** (`Microsoft.Resources/deployments`) | A large engine of its own; a later phase if the family needs it |
| **Management groups, multiple subscriptions, cross-tenant** | Directory topology, not authorization behaviour |
| **Azure Policy, Activity Log, Resource Graph, locks** | Separate services layered on ARM |
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
