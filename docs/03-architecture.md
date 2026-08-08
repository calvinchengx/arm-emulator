# 03 — Architecture

A clean-room, local emulator of the **Azure Resource Manager (ARM) control
plane** — `management.azure.com` — scoped to what the emulator family's data
planes need. The fourth member of a family built on one principle: **the same
trust relationships as production**.

```
 az CLI / ARM SDKs (armauthorization, azure-mgmt-*, @azure/arm-*, Azure.ResourceManager.*)
      │  aud = https://management.azure.com          (entra-emulator mints it — v0.2.1 carve-out)
      ▼
 arm-emulator ── subscriptions · resource groups
      │          Microsoft.Authorization/{roleDefinitions,roleAssignments}
      │          Microsoft.KeyVault/vaults (accessPolicies, purge protection)
      │          (later) Microsoft.Fabric/capacities
      ▼
 azure-keyvault-emulator ── enforces the assignments on its data plane
                            (the enforcement engine already exists; ARM becomes its feed)
```

## Why

azure-keyvault-emulator reached full data-plane parity, but its three
authorization rows sit at 🟡: enforcement is real, **assignment is not the
real wire** — in Azure, role assignments and access policies are ARM
resources. This emulator moves assignment onto the real protocol, flipping
those rows 🟢 with real-client witnesses.

## Scope and phases

**P0 — the ARM envelope + authorization.**
- ARM resource-ID grammar (`/subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}`),
  `api-version` validation, the ARM error envelope, ARM-audience RS256 token
  validation against entra-emulator's JWKS (reuse the family validator).
- Subscriptions (seeded) + resource groups CRUD + tags.
- `Microsoft.Authorization/roleDefinitions` — the built-in Key Vault roles
  seeded with their **real role-definition GUIDs**.
- `Microsoft.Authorization/roleAssignments` — PUT/GET/DELETE/list at
  subscription, resource-group, resource, and child-object scopes, with scope
  inheritance on evaluation.
- **Assignment feed**: `GET /_family/authorization?scope=...` — a stable
  internal endpoint azure-keyvault-emulator polls (short TTL) to compile
  assignments onto its existing allowlist engine. (Azure's internal
  ARM→data-plane sync is not public wire, so the feed's shape is ours to
  choose; the *public* wire — ARM's REST — is exact.)

**P1 — Microsoft.KeyVault/vaults.**
- Vault resource CRUD; `properties.accessPolicies` (+ `updateAccessPolicy`
  operation), `enablePurgeProtection`, `enableRbacAuthorization` — fed to the
  data-plane emulator the same way.

**P2 — groups.**
- entra-emulator v0.3.0 ships seeded group memberships + `groups` claims;
  evaluation here matches assignments against oid OR group — the piece of
  real RBAC the family could not do at all before.

**P3 — the flagship witness + deployments.**
- `az cloud register` profile: the family becomes a first-class "cloud" the
  real CLI targets (`az login --service-principal` against entra-emulator,
  then `az role assignment create`, `az keyvault set-policy`).
- Later: `Microsoft.Resources/deployments` (template deployment) and
  `Microsoft.Fabric/capacities` when fabric-emulator integrates.

## Witnesses (the oracle, per the family discipline)

| Client | Kind |
|---|---|
| **`az` CLI** via a registered custom cloud — login, group create, role assignment create, set-policy | CI job (flagship) |
| Go `sdk/resourcemanager`: `armresources`, `armauthorization`, `armkeyvault` | in `go test` |
| Python `azure-mgmt-{resource,authorization,keyvault}` · JS `@azure/arm-*` · .NET `Azure.ResourceManager.*` | `e2e/sdk/run.py` matrix, 3 OSes |
| End-to-end family chain: ARM assignment → keyvault data-plane enforcement flip | CI chain job |

Every 🟢 parity claim names its witness in `docs/witnesses.json`, enforced by
a strict checker in CI — same as azure-keyvault-emulator.

## Clean-room grounding (pinned)

> `Azure/azure-rest-api-specs @ 0a6e8869` (2026-08-07) — sparse clone at
> `~/calvinchengx/azure-rest-api-specs`:
> `specification/{authorization,keyvault,resources}` — the OpenAPI ARM's own
> SDKs are generated from.
> [ARM REST reference](https://learn.microsoft.com/en-us/rest/api/resources/)
> and [Azure RBAC docs](https://learn.microsoft.com/en-us/azure/role-based-access-control/).

## Honest boundaries

PIM eligibility, deny assignments beyond storage, ABAC condition *evaluation*
(stored + returned verbatim first), cross-tenant, Azure Policy, activity log.
Declared in the parity map from day one, refusals faithful.

## Build discipline

Same as siblings: Go stdlib + modernc sqlite, controllable clock, ≥90%
coverage floor, GoReleaser (brew/winget/GHCR), Starlight docs site,
docker-compose slots into the family compose as the fourth service.
