# 09 — Roadmap

Phases P0–P3 are shipped. What follows is driven by what the family's data
planes actually need — a provider arrives when a sibling needs it, not
speculatively.

## Shipped

- **P0** — the ARM envelope (resource-ID grammar, error shape, ARM-audience
  tokens, `api-version` validation, anonymous cloud discovery), subscriptions,
  resource groups, `Microsoft.Authorization` role definitions and assignments
  with scope inheritance, and the family feed.
- **P1** — `Microsoft.KeyVault/vaults` with the access-policy operation, and
  azure-keyvault-emulator consuming the feed.
- **P2** — group principals: a member reaches an assignment through the
  `groups` claim (needed entra-emulator v0.3.1's delegated Azure-resource
  carve-out).
- **P3** — the `az` CLI as the flagship witness, via `az cloud register`.
- **P5** — **custom role definitions**: real CRUD, with `assignableScopes`
  enforced on assignment and the definition's `dataActions` reaching the
  family feed. `az role definition create` writes them.
- **P4** — ARM's **asynchronous-operation protocol**, both shapes: `Location`
  polling for a group delete and `Azure-AsyncOperation` polling for a vault
  create, completing on the controllable clock. Microsoft's own pollers
  genuinely spin against it — held `InProgress`, released by advancing the
  clock — rather than shortcutting a terminal first response.

## Candidates

- **`Microsoft.Fabric/capacities`** — Fabric capacities are ARM resources, and
  `armfabric` exists as a real SDK witness. This is the natural next provider,
  waiting on fabric-emulator being free to consume it.
- **Template deployments** (`Microsoft.Resources/deployments`) — the engine
  behind `az deployment group create` and Bicep. A large piece; worth it only
  when something in the family wants to stand a stack up from a template.
- **ABAC condition evaluation** — conditions are stored and returned verbatim
  today; evaluating them is a real feature, not a shape.

## Not planned

Declared in the [parity map](parity.md) and meant to stay declared:
arbitrary resource providers, management groups and multi-subscription
topology, Azure Policy, Resource Graph, locks, and PIM. Each needs
infrastructure or directory state a localhost process cannot honestly hold.
