# arm-emulator

A clean-room, local emulator of the **Azure Resource Manager control plane**
(`management.azure.com`), scoped to what its sibling data planes need — the
fourth member of an emulator family built on one principle: **the same trust
relationships as production**.

- [entra-emulator](https://github.com/calvinchengx/entra-emulator) — the STS:
  issues the tokens (including `aud: https://management.azure.com`).
- **arm-emulator** — the management plane: subscriptions, resource groups,
  **role assignments** (`Microsoft.Authorization`), and vault resources
  (`Microsoft.KeyVault/vaults` access policies).
- [azure-keyvault-emulator](https://github.com/calvinchengx/azure-keyvault-emulator)
  — the data plane that **enforces** those assignments on every request.
- [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) — future
  consumer (`Microsoft.Fabric/capacities`).

The point: `az role assignment create` and Microsoft's real management SDKs
(`armauthorization`, `azure-mgmt-authorization`, `@azure/arm-authorization`,
`Azure.ResourceManager`) run **unmodified** against this emulator, and the
assignments they write are genuinely enforced by the Key Vault data plane —
closing the last emulated gap in the family's authorization story.

## Status

**Design phase.** See [docs/01-design.md](docs/01-design.md) for the scope,
phases, witness plan, and honest boundaries.

## License

Apache-2.0. Clean-room: grounded solely in Microsoft's public documentation
and the pinned [`Azure/azure-rest-api-specs`](https://github.com/Azure/azure-rest-api-specs)
OpenAPI specifications, with Microsoft's own management clients as the
conformance oracle — no Microsoft source.
