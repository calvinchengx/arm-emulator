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

**Working** — the ARM envelope (resource-ID grammar, error shape,
ARM-audience tokens, anonymous cloud discovery), subscriptions and resource
groups, `Microsoft.Authorization` role definitions and assignments with real
scope inheritance, and `Microsoft.KeyVault/vaults` with access policies.
Microsoft's own clients drive it unmodified — the **`az` CLI** via
`az cloud register`, and the `armresources` / `armauthorization` /
`armkeyvault` SDKs — and the assignments it stores are enforced by
azure-keyvault-emulator's data plane. 98%+ coverage with a CI floor; every
green parity claim names its witness.

Install: `go install github.com/calvinchengx/arm-emulator/cmd/arm-emulator@latest`,
`brew install calvinchengx/tap/arm-emulator`,
`winget install calvinchengx.arm-emulator`, or the
`ghcr.io/calvinchengx/arm-emulator` image (see
[`docker-compose.yml`](docker-compose.yml) for the entra-emulator pairing).

```bash
make up       # entra-emulator + arm-emulator
make status   # is the pair actually usable?
make doctor   # what is missing from the toolchain?
```

See [docs/01-design.md](docs/01-design.md) for the scope and phases, and
[docs/parity.md](docs/parity.md) for what is real versus emulated.

## License

Apache-2.0. Clean-room: grounded solely in Microsoft's public documentation
and the pinned [`Azure/azure-rest-api-specs`](https://github.com/Azure/azure-rest-api-specs)
OpenAPI specifications, with Microsoft's own management clients as the
conformance oracle — no Microsoft source.
