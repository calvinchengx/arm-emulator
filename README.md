# arm-emulator

[![version](https://img.shields.io/github/v/release/calvinchengx/arm-emulator?label=version)](https://github.com/calvinchengx/arm-emulator/releases/latest)
[![CI](https://github.com/calvinchengx/arm-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/calvinchengx/arm-emulator/actions/workflows/ci.yml)
[![Docs](https://github.com/calvinchengx/arm-emulator/actions/workflows/docs-site.yml/badge.svg)](https://calvinchengx.github.io/arm-emulator/)
[![CodeQL](https://github.com/calvinchengx/arm-emulator/actions/workflows/codeql.yml/badge.svg)](https://github.com/calvinchengx/arm-emulator/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

[![go coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fcalvinchengx.github.io%2Farm-emulator%2Fcoverage-go.json)](https://calvinchengx.github.io/arm-emulator/08-testing/)
[![parity claims witnessed](https://img.shields.io/endpoint?url=https%3A%2F%2Fcalvinchengx.github.io%2Farm-emulator%2Fwitnesses.json)](https://calvinchengx.github.io/arm-emulator/parity/)

> Coverage measures the **unit** suites. What catches consumer-facing defects
> is the real-client fleet — the `az` CLI and the management SDKs — which no
> percentage scores; hence *parity claims witnessed* beside it: every claim of
> support names a test that exists and ran.

A clean-room, local emulator of the **Azure Resource Manager control plane**
(`management.azure.com`), scoped to what its sibling data planes need, part
of an emulator family built on one principle: **the same trust
relationships as production**.

- [entra-emulator](https://github.com/calvinchengx/entra-emulator) — the STS:
  issues the tokens (including `aud: https://management.azure.com`).
- **arm-emulator** — the management plane: subscriptions, resource groups,
  **role assignments** (`Microsoft.Authorization`), vault resources
  (`Microsoft.KeyVault/vaults` access policies), and Fabric capacities
  (`Microsoft.Fabric/capacities`).
- [azure-keyvault-emulator](https://github.com/calvinchengx/azure-keyvault-emulator)
  — the data plane that **enforces** those assignments on every request.
- [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) — consumes
  `Microsoft.Fabric/capacities` over the family feed.

The point: `az role assignment create` and Microsoft's real management SDKs
(`armauthorization`, `azure-mgmt-authorization`, `@azure/arm-authorization`,
`Azure.ResourceManager`) run **unmodified** against this emulator, and the
assignments they write are genuinely enforced by the Key Vault data plane —
closing the last emulated gap in the family's authorization story.

## Status

**Working** — the ARM envelope (resource-ID grammar, error shape,
ARM-audience tokens, anonymous cloud discovery), subscriptions and resource
groups, `Microsoft.Authorization` role definitions and assignments with real
scope inheritance, `Microsoft.KeyVault/vaults` with access policies, and
`Microsoft.Fabric/capacities`. Microsoft's own clients drive it unmodified —
the **`az` CLI** via `az cloud register`, and the `armresources` /
`armauthorization` / `armkeyvault` / `armfabric` SDKs — and the assignments
it stores are enforced by azure-keyvault-emulator's data plane. 98%+ coverage
with a CI floor; every green parity claim names its witness.

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

Docs: <https://calvinchengx.github.io/arm-emulator/> — start with the
[Quickstart](docs/01-quickstart.md), then [Architecture](docs/03-architecture.md),
[Authorization](docs/05-authorization.md),
[Microsoft.Fabric](docs/10-fabric-provider.md) and
[The family feed](docs/07-family-feed.md). What is real versus emulated is in
the [parity map](docs/parity.md).

## Emulator family

`arm-emulator` is the ARM control plane. Its siblings are `entra-emulator` (the
STS whose tokens this one validates), `azure-keyvault-emulator`,
`fabric-emulator`, `azure-apim-emulator` and `databricks-emulator`.

To run them together, see [**azure-emulators**](https://github.com/calvinchengx/azure-emulators): a composition-only repo
holding the family `docker-compose.yml`, the shared issuer wiring, and the
pinned image versions the members are tested against.

## License

Apache-2.0. Clean-room: grounded solely in Microsoft's public documentation
and the pinned [`Azure/azure-rest-api-specs`](https://github.com/Azure/azure-rest-api-specs)
OpenAPI specifications, with Microsoft's own management clients as the
conformance oracle — no Microsoft source.
