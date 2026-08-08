# 08 — Testing against this emulator

## Deterministic time and injected faults

Token expiry and retry behaviour are otherwise untestable offline:

```bash
curl -sk -X POST https://localhost:8445/_emulator/clock -d '{"freeze":true}'
curl -sk -X POST https://localhost:8445/_emulator/clock -d '{"advance":7200}'
curl -sk -X POST https://localhost:8445/_emulator/faults -d '{"throttleNextRequests":2}'
```

## Pointing an SDK at it

The management SDKs take a cloud configuration. In Go:

```go
cloudCfg := cloud.Configuration{
    ActiveDirectoryAuthorityHost: entraOrigin,
    Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
        cloud.ResourceManager: {Endpoint: armURL, Audience: "https://management.azure.com"},
    },
}
```

That is the same mechanism a sovereign cloud uses — no SDK patching. The
equivalent for the CLI is `az cloud register`; see the
[Quickstart](01-quickstart.md).

## What the project itself verifies

- **Real management SDKs** in `go test`: `armresources` (resource groups),
  `armauthorization` (role definitions, assignments, inheritance, `atScope()`,
  duplicate conflict) and `armkeyvault` (vault CRUD, access-policy add and
  remove) — all against an in-process real entra-emulator.
- **The `az` CLI**, unmodified, driving the family as a registered cloud
  (in azure-keyvault-emulator's CI).
- **The authorization chain**: an ARM assignment flipping a data plane's
  answer, and back on revocation.
- **A 98% coverage floor** in CI, on Linux, macOS and Windows.
- **Every 🟢 parity claim names its witness**, enforced by
  `scripts/check_witnesses.py --strict`.

## The coverage honesty note

The coverage number describes the unit and in-process suites. What catches
consumer-facing defects is the witness fleet — real Microsoft clients driving
real wire — which no percentage scores. That is why the badges show
*claims witnessed* beside coverage: "every claim of support names a test that
ran" is a stronger statement than any percentage, and the two measure
different things.
