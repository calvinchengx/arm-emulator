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

## Not every witness is equal evidence

`docs/witnesses.json` names each witness with its kind, and the kinds are
ranked deliberately:

| kind | what it means |
|---|---|
| `ci:<job>` | a CI job driving a real external client — a packaged release over a real network |
| `sdk:<Test>` | a Go test in which **Microsoft's own** client does the talking: `armresources`, `armauthorization`, `armkeyvault` over ARM's wire, in-process |
| `go:<Test>` | a Go test using our own client — real HTTP and real tokens, but our reading of the contract on both ends |
| `boundary:…` | the claim is scoped by a documented limitation |

`sdk:` was added after the vocabulary was found to be understating this repo.
`internal/server/sdk_test.go` has driven Microsoft's real management SDKs since
P0, but had no kind that fitted, so its tests were filed as `go:` — whose own
definition reads "our own client rather than a third party's". The checker
duly reported *witnessed by a real external client: 0*, and arm looked like the
family's thinnest evidence when it was only its worst-labelled. Eleven of the
seventeen green claims rest on Microsoft's clients.

What is still true, and is the honest remaining gap: `sdk:` runs in-process
against a `httptest` server. It proves the wire contract and the SDK's own
expectations, not that a packaged release behaves the same over a network — so
it ranks below `ci:`, and this repo has no `ci:` witness yet.
