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
  duplicate conflict), `armkeyvault` (vault CRUD, access-policy add and
  remove) and `armfabric` (capacity CRUD, suspend/resume, check-name,
  `list_usages`) — all against an in-process real entra-emulator.
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
family's thinnest evidence when it was only its worst-labelled.

Every green claim now names at least one `ci:` or `sdk:` witness — nothing
rests on our own reading of the contract at both ends. Four independent client
stacks drive the emulator: Microsoft's Go SDKs in-process, the packaged `az`
CLI over a network, and the Python, JavaScript and .NET management SDKs
(`e2e/sdks/run.py`, CI job `sdks`).

The fourth stack is not redundancy. An emulator that only ever meets one SDK
gets shaped by that SDK's habits, and the tests keep passing because nothing
else looks. Writing the three new harnesses found two real defects that Go had
no way to see:

- Microsoft's **JavaScript** clients join their endpoint to an ARM scope
  without normalizing, so every request begins `//subscriptions/…`. `ServeMux`
  answered with a 301 to the clean path, and a client following it drops its
  `Authorization` header — an authenticated request arrived anonymous and came
  back 401. Real ARM serves the doubled slash, and now so does this emulator.
- The emulator's self-signed certificate was valid for **ten years**. Apple
  refuses to trust any TLS server certificate over 825 days, so no .NET client
  on macOS could verify it even when the developer deliberately trusted the
  file. It is 397 days now, and a unit test fails if that creeps back up.

Both are pinned by Go tests as well, so the regression is caught in seconds
rather than only by the cross-language job.
