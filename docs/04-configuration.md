# 04 — Configuration

Every setting is an `ARM_*` environment variable with a flag override. The
compose contract (`ARM_ENTRA_ISSUER`, `ARM_ENTRA_TLS_INSECURE`) is the
canonical wiring to entra-emulator, matching the sibling emulators.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--addr` | `ARM_ADDR` | `:8445` | Listen address. |
| `--data-dir` | `ARM_DATA_DIR` | *(empty)* | State directory (SQLite + persisted TLS cert). Empty = in-memory DB and ephemeral TLS keys. |
| `--entra-issuer` | `ARM_ENTRA_ISSUER` | *(required)* | The exact `iss` bearer tokens must carry. A comma-separated list trusts several issuers, each validated against its own JWKS. |
| `--entra-jwks-url` | `ARM_ENTRA_JWKS_URL` | *(derived)* | Where signing keys are fetched; derived from the issuer when unset. |
| `--entra-tls-insecure` | `ARM_ENTRA_TLS_INSECURE` | `false` | Skip TLS verification fetching JWKS — for a sibling emulator's self-signed cert. |
| `--subscription-id` | `ARM_SUBSCRIPTION_ID` | `6082bfda-…-9feb` | The seeded subscription every resource lives under. |
| `--tenant-id` | `ARM_TENANT_ID` | `6f89cf12-…-cf87` | Reported by `/tenants` and on subscription resources. |
| `--disable-tls` | `ARM_DISABLE_TLS` | `false` | Serve plain HTTP (behind a terminating proxy, or for curl). |
| `--lro-delay` | `ARM_LRO_DELAY_SECONDS` | `0` | Virtual seconds an asynchronous operation stays `InProgress`. Zero still walks the whole protocol — the operation is simply terminal on its first poll, so CI never waits. Raise it to watch a real SDK poller spin. |
| `--retry-after` | `ARM_RETRY_AFTER_SECONDS` | `1` | Advertised in `Retry-After` on `202`s and in-progress polls. |

Asynchronous operations complete on the **controllable clock**, not a timer:
with a delay set, `POST /_emulator/clock {"advance": N}` is what finishes
them, so a test can hold a poller in flight and release it deterministically
with no sleeps. See [08-testing.md](08-testing.md).

### Default IDs changed in v0.2.0 (breaking)

The defaults were patterned placeholders; they are still fixed, only the values changed.

| Setting | Old | New |
|---|---|---|
| `ARM_SUBSCRIPTION_ID` | `00000000-0000-0000-0000-000000000001` | `6082bfda-63d0-46f4-8272-ae9195139feb` |
| `ARM_TENANT_ID` | `11111111-1111-1111-1111-111111111111` | `6f89cf12-978b-4d23-ac18-9ef0c127cf87` |

The tenant must match `entra-emulator` v0.4.0+, whose seeded tenant moved to the same
value — the quickstart's client-credentials exchange fails if the two disagree. Azure
built-in role definition IDs (Owner, Contributor, Reader, the Key Vault roles) are real
Azure identifiers and are unchanged.

## What is validated

`Finish()` refuses to start on a configuration that cannot work: a missing or
non-URL issuer, or an empty subscription id. Failing at startup beats serving
requests that can never authenticate.

## Emulator-only control surface

Neither of these exists in real ARM; they exist so tests are deterministic.

```bash
# Freeze, offset or advance the clock — token expiry becomes reproducible.
curl -sk -X POST https://localhost:8445/_emulator/clock -d '{"freeze":true}'
curl -sk -X POST https://localhost:8445/_emulator/clock -d '{"advance":3600}'

# Force the next N requests to 429 (with Retry-After) or 500, to exercise
# an SDK's retry path.
curl -sk -X POST https://localhost:8445/_emulator/faults -d '{"throttleNextRequests":1}'
curl -sk -X POST https://localhost:8445/_emulator/faults -d '{"rejectNextRequests":1}'
```
