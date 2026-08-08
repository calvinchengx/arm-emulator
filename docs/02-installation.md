# 02 — Installation

Every route ships the same single static binary — pure Go, no CGO, no runtime
dependency.

| Route | Command |
|---|---|
| Go | `go install github.com/calvinchengx/arm-emulator/cmd/arm-emulator@latest` |
| Homebrew | `brew install calvinchengx/tap/arm-emulator` |
| winget | `winget install calvinchengx.arm-emulator` |
| Docker | `docker run ghcr.io/calvinchengx/arm-emulator:latest` |
| Compose | `make up` (the pair: entra + arm) |
| Source | `go build ./cmd/arm-emulator` |

## Docker

The image is distroless and runs as nonroot. It has no shell, so the
container healthcheck runs the binary's own `healthcheck` subcommand.

```bash
docker run --rm -p 8445:8445 \
  -e ARM_ENTRA_ISSUER=https://host.docker.internal:8443/6f89cf12-978b-4d23-ac18-9ef0c127cf87/v2.0 \
  -e ARM_ENTRA_TLS_INSECURE=true \
  ghcr.io/calvinchengx/arm-emulator:latest
```

`ARM_DATA_DIR=/data` is baked in for callers who mount a volume there. Mount
nothing and SQLite cannot open its file — set `ARM_DATA_DIR=""` for a
throwaway in-memory run, which is what the compose file does.

## Compose

[`docker-compose.yml`](https://github.com/calvinchengx/arm-emulator/blob/main/docker-compose.yml)
brings up entra + arm with the trust between them pre-wired. Ports take
overrides so this stack can coexist with the other emulator families':

```bash
ENTRA_PORT=18443 ARM_PORT=18445 make up
```

## Checking the toolchain

```bash
make doctor   # what is missing, and how to get it
```
