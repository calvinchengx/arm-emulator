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
  -e ARM_ENTRA_ISSUER=https://host.docker.internal:8443/11111111-1111-1111-1111-111111111111/v2.0 \
  -e ARM_ENTRA_TLS_INSECURE=true \
  ghcr.io/calvinchengx/arm-emulator:latest
```

`ARM_DATA_DIR=/data` is baked in, and `/data` is owned by the nonroot uid, so
mounting a volume there persists SQLite and the TLS cert across restarts:

```bash
docker run --rm -p 8445:8445 -v arm-data:/data \
  -e ARM_ENTRA_ISSUER=https://host.docker.internal:8443/11111111-1111-1111-1111-111111111111/v2.0 \
  ghcr.io/calvinchengx/arm-emulator:latest
```

Mount nothing and the state lands in an anonymous volume that outlives the
container. Set `ARM_DATA_DIR=""` for a throwaway in-memory run that leaves
nothing behind, which is what the compose file does.

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
