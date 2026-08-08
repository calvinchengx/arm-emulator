# 01 — Quickstart

Bring up the management plane and its STS, register the pair with the real
`az` CLI, and make a role assignment that a data plane will actually enforce.

## Start the pair

```bash
make up       # entra-emulator :8443 + arm-emulator :8445
make status   # is the pair actually usable?
```

`make status` is the honest check: it verifies both containers are healthy,
that the 401 challenge names the seeded tenant, and that cloud discovery
answers — the three things every Azure client depends on before it can do
anything.

## Register it as a cloud

`az cloud register` exists so the CLI can target non-public ARM endpoints
(sovereign clouds, Stack Hub). The emulator family becomes one of those:

```bash
az cloud register --name EmulatorCloud \
  --endpoint-resource-manager https://localhost:8445 \
  --endpoint-active-directory https://localhost:8443 \
  --endpoint-active-directory-resource-id https://management.azure.com/ \
  --suffix-keyvault-dns .vault.azure.net
az cloud set --name EmulatorCloud

# Private cloud: skip MSAL's login.microsoftonline.com probe.
az config set core.instance_discovery=false
# The CLI verifies TLS like any client; trust the emulators' certificates.
export REQUESTS_CA_BUNDLE=/path/to/emulator-certs.pem
```

## Sign in and use it

```bash
az login --service-principal \
  -u cccccccc-0000-0000-0000-000000000002 \
  -p daemon-app-secret \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --allow-no-subscriptions

az group create --name my-rg --location westeurope
az keyvault create --name myvault --resource-group my-rg --location westeurope

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id <principal-oid> \
  --assignee-principal-type ServicePrincipal \
  --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/my-rg/providers/Microsoft.KeyVault/vaults/myvault
```

Those are real ARM calls. The seeded values are entra-emulator's public dev
credentials — see [Configuration](04-configuration.md) to change them.

## Make it mean something

An assignment is only interesting if a data plane enforces it. Point
[azure-keyvault-emulator](https://github.com/calvinchengx/azure-keyvault-emulator)
at this emulator and it will:

```bash
azure-keyvault-emulator -arm-url https://localhost:8445 \
  -arm-subscription 00000000-0000-0000-0000-000000000001 \
  -arm-resource-group my-rg
```

Now the assignment above decides whether a secret read returns `200` or
`403` — and revoking it flips the answer back. That round trip is exercised
in CI; see [The family feed](07-family-feed.md).

## Without Docker

```bash
go install github.com/calvinchengx/arm-emulator/cmd/arm-emulator@latest
arm-emulator -entra-issuer https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0 \
             -entra-tls-insecure
```

More install routes in [Installation](02-installation.md).
