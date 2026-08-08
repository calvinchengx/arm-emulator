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
  -u 00d88624-f0d7-46f6-a641-6232c2608928 \
  -p daemon-app-secret \
  --tenant 6f89cf12-978b-4d23-ac18-9ef0c127cf87 \
  --allow-no-subscriptions

az group create --name my-rg --location westeurope
az keyvault create --name myvault --resource-group my-rg --location westeurope

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id <principal-oid> \
  --assignee-principal-type ServicePrincipal \
  --scope /subscriptions/6082bfda-63d0-46f4-8272-ae9195139feb/resourceGroups/my-rg/providers/Microsoft.KeyVault/vaults/myvault
```

Those are real ARM calls. The seeded values are entra-emulator's public dev
credentials — see [Configuration](04-configuration.md) to change them.

## Make it mean something

An assignment is only interesting if a data plane enforces it. Point
[azure-keyvault-emulator](https://github.com/calvinchengx/azure-keyvault-emulator)
at this emulator and it will:

```bash
azure-keyvault-emulator -arm-url https://localhost:8445 \
  -arm-subscription 6082bfda-63d0-46f4-8272-ae9195139feb \
  -arm-resource-group my-rg
```

Now the assignment above decides whether a secret read returns `200` or
`403` — and revoking it flips the answer back. That round trip is exercised
in CI; see [The family feed](07-family-feed.md).

## Without Docker

```bash
go install github.com/calvinchengx/arm-emulator/cmd/arm-emulator@latest
arm-emulator -entra-issuer https://localhost:8443/6f89cf12-978b-4d23-ac18-9ef0c127cf87/v2.0 \
             -entra-tls-insecure
```

More install routes in [Installation](02-installation.md).
