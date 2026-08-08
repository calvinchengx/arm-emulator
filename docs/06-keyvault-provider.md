# 06 — Microsoft.KeyVault

The vault resource itself: where access policies, purge protection and the
RBAC-authorization switch are configured in real Azure — and therefore where
azure-keyvault-emulator's data plane gets them from.

```
PUT    /subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}
GET    …/vaults/{name}
DELETE …/vaults/{name}
GET    …/vaults                       (by resource group)
GET    /subscriptions/{s}/providers/Microsoft.KeyVault/vaults   (by subscription)
PUT    …/vaults/{name}/accessPolicies/{add|replace|remove}
```

## Creation

A vault must be created inside an existing resource group, as ARM requires —
creating into a missing group returns `ResourceGroupNotFound`. The response
fills in `vaultUri` (`https://{name}.vault.azure.net/`) and a terminal
`provisioningState`, which is the shape SDK pollers accept.

Real ARM runs vault creation as a long-running operation. The emulator
completes it inline and answers `200`; `armkeyvault`'s
`BeginCreateOrUpdate(...).PollUntilDone(...)` is satisfied by that, which is
the behaviour that matters.

## Access policies

The `accessPolicies/{operationKind}` operation is what `az keyvault set-policy`
and `az keyvault delete-policy` call:

| Kind | Behaviour |
|---|---|
| `add` | Merges each entry, replacing an existing entry with the same `objectId` |
| `replace` | Swaps the whole list (a null list clears it) |
| `remove` | Drops the named `objectId`s |

Object ids match case-insensitively. The operation echoes the resulting policy
list, not the whole vault — as the real operation does.

## The either/or that matters

`enableRbacAuthorization` decides which authorization model a vault uses. When
it is on, **access policies are ignored** and only role assignments count —
exactly as real Key Vault behaves. The family feed reports both the policies
and the flag so the data plane can honour the same rule; a test asserts a
policy is dropped in RBAC mode.

`enablePurgeProtection` and the soft-delete settings round-trip and are read
by the data plane the same way.
