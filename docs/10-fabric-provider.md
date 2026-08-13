# 10 — Microsoft.Fabric/capacities

Fabric capacities are **ARM resources**. The Fabric REST plane
(`api.fabric.microsoft.com`) only lists them and assigns workspaces; create,
SKU, suspend and resume happen on `management.azure.com`. This is that ARM
half. [fabric-emulator](https://github.com/calvinchengx/fabric-emulator)
consumes it over the family feed.

```
PUT    /subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Fabric/capacities/{name}
GET    …/capacities/{name}
PATCH  …/capacities/{name}
DELETE …/capacities/{name}
GET    …/capacities                       (by resource group)
GET    /subscriptions/{s}/providers/Microsoft.Fabric/capacities   (by subscription)
POST   …/capacities/{name}/suspend
POST   …/capacities/{name}/resume
GET    …/capacities/{name}/skus
GET    /subscriptions/{s}/providers/Microsoft.Fabric/skus
POST   /subscriptions/{s}/providers/Microsoft.Fabric/locations/{loc}/checkNameAvailability
GET    /subscriptions/{s}/providers/Microsoft.Fabric/locations/{loc}/usages
```

## Creation

A capacity must be created inside an existing resource group — creating into
a missing group returns `ResourceGroupNotFound`. The name is 3–63 lowercase
alphanumeric characters starting with a letter, as the REST reference
requires. `sku.name` is an F-series SKU (`F2`…`F2048`), `sku.tier` is
`Fabric`, and `properties.administration.members` is required.

Real ARM runs create, update, suspend, resume and delete as long-running
operations. The emulator answers with the same headers the SDKs poll
(`Azure-AsyncOperation` on PUT/PATCH, `Location` on DELETE/suspend/resume)
and completes them on the controllable clock. With the default zero delay
the first poll is already terminal, which is what `armfabric` and
`azure-mgmt-fabric` accept.

A new capacity is assigned a Fabric REST GUID at create. ARM's own document
does not carry it — Azure doesn't either — so it travels on the family feed
instead of being invented twice.

## What this does not do

SKU is an assignable label and a CU count for `list_usages`. There is no
billing, no job metering, and no throttling. `properties.overage` round-trips
(`Enabled`/`Disabled` and the threshold) and does nothing else.
`list_usages` reports **provisioned** F-SKU CU in the location, not consumed
compute: an F64 that has never run a notebook still counts as 64. A paused
capacity counts as zero.

That is the honest split: the ARM resource is real, the capacity *as a
compute bound* is still fabric-emulator's unbuilt job-queueing work.

## The family feed

```
GET /_family/capacities
```

Unauthenticated, like `/_family/authorization`. The document is every
capacity this process holds, with the Fabric REST `id`, the ARM resource id,
SKU, region, state and admins. fabric-emulator polls it and upserts those
rows into `GET /v1/capacities`.
