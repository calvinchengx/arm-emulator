#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "azure-identity==1.25.3",
#     "azure-mgmt-resource==26.0.0",
#     "azure-mgmt-authorization==4.0.0",
#     "azure-mgmt-fabric==1.1.0b1",
# ]
# ///
"""Microsoft's Python management SDKs driving arm-emulator.

WHY A SECOND LANGUAGE. The Go SDKs already witness most of this repo, and the
`az` CLI witnesses it over a real network. Both are worth having, but they
share a failure mode: an emulator can drift into being shaped by ONE client's
expectations — a header only that client reads, a JSON shape only its
deserializer tolerates — and the tests keep passing because nothing else ever
looks. A different vendor stack, with its own transport, its own token cache
and its own deserializer, is the check that catches that.

Nothing here is emulator-specific beyond configuration real Azure supports:
`base_url` and `credential_scopes` are how these clients target a sovereign or
disconnected cloud, and `authority` + `disable_instance_discovery` are how
azure-identity is pointed at a login endpoint that is not the public one.

Run standalone (it starts nothing itself — see e2e/sdks/run.py):

    ARM_URL=… ENTRA_URL=… ./main.py
"""

import os
import sys

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.fabric import FabricMgmtClient
from azure.mgmt.resource.resources import ResourceManagementClient

ARM = os.environ["ARM_URL"]
ENTRA = os.environ["ENTRA_URL"]
TENANT = os.environ["ARM_TENANT_ID"]
SUB = os.environ["ARM_SUBSCRIPTION_ID"]
CLIENT_ID = os.environ["ARM_CLIENT_ID"]
CLIENT_SECRET = os.environ["ARM_CLIENT_SECRET"]

SCOPES = ["https://management.azure.com/.default"]
# The multi-API client's models for the api-version its default profile pins,
# rather than importing a versioned subpackage by hand.
MODELS = AuthorizationManagementClient.models()
RG = "python-sdk-rg"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
SECRETS_USER = "4633458b-17de-408a-b874-0445c86b69e6"
CONDITION = ("((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) "
             "OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))")


def fail(msg):
    sys.exit(f"FAIL (python): {msg}")


def main():
    # TLS is verified: REQUESTS_CA_BUNDLE / SSL_CERT_FILE point at the
    # emulator's certificate, set by the runner before this process starts.
    credential = ClientSecretCredential(
        tenant_id=TENANT, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
        authority=ENTRA,
        # MSAL otherwise asks login.microsoftonline.com whether this authority
        # is real — the switch every private-cloud deployment sets.
        disable_instance_discovery=True,
    )

    print("-- 1. a real ARM-audience token from entra-emulator")
    token = credential.get_token(*SCOPES)
    if not token.token:
        fail("no token")
    print("   acquired")

    resources = ResourceManagementClient(
        credential, SUB, base_url=ARM, credential_scopes=SCOPES)
    authorization = AuthorizationManagementClient(
        credential, SUB, base_url=ARM, credential_scopes=SCOPES)

    print("-- 2. resource groups: create, get, list")
    made = resources.resource_groups.create_or_update(
        RG, {"location": "westeurope", "tags": {"harness": "python"}})
    if made.name != RG or made.tags.get("harness") != "python":
        fail(f"create_or_update returned {made}")
    got = resources.resource_groups.get(RG)
    if got.location != "westeurope":
        fail(f"get returned {got}")
    if not any(g.name == RG for g in resources.resource_groups.list()):
        fail("the group is missing from the list")
    print(f"   {made.id}")

    print("-- 3. the ARM error envelope, as this SDK parses it")
    try:
        resources.resource_groups.get("no-such-group-here")
        fail("a missing group was not an error")
    except HttpResponseError as e:
        if e.status_code != 404 or e.error is None or e.error.code != "ResourceGroupNotFound":
            fail(f"error envelope = {e.status_code} {getattr(e.error, 'code', None)}")
    print("   ResourceGroupNotFound, typed")

    print("-- 4. role definitions: list with $filter, by real GUID")
    scope = f"/subscriptions/{SUB}"
    found = list(authorization.role_definitions.list(
        scope, filter="roleName eq 'Key Vault Secrets User'"))
    if len(found) != 1 or found[0].name != SECRETS_USER:
        fail(f"$filter returned {[d.role_name for d in found]}")
    if not found[0].permissions or not found[0].permissions[0].data_actions:
        fail("the role arrived with no dataActions")
    print(f"   {found[0].role_name} = {found[0].name}")

    print("-- 5. role assignments: create, read back, delete")
    name = "0d7f8b21-4c3a-4e55-9a1b-2c3d4e5f6a7b"
    role_id = f"{scope}/providers/Microsoft.Authorization/roleDefinitions/{READER}"
    created = authorization.role_assignments.create(
        scope, name, MODELS.RoleAssignmentCreateParameters(
            role_definition_id=role_id, principal_id=CLIENT_ID,
            principal_type="ServicePrincipal"))
    if created.name != name:
        fail(f"create returned {created}")
    if authorization.role_assignments.get(scope, name).principal_id.lower() != CLIENT_ID.lower():
        fail("the assignment did not read back")
    print(f"   {created.id}")

    print("-- 6. an ABAC condition, written and refused")
    conditional = "1e8f9c32-5d4b-4f66-8b2c-3d4e5f6a7b8c"
    with_condition = authorization.role_assignments.create(
        scope, conditional, MODELS.RoleAssignmentCreateParameters(
            role_definition_id=(f"{scope}/providers/Microsoft.Authorization"
                                f"/roleDefinitions/{SECRETS_USER}"),
            principal_id=CLIENT_ID, principal_type="ServicePrincipal",
            condition=CONDITION, condition_version="2.0"))
    if with_condition.condition != CONDITION:
        fail(f"the condition did not round-trip: {with_condition.condition!r}")
    try:
        authorization.role_assignments.create(
            scope, "2f9a0d43-6e5c-4a77-9c3d-4e5f6a7b8c9d",
            MODELS.RoleAssignmentCreateParameters(
                role_definition_id=(f"{scope}/providers/Microsoft.Authorization"
                                    f"/roleDefinitions/{SECRETS_USER}"),
                principal_id=CLIENT_ID,
                condition="@Resource[x] Frobnicates 'y'", condition_version="2.0"))
        fail("a malformed condition was accepted")
    except HttpResponseError as e:
        if e.error is None or e.error.code != "InvalidCondition":
            fail(f"malformed condition refused as {getattr(e.error, 'code', None)}")
    print("   round-tripped, and a malformed one refused with InvalidCondition")

    print("-- 7. a garbage token is challenged")
    # A credential that hands over nonsense: the 401 and its WWW-Authenticate
    # challenge have to be recognised by THIS stack too, not only by Go's.
    class BadCredential:
        def get_token(self, *scopes, **kwargs):
            from azure.core.credentials import AccessToken
            import time as _t
            return AccessToken("not-a-real-token", int(_t.time()) + 3600)

    rejected = ResourceManagementClient(
        BadCredential(), SUB, base_url=ARM, credential_scopes=SCOPES)
    try:
        rejected.resource_groups.get(RG)
        fail("a garbage token was accepted")
    except (HttpResponseError, ClientAuthenticationError) as e:
        status = getattr(e, "status_code", None)
        if status != 401:
            fail(f"garbage token produced {status}: {e}")
    print("   401, as ARM challenges")

    print("-- 8. Microsoft.Fabric/capacities via azure-mgmt-fabric")
    fabric = FabricMgmtClient(
        credential, SUB, base_url=ARM, credential_scopes=SCOPES)
    cap_name = "pythonsdkcap"
    avail = fabric.fabric_capacities.check_name_availability(
        "westeurope", {"name": cap_name, "type": "Microsoft.Fabric/capacities"})
    if not avail.name_available:
        fail(f"check_name_availability = {avail}")
    created = fabric.fabric_capacities.begin_create_or_update(
        RG, cap_name, {
            "location": "westeurope",
            "sku": {"name": "F2", "tier": "Fabric"},
            "properties": {
                "administration": {"members": ["python-sdk@example.com"]},
                "overage": {"state": "Enabled", "thresholdCapacityUnitHours": 4},
            },
        }).result()
    if created.name != cap_name:
        fail(f"create capacity returned {created}")
    got = fabric.fabric_capacities.get(RG, cap_name)
    if got.sku.name != "F2" or got.properties.state != "Active":
        fail(f"get capacity = {got.sku} {got.properties}")
    if got.properties.overage is None or got.properties.overage.state != "Enabled":
        fail(f"overage did not round-trip: {got.properties.overage}")
    names = [c.name for c in fabric.fabric_capacities.list_by_resource_group(RG)]
    if cap_name not in names:
        fail(f"capacity missing from list: {names}")
    usages = list(fabric.fabric_capacities.list_usages("westeurope"))
    if not usages or usages[0].current_value != 2:
        fail(f"list_usages = {usages}")
    fabric.fabric_capacities.begin_delete(RG, cap_name).result()
    print(f"   {created.id}")

    print("-- 9. cleanup: delete the assignments and the group")
    authorization.role_assignments.delete(scope, name)
    authorization.role_assignments.delete(scope, conditional)
    resources.resource_groups.begin_delete(RG).result()
    try:
        resources.resource_groups.get(RG)
        fail("the group survived its delete")
    except HttpResponseError:
        pass
    print("   gone")

    print("\nPYTHON SDK E2E: PASS — azure-mgmt-resource, "
          "azure-mgmt-authorization and azure-mgmt-fabric drive arm-emulator")


if __name__ == "__main__":
    main()
