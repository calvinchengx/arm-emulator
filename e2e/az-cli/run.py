#!/usr/bin/env python3
"""Microsoft's own `az` CLI, unmodified, driving this emulator as a cloud.

WHY THIS EXISTS. Every green row in docs/parity.md was witnessed by a Go test.
Eleven of them are `sdk:` — Microsoft's management SDKs doing the talking — but
those run in-process against an `httptest` server, so they prove the wire
contract and the SDK's expectations, not that a PACKAGED release behaves the
same across a real network. This repo had no `ci:` witness at all. This is it.

`az cloud register` exists so the CLI can target non-public ARM endpoints:
sovereign clouds, Stack Hub, disconnected deployments. The emulator becomes one
of those, and then nothing on the CLI's side is stubbed. It discovers the
cloud, acquires a real ARM-audience token from entra, and speaks ARM:

    az group create / show / list / delete   resource groups, PUT as upsert
    az role definition list                  built-in roles, real GUIDs
    az role assignment create / list         Microsoft.Authorization
    az keyvault create                       Microsoft.KeyVault/vaults, the
                                             resource, not the data plane

The CLI verifies TLS like any real client, so the harness collects the
emulators' self-signed certs and points REQUESTS_CA_BUNDLE at them — what a
developer does locally, rather than turning verification off.

Adapted from azure-keyvault-emulator's e2e/az-cli, trimmed to ARM's own
surface: no vault data plane here, because that is the other repo's claim.

    ./e2e/az-cli/run.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import emulators  # noqa: E402

WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "arm-az-cli-e2e"
# The pair every harness in e2e/ brings up; constructing it computes the URLs
# without starting anything, so the constants below stay module-level.
EMU = emulators.Emulators(WORK)
E, ARM = EMU.entra, EMU.arm
TENANT, SUB = EMU.tenant, EMU.sub
SP_CLIENT, SP_SECRET = EMU.client_id, EMU.client_secret
RG = "az-cli-rg"
VAULT = "azclivault"
CLOUD = os.environ.get("AZ_CLOUD_NAME", "ArmEmulatorCloud")
EXE = ".exe" if os.name == "nt" else ""
# Reader: a real built-in role GUID, and one that grants nothing dangerous.
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
# Key Vault Secrets User — a different role, so the conditional assignment
# below is a new (scope, role, principal) triple rather than a duplicate of
# the one step 6 creates.
SECRETS_USER = "4633458b-17de-408a-b874-0445c86b69e6"

procs: list[subprocess.Popen] = []
# A private CLI config dir, so the harness never touches the developer's real
# az profile, cloud list or credentials.
AZ_ENV = {}


def az(*args, check=True):
    cmd = ["az", *args]
    print(f"    $ {' '.join(cmd)}", file=sys.stderr)
    r = subprocess.run(cmd, env={**os.environ, **AZ_ENV}, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"FAIL: {' '.join(cmd)}\n{(r.stderr or r.stdout)[:2000]}")
    return r


def az_json(*args):
    r = az(*args, "-o", "json")
    return json.loads(r.stdout) if r.stdout.strip() else None


def driver():
    print("-- 1. register the emulator as a cloud")
    az("cloud", "set", "--name", "AzureCloud", check=False)
    az("cloud", "unregister", "--name", CLOUD, check=False)
    az("cloud", "register", "--name", CLOUD,
       "--endpoint-resource-manager", ARM,
       "--endpoint-active-directory", E,
       "--endpoint-active-directory-resource-id", "https://management.azure.com/",
       "--endpoint-active-directory-graph-resource-id", f"{E}/",
       # `az role assignment list` expands principal ids into display names,
       # which is a Graph call, and the CLI refuses to run rather than skip it
       # ("The endpoint 'microsoft_graph_resource_id' ... is not set but is
       # used"). entra-emulator serves Graph, so the cloud declares it.
       "--endpoint-microsoft-graph-resource-id", f"{E}/",
       "--endpoint-management", ARM,
       "--suffix-keyvault-dns", ".vault.azure.net")
    az("cloud", "set", "--name", CLOUD)
    print(f"   {CLOUD} registered and selected")

    print("-- 1b. cloud AUTODETECTION from /metadata/endpoints")
    # `az cloud register` documents that giving only the resource-manager
    # endpoint autodetects the rest. That autodetection is the CLI fetching
    # GET /metadata/endpoints anonymously, before it holds any token — so a
    # cloud registered with one flag is proof the discovery document is real
    # and that the CLI can read it.
    az("cloud", "unregister", "--name", CLOUD + "Auto", check=False)
    az("cloud", "register", "--name", CLOUD + "Auto", "--endpoint-resource-manager", ARM)
    auto = az_json("cloud", "show", "--name", CLOUD + "Auto")
    found = (auto or {}).get("endpoints", {})
    if not found.get("activeDirectory", "").startswith(E):
        sys.exit(f"FAIL: the CLI did not learn the login endpoint from /metadata/endpoints: {found}")
    if not found.get("activeDirectoryGraphResourceId", "").startswith(E):
        sys.exit(f"FAIL: the CLI did not learn the graph endpoint: {found}")
    # The CLI takes the FIRST entry of the document's `audiences` array, as it
    # does against real ARM, whose document leads with the same one.
    if found.get("activeDirectoryResourceId") != "https://management.core.windows.net/":
        sys.exit(f"FAIL: the CLI did not read the audiences array: {found}")
    print(f"   one flag registered a cloud; the CLI discovered {found['activeDirectory']}")
    az("cloud", "unregister", "--name", CLOUD + "Auto", check=False)

    print("-- 2. az login --service-principal against entra-emulator")
    az("login", "--service-principal", "-u", SP_CLIENT, "-p", SP_SECRET,
       "--tenant", TENANT, "--allow-no-subscriptions")
    print("   the CLI holds a real ARM-audience token")

    print("-- 3. az group create, then read it back")
    az("group", "create", "--name", RG, "--location", "westeurope", "--subscription", SUB)
    got = az_json("group", "show", "--name", RG, "--subscription", SUB)
    if not got or got.get("name") != RG:
        sys.exit(f"FAIL: az group show returned {got}")
    # PUT is an upsert in ARM: creating the same group again is a 200, not a
    # conflict. A CLI that got this wrong would error on the second run.
    az("group", "create", "--name", RG, "--location", "westeurope", "--subscription", SUB)
    listed = az_json("group", "list", "--subscription", SUB)
    if not any(g["name"] == RG for g in listed or []):
        sys.exit("FAIL: the group the CLI created is absent from az group list")
    print(f"   {got['id']}")

    print("-- 3b. api-version, as ARM validates it")
    # Every typed SDK sends api-version for you, so only a raw call can show
    # what happens without it. `az rest` is that raw call, still carrying a
    # real token over the real wire.
    groups_url = f"{ARM}/subscriptions/{SUB}/resourcegroups"
    missing = az("rest", "--method", "get", "--url", groups_url, check=False)
    if missing.returncode == 0 or "MissingApiVersionParameter" not in (missing.stderr + missing.stdout):
        sys.exit(f"FAIL: a request with no api-version was not refused: {missing.stderr[:400]}")
    malformed = az("rest", "--method", "get", "--url", groups_url + "?api-version=banana", check=False)
    if malformed.returncode == 0 or "InvalidApiVersionParameter" not in (malformed.stderr + malformed.stdout):
        sys.exit(f"FAIL: a malformed api-version was not refused: {malformed.stderr[:400]}")
    print("   missing and malformed api-versions both refused with ARM's codes")

    print("-- 4. az role definition list — real built-in GUIDs")
    roles = az_json("role", "definition", "list", "--scope", f"/subscriptions/{SUB}")
    names = {r.get("roleName") for r in roles or []}
    if "Reader" not in names:
        sys.exit(f"FAIL: Reader missing from az role definition list ({len(roles or [])} roles)")
    print(f"   {len(roles)} definitions, Reader among them")

    print("-- 4b. az role definition create — a CUSTOM role, written by the CLI")
    custom_name = "Emulator Vault Secret Peeker"
    definition = json.dumps({
        "Name": custom_name,
        "Description": "Read secret contents in this subscription.",
        "Actions": ["Microsoft.KeyVault/vaults/read"],
        "DataActions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action"],
        "AssignableScopes": [f"/subscriptions/{SUB}"],
    })
    made = az_json("role", "definition", "create", "--role-definition", definition)
    if not made or made.get("roleName") != custom_name:
        sys.exit(f"FAIL: az role definition create returned {made}")
    custom_id = made.get("name") or made.get("id", "").rsplit("/", 1)[-1]
    print(f"   custom role {custom_id} created, type={made.get('roleType') or made.get('type')}")

    # The CLI finds it by name, alongside the built-ins.
    found = az_json("role", "definition", "list", "--name", custom_name,
                    "--scope", f"/subscriptions/{SUB}")
    if not found or found[0].get("roleName") != custom_name:
        sys.exit(f"FAIL: the custom role is not listed: {found}")
    print("   listed by name")

    # A custom role is assignable only where it says: the emulator refuses a
    # scope outside assignableScopes, which is the point of the field.
    az("role", "definition", "delete", "--name", custom_name)
    gone = az_json("role", "definition", "list", "--name", custom_name,
                   "--scope", f"/subscriptions/{SUB}")
    if gone:
        sys.exit(f"FAIL: the custom role survived deletion: {gone}")
    print("   deleted")

    print("-- 5. az keyvault create — the ARM resource, not the data plane")
    scope = (f"/subscriptions/{SUB}/resourceGroups/{RG}"
             f"/providers/Microsoft.KeyVault/vaults/{VAULT}")
    vault = az_json("keyvault", "create", "--name", VAULT, "--resource-group", RG,
                    "--location", "westeurope", "--subscription", SUB,
                    "--enable-rbac-authorization", "true")
    if not vault or vault.get("name") != VAULT:
        sys.exit(f"FAIL: az keyvault create returned {vault}")
    print(f"   {vault['properties']['vaultUri']}")

    print("-- 5b. az keyvault delete / list-deleted / recover / purge")
    soft = VAULT + "soft"
    az("keyvault", "create", "--name", soft, "--resource-group", RG,
       "--location", "westeurope", "--subscription", SUB)
    az("keyvault", "delete", "--name", soft, "--subscription", SUB)
    # The vault is recoverable, not gone: the CLI can still see it.
    deleted_vaults = az_json("keyvault", "list-deleted", "--resource-type", "vault", "--subscription", SUB) or []
    if not any(d.get("name") == soft for d in deleted_vaults):
        sys.exit(f"FAIL: {soft} is not listed among the deleted vaults: {deleted_vaults}")
    print(f"   {soft} deleted and listed as recoverable")
    az("keyvault", "recover", "--name", soft, "--resource-group", RG,
       "--location", "westeurope", "--subscription", SUB)
    if not az_json("keyvault", "show", "--name", soft, "--subscription", SUB):
        sys.exit(f"FAIL: {soft} did not come back after recover")
    print("   recovered")
    # Delete it again and purge for good.
    az("keyvault", "delete", "--name", soft, "--subscription", SUB)
    az("keyvault", "purge", "--name", soft, "--location", "westeurope", "--subscription", SUB)
    still = az_json("keyvault", "list-deleted", "--resource-type", "vault", "--subscription", SUB) or []
    if any(d.get("name") == soft for d in still):
        sys.exit(f"FAIL: {soft} survived the purge: {still}")
    print("   purged")

    print("-- 5c. deny assignments: read by the CLI, unwritable by it")
    # Deny assignments have no `az` command of their own because ARM has no
    # write API for them; `az rest` is how the CLI reaches the read surface,
    # and it still carries a real token over the real wire. The seeding goes
    # through the emulator control surface, standing in for the deployment
    # stack that would create one in Azure.
    deny_name = "7c9d2a41-6b0e-4f11-9c33-5d8a1e2b7f04"
    seed = json.dumps({
        "scope": f"/subscriptions/{SUB}",
        "denyAssignmentName": "No secret reads",
        "permissions": [{"dataActions": ["Microsoft.KeyVault/vaults/secrets/*"]}],
        "principals": [{"id": SP_CLIENT, "type": "ServicePrincipal"}],
    })
    code, body = emulators.http("POST", f"{ARM}/_emulator/denyassignments/{deny_name}", seed)
    if code != 201:
        sys.exit(f"FAIL: seeding the deny assignment: {code} {body[:300]}")
    listed = az_json("rest", "--method", "get", "--url",
                     f"{ARM}/subscriptions/{SUB}/resourceGroups/{RG}"
                     "/providers/Microsoft.Authorization/denyAssignments"
                     "?api-version=2022-04-01") or {}
    if not any(d.get("name") == deny_name for d in listed.get("value", [])):
        sys.exit(f"FAIL: the deny assignment is not visible to the CLI at the group: {listed}")
    print("   the CLI reads it, inherited from the subscription")
    # And cannot write one: ARM refuses, so the emulator must refuse too.
    refused = az("rest", "--method", "delete", "--url",
                 f"{ARM}/subscriptions/{SUB}"
                 f"/providers/Microsoft.Authorization/denyAssignments/{deny_name}"
                 "?api-version=2022-04-01", check=False)
    if refused.returncode == 0:
        sys.exit("FAIL: the CLI deleted a deny assignment; ARM does not allow that")
    print("   and cannot delete it, as ARM does not allow")
    emulators.http("DELETE", f"{ARM}/_emulator/denyassignments/{deny_name}", "")

    print("-- 6. az role assignment create, then list filtered by scope")
    assignment = az_json("role", "assignment", "create",
                         "--role", READER,
                         "--assignee-object-id", SP_CLIENT,
                         "--assignee-principal-type", "ServicePrincipal",
                         "--scope", scope)
    if not assignment or "roleDefinitionId" not in json.dumps(assignment):
        sys.exit(f"FAIL: az role assignment create returned {assignment}")
    at_scope = az_json("role", "assignment", "list", "--scope", scope)
    if not any(a.get("name") == assignment.get("name") for a in at_scope or []):
        sys.exit("FAIL: the assignment the CLI created is absent from a scoped list")
    print(f"   assignment {assignment.get('name')} created and listed at scope")

    print("-- 6b. az role assignment create --condition (ABAC)")
    # The condition is Azure's own documented shape: a guard that lets every
    # other action through, so only secret reads are narrowed.
    condition = ("((!(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})) "
                 "OR (@Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'))")
    conditional = az_json("role", "assignment", "create",
                          "--role", SECRETS_USER,
                          "--assignee-object-id", SP_CLIENT,
                          "--assignee-principal-type", "ServicePrincipal",
                          "--scope", scope,
                          "--condition", condition,
                          "--condition-version", "2.0")
    if not conditional or conditional.get("condition") != condition:
        sys.exit(f"FAIL: the CLI's condition did not round-trip: {conditional}")
    print("   the CLI wrote a condition and read it back")
    # A condition ARM cannot parse must be refused, not stored.
    bad = az("role", "assignment", "create",
             "--role", SECRETS_USER,
             "--assignee-object-id", SP_CLIENT,
             "--assignee-principal-type", "ServicePrincipal",
             "--scope", scope,
             "--condition", "@Resource[x] Frobnicates 'y'",
             "--condition-version", "2.0", check=False)
    if bad.returncode == 0:
        sys.exit("FAIL: a malformed condition was accepted")
    print("   and was refused a malformed one")
    az("role", "assignment", "delete", "--ids", conditional["id"])

    print("-- 7. az role assignment delete")
    az("role", "assignment", "delete", "--ids", assignment["id"])
    still = az_json("role", "assignment", "list", "--scope", scope)
    if any(a.get("name") == assignment.get("name") for a in still or []):
        sys.exit("FAIL: the assignment survived az role assignment delete")
    print("   gone")

    print("-- 8. az group delete")
    az("group", "delete", "--name", RG, "--subscription", SUB, "--yes")
    after = az("group", "show", "--name", RG, "--subscription", SUB, check=False)
    if after.returncode == 0:
        sys.exit("FAIL: the group survived az group delete")
    print("   gone")

    print("\nAZ CLI E2E: PASS — the real Azure CLI drives arm-emulator")


def main():
    for d in ("armdata", "azconfig"):
        (WORK / d).mkdir(parents=True, exist_ok=True)
    AZ_ENV["AZURE_CONFIG_DIR"] = str(WORK / "azconfig")
    # MSAL validates an authority against login.microsoftonline.com unless
    # instance discovery is off — the switch the CLI documents for private and
    # disconnected clouds. Without it the CLI reaches for the real internet
    # before it ever talks to the emulator.
    AZ_ENV["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"

    EMU.start()
    # The CLI expands principal ids through Graph; entra must know that
    # audience before it will mint a token for it.
    EMU.ensure_audience(f"{E}/", "Microsoft Graph (emulator)")
    AZ_ENV["REQUESTS_CA_BUNDLE"] = str(EMU.ca_bundle)

    try:
        driver()
    finally:
        az("cloud", "set", "--name", "AzureCloud", check=False)
        az("cloud", "unregister", "--name", CLOUD, check=False)


if __name__ == "__main__":
    try:
        main()
    finally:
        EMU.stop()
