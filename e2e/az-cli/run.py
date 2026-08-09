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
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "arm-az-cli-e2e"
ENTRA_PORT = int(os.environ.get("ENTRA_PORT", "18943"))
ARM_PORT = int(os.environ.get("ARM_PORT", "18945"))
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.4.1")

E = f"https://localhost:{ENTRA_PORT}"
ARM = f"https://localhost:{ARM_PORT}"
ISSUER = f"{E}/{TENANT}/v2.0"
SUB = "6082bfda-63d0-46f4-8272-ae9195139feb"
RG = "az-cli-rg"
VAULT = "azclivault"
CLOUD = os.environ.get("AZ_CLOUD_NAME", "ArmEmulatorCloud")
EXE = ".exe" if os.name == "nt" else ""
# Reader: a real built-in role GUID, and one that grants nothing dangerous.
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE

procs: list[subprocess.Popen] = []
# A private CLI config dir, so the harness never touches the developer's real
# az profile, cloud list or credentials.
AZ_ENV = {}


def ensure_audience(audience, name):
    """Register a resource app in entra so tokens for `audience` can be minted.

    A no-op against real Azure: Microsoft Graph is a first-party resource every
    tenant can already request. entra-emulator mints only for audiences it
    knows, so a non-default one is registered first — a setup difference, the
    same one keyvault's harness handles.
    """
    body = json.dumps({"displayName": name, "appIdUri": audience,
                       "isConfidential": False}).encode()
    req = urllib.request.Request(f"{E}/admin/api/apps", method="POST", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        # 409 means it is already there, which is the normal case on a re-run.
        if e.code == 409:
            return e.code
        sys.exit(f"FAIL: registering {audience}: {e.code} {e.read()[:300]}")


def http(method, url):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, b""


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


def build_entra():
    """Prefer a sibling checkout so the family develops together."""
    repo = Path(os.environ.get("ENTRA_EMULATOR_REPO", REPO.parent / "entra-emulator"))
    out = WORK / ("entra-emulator" + EXE)
    env = {**os.environ, "GOTOOLCHAIN": "auto"}
    if (repo / "go.mod").exists():
        subprocess.run(["go", "build", "-C", str(repo), "-o", str(out),
                        "./cmd/entra-emulator"], check=True, env=env)
        return out
    subprocess.run(["go", "install",
                    f"github.com/calvinchengx/entra-emulator/cmd/entra-emulator@{ENTRA_VERSION}"],
                   check=True, env={**env, "GOBIN": str(WORK)})
    return out


def start(name, argv, env_extra=None):
    log = open(WORK / f"{name}.log", "w")
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         env={**os.environ, **(env_extra or {})})
    procs.append(p)
    return p


def wait_healthy():
    deadline = time.time() + 40
    while time.time() < deadline:
        if all(http("GET", f"{b}/health")[0] == 200 for b in (E, ARM)):
            return
        time.sleep(0.3)
    for n in ("entra", "arm"):
        log = WORK / f"{n}.log"
        if log.exists():
            print(f"---- {n}.log ----\n{log.read_text()}", file=sys.stderr)
    sys.exit("emulators did not become healthy in time")


def collect_ca():
    """One bundle the CLI trusts. Self-signed certs are their own CA."""
    bundle = WORK / "emulator-ca.pem"
    pems = []
    for sub in ("entra-tls/cert.pem", "armdata/tls/cert.pem"):
        p = WORK / sub
        if p.exists():
            pems.append(p.read_text())
    if not pems:
        sys.exit("no emulator certificates found to trust")
    bundle.write_text("\n".join(pems))
    return bundle


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
    if WORK.exists():
        shutil.rmtree(WORK)
    for d in ("armdata", "azconfig"):
        (WORK / d).mkdir(parents=True)

    AZ_ENV["AZURE_CONFIG_DIR"] = str(WORK / "azconfig")
    # MSAL validates an authority against login.microsoftonline.com unless
    # instance discovery is off — the switch the CLI documents for private and
    # disconnected clouds. Without it the CLI reaches for the real internet
    # before it ever talks to the emulator.
    AZ_ENV["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"

    print("==> building the emulators")
    entra_bin = build_entra()
    arm_bin = WORK / ("arm-emulator" + EXE)
    subprocess.run(["go", "build", "-C", str(REPO), "-o", str(arm_bin),
                    "./cmd/arm-emulator"],
                   check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})

    print(f"==> starting entra :{ENTRA_PORT}, arm :{ARM_PORT}")
    start("entra", [str(entra_bin)], {
        "ORIGIN_MODE": "compat", "PORT": str(ENTRA_PORT), "PUBLIC_ORIGIN": E,
        "DB_PATH": str(WORK / "entra.sqlite"), "TLS_CERT_DIR": str(WORK / "entra-tls"),
    })
    start("arm", [str(arm_bin), "-addr", f":{ARM_PORT}", "-data-dir", str(WORK / "armdata"),
                  "-entra-issuer", ISSUER, "-entra-tls-insecure",
                  "-subscription-id", SUB, "-tenant-id", TENANT])
    wait_healthy()

    # The CLI expands principal ids through Graph; entra must know that
    # audience before it will mint a token for it.
    ensure_audience(f"{E}/", "Microsoft Graph (emulator)")

    bundle = collect_ca()
    AZ_ENV["REQUESTS_CA_BUNDLE"] = str(bundle)
    print(f"==> trusting the emulator certificates via {bundle}")

    try:
        driver()
    finally:
        az("cloud", "set", "--name", "AzureCloud", check=False)
        az("cloud", "unregister", "--name", CLOUD, check=False)


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in procs:
            p.terminate()
