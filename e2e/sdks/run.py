#!/usr/bin/env python3
"""Microsoft's Python, JavaScript and .NET management SDKs driving this
emulator — three vendor stacks that share nothing with the Go one.

WHY. Most of this repo's evidence comes from Go: `armresources`,
`armauthorization` and `armkeyvault` in-process, plus the packaged `az` CLI
over a network. That is strong, but one language's SDKs can quietly teach an
emulator their own habits — a header only they read, a JSON shape only their
deserializer forgives, a status code only their poller accepts — and every
test keeps passing because nothing else ever looks. Three unrelated client
stacks re-deriving the same wire is the check that finds that.

Each harness does the same work, in its own idiom: acquire an ARM-audience
token from entra-emulator, create and read a resource group, parse ARM's error
envelope for something absent, filter role definitions by name, write a role
assignment, write one carrying an ABAC condition and be refused a malformed
one, and be challenged for a garbage token.

    ./e2e/sdks/run.py                # all three
    ./e2e/sdks/run.py --only python  # one, when iterating

A missing toolchain is a FAILURE, not a skip: a harness that quietly does
nothing reports the same green as one that passed.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import emulators  # noqa: E402

HERE = Path(__file__).resolve().parent
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "arm-sdk-e2e"

LANGUAGES = ("python", "js", "dotnet")


def tool(*candidates, probe=("--version",)):
    """The first candidate that actually RUNS, not merely the first on PATH.

    Version managers install shims that exist, resolve, and then fail: asdf's
    `dotnet` shim exits non-zero with "No version is set for command dotnet",
    and the Microsoft Store's `python3` stub does the same on Windows. Locating
    a command therefore proves nothing; this executes each candidate and keeps
    the first that answers.
    """
    for c in candidates:
        found = shutil.which(c) or (c if os.path.isabs(c) and os.path.exists(c) else None)
        if not found:
            continue
        try:
            r = subprocess.run([found, *probe], capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return found
    return None


def run(name, argv, cwd, env):
    print(f"\n==================== {name} ====================")
    print(f"    $ {' '.join(str(a) for a in argv)}", file=sys.stderr)
    r = subprocess.run([str(a) for a in argv], cwd=str(cwd), env=env)
    if r.returncode != 0:
        sys.exit(f"FAIL: the {name} harness exited {r.returncode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=LANGUAGES, action="append",
                    help="run a subset (repeatable); the default is all three")
    args = ap.parse_args()
    wanted = tuple(args.only) if args.only else LANGUAGES

    emu = emulators.Emulators(WORK)
    emu.start()

    ca = str(emu.ca_bundle)
    base = {
        **os.environ,
        "ARM_URL": emu.arm,
        "ENTRA_URL": emu.entra,
        "ARM_TENANT_ID": emu.tenant,
        "ARM_SUBSCRIPTION_ID": emu.sub,
        "ARM_CLIENT_ID": emu.client_id,
        "ARM_CLIENT_SECRET": emu.client_secret,
    }

    try:
        if "python" in wanted:
            uv = tool("uv")
            if not uv:
                sys.exit("FAIL: uv is not installed; the Python harness needs it")
            script = HERE / "python" / "main.py"
            # Resolve dependencies FIRST, with the ambient trust store: the
            # CA bundle below trusts the emulator and nothing else, which is
            # right for the client under test and fatal for a PyPI fetch.
            run("Python install", [uv, "sync", "--script", script], HERE, base)
            # azure-core's transport is requests, which reads
            # REQUESTS_CA_BUNDLE; SSL_CERT_FILE covers anything on the stdlib.
            # Verification stays ON — the emulator's certificate is trusted,
            # not ignored. --offline guarantees the run needs no network of
            # its own now that the narrow bundle is in force.
            run("Python SDKs", [uv, "run", "--offline", "--script", script], HERE,
                {**base, "REQUESTS_CA_BUNDLE": ca, "SSL_CERT_FILE": ca})

        if "js" in wanted:
            pnpm = tool("pnpm")
            if not pnpm:
                sys.exit("FAIL: pnpm is not installed; the JavaScript harness needs it")
            js = HERE / "js"
            run("JavaScript install", [pnpm, "install", "--frozen-lockfile"], js, base)
            # Node trusts extra roots only through this variable; there is no
            # per-client option in @azure/identity for it.
            run("JavaScript SDKs", [pnpm, "start"], js, {**base, "NODE_EXTRA_CA_CERTS": ca})

        if "dotnet" in wanted:
            dn = tool("dotnet", "/usr/local/share/dotnet/dotnet",
                      "/usr/share/dotnet/dotnet")
            if not dn:
                sys.exit("FAIL: dotnet is not installed; the .NET harness needs it")
            # .NET reads no CA-bundle environment variable, so the harness
            # PINS the emulator's certificate instead of disabling validation.
            run(".NET SDKs", [dn, "run", "--project", HERE / "dotnet"], HERE / "dotnet",
                {**base, "ARM_CA_BUNDLE": ca, "DOTNET_NOLOGO": "1",
                 "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
    except SystemExit:
        emu.dump_logs()
        raise
    finally:
        emu.stop()

    print(f"\nSDK E2E: PASS — {', '.join(wanted)} drove arm-emulator")


if __name__ == "__main__":
    main()
