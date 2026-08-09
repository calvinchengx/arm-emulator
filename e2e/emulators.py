"""Bring up the pair every e2e harness needs: entra-emulator issuing
ARM-audience tokens, and arm-emulator validating them.

This lives beside the harnesses rather than inside one of them because there
are now four unrelated clients to drive — the `az` CLI, and the Python,
JavaScript and .NET management SDKs — and each of them wants exactly the same
two processes, the same seeded tenant, and the same self-signed certificates
to trust. Copying the lifecycle into each harness would mean four places to
fix when a flag changes.

The identifiers below are fixed rather than random: entra-emulator seeds this
tenant, this daemon application and this secret, so a harness can authenticate
without a provisioning step.
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

REPO = Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""

TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"
SUB = "6082bfda-63d0-46f4-8272-ae9195139feb"
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.4.1")
ARM_AUDIENCE = "https://management.azure.com"

# The harness's own health checks bypass verification deliberately: they run
# before the CA bundle exists, and their job is to find out whether a process
# is listening at all. Every CLIENT under test verifies properly.
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


def http(method, url, body=None):
    """A request that answers rather than raises: (status, bytes), or (0, b'')
    when nothing is listening yet."""
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(url, method=method,
                                 data=body.encode() if body else None, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_TLS, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, b""


class Emulators:
    """The running pair, with everything a client needs to reach it."""

    def __init__(self, work: Path, entra_port=None, arm_port=None):
        self.work = work
        self.entra_port = int(entra_port or os.environ.get("ENTRA_PORT", "18943"))
        self.arm_port = int(arm_port or os.environ.get("ARM_PORT", "18945"))
        self.entra = f"https://localhost:{self.entra_port}"
        self.arm = f"https://localhost:{self.arm_port}"
        self.issuer = f"{self.entra}/{TENANT}/v2.0"
        self.tenant, self.sub = TENANT, SUB
        self.client_id, self.client_secret = SP_CLIENT, SP_SECRET
        self.ca_bundle = work / "emulator-ca.pem"
        self._procs: list[subprocess.Popen] = []

    # ---- lifecycle ----

    def start(self, fresh=True):
        if fresh and self.work.exists():
            shutil.rmtree(self.work)
        (self.work / "armdata").mkdir(parents=True, exist_ok=True)

        print("==> building the emulators")
        entra_bin = self._build_entra()
        arm_bin = self.work / ("arm-emulator" + EXE)
        subprocess.run(["go", "build", "-C", str(REPO), "-o", str(arm_bin),
                        "./cmd/arm-emulator"],
                       check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})

        print(f"==> starting entra :{self.entra_port}, arm :{self.arm_port}")
        self._spawn("entra", [str(entra_bin)], {
            "ORIGIN_MODE": "compat", "PORT": str(self.entra_port),
            "PUBLIC_ORIGIN": self.entra, "DB_PATH": str(self.work / "entra.sqlite"),
            "TLS_CERT_DIR": str(self.work / "entra-tls"),
        })
        self._spawn("arm", [str(arm_bin), "-addr", f":{self.arm_port}",
                            "-data-dir", str(self.work / "armdata"),
                            "-entra-issuer", self.issuer, "-entra-tls-insecure",
                            "-subscription-id", SUB, "-tenant-id", TENANT])
        self._wait_healthy()
        self._collect_ca()
        print(f"==> trusting the emulator certificates via {self.ca_bundle}")
        return self

    def stop(self):
        for p in self._procs:
            p.terminate()
        for p in self._procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        self._procs.clear()

    def dump_logs(self):
        for name in ("entra", "arm"):
            log = self.work / f"{name}.log"
            if log.exists():
                print(f"---- {name}.log ----\n{log.read_text()}", file=sys.stderr)

    # ---- helpers a harness may need ----

    def ensure_audience(self, audience, name):
        """Register a resource app so entra will mint tokens for `audience`.

        A no-op against real Azure, where first-party resources already exist;
        entra-emulator mints only for audiences it knows.
        """
        body = json.dumps({"displayName": name, "appIdUri": audience,
                           "isConfidential": False})
        code, payload = http("POST", f"{self.entra}/admin/api/apps", body)
        # 409 means it is already registered, which is the normal case on a
        # re-run against a warm emulator.
        if code not in (200, 201, 409):
            sys.exit(f"FAIL: registering {audience}: {code} {payload[:300]}")
        return code

    # ---- internals ----

    def _build_entra(self):
        """Prefer a sibling checkout so the family develops together."""
        repo = Path(os.environ.get("ENTRA_EMULATOR_REPO", REPO.parent / "entra-emulator"))
        out = self.work / ("entra-emulator" + EXE)
        env = {**os.environ, "GOTOOLCHAIN": "auto"}
        if (repo / "go.mod").exists():
            subprocess.run(["go", "build", "-C", str(repo), "-o", str(out),
                            "./cmd/entra-emulator"], check=True, env=env)
            return out
        subprocess.run(
            ["go", "install",
             f"github.com/calvinchengx/entra-emulator/cmd/entra-emulator@{ENTRA_VERSION}"],
            check=True, env={**env, "GOBIN": str(self.work)})
        return out

    def _spawn(self, name, argv, env_extra=None):
        log = open(self.work / f"{name}.log", "w")
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                             env={**os.environ, **(env_extra or {})})
        self._procs.append(p)
        return p

    def _wait_healthy(self):
        deadline = time.time() + 40
        while time.time() < deadline:
            if all(http("GET", f"{b}/health")[0] == 200 for b in (self.entra, self.arm)):
                return
            time.sleep(0.3)
        self.dump_logs()
        sys.exit("emulators did not become healthy in time")

    def _collect_ca(self):
        """One bundle every client can trust. A self-signed cert is its own CA,
        so trusting it is the local equivalent of trusting a private root —
        what a developer does, rather than turning verification off."""
        pems = []
        for sub in ("entra-tls/cert.pem", "armdata/tls/cert.pem"):
            p = self.work / sub
            if p.exists():
                pems.append(p.read_text())
        if not pems:
            sys.exit("no emulator certificates found to trust")
        self.ca_bundle.write_text("\n".join(pems))
        return self.ca_bundle
