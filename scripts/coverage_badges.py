#!/usr/bin/env python3
"""Emit shields.io endpoint JSON for the numbers this repo can honestly claim.

Self-hosted on purpose: no third-party coverage service, no upload token, no
account. CI computes the numbers, this writes them as shields `endpoint`
documents, and the docs site serves them from its own origin — so the badges
are as trustworthy as the site, and nothing leaves the project.

TWO NUMBERS, because one would lie:

  go          statement coverage of the Go unit + in-process server tests
  witnesses   parity claims that name a test which exists and ran

`witnesses` is the integration measure. "15/15 claims witnessed" says every
claim of support is backed by something that ran — precisely what a coverage
percentage cannot say, because coverage scores the unit suites and the work
that catches consumer-facing defects here is the real-client fleet (the az
CLI, armresources, armauthorization, armkeyvault).

Usage:
    coverage_badges.py --out DIR [--go PCT]

The percentage is supplied by the caller because only CI knows it. Omit it and
the badge is written as "n/a" rather than a wrong number.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WITNESSES = REPO / "docs" / "witnesses.json"
PARITY = REPO / "docs" / "parity.md"


def colour_for(pct: float) -> str:
    """Deliberately not flattering: a repo enforcing a 98% floor should not
    paint 80% green."""
    if pct >= 95:
        return "brightgreen"
    if pct >= 90:
        return "green"
    if pct >= 80:
        return "yellow"
    return "orange"


def badge(label: str, message: str, colour: str) -> dict:
    return {"schemaVersion": 1, "label": label, "message": message, "color": colour}


def witness_counts() -> tuple[int, int]:
    """(claims that are witnessed, total green claims in the parity map).

    Counting the map rather than the manifest is the point: a claim added to
    the map without an entry here must show as unwitnessed, not vanish.
    """
    manifest = json.loads(WITNESSES.read_text()) if WITNESSES.exists() else {}
    total = witnessed = 0
    section = None
    skip = {"Legend", "Ecosystem conformance: real clients as witnesses",
            "Emulator-only (no ARM equivalent — these exist for testing)",
            "Scope boundary: the authorization slice, not all of ARM",
            "Test coverage"}
    import re
    for line in PARITY.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or section in skip or section is None:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] in ("ARM feature", "Feature") or set(cells[0]) <= set("-"):
            continue
        if "🟢" not in cells[-1]:
            continue
        total += 1
        text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cells[0])
        text = re.sub(r"[*`_]", "", text)
        key = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
        if manifest.get(key, {}).get("witnesses"):
            witnessed += 1
    return witnessed, total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--go", default="")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.go:
        pct = float(args.go)
        go = badge("go coverage", f"{pct:.1f}%", colour_for(pct))
    else:
        go = badge("go coverage", "n/a", "lightgrey")
    (out / "coverage-go.json").write_text(json.dumps(go) + "\n")

    witnessed, total = witness_counts()
    colour = "brightgreen" if total and witnessed == total else "orange"
    (out / "witnesses.json").write_text(
        json.dumps(badge("parity claims witnessed", f"{witnessed}/{total}", colour)) + "\n")

    print(f"badges: go={go['message']} witnesses={witnessed}/{total} → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
