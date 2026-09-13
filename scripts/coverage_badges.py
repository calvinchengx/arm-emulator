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

It also GUARDS the one place the ledger types that percentage in prose. The
badge is bound to the measurement and the landing tile reads the badge, so
both move on their own; the sentence under `## Test coverage` is a hand-copied
duplicate, and it drifted half a point (98.7% typed, 98.2% measured) with
nothing in CI to notice. Same defect `build_landing_data.py` exists to stop,
one file over. So the measured figure is compared against the prose here, and
a build that disagrees is red.

Usage:
    coverage_badges.py --go PCT --out DIR   # badges, and check the ledger
    coverage_badges.py --go PCT             # check the ledger only
    coverage_badges.py --out DIR            # badges, coverage written as "n/a"

The percentage is supplied by the caller because only CI knows it. Omit it and
the badge is written as "n/a" rather than a wrong number — and the ledger goes
unchecked, because there is nothing to check it against.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WITNESSES = REPO / "docs" / "witnesses.json"
PARITY = REPO / "docs" / "parity.md"

# The ledger's prose figure lives under this heading, written bold. The floor
# in the same sentence ("a CI floor at 98%") is deliberately not bold, so the
# first bold percentage in the section is the measured claim.
COVERAGE_SECTION = "Test coverage"
STATED_PCT = re.compile(r"\*\*(\d+(?:\.\d+)?)%\*\*")


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
            COVERAGE_SECTION}
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


def stated_coverage() -> str | None:
    """The percentage the ledger's prose claims, exactly as it is written.

    Returned as the literal rather than a float because how many digits it
    prints is what says how precise the claim is, and that sets the tolerance.
    """
    section: str | None = None
    for line in PARITY.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section != COVERAGE_SECTION:
            continue
        found = STATED_PCT.search(line)
        if found:
            return found.group(1)
    return None


def rounding_tolerance(literal: str) -> float:
    """Half a unit in the ledger's last printed place.

    "98.2" stands for anything that rounds to it, so the prose is allowed to
    be a rounding of the measurement and nothing else. Writing "98" instead
    buys a wider tolerance honestly: it claims less.
    """
    _, _, decimals = literal.partition(".")
    return 0.5 * 10 ** -len(decimals)


def check_ledger(measured: float) -> str | None:
    """The reason the ledger's prose is not publishable, or None.

    Refuses a MISSING figure as well as a wrong one. A guard that a later
    edit can switch off by deleting the number it guards is not a guard, and
    the failure it hides looks exactly like success.
    """
    ledger = PARITY.relative_to(REPO)
    literal = stated_coverage()
    if literal is None:
        return (
            f"{ledger}'s '## {COVERAGE_SECTION}' section states no bold percentage, so "
            f"this check would pass forever. State the measured figure as **{measured:.1f}%**."
        )
    if abs(float(literal) - measured) > rounding_tolerance(literal):
        return (
            f"{ledger} claims **{literal}%** coverage; this build measured "
            f"{measured:.1f}%. Update the prose to **{measured:.1f}%** — the profile is "
            "the fact and the sentence is a copy of it, so the copy is what is wrong."
        )
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    # Neither is required alone: the code CI job checks the ledger without
    # publishing badges, and only the docs job has somewhere to write them.
    ap.add_argument("--out", default="")
    ap.add_argument("--go", default="")
    args = ap.parse_args()
    if not args.out and not args.go:
        print("FAIL: nothing to do — pass --out to write badges, --go to check the ledger.")
        return 1

    # Before the badges: a build whose ledger lies should not publish one.
    if args.go:
        problem = check_ledger(float(args.go))
        if problem:
            print(f"FAIL: {problem}")
            return 1
        if not args.out:
            print(f"ledger: docs/parity.md agrees with the measured {float(args.go):.1f}%")
            return 0

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
