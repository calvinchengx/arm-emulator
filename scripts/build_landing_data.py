#!/usr/bin/env python3
"""Assemble the landing page's data, and refuse a page that hardcodes a number.

The landing page states six totals. Every one of them moves, and a number typed
into a page has no idea a witness was added: the sibling repos found four stale
copies of one count, two of them inside the sentence arguing that a witness
count is a better claim than a coverage percentage.

So the page reads its totals at run time from JSON copied beside it, and this
script FAILS when the page carries a literal where a placeholder belongs, or
stops reading one of the documents that fills a placeholder. The check is the
point; copying the files is the easy half.

The witnessed/green pair is NOT recomputed here. It comes from
`coverage_badges.witness_counts`, which is what writes the README's badge, so
the tile and the badge cannot disagree. A second copy of that parser under a
comment saying "keep in step" is a defect already filed, with no owner and no
failing test.

    ./scripts/build_landing_data.py --out _site --landing website/src/pages/index.astro
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from coverage_badges import witness_counts  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
WITNESSES = ROOT / "docs" / "witnesses.json"
LEDGER = ROOT / "docs" / "parity.md"

# Headings that carry no gradeable ARM claim. Spelled as this repo spells them:
# the same set inherited from a sibling once named sections that did not exist
# here, and silently graded nothing.
CONFORMANCE = "Ecosystem conformance: real clients as witnesses"
EMULATOR_ONLY = "Emulator-only (no ARM equivalent — these exist for testing)"
BOUNDARY = "Scope boundary: the authorization slice, not all of ARM"
NON_CLAIM = {"Legend", "Test coverage", CONFORMANCE, EMULATOR_ONLY, BOUNDARY}

HEADER_CELLS = {"ARM feature", "Feature", "Azure feature", "Real client (pinned)", ""}

# Each is (the id the page fills, the document that fills it). A page that
# stops reading one of these shows a dash forever, which is worse than a wrong
# number because nothing looks broken.
BINDINGS = {
    "witness-count": "witnesses-manifest.json",
    "claims-witnessed": "parity-summary.json",
    "claims-green": "parity-summary.json",
    "third-party-count": "parity-summary.json",
    "client-count": "parity-summary.json",
    "scope-count": "parity-summary.json",
    "verified-count": "parity-summary.json",
    "verified-tag": "parity-summary.json",
    "verified-sentence": "parity-summary.json",
    "third-party-sentence": "parity-summary.json",
    # Written by coverage_badges.py in the same job, from a profile measured
    # there. Not produced by this script, so only the reading end is checked.
    "coverage-go": "coverage-go.json",
    "release-tag": "releases/latest",
}

STATS_BLOCK = re.compile(r'<div class="stats">(.*?)</div></section>', re.S)
TAGS = re.compile(r"<[^>]*>")


def ledger_rows() -> dict[str, list[list[str]]]:
    """The ledger's tables, keyed by the heading they sit under."""
    tables: dict[str, list[list[str]]] = {}
    section: str | None = None
    for line in LEDGER.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section is None or not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or set(cells[0]) <= set("-") or cells[0] in HEADER_CELLS:
            continue
        tables.setdefault(section, []).append(cells)
    return tables


def parity_summary() -> dict:
    """Everything the page states about the ledger, counted from the ledger."""
    tables = ledger_rows()
    manifest = json.loads(WITNESSES.read_text())

    grades = {"real": 0, "emulated": 0, "not-implemented": 0}
    for section, rows in tables.items():
        if section in NON_CLAIM:
            continue
        for cells in rows:
            for symbol, name in (("🟢", "real"), ("🟡", "emulated"), ("🔴", "not-implemented")):
                if symbol in cells[-1]:
                    grades[name] += 1

    # A claim counts as third-party evidence when something Microsoft wrote
    # drove the surface: a CI job with a packaged client, or its SDK in
    # process. `go:` is our own client on both ends and proves only that the
    # emulator agrees with itself, so it is counted apart rather than added in.
    third_party = go_only = 0
    for claim in manifest.values():
        kinds = {w.split(":", 1)[0] for w in claim.get("witnesses", [])}
        if kinds & {"ci", "sdk"}:
            third_party += 1
        elif kinds == {"go"}:
            go_only += 1

    # `verified` is not a tier this repo's taxonomy has, and there is no
    # differential harness to produce one. Counted rather than asserted so the
    # page changes by itself on the day that stops being true.
    verified = sum(
        1
        for claim in manifest.values()
        for w in claim.get("witnesses", [])
        if w.split(":", 1)[0] == "verified"
    )

    witnessed, green = witness_counts()
    if not green:
        raise SystemExit(f"FAIL: no green rows parsed from {LEDGER.relative_to(ROOT)}")

    return {
        "claims": len(manifest),
        "witnessed": witnessed,
        "green": green,
        "grades": grades,
        "third_party": third_party,
        "go_only": go_only,
        "verified": verified,
        "clients": len(tables.get(CONFORMANCE, [])),
        "emulator_only": len(tables.get(EMULATOR_ONLY, [])),
        "out_of_scope": len(tables.get(BOUNDARY, [])),
    }


def check_page(page: pathlib.Path) -> str | None:
    """The reason the page is not publishable, or None."""
    if not page.exists():
        return f"{page} does not exist."
    text = page.read_text()

    block = STATS_BLOCK.search(text)
    if not block:
        return f"{page} has no stat row, so the totals this script exists to bind are gone."
    literal = re.search(r"\d", TAGS.sub("", block.group(1)))
    if literal:
        stripped = " ".join(TAGS.sub(" ", block.group(1)).split())
        return (
            f"{page} hardcodes a number in the stat row: {stripped!r}. The page reads "
            "its totals at run time; a typed number goes stale the day the count moves."
        )

    for element, source in BINDINGS.items():
        if f'id="{element}"' not in text:
            return f"{page} no longer has #{element}, so a headline number would never fill."
        if source not in text:
            return f"{page} no longer reads {source}, so #{element} would show a dash forever."
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--landing", required=True)
    args = parser.parse_args()

    problem = check_page(pathlib.Path(args.landing))
    if problem:
        print(f"FAIL: {problem}")
        return 1

    summary = parity_summary()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "witnesses-manifest.json").write_text(WITNESSES.read_text())
    (out / "parity-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    print(
        "landing data: {witnessed}/{green} green rows witnessed, {claims} claims "
        "({third_party} third-party, {go_only} go-only), {clients} real clients, "
        "{verified} verified against Azure".format(**summary)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
