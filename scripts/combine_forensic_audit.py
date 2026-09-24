#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Combine per-OS forensic audit runs into the report attached to a release.

Each CI platform writes its own reports/forensic_audit.json (see
crush/tests/conftest.py). This merges them into one HTML report with a
result column per OS, one combined JSON holding every run unchanged, and a
Markdown summary for the release notes.

Usage:
    python scripts/combine_forensic_audit.py RUN.json [RUN.json ...] \\
        --html crush-forensic-audit.html --json crush-forensic-audit.json \\
        [--notes release-notes.md --report-url URL] [--expected N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crush.tests import forensic_report  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("runs", nargs="+", type=Path, help="per-OS forensic_audit.json files")
    ap.add_argument("--html", type=Path, required=True, help="combined HTML report to write")
    ap.add_argument("--json", type=Path, required=True, help="combined JSON to write")
    ap.add_argument("--notes", type=Path, help="Markdown summary for the release notes")
    ap.add_argument("--report-url", default="", help="report link to put in --notes")
    ap.add_argument("--expected", type=int, help="number of platforms that should have reported")
    args = ap.parse_args(argv)

    runs = [json.loads(p.read_text(encoding="utf-8")) for p in args.runs]
    # Stable column order regardless of artifact download order
    runs.sort(key=lambda r: str(r["environment"].get("os")))

    commits = {r["environment"].get("commit") for r in runs}
    if len(commits) > 1:
        print(f"error: runs are from different commits: {sorted(map(str, commits))}",
              file=sys.stderr)
        return 2

    args.html.write_text(forensic_report.render_html(runs, args.expected), encoding="utf-8")
    args.json.write_text(
        json.dumps({"schema_version": forensic_report.SCHEMA_VERSION, "runs": runs}, indent=2),
        encoding="utf-8",
    )
    if args.notes:
        footer = (
            f"Full report: [{args.html.name}]({args.report_url}) — every check, "
            "with a link to its test source at this release's commit."
            if args.report_url else ""
        )
        args.notes.write_text(
            forensic_report.render_markdown_summary(runs, footer, args.expected), encoding="utf-8",
        )

    verdict = forensic_report.overall_verdict(runs, args.expected)
    print(f"Forensic audit ({len(runs)} platform(s)): {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
