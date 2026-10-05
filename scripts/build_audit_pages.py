#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Build the GitHub Pages site for the forensic audit reports of all releases.

The site is rebuilt from scratch on every run, from the
crush-forensic-audit.{html,json} files attached to the GitHub releases
(written by scripts/combine_forensic_audit.py). The releases are the only
source; the site keeps no state of its own. Network access stays in the
workflow (.github/workflows/pages.yml), which provides:

  --releases  JSON Lines, one object per release with an audit report:
              {"tag", "published_at", "url"}
  --assets    a directory holding <tag>/crush-forensic-audit.{html,json}
  --latest    the tag GitHub marks as the latest release

Output (--out):
  audit/index.html, audit/report.json   the latest release's files, unchanged
  audit/<tag>/index.html, report.json   every release's files, unchanged
  audit/history.html                    overview of all releases
  audit/badge.json                      shields.io endpoint badge (latest)

Usage:
    python scripts/build_audit_pages.py --releases releases.jsonl \\
        --assets audit-releases --latest v0.21.0 --out site [--expected 3]
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crush.tests import forensic_report  # noqa: E402

HTML_ASSET = "crush-forensic-audit.html"
JSON_ASSET = "crush-forensic-audit.json"
# A tag becomes a directory name on the site
_SAFE_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


class PagesError(Exception):
    pass


def _published(value: str | None) -> str:
    """GitHub's ISO-8601 UTC timestamp, shown as 'YYYY-MM-DD HH:MM:SS'."""
    if not value:
        return ""
    ts = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def read_releases(path: Path) -> list[dict[str, str]]:
    releases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            releases.append(json.loads(line))
    return releases


def build(
    releases: list[dict[str, str]],
    assets: Path,
    latest: str,
    out: Path,
    fallback_expected: int | None = None,
) -> dict[str, Any]:
    """Write the site into `out` (must not exist yet). Returns the latest summary."""
    if not releases:
        raise PagesError("no release has an audit report attached")
    audit = out / "audit"
    audit.mkdir(parents=True)

    entries: list[dict[str, Any]] = []
    for rel in releases:
        tag = rel["tag"]
        if not _SAFE_TAG.fullmatch(tag):
            raise PagesError(f"release tag {tag!r} cannot be used as a directory name")
        # The listing is paginated; a release created mid-listing shifts the
        # pages and can repeat an entry. Re-run the workflow in that case.
        if (audit / tag).exists():
            raise PagesError(f"release {tag} is listed twice")
        src = assets / tag
        html_src, json_src = src / HTML_ASSET, src / JSON_ASSET
        for f in (html_src, json_src):
            if not f.is_file():
                raise PagesError(f"release {tag}: {f.name} is not attached")
        combined = json.loads(json_src.read_text(encoding="utf-8"))
        summary = forensic_report.release_summary(combined, fallback_expected)

        dest = audit / tag
        dest.mkdir()
        shutil.copyfile(html_src, dest / "index.html")
        shutil.copyfile(json_src, dest / "report.json")
        entries.append({
            "tag": tag,
            "published_at": _published(rel.get("published_at")),
            "sort_key": rel.get("published_at") or "",
            "release_url": rel["url"],
            "summary": summary,
        })

    by_tag = {e["tag"]: e for e in entries}
    if latest not in by_tag:
        raise PagesError(f"latest release {latest} has no audit report attached")

    shutil.copyfile(audit / latest / "index.html", audit / "index.html")
    shutil.copyfile(audit / latest / "report.json", audit / "report.json")
    latest_summary: dict[str, Any] = by_tag[latest]["summary"]
    (audit / "badge.json").write_text(
        forensic_report.render_badge_json(latest_summary), encoding="utf-8",
    )
    entries.sort(key=lambda e: e["sort_key"], reverse=True)
    (audit / "history.html").write_text(
        forensic_report.render_history_html(entries, latest), encoding="utf-8",
    )
    return latest_summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--releases", type=Path, required=True, help="JSON Lines release list")
    ap.add_argument("--assets", type=Path, required=True, help="directory with <tag>/ assets")
    ap.add_argument("--latest", required=True, help="tag of the latest release")
    ap.add_argument("--out", type=Path, required=True, help="site directory to create")
    ap.add_argument("--expected", type=int,
                    help="platform count for reports that predate expected_platforms")
    args = ap.parse_args(argv)

    try:
        summary = build(read_releases(args.releases), args.assets, args.latest,
                        args.out, args.expected)
    except PagesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Audit pages built; latest {args.latest}: {summary['verdict']}, "
          f"{summary['checks']} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
