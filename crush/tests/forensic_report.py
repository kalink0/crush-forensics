# SPDX-License-Identifier: Apache-2.0
"""Forensic integrity audit report: run data model + HTML/Markdown rendering.

Shared by conftest.py (one run → reports/forensic_audit.{json,html}) and
scripts/combine_forensic_audit.py (one run per OS → the combined report
attached to every GitHub release). Standard library only, so the combine
step needs no dependency install.

A *run* is a plain dict (see build_run()); schema_version bumps whenever a
field changes meaning, so an archived JSON stays interpretable.
"""
from __future__ import annotations

import datetime
import html as _html
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_REPOSITORY = "https://github.com/kalink0/crush-forensics"

CATEGORY_ORDER = [
    "Source Immutability",
    "No Side Effects",
    "Read-only Media",
    "Known-output Verification",
    "Completeness",
    "Reproducibility",
]

CATEGORY_INTROS: dict[str, str] = {
    "Source Immutability": (
        "The tool must never modify digital evidence it reads. "
        "These tests verify that after any VFS read operation the source data is "
        "byte-identical to its pre-examination state."
    ),
    "No Side Effects": (
        "Parsing an artifact must not create additional files next to the evidence. "
        "Sibling files such as SQLite WAL or journal entries would alter the "
        "evidence directory and compromise the examination."
    ),
    "Read-only Media": (
        "The tool must operate correctly when evidence has read-only permissions "
        "(chmod 0o444 / 0o555), simulating examination of write-protected forensic media."
    ),
    "Known-output Verification": (
        "Committed reference artifacts must parse to their exact, pre-computed values. "
        "These are fixed-point checks: if parser output changes for a known input, "
        "the test fails."
    ),
    "Completeness": (
        "Every plausible interpretation of a value must always be produced — silently "
        "omitting a valid interpretation means potentially missing forensic evidence. "
        "These tests verify that no interpretation group is ever dropped."
    ),
    "Reproducibility": (
        "Parsing the same artifact twice must produce identical results. "
        "Non-deterministic output would undermine the reliability of forensic findings."
    ),
}


# ---------------------------------------------------------------------------
# Run data
# ---------------------------------------------------------------------------

def _git(rootdir: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=rootdir, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def collect_environment(rootdir: Path) -> dict[str, Any]:
    """What this run was executed against: code revision, OS, interpreter."""
    from crush import __version__

    commit = os.environ.get("GITHUB_SHA") or _git(rootdir, "rev-parse", "HEAD")
    # Uncommitted tracked changes mean the report does not describe `commit`
    # exactly; None when git itself isn't available.
    status = _git(rootdir, "status", "--porcelain", "--untracked-files=no")
    try:
        import PySide6
        pyside: str | None = PySide6.__version__
    except ImportError:
        pyside = None

    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    return {
        "crush_version": __version__,
        "commit": commit,
        "commit_dirty": None if status is None else bool(status),
        "ref": os.environ.get("GITHUB_REF_NAME"),
        "repository": f"{server}/{repo}" if server and repo else DEFAULT_REPOSITORY,
        "os": platform.system(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "pyside6": pyside,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }


def build_run(
    results: list[dict[str, Any]],
    environment: dict[str, Any],
    corpus: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": environment,
        "corpus": corpus,
        "results": results,
    }


def counts(results: list[dict[str, Any]]) -> dict[str, int]:
    c = {"passed": 0, "failed": 0, "skipped": 0}
    for r in results:
        c[r["outcome"]] = c.get(r["outcome"], 0) + 1
    return c


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _source_url(env: dict[str, Any], path: str | None, line: int | None) -> str | None:
    """Commit-pinned link to the test's source, so a reader sees exactly the
    code that produced this result. None without a commit to pin to."""
    if not env.get("commit") or not path:
        return None
    # A Windows run records the path with backslashes; the URL needs slashes
    # whichever OS renders it.
    url = f"{env['repository']}/blob/{env['commit']}/{path.replace(chr(92), '/')}"
    return f"{url}#L{line}" if line else url


def _run_label(env: dict[str, Any]) -> str:
    os_name = str(env.get("os") or "unknown")
    return "macOS" if os_name == "Darwin" else os_name


def _merged_tests(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Union of all runs' tests, first-seen order, with per-run outcomes."""
    merged: dict[str, dict[str, Any]] = {}
    for idx, run in enumerate(runs):
        for r in run["results"]:
            entry = merged.setdefault(r["nodeid"], {**r, "outcomes": {}})
            entry["outcomes"][idx] = r
    return list(merged.values())


def _by_category(tests: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_cat: dict[str, list[dict[str, Any]]] = {c: [] for c in CATEGORY_ORDER}
    for t in tests:
        by_cat.setdefault(t["category"], []).append(t)
    return by_cat


def overall_verdict(runs: list[dict[str, Any]], expected: int | None = None) -> str:
    """FAIL on any failed check, or when a platform produced no run at all."""
    if expected is not None and len(runs) < expected:
        return "FAIL"
    return "FAIL" if any(counts(r["results"])["failed"] for r in runs) else "PASS"


def missing_runs_note(runs: list[dict[str, Any]], expected: int | None) -> str:
    if expected is None or len(runs) >= expected:
        return ""
    return (
        f"Only {len(runs)} of {expected} platforms produced results; the missing "
        "platform(s) never reached the end of the test run (see the workflow log)."
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         font-size:14px;color:#1a1a2e;background:#f0f2f5}
    a{color:inherit}
    header{background:#1a1a2e;color:#fff;padding:24px 32px 20px}
    header h1{font-size:20px;font-weight:600;letter-spacing:.3px}
    .meta{margin-top:5px;font-size:12px;opacity:.75;line-height:1.6}
    .meta code{font-family:"SF Mono","Fira Code",monospace}
    .overall{display:inline-flex;align-items:center;gap:12px;
             margin-top:14px;background:rgba(255,255,255,.08);
             padding:8px 16px;border-radius:6px}
    .verdict{font-size:18px;font-weight:700;letter-spacing:1px}
    .verdict.pass{color:#4ade80}.verdict.fail{color:#f87171}
    .counts{font-size:12px;opacity:.75}
    main{max-width:1040px;margin:0 auto;padding:24px 16px 40px}
    section{background:#fff;border-radius:8px;padding:20px 24px;
            margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.08);overflow-x:auto}
    .cat-header{display:flex;align-items:center;gap:10px;margin-bottom:6px}
    .cat-header h2{font-size:15px;font-weight:600}
    .cat-count{font-size:12px;color:#666}
    .badge{font-size:11px;font-weight:700;letter-spacing:.4px;
           padding:2px 8px;border-radius:4px}
    .badge.pass{background:#dcfce7;color:#166534}
    .badge.fail{background:#fee2e2;color:#991b1b}
    .cat-intro{font-size:13px;color:#555;line-height:1.55;margin-bottom:14px}
    table{width:100%;border-collapse:collapse}
    th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;
       letter-spacing:.5px;color:#999;padding:6px 10px;
       border-bottom:2px solid #e5e7eb}
    td{padding:8px 10px;border-bottom:1px solid #f3f4f6;vertical-align:top}
    tr:last-child td{border-bottom:none}
    .col-status{width:80px}.col-fn{width:260px}
    .cell-status{font-weight:700;font-size:11px;letter-spacing:.5px;white-space:nowrap}
    .status-passed{color:#16a34a}.status-failed{color:#dc2626}
    .status-skipped,.status-missing{color:#9ca3af}
    .cell-fn{font-family:"SF Mono","Fira Code",monospace;font-size:12px;color:#6366f1;
             word-break:break-all}
    .cell-hash{font-family:"SF Mono","Fira Code",monospace;font-size:11px;
               color:#888;word-break:break-all}
    .cell-size{text-align:right;color:#888;font-size:12px;white-space:nowrap}
    .row-failed{background:#fff5f5}
    details{margin-top:6px;font-size:12px;color:#555}
    details pre{white-space:pre-wrap;word-break:break-word;font-size:11px;
                background:#f9fafb;padding:8px;border-radius:4px;margin-top:4px}
    footer{text-align:center;font-size:11px;color:#bbb;padding:0 0 24px}
"""


def _status_cell(result: dict[str, Any] | None) -> str:
    oc = result["outcome"] if result else "missing"
    label = "NOT RUN" if oc == "missing" else oc.upper()
    return f'<td class="cell-status status-{oc}">{label}</td>'


def _reason_block(test: dict[str, Any], labels: list[str]) -> str:
    parts = ""
    for idx, r in sorted(test["outcomes"].items()):
        if r["outcome"] != "passed" and r.get("reason"):
            parts += (
                f"<details><summary>{_html.escape(labels[idx])}: "
                f"{_html.escape(r['outcome'])}</summary>"
                f"<pre>{_html.escape(r['reason'])}</pre></details>"
            )
    return parts


def _environment_table(runs: list[dict[str, Any]]) -> str:
    rows = ""
    for run in runs:
        env = run["environment"]
        c = counts(run["results"])
        rows += (
            "<tr>"
            f"<td>{_html.escape(_run_label(env))}</td>"
            f'<td class="cell-fn">{_html.escape(str(env.get("platform") or ""))}</td>'
            f"<td>{_html.escape(str(env.get('python') or ''))}</td>"
            f"<td>{_html.escape(str(env.get('pyside6') or '—'))}</td>"
            f"<td>{c['passed']} passed · {c['failed']} failed · {c['skipped']} skipped</td>"
            f"<td>{_html.escape(str(env.get('generated_at') or ''))}</td>"
            "</tr>\n"
        )
    return f"""
<section>
  <div class="cat-header"><h2>Test Environments</h2></div>
  <p class="cat-intro">
    Every platform below ran the same forensic test suite against the same
    commit. A test marked NOT RUN was not collected on that platform.
  </p>
  <table>
    <thead><tr>
      <th>OS</th><th>Platform</th><th>Python</th><th>PySide6</th>
      <th>Result</th><th>Run at (UTC)</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _corpus_section(corpus: dict[str, dict[str, Any]]) -> str:
    rows = ""
    for name, info in sorted(corpus.items()):
        rows += (
            "<tr>"
            f'<td class="cell-fn">{_html.escape(name)}</td>'
            f'<td class="cell-hash">{_html.escape(info["sha256"])}</td>'
            f'<td class="cell-size">{info["size"]:,}&thinsp;B</td>'
            "</tr>\n"
        )
    return f"""
<section>
  <div class="cat-header">
    <h2>Reference Corpus</h2>
    <span class="badge pass">VERIFIED</span>
  </div>
  <p class="cat-intro">
    SHA-256 checksums of the committed test-evidence files.
    The corpus integrity check runs before the first test and aborts the session
    if any file has been modified.
  </p>
  <table>
    <thead><tr>
      <th class="col-fn">File</th>
      <th>SHA-256</th>
      <th style="text-align:right">Size</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def render_html(runs: list[dict[str, Any]], expected: int | None = None) -> str:
    """Render one or more runs (one per OS) of the same commit as one report.

    `expected`: how many platforms should have reported; fewer is shown as a
    FAIL with a warning rather than as a clean report over fewer columns.
    """
    if not runs:
        raise ValueError("no runs to render")
    env0 = runs[0]["environment"]
    labels = [_run_label(r["environment"]) for r in runs]
    tests = _merged_tests(runs)
    verdict = overall_verdict(runs, expected)
    ov_cls = verdict.lower()
    missing = missing_runs_note(runs, expected)
    warning = f'<div class="meta"><strong>{_html.escape(missing)}</strong></div>' if missing else ""
    total = counts([r for run in runs for r in run["results"]])

    status_heads = "".join(
        f'<th class="col-status">{_html.escape(lbl)}</th>' for lbl in labels
    )
    sections = ""
    for category, cat_tests in _by_category(tests).items():
        if not cat_tests:
            continue
        cat_results = [r for t in cat_tests for r in t["outcomes"].values()]
        c = counts(cat_results)
        badge_cls = "pass" if c["failed"] == 0 else "fail"
        counter = f"{len(cat_tests)} checks"
        if c["failed"]:
            counter += f" &nbsp;·&nbsp; {c['failed']} failed"
        rows = ""
        for t in cat_tests:
            failed = any(r["outcome"] == "failed" for r in t["outcomes"].values())
            url = _source_url(env0, t.get("path"), t.get("line"))
            name = _html.escape(t["name"])
            fn = f'<a href="{_html.escape(url)}">{name}</a>' if url else name
            statuses = "".join(_status_cell(t["outcomes"].get(i)) for i in range(len(runs)))
            rows += (
                f'<tr class="{"row-failed" if failed else ""}">'
                f"{statuses}"
                f'<td>{_html.escape(t["desc"])}{_reason_block(t, labels)}</td>'
                f'<td class="cell-fn">{fn}</td>'
                "</tr>\n"
            )
        sections += f"""
<section>
  <div class="cat-header">
    <h2>{_html.escape(category)}</h2>
    <span class="badge {badge_cls}">{badge_cls.upper()}</span>
    <span class="cat-count">{counter}</span>
  </div>
  <p class="cat-intro">{_html.escape(CATEGORY_INTROS.get(category, ""))}</p>
  <table>
    <thead><tr>
      {status_heads}
      <th>Forensic Property Verified</th>
      <th class="col-fn">Test Function</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    commit = env0.get("commit")
    if commit:
        commit_html = (
            f'<a href="{_html.escape(env0["repository"])}/tree/{_html.escape(commit)}">'
            f"<code>{_html.escape(commit[:12])}</code></a>"
        )
        if env0.get("commit_dirty"):
            commit_html += " (with uncommitted changes)"
    else:
        commit_html = "unknown"
    ref = f" &nbsp;|&nbsp; {_html.escape(env0['ref'])}" if env0.get("ref") else ""
    generated = _html.escape(max(str(r["environment"].get("generated_at", "")) for r in runs))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Crush Forensic Audit</title>
  <style>{_CSS}</style>
</head>
<body>
<header>
  <h1>Crush &mdash; Forensic Integrity Audit Report</h1>
  <div class="meta">
    Crush {_html.escape(str(env0.get("crush_version")))}{ref} &nbsp;|&nbsp;
    Commit {commit_html} &nbsp;|&nbsp;
    Platforms: {_html.escape(", ".join(labels))}
  </div>
  <div class="overall">
    <span class="verdict {ov_cls}">{verdict}</span>
    <span class="counts">
      {len(tests)} checks &nbsp;&middot;&nbsp;
      {total["passed"]} passed &nbsp;&middot;&nbsp;
      {total["failed"]} failed &nbsp;&middot;&nbsp;
      {total["skipped"]} skipped (across all platforms)
    </span>
  </div>
  {warning}
</header>
<main>
{_environment_table(runs)}
{sections}
{_corpus_section(runs[0]["corpus"])}
</main>
<footer>crush-forensics &nbsp;&middot;&nbsp; forensic audit report &nbsp;&middot;&nbsp; {generated}</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Markdown (GitHub Actions job summary / release notes)
# ---------------------------------------------------------------------------

def render_markdown_summary(
    runs: list[dict[str, Any]], footer: str, expected: int | None = None,
) -> str:
    verdict = overall_verdict(runs, expected)
    missing = missing_runs_note(runs, expected)
    icon = "white_check_mark" if verdict == "PASS" else "x"
    labels = [_run_label(r["environment"]) for r in runs]
    tests = _merged_tests(runs)

    head = "| Category | " + " | ".join(labels) + " |\n"
    head += "|---|" + "---|" * len(labels) + "\n"
    rows = ""
    for category, cat_tests in _by_category(tests).items():
        if not cat_tests:
            continue
        cells = []
        for idx in range(len(runs)):
            c = counts([t["outcomes"][idx] for t in cat_tests if idx in t["outcomes"]])
            cell = f"{':white_check_mark:' if c['failed'] == 0 else ':x:'} {c['passed']} passed"
            if c["failed"]:
                cell += f", {c['failed']} failed"
            if c["skipped"]:
                cell += f", {c['skipped']} skipped"
            cells.append(cell)
        rows += f"| {category} | " + " | ".join(cells) + " |\n"

    return (
        f"\n## :{icon}: Forensic Integrity Audit &mdash; {verdict}\n\n"
        f"{head}{rows}\n"
        + (f"> **Warning:** {missing}\n\n" if missing else "")
        + f"{footer}\n"
    )


def write_run(run: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "forensic_audit.json"
    html_path = out_dir / "forensic_audit.html"
    json_path.write_text(json.dumps(run, indent=2), encoding="utf-8")
    html_path.write_text(render_html([run]), encoding="utf-8")
    return json_path, html_path
