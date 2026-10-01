# SPDX-License-Identifier: Apache-2.0
"""scripts/build_audit_pages.py: the GitHub Pages site built from the audit
reports attached to the releases."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from crush.tests import forensic_report

ROOT = Path(__file__).resolve().parents[2]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "build_audit_pages_script", ROOT / "scripts" / "build_audit_pages.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pages = _load_script()


def _run(os_name: str, outcomes: list[str]) -> dict:
    return {
        "schema_version": 1,
        "environment": {
            "os": os_name, "commit": "a" * 40, "crush_version": "0.21.0",
            "repository": forensic_report.DEFAULT_REPOSITORY,
        },
        "corpus": {},
        "results": [
            {"nodeid": f"t{i}", "outcome": oc, "category": "Source Immutability",
             "name": f"test_{i}", "desc": "d"}
            for i, oc in enumerate(outcomes)
        ],
    }


def _combined(outcomes_per_os: list[list[str]], expected: int | None = 3,
              store_expected: bool = True) -> dict:
    labels = ["Darwin", "Linux", "Windows"]
    data: dict = {"schema_version": 1,
                  "runs": [_run(labels[i], oc) for i, oc in enumerate(outcomes_per_os)]}
    if store_expected:
        data["expected_platforms"] = expected
    return data


def _release(assets: Path, tag: str, combined: dict, html: bytes = b"<html>r</html>",
             published: str = "2026-09-30T17:54:12Z") -> dict:
    d = assets / tag
    d.mkdir(parents=True)
    (d / pages.HTML_ASSET).write_bytes(html)
    (d / pages.JSON_ASSET).write_text(json.dumps(combined), encoding="utf-8")
    return {"tag": tag, "published_at": published,
            "url": f"https://github.com/x/y/releases/tag/{tag}"}


def test_site_layout_and_files_copied_unchanged(tmp_path):
    assets = tmp_path / "assets"
    ok = _combined([["passed", "passed"]] * 3)
    rels = [
        _release(assets, "v0.21.0", ok, b"<html>21</html>", "2026-09-30T17:54:12Z"),
        _release(assets, "v0.22.0", ok, b"<html>22</html>", "2026-10-20T08:00:00Z"),
    ]
    out = tmp_path / "site"
    pages.build(rels, assets, "v0.22.0", out)

    audit = out / "audit"
    assert (audit / "index.html").read_bytes() == b"<html>22</html>"
    assert (audit / "v0.21.0" / "index.html").read_bytes() == b"<html>21</html>"
    assert (audit / "v0.22.0" / "report.json").read_bytes() == \
        (assets / "v0.22.0" / pages.JSON_ASSET).read_bytes()
    history = (audit / "history.html").read_text(encoding="utf-8")
    # newest first, latest marked, UTC timestamps
    body = history[history.index("<tbody>"):]
    assert body.index("v0.22.0") < body.index("v0.21.0")
    assert "v0.22.0</a> (latest)" in history
    assert "2026-09-30 17:54:12" in history


def test_history_lists_every_release_beyond_one_api_page(tmp_path):
    """The releases API returns at most 100 entries per page; every release
    with a report must still appear -- none may drop out of the archive."""
    assets = tmp_path / "assets"
    ok = _combined([["passed"]] * 3)
    n = 105
    rels = [_release(assets, f"v0.{i}.0", ok, published=f"2026-01-01T00:00:{i % 60:02d}Z")
            for i in range(n)]
    pages.build(rels, assets, "v0.104.0", tmp_path / "site")
    audit = tmp_path / "site" / "audit"
    history = (audit / "history.html").read_text(encoding="utf-8")
    body = history[history.index("<tbody>"):history.index("</tbody>")]
    assert body.count("<tr") == n
    assert sorted(p.name for p in audit.iterdir() if p.is_dir()) == sorted(r["tag"] for r in rels)


def test_workflow_lists_releases_without_a_page_limit():
    """`gh api --paginate` follows every page; `gh release list` stops at
    30 entries (or at its --limit) without saying so."""
    workflow = (ROOT / ".github" / "workflows" / "audit-pages.yml").read_text(encoding="utf-8")
    assert 'gh api --paginate "repos/$REPO/releases"' in workflow
    assert "gh release list" not in workflow


def test_latest_is_githubs_latest_not_the_newest_published(tmp_path):
    """Re-publishing an old release must not make it the site's latest."""
    assets = tmp_path / "assets"
    ok = _combined([["passed"]] * 3)
    rels = [
        _release(assets, "v0.22.0", ok, b"new", "2026-10-20T08:00:00Z"),
        _release(assets, "v0.21.0", ok, b"old", "2026-11-01T08:00:00Z"),
    ]
    pages.build(rels, assets, "v0.22.0", tmp_path / "site")
    assert (tmp_path / "site" / "audit" / "index.html").read_bytes() == b"new"


def test_badge_pass_and_fail(tmp_path):
    assets = tmp_path / "assets"
    rels = [_release(assets, "v1", _combined([["passed", "failed"]] + [["passed", "passed"]] * 2))]
    pages.build(rels, assets, "v1", tmp_path / "site")
    badge = json.loads((tmp_path / "site" / "audit" / "badge.json").read_text(encoding="utf-8"))
    assert badge == {"schemaVersion": 1, "label": "forensic audit",
                     "message": "FAIL · 2 checks", "color": "red"}

    s = forensic_report.release_summary(_combined([["passed", "skipped"]] * 3))
    assert json.loads(forensic_report.render_badge_json(s))["message"] == "PASS · 2 checks"


def test_missing_platform_is_fail_with_note(tmp_path):
    assets = tmp_path / "assets"
    rels = [_release(assets, "v1", _combined([["passed"]] * 2, expected=3))]
    summary = pages.build(rels, assets, "v1", tmp_path / "site")
    assert summary["verdict"] == "FAIL"
    history = (tmp_path / "site" / "audit" / "history.html").read_text(encoding="utf-8")
    assert "Only 2 of 3 platforms" in history


def test_report_without_expected_platforms_uses_fallback():
    old = _combined([["passed"]] * 2, store_expected=False)
    assert forensic_report.release_summary(old, fallback_expected=3)["verdict"] == "FAIL"
    assert forensic_report.release_summary(old)["verdict"] == "PASS"
    # a stored value wins over the fallback
    stored = _combined([["passed"]] * 2, expected=2)
    assert forensic_report.release_summary(stored, fallback_expected=3)["verdict"] == "PASS"


def test_errors_are_explicit(tmp_path):
    assets = tmp_path / "assets"
    rel = _release(assets, "v1", _combined([["passed"]] * 3))
    with pytest.raises(pages.PagesError, match="latest release v2 has no audit report"):
        pages.build([rel], assets, "v2", tmp_path / "s1")
    (assets / "v1" / pages.HTML_ASSET).unlink()
    with pytest.raises(pages.PagesError, match="crush-forensic-audit.html is not attached"):
        pages.build([rel], assets, "v1", tmp_path / "s2")
    with pytest.raises(pages.PagesError, match="cannot be used as a directory name"):
        pages.build([{**rel, "tag": "../x"}], assets, "v1", tmp_path / "s3")
    (assets / "v1" / pages.HTML_ASSET).write_bytes(b"x")
    with pytest.raises(pages.PagesError, match="release v1 is listed twice"):
        pages.build([rel, rel], assets, "v1", tmp_path / "s5")
    with pytest.raises(pages.PagesError, match="no release has an audit report"):
        pages.build([], assets, "v1", tmp_path / "s4")


def test_main_reads_jsonl_and_reports_errors(tmp_path, capsys):
    assets = tmp_path / "assets"
    rel = _release(assets, "v1", _combined([["passed"]] * 3))
    jsonl = tmp_path / "releases.jsonl"
    jsonl.write_text(json.dumps(rel) + "\n\n", encoding="utf-8")
    args = ["--releases", str(jsonl), "--assets", str(assets), "--out"]
    assert pages.main([*args, str(tmp_path / "ok"), "--latest", "v1"]) == 0
    assert pages.main([*args, str(tmp_path / "bad"), "--latest", "v9"]) == 2
    assert "error: latest release v9" in capsys.readouterr().err


def test_combine_stores_expected_platforms(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "combine_forensic_audit_script", ROOT / "scripts" / "combine_forensic_audit.py"
    )
    assert spec and spec.loader
    combine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(combine)
    run = tmp_path / "run.json"
    run.write_text(json.dumps(_run("Linux", ["passed"])), encoding="utf-8")
    out = tmp_path / "c.json"
    assert combine.main([str(run), "--html", str(tmp_path / "c.html"), "--json", str(out),
                         "--expected", "3"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["expected_platforms"] == 3
