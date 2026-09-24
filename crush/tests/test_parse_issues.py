"""ParseIssue contract: codes, English catalog rendering, and the parsers
that already report through it (JSON, SQLite WAL; Realm is covered in
test_parsers.py / test_forensic.py)."""
from __future__ import annotations

import re
from pathlib import Path

from crush.core.vfs import DirectoryVFS
from crush.parsers.issues import MESSAGES, ParseIssue, render, render_value
from crush.parsers.json_parser import JsonParser
from crush.parsers.sqlite_wal_parser import SQLiteWALParser

_PARSERS_DIR = Path(__file__).resolve().parent.parent / "parsers"


def _node(tmp_path: Path, name: str, content: bytes):  # type: ignore[no-untyped-def]
    (tmp_path / name).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return node, vfs


# -- catalog ------------------------------------------------------------------

def test_every_code_used_by_a_parser_has_a_catalog_entry() -> None:
    used: set[str] = set()
    for path in _PARSERS_DIR.glob("*.py"):
        used |= set(re.findall(r'ParseIssue\(\s*"([a-z0-9_.]+)"', path.read_text("utf-8")))
    assert used, "no ParseIssue codes found -- scan pattern broken?"
    missing = sorted(used - MESSAGES.keys())
    assert missing == [], f"codes without an English template: {missing}"


def test_unknown_code_still_renders_everything_it_carries() -> None:
    text = render(ParseIssue("x.unknown", {"offset": 12}, detail="lib says no"))
    assert "x.unknown" in text
    assert "offset=12" in text
    assert "lib says no" in text


def test_nested_issues_render_recursively_and_lists_join() -> None:
    issue = ParseIssue("realm.pre_cluster_partial", {"reasons": [
        ParseIssue("realm.table_failed", {
            "table": "class_A", "reason": ParseIssue("realm.spec_no_columns"),
        }),
        ParseIssue("realm.pre_cluster_undecoded_columns", {"columns": 2, "tables": 1}),
    ]})
    assert str(issue) == (
        "Pre-Cluster layout — class_A: Spec array has no columns (empty or malformed); "
        "2 column(s) across 1 table(s) not yet decoded (unimplemented old column type)"
    )


def test_render_value_leaves_plain_values_as_before() -> None:
    assert render_value("1,024 B") == "1,024 B"
    assert render_value(3) == "3"
    assert render_value(ParseIssue("sqlite_wal.invalid")) == (
        "Not a valid WAL file (magic mismatch or file too short)"
    )


# -- JSON ---------------------------------------------------------------------

def test_json_syntax_error_reports_location_and_excerpt_around_it(tmp_path: Path) -> None:
    # Error far past the first 500 chars: the old view (first 500 chars
    # only) never showed it.
    body = "[" + ", ".join(str(i) for i in range(2000)) + ", oops]"
    node, vfs = _node(tmp_path, "broken.json", body.encode())
    result = JsonParser().parse(node, vfs)

    status = result.metadata["Status"]
    assert status.code == "json.syntax_error"
    assert "line 1 column" in status.detail
    assert status.detail in str(status)

    error_pos = body.index("oops")
    (key, excerpt), = [(k, v) for k, v in result.data.items() if k.startswith("excerpt")]
    m = re.fullmatch(r"excerpt \(chars ([\d,]+)–([\d,]+) of ([\d,]+)\)", key)
    assert m is not None
    start, end, total = (int(g.replace(",", "")) for g in m.groups())
    assert total == len(body)
    assert start <= error_pos < end
    assert excerpt == body[start:end]
    assert "raw" not in result.data


def test_json_invalid_utf8_is_reported_not_silently_replaced(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "latin1.json", b'{"name": "M\xfcller"}')
    result = JsonParser().parse(node, vfs)
    enc = result.metadata["Encoding"]
    assert enc.code == "json.not_utf8"
    assert enc.params["offset"] == 11
    assert "offset 11" in str(enc)


def test_valid_json_carries_no_issue(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "ok.json", b'{"a": 1}')
    result = JsonParser().parse(node, vfs)
    assert not any(isinstance(v, ParseIssue) for v in result.metadata.values())


# -- SQLite WAL ---------------------------------------------------------------

def test_wal_invalid_file_status_code_and_unchanged_wording(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "x.db-wal", b"\x37\x7f\x06\x82" + b"\x00" * 10)
    result = SQLiteWALParser().parse(node, vfs)
    assert result.metadata["Status"].code == "sqlite_wal.invalid"
    assert str(result.metadata["Status"]) == (
        "Not a valid WAL file (magic mismatch or file too short)"
    )
    assert result.metadata["Note"].code == "sqlite_wal.standalone"
