"""ParseIssue contract: codes, English catalog rendering, and the parsers
that already report through it (JSON, SQLite WAL; Realm is covered in
test_parsers.py / test_forensic.py)."""
from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtWidgets import QLabel

from crush.core.vfs import DirectoryVFS
from crush.core.issues import MESSAGES, ParseIssue, render, render_value
from crush.parsers.json_parser import JsonParser
from crush.parsers.sqlite_wal_parser import SQLiteWALParser

_SOURCE_DIR = Path(__file__).resolve().parent.parent


def _node(tmp_path: Path, name: str, content: bytes):  # type: ignore[no-untyped-def]
    (tmp_path / name).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return node, vfs


# -- catalog ------------------------------------------------------------------

def test_every_code_used_in_source_has_a_catalog_entry() -> None:
    used: set[str] = set()
    for path in _SOURCE_DIR.rglob("*.py"):
        if "tests" in path.relative_to(_SOURCE_DIR).parts:
            continue
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


# -- SQLite -------------------------------------------------------------------

def _make_db(path: Path) -> None:
    import sqlite3
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()


def test_sqlite_unreadable_companion_is_reported_not_silently_skipped(
    tmp_path: Path, monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    from crush.parsers.sqlite_parser import SQLiteParser

    _make_db(tmp_path / "a.db")
    (tmp_path / "a.db-wal").write_bytes(b"\x37\x7f\x06\x82" + b"\x00" * 60)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "a.db")

    real_read = vfs.read

    def _read(n):  # type: ignore[no-untyped-def]
        if n.name == "a.db-wal":
            raise OSError("device not ready")
        return real_read(n)

    monkeypatch.setattr(vfs, "read", _read)
    result = SQLiteParser().parse(node, vfs)

    failures = result.metadata["Companion files not loaded"]
    assert [f.code for f in failures] == ["sqlite.companion_read_failed"]
    assert failures[0].params["name"] == "a.db-wal"
    assert failures[0].detail == "device not ready"
    assert "device not ready" in render_value(failures)
    assert [i.code for i in result.data["__wal_diag"]] == ["sqlite.companion_read_failed"]


def test_sqlcipher_rejection_carries_code_and_library_detail(tmp_path: Path) -> None:
    import pytest

    from crush.core.passwords import WrongPasswordError
    from crush.parsers.sqlite_parser import SQLiteParser

    _make_db(tmp_path / "plain.db")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "plain.db")

    with pytest.raises(WrongPasswordError) as excinfo:
        SQLiteParser().parse(node, vfs, password="zz-not-hex", raw_key=True)
    issue = excinfo.value.args[0]
    assert issue.code == "sqlite.invalid_hex_key"
    assert str(excinfo.value).startswith("Not a valid hex key: ")


# -- password retry prompts ---------------------------------------------------

def test_retry_prompts_show_the_rejection_reason(qapp) -> None:  # type: ignore[no-untyped-def]
    from crush.ui.main_window import _with_reason
    from crush.ui.mmkv_key_dialog import MMKVKeyDialog
    from crush.ui.sqlcipher_dialog import SQLCipherCredentialsDialog

    assert _with_reason("Try again:", "Key must be 64 bytes") == (
        "Key must be 64 bytes\n\nTry again:"
    )
    assert _with_reason("Try again:", "") == "Try again:"

    for dialog_cls in (MMKVKeyDialog, SQLCipherCredentialsDialog):
        retry = dialog_cls(wrong_reason="Key must be 64 bytes")
        texts = [lbl.text() for lbl in retry.findChildren(QLabel)]
        assert any(t.startswith("Key must be 64 bytes\n\n") for t in texts), dialog_cls
        first = dialog_cls()
        assert not any("Try again" in lbl.text() for lbl in first.findChildren(QLabel))


def test_sqlcipher_rejection_prompt_omits_misleading_library_text(tmp_path: Path) -> None:
    """SQLCipher reports every failed page decrypt as "file is not a
    database"; in a password prompt that reads as "not a database"."""
    import pytest

    from crush.core.passwords import WrongPasswordError
    from crush.parsers.sqlite_parser import _connect_sqlcipher

    from sqlcipher3 import dbapi2 as sqlcipher

    db = tmp_path / "enc.db"
    con = sqlcipher.connect(str(db))
    con.execute("PRAGMA key = 'hunter2'")
    con.execute("CREATE TABLE t (x)")
    con.commit()
    con.close()

    with pytest.raises(WrongPasswordError) as excinfo:
        _connect_sqlcipher(str(db), "wrong")
    issue = excinfo.value.args[0]
    assert issue.code == "sqlite.password_rejected"
    assert issue.detail  # library text kept on the issue
    assert issue.detail not in str(excinfo.value)
    assert str(excinfo.value) == (
        "Incorrect password, or an unsupported SQLCipher version/parameters"
    )


def test_sqlite_journal_mode_shows_only_what_the_header_records(tmp_path: Path) -> None:
    """Header bytes 18/19 store only WAL vs. rollback; "delete" etc. is the
    connection's default and must not be shown as the file's state."""
    import sqlite3

    from crush.parsers.sqlite_parser import SQLiteParser

    _make_db(tmp_path / "rollback.db")
    wal_db = tmp_path / "wal.db"
    con = sqlite3.connect(wal_db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (x)")
    con.commit()
    con.close()
    assert wal_db.read_bytes()[18:20] == b"\x02\x02"

    vfs = DirectoryVFS(tmp_path)
    nodes = {c.name: c for c in vfs.root().children}
    rollback = SQLiteParser().parse(nodes["rollback.db"], vfs).metadata["Journal mode"]
    assert rollback.code == "sqlite.journal_mode_rollback"
    assert "delete" not in str(rollback).split("(")[0].lower()
    assert SQLiteParser().parse(nodes["wal.db"], vfs).metadata["Journal mode"] == "WAL"
