# SPDX-License-Identifier: Apache-2.0
"""Tests for crush/core/sqlite_strings.py -- strings in a SQLite database
and its companions, attributed to the file-format region they sit in."""
from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from crush.core.sqlite_freeblocks import scan_database_freeblocks
from crush.core.sqlite_strings import FileStrings, Region, scan_sqlite_strings


def _regions_of(fs: FileStrings, needle: str) -> list[list[Region]]:
    return [
        [fs.regions[i] for i in idx]
        for hit, idx in zip(fs.hits, fs.hit_regions)
        if needle in hit.value
    ]


def _file(result, kind: str) -> FileStrings:
    return next(fs for fs in result.files if fs.file_kind == kind)


def _codes(result) -> list[str]:
    return [p.code for p in result.problems]


def _make_db(path: Path, page_size: int = 1024) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("CREATE INDEX messages_body ON messages(body)")
    for i in range(10):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"row-{i}-payload-CANARY{i:02d}",))
    conn.execute("INSERT INTO messages (body) VALUES (?)", ("LONGVALUE-" + "y" * 3000 + "-TAIL",))
    conn.commit()
    conn.execute("DELETE FROM messages WHERE id = 5")
    conn.commit()
    conn.close()


def test_every_hit_is_attributed_and_offsets_point_at_the_bytes(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    result = scan_sqlite_strings(db)
    base = _file(result, "base")
    data = db.read_bytes()
    assert base.hits
    for hit, idx in zip(base.hits, base.hit_regions):
        assert idx, hit
        assert data[hit.offset:hit.end].decode("utf-8") == hit.value
        assert base.regions[idx[0]].start <= hit.offset < base.regions[idx[0]].end
        assert base.regions[idx[-1]].start < hit.end <= base.regions[idx[-1]].end


def test_regions_from_the_file_format(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    base = _file(scan_sqlite_strings(db), "base")

    header = _regions_of(base, "SQLite format 3")[0]
    assert (header[0].kind, header[0].area, header[0].page) == ("table leaf", "database header", 1)

    live = _regions_of(base, "CANARY03")
    kinds = {(r.kind, r.area, r.attribution) for regions in live for r in regions}
    assert ("table leaf", "cell content area", "walk") in kinds
    assert ("index leaf", "cell content area", "walk") in kinds

    # Freeblock areas are exactly the ranges the Freeblocks view carves.
    page_size = 1024
    expected = {
        ((fb["page"] - 1) * page_size + fb["offset"],
         (fb["page"] - 1) * page_size + fb["offset"] + fb["size"])
        for fb in scan_database_freeblocks(db, page_size)
    }
    table_freeblocks = {
        (r.start, r.end) for r in base.regions if r.kind == "table leaf" and r.area == "freeblock"
    }
    assert expected and table_freeblocks == expected

    overflow = [r for rs in _regions_of(base, "yyyy") for r in rs if r.kind == "overflow"]
    assert overflow and all(r.attribution == "walk" for r in overflow)


def test_freelist_pages_are_labelled(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA page_size=1024")
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE gone (body TEXT)")
    for i in range(40):
        conn.execute("INSERT INTO gone VALUES (?)", (f"dropped-table-text-{i:03d}" * 3,))
    conn.execute("CREATE TABLE kept (body TEXT)")
    conn.execute("INSERT INTO kept VALUES ('still here')")
    conn.commit()
    conn.execute("DROP TABLE gone")
    conn.commit()
    conn.close()

    base = _file(scan_sqlite_strings(db), "base")
    # Where each string starts (one may run on into the next page's header).
    kinds = {rs[0].kind for rs in _regions_of(base, "dropped-table-text")}
    assert kinds and kinds <= {"freelist trunk", "freelist leaf"}


def test_pointer_map_pages_in_auto_vacuum_database(tmp_path: Path) -> None:
    db = tmp_path / "av.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA page_size=1024")
    conn.execute("PRAGMA auto_vacuum=FULL")
    conn.execute("CREATE TABLE t (body TEXT)")
    conn.execute("INSERT INTO t VALUES ('auto vacuum row')")
    conn.commit()
    conn.close()
    base = _file(scan_sqlite_strings(db), "base")
    page2 = [r for r in base.regions if r.page == 2]
    assert [r.kind for r in page2] == ["pointer map"]


def test_wal_frames_current_copy_walked_older_copy_by_type_byte(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    conn = sqlite3.connect(str(src))
    conn.execute("PRAGMA page_size=1024")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE m (body TEXT)")
    conn.execute("INSERT INTO m VALUES ('first-version-text')")
    conn.commit()
    conn.execute("UPDATE m SET body = 'second-version-text'")
    conn.commit()
    out = tmp_path / "copy"
    out.mkdir()
    shutil.copy(src, out / "live.db")
    shutil.copy(str(src) + "-wal", out / "live.db-wal")
    conn.close()

    result = scan_sqlite_strings(out / "live.db", out / "live.db-wal")
    wal = _file(result, "wal")
    data = (out / "live.db-wal").read_bytes()
    for hit in wal.hits:
        assert data[hit.offset:hit.end].decode("utf-8") == hit.value

    current = [r for rs in _regions_of(wal, "second-version-text") for r in rs]
    assert current and current[0].frame is not None
    assert current[0].frame_status == "Active"
    assert (current[0].kind, current[0].attribution) == ("table leaf", "walk")

    older = [r for rs in _regions_of(wal, "first-version-text") for r in rs]
    assert older and older[0].frame_status == "Superseded"
    assert older[0].attribution == "type byte"

    assert any(r.kind == "WAL header" for r in wal.regions)
    assert any(r.kind == "WAL frame header" for r in wal.regions)


def test_journal_records_are_attributed(tmp_path: Path) -> None:
    db = tmp_path / "crash.db"
    conn = sqlite3.connect(str(db), isolation_level=None)
    conn.execute("PRAGMA page_size=1024")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('before-crash')")
    for i in range(400):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"pre-{i}" * 20,))
    conn.commit()
    conn.execute("PRAGMA cache_size=10")
    conn.execute("BEGIN")
    conn.execute("UPDATE messages SET body = 'during-crash-txn' WHERE id = 1")
    conn.execute("UPDATE messages SET body = body || '-x' WHERE id > 1")
    out = tmp_path / "copy"
    out.mkdir()
    shutil.copy(db, out / "crash.db")
    shutil.copy(str(db) + "-journal", out / "crash.db-journal")
    conn.rollback()
    conn.close()

    result = scan_sqlite_strings(out / "crash.db", None, out / "crash.db-journal")
    journal = _file(result, "journal")
    regions = [r for rs in _regions_of(journal, "before-crash") for r in rs]
    assert regions and regions[0].record is not None
    assert regions[0].attribution == "type byte"
    assert any(r.kind == "journal header" for r in journal.regions)
    assert any(r.kind == "journal record page number" for r in journal.regions)


def test_unreadable_and_empty_companions_are_reported(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    empty_wal = tmp_path / "t.db-wal"
    empty_wal.write_bytes(b"")
    result = scan_sqlite_strings(db, empty_wal, tmp_path / "missing-journal")
    assert "strings.file_empty" in _codes(result)
    assert "strings.file_unreadable" in _codes(result)
    assert [fs.file_kind for fs in result.files] == ["base", "wal"]


def test_not_a_sqlite_file_is_scanned_without_page_attribution(tmp_path: Path) -> None:
    path = tmp_path / "not.db"
    path.write_bytes(b"\x00\x01some text here\x00")
    result = scan_sqlite_strings(path)
    assert _codes(result) == ["strings.no_page_size"]
    base = _file(result, "base")
    assert [h.value for h in base.hits] == ["some text here"]
    assert [base.regions[i].kind for i in base.hit_regions[0]] == ["no structure read"]


def test_wal_without_header_is_reported(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    wal = tmp_path / "t.db-wal"
    wal.write_bytes(b"\x00" * 40 + b"stray text in a wal" + b"\x00" * 40)
    result = scan_sqlite_strings(db, wal)
    assert "strings.wal_no_header" in _codes(result)
    assert [h.value for h in _file(result, "wal").hits] == ["stray text in a wal"]


def test_declared_utf16_database_is_searched_with_full_range(tmp_path: Path) -> None:
    db = tmp_path / "u16.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA encoding='UTF-16le'")
    conn.execute("CREATE TABLE t (body TEXT)")
    for text in ("Привет мир", "你好世界你好", "Hello World"):
        conn.execute("INSERT INTO t VALUES (?)", (text,))
    conn.commit()
    conn.close()

    result = scan_sqlite_strings(db)
    assert result.full_utf16 == "UTF-16LE"
    found = {(h.value, h.encoding) for h in _file(result, "base").hits}
    for text in ("Привет мир", "你好世界你好", "Hello World"):
        assert any(text in value and enc == "UTF-16LE (full range)" for value, enc in found)


def test_utf8_database_keeps_the_latin1_utf16_rule(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    result = scan_sqlite_strings(db)
    assert result.full_utf16 is None
    assert not any("full range" in h.encoding for h in _file(result, "base").hits)


def test_min_chars_threshold(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    few = scan_sqlite_strings(db, min_chars=20)
    many = scan_sqlite_strings(db, min_chars=4)
    assert few.min_chars == 20
    assert len(_file(few, "base").hits) < len(_file(many, "base").hits)
    assert all(len(h.value) >= 20 for h in _file(few, "base").hits)
