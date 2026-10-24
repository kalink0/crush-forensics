# SPDX-License-Identifier: Apache-2.0
"""Which -wal frames count as the database's current state: only the log
SQLite itself reads (salts and cumulative checksums valid, up to the last
commit frame). Uncommitted tails and frames outside the log must never be
resolved as "current" by the page index/overlay every raw-byte path uses.
"""
from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from crush.core.issues import ParseIssue
from crush.core.sqlite_wal import (
    build_page_table_map,
    build_wal_page_index,
    build_wal_page_overlay,
    classify_wal_frames,
    locate_cell,
)

_PAGE_SIZE = 512
_FRAME_SIZE = 24 + _PAGE_SIZE


def _wal_db(path: Path) -> sqlite3.Connection:
    """WAL-mode DB, schema checkpointed into the base file, autocheckpoint
    off. Keep the connection open: closing the last one checkpoints and
    removes the -wal."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("CREATE TABLE filler (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return conn


def _committed_wal(tmp_path: Path, transactions: int) -> bytes:
    """Raw -wal bytes after *transactions* separate committed inserts."""
    db_path = tmp_path / "multi.db"
    conn = _wal_db(db_path)
    try:
        for i in range(transactions):
            conn.execute("INSERT INTO messages (body) VALUES (?)", (f"row-{i}",))
        return Path(str(db_path) + "-wal").read_bytes()
    finally:
        conn.close()


def _flip(data: bytes, offset: int) -> bytes:
    return data[:offset] + bytes([data[offset] ^ 0xFF]) + data[offset + 1:]


def _active_offsets(frames: list[dict]) -> dict[int, int]:
    return {f["page"]: f["offset"] + 24 for f in frames if f["status"] == "Active"}


def test_uncommitted_tail_is_not_current_state(tmp_path: Path) -> None:
    """A WAL copied while a transaction is open (SQLite spilled dirty pages
    into it without a commit frame): the uncommitted version of the row's
    page must not be what the index, overlay or locate_cell() resolve.

    The filler inserts go to another table so the updated messages page is
    evicted from the 1-page cache and spilled. Mid-transaction, SQLite can
    leave frames with stale checksums and zero salts behind the spilled
    ones (it rewrites frames in place and fixes checksums only at commit),
    so the tail may also hold Invalid and WAL slack frames."""
    db_path = tmp_path / "live.db"
    conn = _wal_db(db_path)
    try:
        conn.execute("INSERT INTO messages (body) VALUES ('committed-v1')")
        conn.execute("PRAGMA cache_size=1")
        conn.execute("BEGIN")
        conn.execute("UPDATE messages SET body = 'uncommitted-v2' WHERE id = 1")
        conn.executemany(
            "INSERT INTO filler (body) VALUES (?)", [("x" * 200,) for _ in range(200)]
        )
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        shutil.copy(db_path, evidence / "live.db")
        shutil.copy(Path(str(db_path) + "-wal"), evidence / "live.db-wal")
        conn.execute("ROLLBACK")
    finally:
        conn.close()

    copy_db = evidence / "live.db"
    wal = (evidence / "live.db-wal").read_bytes()
    page_size, frames = classify_wal_frames(wal)
    spilled = [
        f for f in frames
        if f["status"] in ("Uncommitted", "Invalid")
        and b"uncommitted-v2" in wal[f["offset"] + 24:f["offset"] + _FRAME_SIZE]
    ]
    assert spilled, "SQLite didn't spill the updated page; the test setup no longer works"

    index = build_wal_page_index(wal, page_size)
    assert {pn: off for pn, (off, _b) in index.items()} == _active_offsets(frames)
    overlay = build_wal_page_overlay(wal, page_size)
    assert all(b"uncommitted-v2" not in page for page in overlay.values())
    assert any(b"committed-v1" in page for page in overlay.values())

    ro = sqlite3.connect(f"file:{copy_db}?immutable=1", uri=True)
    try:
        page_table_map = build_page_table_map(ro, wal, page_size)
    finally:
        ro.close()
    location = locate_cell(copy_db, "messages", 1, 1, page_size, page_table_map, wal)
    assert location is not None
    assert location.file_kind == "wal"
    assert b"".join(wal[s:e] for s, e in location.column_ranges) == b"committed-v1"


def test_real_wal_checksums_validate(tmp_path: Path) -> None:
    wal = _committed_wal(tmp_path, 3)
    problems: list[ParseIssue] = []
    _page_size, frames = classify_wal_frames(wal, problems)
    assert frames and not problems
    assert {f["status"] for f in frames} <= {"Active", "Superseded"}
    assert all(f["reason"] is None for f in frames)


def test_checksum_mismatch_ends_the_log(tmp_path: Path) -> None:
    wal = _committed_wal(tmp_path, 3)
    _page_size, clean = classify_wal_frames(wal)
    # First frame of the last transaction: everything before it is two
    # complete transactions.
    last_tx = max(f["tx"] for f in clean)
    bad = next(f for f in clean if f["tx"] == last_tx)
    corrupted = _flip(wal, bad["offset"] + 24 + 100)

    _page_size, frames = classify_wal_frames(corrupted)
    before = [f for f in frames if f["frame"] < bad["frame"]]
    after = [f for f in frames if f["frame"] >= bad["frame"]]
    assert all(f["status"] == "Invalid" and f["tx"] is None for f in after)
    assert after[0]["reason"].code == "sqlite_wal.frame_checksum_mismatch"
    assert all(
        f["reason"] == ParseIssue("sqlite_wal.frame_after_checksum_mismatch",
                                  {"frame": bad["frame"]})
        for f in after[1:]
    )
    assert before[-1]["is_commit"] and before[-1]["status"] == "Active"
    assert {f["status"] for f in before} <= {"Active", "Superseded"}

    index = build_wal_page_index(corrupted, _PAGE_SIZE)
    assert {pn: off for pn, (off, _b) in index.items()} == _active_offsets(before)


def test_header_checksum_mismatch_ignores_whole_wal(tmp_path: Path) -> None:
    wal = _committed_wal(tmp_path, 2)
    corrupted = _flip(wal, 12)  # checkpoint sequence number: covered by the checksum, not a salt

    problems: list[ParseIssue] = []
    _page_size, frames = classify_wal_frames(corrupted, problems)
    assert [p.code for p in problems] == ["sqlite_wal.header_checksum_mismatch"]
    assert frames and all(f["status"] == "Invalid" for f in frames)
    assert all(f["reason"].code == "sqlite_wal.frame_after_header_mismatch" for f in frames)
    assert build_wal_page_index(corrupted, _PAGE_SIZE) == {}


def test_header_page_size_not_power_of_two_ignores_whole_wal(tmp_path: Path) -> None:
    wal = _committed_wal(tmp_path, 1)
    corrupted = wal[:8] + (1000).to_bytes(4, "big") + wal[12:]

    problems: list[ParseIssue] = []
    _page_size, frames = classify_wal_frames(corrupted, problems)
    assert problems == [ParseIssue("sqlite_wal.header_page_size_invalid", {"page_size": 1000})]
    assert all(f["status"] in ("Invalid", "WAL slack") for f in frames)
    assert build_wal_page_index(corrupted, _PAGE_SIZE) == {}


def test_salt_valid_frames_after_salt_mismatch_are_invalid(tmp_path: Path) -> None:
    wal = _committed_wal(tmp_path, 3)
    _page_size, clean = classify_wal_frames(wal)
    slack = clean[1]
    corrupted = _flip(wal, slack["offset"] + 8)  # frame salt-1

    _page_size, frames = classify_wal_frames(corrupted)
    assert frames[0]["status"] in ("Active", "Superseded", "Uncommitted")
    assert frames[1]["status"] == "WAL slack" and frames[1]["reason"] is None
    assert all(
        f["status"] == "Invalid"
        and f["reason"] == ParseIssue("sqlite_wal.frame_after_salt_mismatch", {"frame": 2})
        for f in frames[2:]
    )


def test_standalone_parser_reports_invalid_frames(tmp_path: Path) -> None:
    from crush.core.vfs import DirectoryVFS
    from crush.parsers.sqlite_wal_parser import SQLiteWALParser

    wal = _committed_wal(tmp_path, 2)
    out = tmp_path / "standalone"
    out.mkdir()
    (out / "x.db-wal").write_bytes(_flip(wal, 12))

    vfs = DirectoryVFS(out)
    node = next(c for c in vfs.root().children if c.name == "x.db-wal")
    meta = SQLiteWALParser().parse(node, vfs).metadata
    assert meta["Active"] == "0"
    assert meta["Invalid"] == str(len(wal[32:]) // _FRAME_SIZE)
    assert meta["Log end"].code == "sqlite_wal.log_end"
    assert [p.code for p in meta["Status"]] == ["sqlite_wal.header_checksum_mismatch"]
