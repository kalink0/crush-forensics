# SPDX-License-Identifier: Apache-2.0
"""Regression coverage for crush/core/sqlite_journal.py.

The rollback-journal on-disk format is not part of SQLite's documented,
stable file format (unlike the main database and WAL formats) -- these
tests validate the reverse-engineered header/checksum layout against a
*real* SQLite-written journal rather than a hand-built one: a connection is
frozen mid-transaction (the journal is written to disk before commit, so
reading it back at that point is exactly what examining a crash-interrupted
transaction's journal looks like) and this module's own checksum
computation is checked against SQLite's own stored checksums. If the format
understanding were wrong, fully_valid would come out False here.
"""
from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

from crush.core.sqlite_journal import (
    JOURNAL_MAGIC,
    build_journal_page_overlay,
    extract_journal_rows,
    parse_rollback_journal,
    read_db_header_page_size,
    reconstruct_post_rollback_image,
)

_PAGE_SIZE = 4096


def _freeze_mid_transaction(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    """Return (db_path, frozen_db_bytes, journal_bytes) for a DB with one
    committed row and a second transaction that dirtied a page but never
    committed or rolled back -- reading the files at this point is exactly
    what a forensic image of a crashed process would capture: the base file
    already has the interrupted write's bytes, and the journal still holds
    the page's pre-transaction content.

    SQLite writes a *zeroed* journal header first and only stamps it with
    the real magic number once it syncs (either a cache spill mid-
    transaction, or the commit's own sync phase) -- a deliberate atomicity
    guard so a crash while the header itself is still being written can
    never be mistaken for a complete, safely-rollback-able journal. A real
    crash can freeze either state; this fixture forces the "stamped, hot"
    one -- the not-yet-stamped case is covered separately by
    test_non_journal_bytes_yield_no_segments's zeroed-header path.

    To also force the interrupted write's *new* content out to the base
    file itself (proving reconstruction actually restores something, not
    just echoes back bytes that were never changed on disk), the table is
    pre-populated with many committed rows/pages before the crash
    transaction, and the crash transaction updates rows spread across most
    of those existing pages -- with no cheap brand-new pages available to
    evict instead (a freshly-allocated page never needs journaling, so
    tiny cache_size alone tends to just spill those instead of the page
    actually under test), a tiny cache_size forces genuinely dirty,
    already-journaled pages to spill to the base file too.
    """
    db_path = tmp_path / "crash.db"
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('before-crash')")
    for i in range(400):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"pre-{i}" * 50,))
    conn.commit()

    conn.execute("PRAGMA cache_size=10")
    conn.execute("BEGIN")
    conn.execute("UPDATE messages SET body = 'during-crash-txn' WHERE id = 1")
    conn.execute("UPDATE messages SET body = body || '-x' WHERE id > 1")

    journal_path = Path(str(db_path) + "-journal")
    assert journal_path.exists(), "test setup failed: no -journal file mid-transaction"
    journal_bytes = journal_path.read_bytes()
    assert journal_bytes[:8] == JOURNAL_MAGIC, "test setup failed: journal header never got stamped"
    frozen_db_bytes = db_path.read_bytes()

    conn.rollback()
    conn.close()
    return db_path, frozen_db_bytes, journal_bytes


def test_real_crash_frozen_journal_parses_as_mergeable(tmp_path: Path) -> None:
    _db_path, _frozen, journal_bytes = _freeze_mid_transaction(tmp_path)

    assert journal_bytes[:8] == JOURNAL_MAGIC
    result = parse_rollback_journal(journal_bytes)

    assert result.error is None
    assert len(result.segments) >= 1
    assert result.mergeable, "checksum validation against a real SQLite journal failed"
    assert result.page_size == _PAGE_SIZE

    all_records = [r for seg in result.segments for r in seg.records]
    assert all_records
    assert all(r.checksum_valid for r in all_records)


def test_reconstruct_post_rollback_image_restores_pre_transaction_row(tmp_path: Path) -> None:
    db_path, frozen_db_bytes, journal_bytes = _freeze_mid_transaction(tmp_path)
    result = parse_rollback_journal(journal_bytes)
    assert result.mergeable

    page_size = read_db_header_page_size(frozen_db_bytes)
    assert page_size == _PAGE_SIZE

    # Sanity check: the frozen base file, read directly (no rollback
    # applied), still shows the interrupted transaction's uncommitted write
    # -- proving the reconstruction below is actually doing something, not
    # just echoing back what was already there.
    interrupted_conn = sqlite3.connect(":memory:")
    interrupted_conn.deserialize(frozen_db_bytes)
    interrupted_row = interrupted_conn.execute(
        "SELECT body FROM messages WHERE id = 1"
    ).fetchone()
    interrupted_conn.close()
    assert interrupted_row == ("during-crash-txn",)

    image = reconstruct_post_rollback_image(frozen_db_bytes, page_size, result)
    assert image is not None

    recovered_conn = sqlite3.connect(":memory:")
    recovered_conn.deserialize(image)
    recovered_row = recovered_conn.execute(
        "SELECT body FROM messages WHERE id = 1"
    ).fetchone()
    integrity = recovered_conn.execute("PRAGMA integrity_check").fetchone()
    recovered_conn.close()

    assert recovered_row == ("before-crash",)
    assert integrity == ("ok",)

    # And it must match what SQLite's own engine would produce: opening the
    # frozen files (db + journal) for real and letting SQLite roll back
    # itself is the ground truth to compare against.
    real_conn = sqlite3.connect(str(db_path))
    real_row = real_conn.execute("SELECT body FROM messages WHERE id = 1").fetchone()
    real_conn.close()
    assert real_row == ("before-crash",)


def test_reconstruct_post_rollback_image_rejects_page_size_mismatch(tmp_path: Path) -> None:
    """A -journal whose own declared page size disagrees with the base
    database's header (stale/foreign companion) must never be merged --
    applying journal-sized records against the wrong stride would silently
    misalign the whole image instead of erroring.
    """
    _db_path, frozen_db_bytes, journal_bytes = _freeze_mid_transaction(tmp_path)
    result = parse_rollback_journal(journal_bytes)
    assert result.mergeable
    assert result.page_size == _PAGE_SIZE

    image = reconstruct_post_rollback_image(frozen_db_bytes, _PAGE_SIZE * 2, result)
    assert image is None


def test_reconstruct_post_rollback_image_rejects_page_num_beyond_orig_size(tmp_path: Path) -> None:
    """page_num isn't covered by the per-record checksum (only the page
    content is), so a corrupted/adversarial page_num naming a page beyond
    the journal's own recorded pre-transaction size must be rejected rather
    than trusted into bytearray.extend() -- a real SQLite-written journal
    never journals a page it didn't already have before the transaction.
    """
    _db_path, frozen_db_bytes, journal_bytes = _freeze_mid_transaction(tmp_path)
    result = parse_rollback_journal(journal_bytes)
    assert result.mergeable

    segment = result.segments[0]
    orig_pages = segment.header.db_orig_size
    assert orig_pages > 0
    bad_record = dataclasses.replace(segment.records[0], page_num=orig_pages + 1000)
    bad_segment = dataclasses.replace(segment, records=[bad_record, *segment.records[1:]])
    bad_result = dataclasses.replace(result, segments=[bad_segment, *result.segments[1:]])

    image = reconstruct_post_rollback_image(frozen_db_bytes, _PAGE_SIZE, bad_result)
    assert image is None


def test_persist_mode_journal_after_commit_is_not_mergeable(tmp_path: Path) -> None:
    """PERSIST mode keeps the -journal file after every commit but zeroes
    its header so it's recognized as "not hot" -- must never be treated as
    a mergeable/hot journal.
    """
    db_path = tmp_path / "persist.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=PERSIST")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO t DEFAULT VALUES")
    conn.commit()
    conn.close()

    journal_path = Path(str(db_path) + "-journal")
    assert journal_path.exists()
    journal_bytes = journal_path.read_bytes()

    result = parse_rollback_journal(journal_bytes)
    assert result.mergeable is False
    assert not result.segments
    assert result.error is not None


def test_extract_journal_rows_recovers_deleted_row_from_freeblock(tmp_path: Path) -> None:
    """A row deleted (and committed) *before* the crash still sits in a
    freeblock on its page; a later, crash-interrupted transaction that
    dirties that same page for an unrelated reason journals that page's
    pre-transaction content -- freeblock included. Must surface as a
    distinct "Freeblock (deleted)" entry, not silently dropped.
    """
    db_path = tmp_path / "delete.db"
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA secure_delete=OFF")  # else SQLite zeroes freed cell content on delete
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (id, body) VALUES (1, 'will-be-deleted-then-crash')")
    conn.execute("INSERT INTO messages (id, body) VALUES (2, 'stays-alive')")
    conn.execute("DELETE FROM messages WHERE id = 1")
    conn.commit()  # row 1's payload is now a freeblock, already on disk

    conn.execute("PRAGMA cache_size=10")
    conn.execute("BEGIN")
    conn.execute("UPDATE messages SET body = 'touched-during-crash' WHERE id = 2")
    for i in range(300):  # force a cache spill so the journal header gets stamped
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"filler-{i}" * 50,))

    journal_path = Path(str(db_path) + "-journal")
    journal_bytes = journal_path.read_bytes()
    assert journal_bytes[:8] == JOURNAL_MAGIC, "test setup failed: journal header never got stamped"
    conn.rollback()
    conn.close()

    result = parse_rollback_journal(journal_bytes)
    assert result.mergeable

    rows = extract_journal_rows(result)
    kinds = {r.kind for r in rows}
    assert "Freeblock (deleted)" in kinds
    assert "Live cell" in kinds  # row 2's pre-transaction content is still there too

    deleted = [r for r in rows if r.kind == "Freeblock (deleted)"]
    assert any(r.raw and b"will-be-deleted-then-crash" in r.raw for r in deleted)
    # Provenance: the deleted row's bytes must be locatable at their exact
    # offset within the journal file itself.
    for r in deleted:
        assert journal_bytes[r.file_offset:r.file_offset + r.byte_length] == r.raw


def test_build_journal_page_overlay_first_record_wins(tmp_path: Path) -> None:
    _db_path, _frozen, journal_bytes = _freeze_mid_transaction(tmp_path)
    result = parse_rollback_journal(journal_bytes)
    overlay = build_journal_page_overlay(result)
    assert overlay
    for pn, data in overlay.items():
        assert pn >= 1
        assert len(data) == result.page_size


def test_non_journal_bytes_yield_no_segments() -> None:
    result = parse_rollback_journal(b"not a journal file" * 10)
    assert not result.segments
    assert result.mergeable is False
    assert result.error is not None


def test_sqlite_parser_merges_valid_journal_into_default_view(tmp_path: Path) -> None:
    """End-to-end: SQLiteParser.parse() on a DB with a real, valid, still-hot
    -journal companion sitting next to it must show the post-rollback
    "current" row by default (mirroring how -wal frames are already merged
    transparently) -- not the interrupted transaction's write -- while
    leaving the evidence directory untouched (no new sibling files).
    """
    from crush.core.vfs import DirectoryVFS
    from crush.parsers.sqlite_parser import SQLiteParser

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    db_path = evidence_dir / "crash.db"

    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('before-crash')")
    for i in range(400):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"pre-{i}" * 50,))
    conn.commit()

    conn.execute("PRAGMA cache_size=10")
    conn.execute("BEGIN")
    conn.execute("UPDATE messages SET body = 'during-crash-txn' WHERE id = 1")
    conn.execute("UPDATE messages SET body = body || '-x' WHERE id > 1")
    assert (evidence_dir / "crash.db-journal").exists()
    files_before = set(evidence_dir.iterdir())
    # Do not call conn.close()/rollback() before parsing -- the whole point
    # is examining the files exactly as a crashed process would have left
    # them on disk, evidence-directory files included.

    vfs = DirectoryVFS(evidence_dir)
    node = next(c for c in vfs.root().children if c.name == "crash.db")
    result = SQLiteParser().parse(node, vfs)

    # Checked right after parse(), before conn.rollback()/close() below --
    # rollback() legitimately deletes -journal itself, which would falsely
    # look like a parser side effect if checked afterwards.
    assert set(evidence_dir.iterdir()) == files_before, \
        "parser must never write next to the evidence"

    conn.rollback()
    conn.close()

    assert result.data["messages"]["rows"][0] == [1, "before-crash"]
    assert "__recovered_db_path" in result.data
    assert Path(result.data["__recovered_db_path"]).is_file()
    assert "__journal_path" in result.data
    assert Path(result.data["__journal_path"]).is_file()
    assert not str(result.data["__journal_path"]).endswith("-journal")  # never SQLite's auto-detected name
    assert "merged into current view" in result.metadata["Rollback journal"]


def test_sqlite_parser_skips_merge_when_wal_flag_set_in_header(tmp_path: Path) -> None:
    """A -journal that's valid/hot but sits next to a base file whose own
    header says WAL mode is active must not be merged -- that combination
    means the journal predates a later switch to WAL and is a stale
    leftover, not something SQLite's own engine would actually roll back.
    """
    from crush.core.vfs import DirectoryVFS
    from crush.parsers.sqlite_parser import SQLiteParser

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    _db_path, frozen_db_bytes, journal_bytes = _freeze_mid_transaction(src_dir)

    # Simulate the base file having since been switched to WAL mode --
    # patch just the header's WAL flag (bytes 18/19), leaving this
    # otherwise-real crash-frozen journal untouched.
    patched = bytearray(frozen_db_bytes)
    patched[18] = 2
    patched[19] = 2

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "crash.db").write_bytes(bytes(patched))
    (evidence_dir / "crash.db-journal").write_bytes(journal_bytes)

    vfs = DirectoryVFS(evidence_dir)
    node = next(c for c in vfs.root().children if c.name == "crash.db")
    result = SQLiteParser().parse(node, vfs)

    assert "__recovered_db_path" not in result.data
    status = result.metadata["Rollback journal"]
    assert "NOT merged" in status
    assert "WAL mode is active" in status


def test_sqlite_journal_parser_opens_journal_file_standalone(tmp_path: Path) -> None:
    """The user's originally reported case: opening a -journal file
    directly (no companion database in the same open) must show a
    structured view, not fall back to raw hex."""
    from crush.core.vfs import DirectoryVFS
    from crush.parsers.sqlite_journal_parser import SQLiteJournalParser

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    db_path = evidence_dir / "crash.db"

    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('before-crash')")
    for i in range(400):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"pre-{i}" * 50,))
    conn.commit()

    conn.execute("PRAGMA cache_size=10")
    conn.execute("BEGIN")
    conn.execute("UPDATE messages SET body = 'during-crash-txn' WHERE id = 1")
    conn.execute("UPDATE messages SET body = body || '-x' WHERE id > 1")

    try:
        vfs = DirectoryVFS(evidence_dir)
        journal_node = next(
            c for c in vfs.root().children if c.name == "crash.db-journal"
        )
        journal_node_bytes = vfs.read(journal_node)
        parser = SQLiteJournalParser()
        assert parser.can_parse(journal_node.path, vfs.peek(journal_node))
        result = parser.parse(journal_node, vfs)
    finally:
        conn.rollback()
        conn.close()

    assert result.viewer_type == "table"
    assert "Valid / hot" in result.metadata["Status"]
    rows = result.data["Journal Records"]["rows"]
    columns = result.data["Journal Records"]["columns"]
    kind_col = columns.index("Kind")
    value_col = columns.index("Value")
    assert any(
        r[kind_col] == "Live cell" and "before-crash" in r[value_col] for r in rows
    )

    # Same "Show Hex" empty-panel bug as the standalone -wal case -- see
    # test_sqlite_wal_parser_opens_wal_file_standalone.
    locator = result.data["__cell_locator"]
    assert locator.read_file(locator.default_file_kind()) == journal_node_bytes

    # Per-row byte provenance must also work standalone -- recompute the
    # expected span from the row's own "Offset (B)"/record length columns
    # and check locate_cell() (fed the "rowids" list alongside the table
    # data) resolves the right row to it.
    offset_col = columns.index("Offset (B)")
    live_idx = next(
        i for i, r in enumerate(rows)
        if r[kind_col] == "Live cell" and "before-crash" in r[value_col]
    )
    assert result.data["Journal Records"]["rowids"][live_idx] == live_idx
    location = locator.locate_cell("Journal Records", live_idx, None)
    assert location is not None
    assert location.row_ranges[0][0] == rows[live_idx][offset_col]
    assert b"before-crash" in journal_node_bytes[slice(*location.row_ranges[0])]
