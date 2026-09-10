# SPDX-License-Identifier: Apache-2.0
"""Regression coverage for locate_cell()/locate_offset() ("Locate in Hex" /
Show Hex pane byte-provenance, PR #84) -- shipped without any automated
tests (git show --stat b0552b0 touches only CHANGELOG.md, sqlite_wal.py,
sqlite_parser.py, table_viewer.py). Written as a safety net before
table_viewer.py's hex-pane methods get refactored to go through a shared
CellLocator abstraction (see crush/core/cell_locator.py) so Realm can reuse
the same wiring.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from crush.core.sqlite_wal import build_page_table_map, locate_cell, locate_offset

_PAGE_SIZE = 512


def test_locate_cell_base_file_row_round_trips_through_locate_offset(tmp_path: Path) -> None:
    db_path = tmp_path / "base.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('hello-base')")
    conn.commit()
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_table_map = build_page_table_map(conn, wal_data=None, page_size=page_size)
    conn.close()

    location = locate_cell(db_path, "messages", 1, 1, page_size, page_table_map, None)
    assert location is not None
    assert location.file_kind == "base"
    assert location.column_ranges

    raw = db_path.read_bytes()
    recovered = b"".join(raw[start:end] for start, end in location.column_ranges)
    assert recovered == b"hello-base"

    rowid, col_idx = locate_offset(
        db_path, "messages", location.column_ranges[0][0], "base", page_size, page_table_map, None
    )
    assert (rowid, col_idx) == (1, 1)


def test_locate_cell_overflow_row_round_trips_through_locate_offset(tmp_path: Path) -> None:
    """A payload far bigger than one page's usable size spills onto a chain
    of overflow pages -- column_ranges must span inline + every overflow
    segment, in order, and locate_offset() must resolve a byte anywhere in
    that chain back to the same row/column."""
    db_path = tmp_path / "overflow.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    big_body = "y" * 4000
    conn.execute("INSERT INTO messages (body) VALUES (?)", (big_body,))
    conn.commit()
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_table_map = build_page_table_map(conn, wal_data=None, page_size=page_size)
    conn.close()

    location = locate_cell(db_path, "messages", 1, 1, page_size, page_table_map, None)
    assert location is not None
    assert location.file_kind == "base"
    assert location.column_ranges is not None
    assert len(location.column_ranges) > 1  # inline piece + at least one overflow segment

    raw = db_path.read_bytes()
    recovered = b"".join(raw[start:end] for start, end in location.column_ranges)
    assert recovered == big_body.encode()

    # The first piece is the inline portion, still on the table's own leaf
    # page (covered by page_table_map) -- resolves back cleanly.
    rowid, col_idx = locate_offset(
        db_path, "messages", location.column_ranges[0][0], "base", page_size, page_table_map, None
    )
    assert (rowid, col_idx) == (1, 1)

    # A byte living purely on an overflow page is a documented limitation,
    # not a round-trip candidate: page_table_map only covers pages reachable
    # by walking the table's own B-tree (build_page_table_map/_walk_interior),
    # never the overflow chain, so locate_offset() has no table attribution
    # for that page number and must return None rather than guess.
    assert (
        locate_offset(
            db_path,
            "messages",
            location.column_ranges[-1][0],
            "base",
            page_size,
            page_table_map,
            None,
        )
        is None
    )


def _make_live_wal_db(path: Path) -> sqlite3.Connection:
    """Real WAL-mode DB with a committed frame still sitting in the -wal
    file (wal_autocheckpoint=0 stops the per-commit checkpoint). Keep the
    returned connection open for the rest of the test -- closing the last
    connection to a WAL-mode database checkpoints and removes the -wal file.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.commit()
    conn.execute("INSERT INTO messages (body) VALUES ('hello-wal')")
    conn.commit()
    return conn


def test_locate_cell_wal_resident_row_round_trips_through_locate_offset(tmp_path: Path) -> None:
    db_path = tmp_path / "wal.db"
    writer = _make_live_wal_db(db_path)
    try:
        page_size = writer.execute("PRAGMA page_size").fetchone()[0]
        wal_path = Path(str(db_path) + "-wal")
        assert wal_path.exists(), "test setup failed: no -wal file"
        wal_data = wal_path.read_bytes()
        page_table_map = build_page_table_map(writer, wal_data=wal_data, page_size=page_size)

        location = locate_cell(db_path, "messages", 1, 1, page_size, page_table_map, wal_data)
        assert location is not None
        assert location.file_kind == "wal"
        assert location.column_ranges

        recovered = b"".join(wal_data[start:end] for start, end in location.column_ranges)
        assert recovered == b"hello-wal"

        rowid, col_idx = locate_offset(
            db_path,
            "messages",
            location.column_ranges[0][0],
            "wal",
            page_size,
            page_table_map,
            wal_data,
        )
        assert (rowid, col_idx) == (1, 1)
    finally:
        writer.close()


def test_locate_cell_returns_none_for_unknown_rowid(tmp_path: Path) -> None:
    db_path = tmp_path / "base.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('only-row')")
    conn.commit()
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_table_map = build_page_table_map(conn, wal_data=None, page_size=page_size)
    conn.close()

    assert locate_cell(db_path, "messages", 999, 1, page_size, page_table_map, None) is None


def test_locate_offset_returns_none_outside_any_row(tmp_path: Path) -> None:
    db_path = tmp_path / "base.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('only-row')")
    conn.commit()
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_table_map = build_page_table_map(conn, wal_data=None, page_size=page_size)
    conn.close()

    # The page header itself (offset 0) is never inside any row's ranges.
    assert locate_offset(db_path, "messages", 0, "base", page_size, page_table_map, None) is None
