# SPDX-License-Identifier: Apache-2.0
"""Tests for SQLite freelist walking and leftover-cell carving."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from crush.core.sqlite_freelist import (
    carve_freelist_rows,
    column_affinity,
    read_raw_page,
    value_matches_affinity,
    walk_freelist_pages,
)

_PAGE_SIZE = 1024


def _make_dropped_table_db(path: Path) -> None:
    """Create a DB, fill a table across multiple pages, then drop it.

    DROP TABLE releases the table's pages onto the freelist.  SQLite writes
    trunk-page bookkeeping into the *first* freed page but leaves the
    remaining freed pages byte-for-byte untouched, so their original
    table-leaf cells are still carveable.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA page_size={_PAGE_SIZE}")
    conn.execute("PRAGMA auto_vacuum=NONE")
    # secure_delete zeroes freed pages on deletion — some SQLite builds default
    # it ON (e.g. several Linux distro packages), which would defeat this test
    # and, in the field, defeat freelist recovery itself. Force it OFF to
    # exercise the "carveable leftover data" path this module targets.
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    padding = "x" * 400
    for i in range(30):
        conn.execute(
            "INSERT INTO messages (body) VALUES (?)", (f"secret-{i}-{padding}",)
        )
    conn.commit()
    conn.execute("DROP TABLE messages")
    conn.commit()
    conn.close()


def test_walk_freelist_pages_finds_freed_pages(tmp_path: Path) -> None:
    db_path = tmp_path / "dropped.db"
    _make_dropped_table_db(db_path)

    entries = walk_freelist_pages(db_path, _PAGE_SIZE)

    assert entries
    kinds = {e["kind"] for e in entries}
    assert "trunk" in kinds
    # Every page number is unique — no duplicate/cyclic entries.
    pages = [e["page"] for e in entries]
    assert len(pages) == len(set(pages))


def test_walk_freelist_pages_empty_db_returns_nothing(tmp_path: Path) -> None:
    db_path = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()

    page_size = sqlite3.connect(str(db_path)).execute("PRAGMA page_size").fetchone()[0]
    assert not walk_freelist_pages(db_path, page_size)


def test_carve_freelist_rows_recovers_dropped_data(tmp_path: Path) -> None:
    db_path = tmp_path / "dropped.db"
    _make_dropped_table_db(db_path)

    carved = carve_freelist_rows(db_path, _PAGE_SIZE)

    assert carved
    all_values = [v for entry in carved for _rowid, v in entry["rows"]]
    bodies = [v[1] for v in all_values if len(v) > 1]
    assert any(isinstance(b, str) and b.startswith("secret-") for b in bodies)


def test_read_raw_page_out_of_range_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "dropped.db"
    _make_dropped_table_db(db_path)

    assert read_raw_page(db_path, 0, _PAGE_SIZE) is None
    assert read_raw_page(db_path, 999_999, _PAGE_SIZE) is None


_OVERFLOW_PAGE_SIZE = 512


def _make_dropped_overflow_db(path: Path, n_filler_tables: int) -> str:
    """Create a DB with one row whose TEXT payload spans several overflow
    pages, then drop it. *n_filler_tables* dummy tables are created and
    dropped first to pre-seed the freelist trunk with spare leaf capacity —
    without that margin, the table's own overflow pages would be the first
    ones ever freed and one of them would become the *new* trunk page
    (overwriting its content), rather than landing as an untouched leaf
    entry on an already-established trunk. Returns the inserted TEXT value.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA page_size={_OVERFLOW_PAGE_SIZE}")
    conn.execute("PRAGMA secure_delete=OFF")

    for i in range(n_filler_tables):
        conn.execute(f"CREATE TABLE dummy{i} (id INTEGER PRIMARY KEY, x TEXT)")
        conn.execute(f"INSERT INTO dummy{i} (x) VALUES ('seed')")
    conn.commit()
    for i in range(n_filler_tables):
        conn.execute(f"DROP TABLE dummy{i}")
    conn.commit()

    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
    big_text = "OVERFLOWSTART-" + ("ABCDEFGHIJ" * 200) + "-OVERFLOWEND"
    conn.execute("INSERT INTO t (body) VALUES (?)", (big_text,))
    conn.commit()
    conn.execute("DROP TABLE t")
    conn.commit()
    conn.close()
    return big_text


def test_carve_freelist_rows_reconstructs_overflow_value_exactly(tmp_path: Path) -> None:
    db_path = tmp_path / "overflow.db"
    big_text = _make_dropped_overflow_db(db_path, n_filler_tables=20)

    carved = carve_freelist_rows(db_path, _OVERFLOW_PAGE_SIZE)

    recovered = [
        v for entry in carved for _rowid, values in entry["rows"]
        for v in values if isinstance(v, str) and v.startswith("OVERFLOWSTART")
    ]
    assert recovered == [big_text]


def test_carve_freelist_rows_falls_back_safely_when_chain_hits_a_trunk_page(
    tmp_path: Path,
) -> None:
    """Without filler margin, the dropped table's own overflow pages are the
    first ever freed, so one becomes the freelist trunk and its content is
    overwritten with trunk bookkeeping. The chain must stop there rather
    than splice trunk-page bytes into the reconstructed value."""
    db_path = tmp_path / "overflow_no_margin.db"
    _make_dropped_overflow_db(db_path, n_filler_tables=0)

    carved = carve_freelist_rows(db_path, _OVERFLOW_PAGE_SIZE)

    all_values = [v for entry in carved for _rowid, values in entry["rows"] for v in values]
    assert "<OVERFLOW>" in all_values
    assert not any(
        isinstance(v, str) and v.startswith("OVERFLOWSTART") for v in all_values
    )


def test_column_affinity_follows_sqlite_type_rules() -> None:
    assert column_affinity("INTEGER") == "INTEGER"
    assert column_affinity("BIGINT") == "INTEGER"
    assert column_affinity("VARCHAR(255)") == "TEXT"
    assert column_affinity("CLOB") == "TEXT"
    assert column_affinity("BLOB") == "BLOB"
    assert column_affinity("") == "BLOB"
    assert column_affinity(None) == "BLOB"
    assert column_affinity("DOUBLE") == "REAL"
    assert column_affinity("FLOAT") == "REAL"
    assert column_affinity("NUMERIC") == "NUMERIC"
    assert column_affinity("DATE") == "NUMERIC"


def test_value_matches_affinity_text_column_rejects_numeric_storage() -> None:
    # A TEXT-affinity column can only ever hold NULL, TEXT or BLOB -- SQLite
    # converts anything else to text form before storing it.
    assert value_matches_affinity("hello", "TEXT") is True
    assert value_matches_affinity(b"raw", "TEXT") is True
    assert value_matches_affinity(None, "TEXT") is True
    assert value_matches_affinity(42, "TEXT") is False
    assert value_matches_affinity(3.14, "TEXT") is False


def test_value_matches_affinity_numeric_family_is_permissive() -> None:
    # NUMERIC/INTEGER/REAL affinity columns can end up holding any storage
    # class (unparseable text is kept as TEXT, BLOB literals bypass
    # conversion entirely), so this gives no rejection signal.
    for affinity in ("INTEGER", "REAL", "NUMERIC"):
        assert value_matches_affinity(42, affinity) is True
        assert value_matches_affinity(3.14, affinity) is True
        assert value_matches_affinity("not-a-number", affinity) is True
        assert value_matches_affinity(b"blob", affinity) is True
        assert value_matches_affinity(None, affinity) is True


def test_value_matches_affinity_blob_column_accepts_anything() -> None:
    assert value_matches_affinity(42, "BLOB") is True
    assert value_matches_affinity("text", "BLOB") is True
    assert value_matches_affinity(b"raw", "BLOB") is True
    assert value_matches_affinity(None, "BLOB") is True
