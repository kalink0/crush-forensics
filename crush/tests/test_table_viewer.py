# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for TableViewer's virtual blob-tab path/metadata (crush/viewers/table_viewer.py)."""
from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt

from crush.viewers.table_viewer import TableViewer, _format_wal_frame_content


def _make_viewer() -> TableViewer:
    data = {"t1": {"columns": ["id", "data"], "rows": [[1, b"hello"]]}}
    return TableViewer(data, source_name="mydb.sqlite")


def test_normal_table_path_and_metadata(qapp) -> None:
    tv = _make_viewer()
    idx = tv._table_view.model().index(0, 2)  # 0=Row, 1=id, 2=data
    col_header = tv._table_view.model().headerData(2, Qt.Orientation.Horizontal)
    path, meta = tv._virtual_cell_path_and_metadata(idx, col_header)
    assert path == "/virtual/mydb.sqlite/t1/data/1"
    assert meta == {"Source column": "data", "Source row": "1", "Source table": "t1"}


def test_different_queries_produce_different_paths(qapp) -> None:
    """Regression: the query-mode path used to hardcode the literal "query"
    for every query, so two different queries could collide on the same
    virtual path and one tab would silently show the other's data."""
    tv = _make_viewer()
    idx = tv._table_view.model().index(0, 2)
    col_header = tv._table_view.model().headerData(2, Qt.Orientation.Horizontal)
    tv._query_results_active = True

    tv._last_executed_query = "SELECT id, data FROM t1 WHERE id=1"
    path_a, meta_a = tv._virtual_cell_path_and_metadata(idx, col_header)
    tv._last_executed_query = "SELECT id, data FROM t1 WHERE id=2"
    path_b, meta_b = tv._virtual_cell_path_and_metadata(idx, col_header)

    assert path_a != path_b
    assert meta_a["Source query"] == "SELECT id, data FROM t1 WHERE id=1"
    assert meta_b["Source query"] == "SELECT id, data FROM t1 WHERE id=2"
    assert "Source table" not in meta_a


def test_editing_sql_input_after_run_does_not_change_already_shown_results_path(
    qapp, tmp_path: Path
) -> None:
    """Regression: the path/metadata used to read the SQL editor's *live*
    text at cell-open time instead of the query that actually produced the
    currently-displayed results. Editing the box (without re-running)
    between opening two cells from the same still-displayed result set must
    not change what "Source query" reports for either of them."""
    db_path = tmp_path / "t.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE t1 (id INTEGER, data BLOB)")
    conn.execute("INSERT INTO t1 VALUES (1, ?)", (b"hello",))
    conn.execute("INSERT INTO t1 VALUES (2, ?)", (b"world",))
    conn.commit()
    conn.close()

    data = {"t1": {"columns": ["id", "data"], "rows": []}, "__db_path": str(db_path)}
    tv = TableViewer(data, source_name="t.sqlite")

    tv._sql_input.setPlainText("SELECT id, data FROM t1 WHERE id = 1")
    tv._run_sql()
    assert tv._query_results_active

    idx0 = tv._table_view.model().index(0, 2)
    col_header = tv._table_view.model().headerData(2, Qt.Orientation.Horizontal)
    path_1, meta_1 = tv._virtual_cell_path_and_metadata(idx0, col_header)

    # Edit the box afterwards WITHOUT re-running — still-displayed results
    # are still from the id=1 query.
    tv._sql_input.setPlainText("SELECT id, data FROM t1 WHERE id = 2")
    path_2, meta_2 = tv._virtual_cell_path_and_metadata(idx0, col_header)

    assert path_1 == path_2
    assert meta_1["Source query"] == meta_2["Source query"] == "SELECT id, data FROM t1 WHERE id = 1"


def test_switching_tables_clears_stale_cell_detail_box(qapp) -> None:
    """Regression for #73: the cell-detail box at the bottom of the view
    kept showing the previously selected cell's data after switching
    tables via the dropdown, until a new cell was clicked in the freshly
    loaded (unselected) table."""
    data = {
        "t1": {"columns": ["id", "data"], "rows": [[1, "alpha"]]},
        "t2": {"columns": ["id", "data"], "rows": [[1, "beta"]]},
    }
    tv = TableViewer(data, source_name="mydb.sqlite")

    idx = tv._table_view.model().index(0, 2)
    tv._table_view.setCurrentIndex(idx)
    tv._on_current_cell_changed(idx, QModelIndex())
    assert "alpha" in tv._cell_detail_view.toPlainText()

    tv._load_table("t2")

    assert tv._cell_detail_view.toPlainText() == ""
    assert tv._cell_detail_label.text() == "—  No cell selected"


def test_switching_to_plain_table_clears_stale_sql_status(qapp) -> None:
    """Same bug class as #73, found in a fourth spot: the status line below
    the SQL box (e.g. WAL Frames' "double-click to open in hex viewer" hint,
    or Freelist Recovery's carve summary) is tab-specific but was never
    cleared on switch -- a plain table's own loader never touches it, so it
    kept describing whichever generated tab was visited last."""
    data = {
        "t1": {"columns": ["id", "data"], "rows": [[1, "alpha"]]},
    }
    tv = TableViewer(data, source_name="mydb.sqlite")

    tv._sql_status.setStyleSheet("color: red;")
    tv._sql_status.setText("Error scanning freelist pages: boom")

    tv._load_table("t1")

    assert tv._sql_status.text() == ""
    assert tv._sql_status.styleSheet() == ""


def test_freelist_table_filter_change_clears_stale_cell_detail_box(qapp) -> None:
    """Same bug class as #73, found in a second spot: switching the Freelist
    Recovery tab's "View as" filter bypasses _load_table entirely, so it
    never got the fix applied there."""
    tv = _make_viewer()
    tv._cell_detail_label.setText("Row 1  ·  data")
    tv._cell_detail_view.setPlainText("alpha")

    tv._freelist_render_state = ([], [], {})
    tv._on_freelist_table_filter_changed("(all tables)")

    assert tv._cell_detail_view.toPlainText() == ""
    assert tv._cell_detail_label.text() == "—  No cell selected"


def test_running_query_clears_stale_cell_detail_box(qapp, tmp_path: Path) -> None:
    """Same bug class as #73, found in a third spot: running a SQL query
    swaps in a whole new model but never cleared the cell-detail box either."""
    db_path = tmp_path / "t.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE t1 (id INTEGER, data TEXT)")
    conn.execute("INSERT INTO t1 VALUES (1, 'alpha')")
    conn.commit()
    conn.close()

    data = {"t1": {"columns": ["id", "data"], "rows": [[1, "alpha"]]}, "__db_path": str(db_path)}
    tv = TableViewer(data, source_name="t.sqlite")
    tv._table_combo.setCurrentText("t1")

    idx = tv._table_view.model().index(0, 2)
    tv._table_view.setCurrentIndex(idx)
    tv._on_current_cell_changed(idx, QModelIndex())
    assert "alpha" in tv._cell_detail_view.toPlainText()

    tv._sql_input.setPlainText("SELECT id, data FROM t1")
    tv._run_sql()

    assert tv._cell_detail_view.toPlainText() == ""
    assert tv._cell_detail_label.text() == "—  No cell selected"


def test_format_wal_frame_content_uses_real_column_names() -> None:
    rows = [(1, ["alice", 30]), (2, ["bob", 25])]
    text = _format_wal_frame_content(rows, ["name", "age"])
    assert text == "1: [name=alice, age=30]; 2: [name=bob, age=25]"


def test_format_wal_frame_content_falls_back_to_positional_on_column_mismatch() -> None:
    """No column-name list, or one whose length doesn't match the decoded
    row's value count (unknown/stale table mapping) — show plain values
    rather than misaligning them with the wrong names."""
    rows = [(1, ["x", "y", "z"])]
    assert _format_wal_frame_content(rows, []) == "1: [x, y, z]"
    assert _format_wal_frame_content(rows, ["only_one_col"]) == "1: [x, y, z]"


def _make_live_wal_db(path: Path) -> sqlite3.Connection:
    """Create a real WAL-mode DB with a committed frame still sitting in the
    -wal file. Returns the writer connection -- keep it open for the rest of
    the test, since closing the last connection to a WAL-mode database
    checkpoints and removes the -wal file (wal_autocheckpoint=0 only stops
    the *automatic* per-commit checkpoint, not the close-time one)."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.commit()
    conn.execute("INSERT INTO messages (body) VALUES ('hello-wal-content')")
    conn.commit()
    return conn


def test_wal_frames_content_column_decodes_row(qapp, tmp_path: Path) -> None:
    """The WAL Frames tab's Content column should decode a frame's page and
    show the actual row values, using real column names for a page mapped
    to a known table."""
    db_path = tmp_path / "live.db"
    writer = _make_live_wal_db(db_path)
    try:
        data = {
            "__db_path": str(db_path),
            "messages": {"columns": ["id", "body"], "rows": [[1, "hello-wal-content"]]},
        }
        tv = TableViewer(data, source_name="live.db")
        tv._load_wal_frames()

        model = tv._source_model
        headers = [
            model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
        ]
        assert "Content" in headers
        content_col = headers.index("Content")

        contents = [model.item(r, content_col).text() for r in range(model.rowCount())]
        assert any("hello-wal-content" in c for c in contents)
        assert any("body=hello-wal-content" in c for c in contents)
    finally:
        writer.close()


def _make_dropped_table_db(path: Path) -> None:
    """Create a DB, fill a table across multiple pages, then drop it.

    DROP TABLE frees the table's pages onto the freelist; with
    secure_delete=OFF and no VACUUM, everything but the first freed page
    (which gets overwritten with trunk bookkeeping) keeps its original
    table-leaf bytes, so the freed rows are still carveable. Mirrors the
    fixture in test_sqlite_freelist.py, but written to a real path (not a
    NamedTemporaryFile) so a TableViewer can open it as __db_path.
    """
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA page_size=1024")
    conn.execute("PRAGMA auto_vacuum=NONE")
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    padding = "x" * 400
    for i in range(30):
        conn.execute("INSERT INTO messages (body) VALUES (?)", (f"secret-{i}-{padding}",))
    conn.commit()
    conn.execute("DROP TABLE messages")
    conn.commit()
    conn.close()


def test_freelist_recovery_tab_carves_dropped_table_rows(qapp, tmp_path: Path) -> None:
    """End-to-end regression guard: a dropped table's freed pages still carry
    old row data (secure_delete=OFF, no VACUUM), so the Freelist Recovery tab
    must show carved rows rather than "0 rows carved". The core carving
    functions already have unit tests in test_sqlite_freelist.py; this covers
    the TableViewer wiring on top (schema lookup, model population, status
    text) that those don't touch."""
    db_path = tmp_path / "dropped.db"
    _make_dropped_table_db(db_path)

    tv = TableViewer({"__db_path": str(db_path)}, source_name="dropped.db")
    tv._freelist_cache = tv._get_freelist_data()  # precompute -> fast path, no bg thread
    tv._load_freelist_recovery()

    model = tv._source_model
    cell_texts = [
        model.item(r, c).text()
        for r in range(model.rowCount())
        for c in range(model.columnCount())
        if model.item(r, c) is not None
    ]
    assert any("secret-" in t for t in cell_texts)
    assert "0 rows carved" not in tv._row_count_label.text()


def test_freeblocks_all_zero_data_shown_explicitly(qapp) -> None:
    """A freeblock whose leftover bytes are all zero (secure_delete was on,
    or the space was never written before being linked into the freeblock)
    decodes fine but renders as an invisible blank cell -- indistinguishable
    from "nothing here" even though Size (B) shows a real freeblock. The
    Data column must say so explicitly instead of looking empty."""
    tv = _make_viewer()
    tv._reset_source_model()
    freeblocks = [{"page": 2, "offset": 100, "size": 20, "data": b"\x00" * 16}]
    tv._populate_freeblocks_table(freeblocks, {}, set())

    model = tv._source_model
    headers = [
        model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
    ]
    data_col = headers.index("Data")
    assert model.item(0, data_col).text() == "(all zero — 16 B)"


def test_freeblocks_nonzero_data_still_shown_as_text(qapp) -> None:
    """Regression guard alongside the all-zero case above: real leftover
    content must still render as plain decoded text, not the placeholder."""
    tv = _make_viewer()
    tv._reset_source_model()
    freeblocks = [{"page": 2, "offset": 100, "size": 20, "data": b"secret-payload"}]
    tv._populate_freeblocks_table(freeblocks, {}, set())

    model = tv._source_model
    headers = [
        model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
    ]
    data_col = headers.index("Data")
    assert model.item(0, data_col).text() == "secret-payload"


def test_freelist_recovery_tab_always_present(qapp, tmp_path: Path) -> None:
    """Regression: the Freelist Recovery tab used to be added to the table
    combo only if PRAGMA freelist_count (read live, through the connection)
    was nonzero at construction time -- inconsistent with Freeblocks/
    Unallocated, which are always present and just report "nothing found".
    A DB with no freed pages at all must still show the tab."""
    db_path = tmp_path / "clean.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()

    tv = TableViewer({"__db_path": str(db_path)}, source_name="clean.db")
    items = [tv._table_combo.itemText(i) for i in range(tv._table_combo.count())]
    assert tv._freelist_label in items


def test_freelist_recovery_sees_pages_freed_only_in_uncheckpointed_wal(
    qapp, tmp_path: Path
) -> None:
    """Regression: walk_freelist_pages()/carve_freelist_rows() used to read
    only the base file's raw bytes, completely ignoring a live -wal
    sidecar. A DROP TABLE recorded only in the WAL (wal_autocheckpoint=0, no
    checkpoint yet) updates the freelist header and frees pages *only*
    inside not-yet-checkpointed WAL frames -- a plain base-file scan sees
    the pre-drop header (first_trunk=0) and reports "No freelist pages
    found" despite a live connection's PRAGMA freelist_count already being
    nonzero. This is exactly the inconsistency a user hit in practice
    (tab shown -- because __init__ checks freelist_count live -- but the
    scan itself came back empty)."""
    db_path = tmp_path / "live.db"
    writer = sqlite3.connect(str(db_path))
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA page_size=1024")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("PRAGMA secure_delete=OFF")
        writer.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
        writer.commit()
        padding = "x" * 400
        for i in range(30):
            writer.execute(
                "INSERT INTO messages (body) VALUES (?)", (f"secret-{i}-{padding}",)
            )
        writer.commit()
        writer.execute("DROP TABLE messages")
        writer.commit()

        # Sanity check on the premise: raw base-file header must indeed
        # still show no freelist (that's what makes this a WAL-only state).
        raw_header = db_path.read_bytes()[:100]
        assert struct.unpack_from(">I", raw_header, 32)[0] == 0

        tv = TableViewer({"__db_path": str(db_path)}, source_name="live.db")
        entries, carved = tv._get_freelist_data()
        assert entries
        assert carved
        assert any(
            "secret-" in v
            for c in carved
            for _rowid, values in c["rows"]
            for v in values
            if isinstance(v, str)
        )
    finally:
        writer.close()


def test_freelist_recovery_tab_explains_zero_carved_rows(qapp, tmp_path: Path) -> None:
    """When freed pages exist but genuinely hold nothing recoverable (e.g.
    secure_delete was on at write time), the status text must say so
    explicitly rather than leaving a bare "0 rows carved" that reads like a
    broken feature."""
    db_path = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA page_size=1024")
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()

    tv = TableViewer({"__db_path": str(db_path)}, source_name="empty.db")
    # No real freelist needed to exercise this path -- feed one synthetic
    # freed-page entry with no carved rows directly, bypassing the scan.
    tv._freelist_cache = ([{"page": 2, "kind": "leaf"}], [])
    tv._load_freelist_recovery()

    assert "0 rows carved" in tv._row_count_label.text()
    assert "not a parsing failure" in tv._sql_status.text()


def test_open_bytes_with_format_requested_carries_metadata_dict(qapp) -> None:
    """The signal must accept fmt=None (auto-detect) alongside the new
    metadata dict without a PySide6 signature mismatch."""
    tv = _make_viewer()
    received = []
    tv.open_bytes_with_format_requested.connect(
        lambda data, name, fmt, meta: received.append((data, name, fmt, meta))
    )
    tv.open_bytes_with_format_requested.emit(b"hi", "/virtual/db/t1/data/1", None, {"Source table": "t1"})
    assert received == [(b"hi", "/virtual/db/t1/data/1", None, {"Source table": "t1"})]
