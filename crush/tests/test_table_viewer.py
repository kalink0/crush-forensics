# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for TableViewer's virtual blob-tab path/metadata (crush/viewers/table_viewer.py)."""
from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt

from crush.core.sqlite_freeblocks import scan_database_freeblocks
from crush.core.sqlite_unallocated import scan_database_unallocated
from crush.viewers.table_viewer import (
    TableViewer,
    _TS_UNDECODED_COLOR,
    _format_wal_frame_content,
    _STRUCTURE_BYTE_RANGE_ROLE,
    _STRUCTURE_FILE_KIND_ROLE,
)


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


def _make_live_wal_db_with_overflow(path: Path) -> tuple[sqlite3.Connection, str]:
    """Real WAL-mode DB, page_size small enough that a single big TEXT value
    spills onto an overflow page -- both the table's leaf page and its
    overflow page(s) end up WAL-resident (wal_autocheckpoint=0), same
    overflow shape as test_sqlite_wal_locate.py's fixture but kept live in
    the -wal file instead of checkpointed to the base file."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA page_size=512")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.commit()
    big_body = "z" * 4000
    conn.execute("INSERT INTO messages (body) VALUES (?)", (big_body,))
    conn.commit()
    return conn, big_body


def test_wal_frames_content_column_resolves_overflow_value(qapp, tmp_path: Path) -> None:
    """Regression: the WAL Frames tab's Content column decoded a frame's
    page via parse_table_leaf_page() without an overflow_reader, so a value
    spilling onto an overflow page rendered as the '<OVERFLOW>' sentinel
    instead of its real content -- even though the same overflow-chasing
    machinery already backs the embedded Hex pane's locate_cell()/
    locate_offset()."""
    db_path = tmp_path / "live.db"
    writer, big_body = _make_live_wal_db_with_overflow(db_path)
    try:
        data = {
            "__db_path": str(db_path),
            "messages": {"columns": ["id", "body"], "rows": [[1, big_body]]},
        }
        tv = TableViewer(data, source_name="live.db")
        tv._load_wal_frames()

        model = tv._source_model
        headers = [
            model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
        ]
        content_col = headers.index("Content")
        contents = [model.item(r, content_col).text() for r in range(model.rowCount())]

        assert any(big_body in c for c in contents)
        assert not any("<OVERFLOW>" in c for c in contents)
    finally:
        writer.close()


def _make_live_wal_db_with_superseded_overflow(path: Path) -> tuple[sqlite3.Connection, str]:
    """Real WAL-mode DB where the frame holding an overflowing row's leaf
    page gets superseded by a later commit that only adds a second,
    unrelated row to the same page -- the first row's overflow chain itself
    is never rewritten, so the superseded frame's reconstructed value must
    still match it exactly."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA page_size=512")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.commit()
    big_body = "z" * 4000
    conn.execute("INSERT INTO messages (id, body) VALUES (1, ?)", (big_body,))
    conn.commit()
    conn.execute("INSERT INTO messages (id, body) VALUES (2, 'small')")
    conn.commit()
    return conn, big_body


def test_inject_wal_rows_resolves_overflow_value(qapp, tmp_path: Path) -> None:
    """Regression: _inject_wal_rows() (the "Show WAL history" toggle's
    superseded/uncommitted row injection into the normal table view) called
    parse_table_leaf_page() without page_size or an overflow_reader at all,
    so an injected row whose value spilled onto an overflow page rendered as
    the '<OVERFLOW>' sentinel instead of its real content."""
    db_path = tmp_path / "live.db"
    writer, big_body = _make_live_wal_db_with_superseded_overflow(db_path)
    try:
        data = {"__db_path": str(db_path)}
        tv = TableViewer(data, source_name="live.db")
        tv._get_wal_frames()  # populate _page_table_map, like _load_table_impl does

        injected_rows: list[list[object]] = []

        def _append_row(
            row_data: list[object],
            source_label: str | None = None,
            row_color: object = None,
            wal_byte_range: tuple[int, int] | None = None,
            wal_row_ranges: list[tuple[int, int]] | None = None,
            wal_column_ranges: list[list[tuple[int, int]] | None] | None = None,
        ) -> None:
            injected_rows.append(row_data)

        count = tv._inject_wal_rows("messages", ["id", "body"], _append_row)

        assert count >= 1
        assert any(row[1] == big_body for row in injected_rows)
        assert not any(row[1] == "<OVERFLOW>" for row in injected_rows)
    finally:
        writer.close()


def test_normal_table_wal_history_row_hex_sync_highlights_frame(qapp, tmp_path: Path) -> None:
    """Regression: a WAL-history row injected into a normal table's own view
    ("Show WAL history" toggle checked) never highlighted anything in the
    embedded Hex pane -- _sync_hex_pane() required a rowid, which these rows
    don't have (that's the whole point: several frames on the same page can
    share one rowid, since this is showing a superseded version of it)."""
    db_path = tmp_path / "live.db"
    writer, big_body = _make_live_wal_db_with_superseded_overflow(db_path)
    try:
        data = {
            "__db_path": str(db_path),
            "messages": {"columns": ["id", "body"], "rows": [[1, big_body], [2, "small"]]},
        }
        tv = TableViewer(data, source_name="live.db")
        tv._table_combo.setCurrentText("messages")
        tv._load_table("messages")

        tv._wal_toggle.setChecked(True)  # triggers _on_wal_toggle -> reload with WAL rows

        model = tv._source_model
        headers = [
            model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
        ]
        body_col = headers.index("body")
        wal_row = next(
            r for r in range(model.rowCount())
            if model.item(r, 0).data(_STRUCTURE_BYTE_RANGE_ROLE) is not None
        )
        assert model.item(wal_row, body_col).text() == big_body

        # _sync_hex_pane() is gated on the hex panel's real Qt visibility,
        # which requires the widget to actually be shown, not just its own
        # setVisible(True) flag (see test_realm_hex_provenance.py).
        tv.show()
        tv._toggle_hex_pane()  # loads + shows the pane
        proxy_idx = tv._proxy_model.mapFromSource(model.index(wal_row, body_col))
        tv._table_view.setCurrentIndex(proxy_idx)

        assert tv._hex_file_kind == "wal"
        assert tv._hex_viewer._focus_ranges
    finally:
        writer.close()


def _make_live_wal_db_with_superseded_row(path: Path) -> sqlite3.Connection:
    """Real WAL-mode DB where an UPDATE rewrites the same row -- the frame
    holding its old value becomes Superseded. Both values stay small enough
    to stay fully inline (no overflow chain), so a column's highlighted
    bytes reconstruct to an exact, easily comparable string."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA page_size=512")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.commit()
    conn.execute("INSERT INTO messages (id, body) VALUES (1, 'first-version')")
    conn.commit()
    conn.execute("UPDATE messages SET body = 'second-version' WHERE id = 1")
    conn.commit()
    return conn


def test_normal_table_wal_history_row_hex_sync_highlights_column(qapp, tmp_path: Path) -> None:
    """Regression: a WAL-history row's hex highlight covered the entire WAL
    frame (24-byte header + whole page) no matter which column was selected,
    unlike a real row (row bytes, plus one specific column's own bytes drawn
    on top). Selecting the "body" column of a superseded row must now
    reconstruct to exactly its own old value, not the whole frame."""
    db_path = tmp_path / "live.db"
    writer = _make_live_wal_db_with_superseded_row(db_path)
    try:
        data = {
            "__db_path": str(db_path),
            "messages": {"columns": ["id", "body"], "rows": [[1, "second-version"]]},
        }
        tv = TableViewer(data, source_name="live.db")
        tv._table_combo.setCurrentText("messages")
        tv._load_table("messages")
        tv._wal_toggle.setChecked(True)

        model = tv._source_model
        headers = [
            model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())
        ]
        body_col = headers.index("body")
        wal_row = next(
            r for r in range(model.rowCount())
            if model.item(r, 0).data(_STRUCTURE_BYTE_RANGE_ROLE) is not None
        )
        assert model.item(wal_row, body_col).text() == "first-version"

        tv.show()
        tv._toggle_hex_pane()
        proxy_idx = tv._proxy_model.mapFromSource(model.index(wal_row, body_col))
        tv._table_view.setCurrentIndex(proxy_idx)

        assert tv._hex_file_kind == "wal"
        ranges = tv._hex_viewer._focus_ranges
        assert ranges
        # Narrower than the whole frame -- proves column precision, not the
        # old whole-frame highlight.
        highlighted_len = sum(e - s for s, e in ranges)
        assert highlighted_len < 24 + tv._wal_page_size

        # Row range(s) come first, drawn under the column range(s) -- same
        # order as a real cell's CellLocation.row_ranges + column_ranges.
        # The column range (the last one here, no overflow on either side)
        # must be exactly the body value's own bytes, not the row's.
        wal_data = Path(str(db_path) + "-wal").read_bytes()
        col_start, col_end = ranges[-1]
        assert wal_data[col_start:col_end] == b"first-version"
    finally:
        writer.close()


def test_wal_frames_hex_sync_highlights_selected_frame(qapp, tmp_path: Path) -> None:
    """Regression: the WAL Frames tab's rows were excluded from the embedded
    Hex pane's table<->hex sync entirely (_is_pseudo_table()), so selecting a
    frame while "Show Hex" was open never highlighted anything, and clicking
    inside that highlight in the hex pane couldn't select anything back
    either. Each row now carries its own exact byte range in the -wal file
    (frame header + page) -- used directly, since an individual WAL frame
    has no rowid/table-name identity the regular CellLocator could resolve."""
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
        offset_col = headers.index("Offset (B)")
        source_row = 0
        expected_offset = int(model.item(source_row, offset_col).text())

        proxy_idx = tv._proxy_model.mapFromSource(model.index(source_row, 0))
        tv._sync_wal_hex_pane(proxy_idx)

        assert tv._hex_file_kind == "wal"
        assert tv._hex_viewer._focus_ranges
        start, end = tv._hex_viewer._focus_ranges[0]
        assert start == expected_offset
        assert end == expected_offset + 24 + tv._wal_page_size

        # Hex → WAL Frames: clicking anywhere inside that range selects the
        # same row back.
        tv._select_row_for_byte_offset(expected_offset + 1)
        selected = tv._table_view.currentIndex()
        assert selected.isValid()
        assert tv._proxy_model.mapToSource(selected).row() == source_row
    finally:
        writer.close()


def _make_single_delete_db(path: Path, page_size: int = 1024) -> None:
    """Insert 10 rows, delete one from the middle -- a single-row DELETE
    doesn't free the whole page (freelist_count stays 0), so SQLite splices
    the cell into the page's freeblock list instead. Same fixture shape as
    test_sqlite_freeblocks.py's."""
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    for i in range(10):
        conn.execute(
            "INSERT INTO messages (body) VALUES (?)", (f"row-{i}-payload-CANARY{i:02d}",)
        )
    conn.commit()
    conn.execute("DELETE FROM messages WHERE id = 5")
    conn.commit()
    conn.close()


def test_freeblocks_hex_sync_highlights_exact_byte_range(qapp, tmp_path: Path) -> None:
    """Regression: Freeblocks rows were excluded from the embedded Hex
    pane's table<->hex sync entirely (_is_pseudo_table()), same gap the WAL
    Frames tab had. Unlike a WAL frame, a freeblock already carries an exact
    page-local (offset, size), so the fix gets cell-level precision here,
    not just whole-page."""
    db_path = tmp_path / "single_delete.db"
    page_size = 1024
    _make_single_delete_db(db_path, page_size)

    freeblocks = scan_database_freeblocks(db_path, page_size)
    assert freeblocks
    fb = freeblocks[0]
    expected_start = (fb["page"] - 1) * page_size + fb["offset"]
    expected_end = expected_start + fb["size"]

    tv = TableViewer({"__db_path": str(db_path)}, source_name="single_delete.db")
    tv._reset_source_model()
    tv._populate_freeblocks_table(freeblocks, {}, set())

    model = tv._source_model
    page_item = model.item(0, 0)
    assert page_item.data(_STRUCTURE_FILE_KIND_ROLE) == "base"
    assert page_item.data(_STRUCTURE_BYTE_RANGE_ROLE) == (expected_start, expected_end)

    tv.show()
    tv._toggle_hex_pane()
    proxy_idx = tv._proxy_model.mapFromSource(model.index(0, 0))
    tv._table_view.setCurrentIndex(proxy_idx)

    assert tv._hex_file_kind == "base"
    assert tv._hex_viewer._focus_ranges == [(expected_start, expected_end)]

    # The freeblock's own 4-byte header overwrites the first 4 bytes of the
    # old cell, so only what follows is the actual leftover row data.
    raw = db_path.read_bytes()
    assert raw[expected_start + 4:expected_end] == fb["data"]

    # Hex → Freeblocks: clicking anywhere inside that range selects the row.
    tv._select_row_for_byte_offset(expected_start + 5)
    selected = tv._table_view.currentIndex()
    assert selected.isValid()
    assert tv._proxy_model.mapToSource(selected).row() == 0


def _corrupt_page_with_unallocated_gap(
    db_path: Path, page_num: int, page_size: int, gap_fill: bytes
) -> None:
    """Overwrite one on-disk table-leaf page's cell-pointer array so the gap
    before its cell-content area holds *gap_fill* instead of whatever was
    there -- deterministic stand-in for the "usually all-zero" real gap
    (see sqlite_unallocated.py's own docstring), same page shape as
    test_sqlite_unallocated.py's _make_page()."""
    with open(db_path, "r+b") as fh:
        fh.seek((page_num - 1) * page_size)
        page = bytearray(fh.read(page_size))
        cell_count = struct.unpack_from(">H", page, 3)[0]
        ptr_array_end = 8 + cell_count * 2
        content_start = struct.unpack_from(">H", page, 5)[0] or 65536
        end = min(ptr_array_end + len(gap_fill), content_start, page_size)
        page[ptr_array_end:end] = gap_fill[: end - ptr_array_end]
        fh.seek((page_num - 1) * page_size)
        fh.write(page)


def test_unallocated_space_hex_sync_highlights_exact_byte_range(qapp, tmp_path: Path) -> None:
    """Regression: Unallocated Space rows had the same missing hex-sync gap
    as Freeblocks -- fixed the same way, using the entry's own exact
    page-local (offset, size)."""
    db_path = tmp_path / "unalloc.db"
    page_size = 1024
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('hello')")
    conn.commit()
    conn.close()

    _corrupt_page_with_unallocated_gap(db_path, 2, page_size, b"stale-pointer-leftover")

    entries = scan_database_unallocated(db_path, page_size)
    assert entries
    entry = entries[0]
    expected_start = (entry["page"] - 1) * page_size + entry["offset"]
    expected_end = expected_start + entry["size"]

    tv = TableViewer({"__db_path": str(db_path)}, source_name="unalloc.db")
    tv._reset_source_model()
    tv._populate_unallocated_table(entries, {}, set())

    model = tv._source_model
    page_item = model.item(0, 0)
    assert page_item.data(_STRUCTURE_FILE_KIND_ROLE) == "base"
    assert page_item.data(_STRUCTURE_BYTE_RANGE_ROLE) == (expected_start, expected_end)

    tv.show()
    tv._toggle_hex_pane()
    proxy_idx = tv._proxy_model.mapFromSource(model.index(0, 0))
    tv._table_view.setCurrentIndex(proxy_idx)

    assert tv._hex_file_kind == "base"
    assert tv._hex_viewer._focus_ranges == [(expected_start, expected_end)]
    raw = db_path.read_bytes()
    assert raw[expected_start:expected_end] == entry["data"]


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


# ---------------------------------------------------------------------------
# "Decode column as timestamp" -- TEXT cells holding a number, and cells that
# can't be decoded (issue #104)
#
# These read the model through model.data()/headerData() rather than holding
# QStandardItem wrappers from model.item(): keeping those wrappers alive until
# the final garbage collection intermittently aborts the whole pytest process
# on exit (PySide teardown, reproducible on the untouched code too).
# ---------------------------------------------------------------------------

_TS = 1713884690406
_TS_DECODED = "2024-04-23 15:04:50 UTC"


def _ts_viewer():
    data = {"t": {"columns": ["n", "txt", "mixed"], "rows": [
        [_TS, str(_TS), "n/a"],
        [_TS, f" {_TS} ", ""],
        [_TS, str(_TS), None],
    ]}}
    tv = TableViewer(data, source_name="ts.sqlite")
    tv._table_combo.setCurrentText("t")
    return tv


def _apply(tv, col: int, fmt: str) -> None:
    tv._col_ts_formats[col] = fmt
    tv._apply_col_ts_format(col)


def _revert(tv, col: int) -> None:
    tv._col_ts_formats.pop(col)
    tv._revert_col_ts_format(col)


def _cell(tv, r: int, c: int, role=Qt.ItemDataRole.DisplayRole):
    m = tv._source_model
    return m.data(m.index(r, c), role)


def _fg_name(tv, r: int, c: int):
    brush = _cell(tv, r, c, Qt.ItemDataRole.ForegroundRole)
    return None if brush is None else brush.color().name()


def _texts(tv, col: int) -> list[str]:
    return [_cell(tv, r, col) for r in range(tv._source_model.rowCount())]


def _htext(tv, col: int) -> str:
    return tv._source_model.headerData(col, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)


def _htip(tv, col: int):
    return tv._source_model.headerData(col, Qt.Orientation.Horizontal, Qt.ItemDataRole.ToolTipRole)


def test_ts_decode_converts_text_cells_like_integer_cells(qapp) -> None:
    tv = _ts_viewer()
    _apply(tv, 1, "unix_ms")  # INTEGER
    _apply(tv, 2, "unix_ms")  # TEXT, one with surrounding whitespace
    assert _texts(tv, 1) == [_TS_DECODED] * 3
    assert _texts(tv, 2) == [_TS_DECODED] * 3
    assert _htext(tv, 2) == "txt [unix ms]"
    assert not _htip(tv, 2)  # nothing failed, nothing to explain


def test_ts_decode_marks_undecodable_cells_and_leaves_them_as_stored(qapp) -> None:
    tv = _ts_viewer()
    _apply(tv, 3, "unix_ms")

    assert _cell(tv, 0, 3) == "n/a"  # shown exactly as stored
    assert _fg_name(tv, 0, 3) == _TS_UNDECODED_COLOR.name()
    assert "not a number" in _cell(tv, 0, 3, Qt.ItemDataRole.ToolTipRole)

    # An empty string and a NULL are nothing to decode -- not flagged.
    assert not _cell(tv, 1, 3, Qt.ItemDataRole.ToolTipRole)
    assert not _cell(tv, 2, 3, Qt.ItemDataRole.ToolTipRole)

    # Nothing in this column decoded, and the header must not look like it did.
    assert _htext(tv, 3) == "mixed [unix ms: none decodable]"
    assert "1 of 1" in _htip(tv, 3)


def test_ts_decode_out_of_range_format_is_reported_not_silent(qapp) -> None:
    """A ms epoch read as seconds is beyond year 9999: the old code left every cell
    unchanged but still put the format suffix in the header."""
    tv = _ts_viewer()
    _apply(tv, 1, "unix_s")
    assert _texts(tv, 1) == [str(_TS)] * 3
    assert all("out of range" in _cell(tv, r, 1, Qt.ItemDataRole.ToolTipRole) for r in range(3))
    assert _htext(tv, 1) == "n [unix s: none decodable]"


def test_ts_decode_partially_decodable_column_says_how_many_failed(qapp) -> None:
    data = {"t": {"columns": ["ts"], "rows": [[_TS], [str(_TS)], ["oops"], [None]]}}
    tv = TableViewer(data, source_name="p.sqlite")
    tv._table_combo.setCurrentText("t")
    _apply(tv, 1, "unix_ms")
    assert _texts(tv, 1) == [_TS_DECODED, _TS_DECODED, "oops", ""]
    assert _htext(tv, 1) == "ts [unix ms]"  # something did decode
    assert "1 of 3" in _htip(tv, 1)


def test_ts_reapplying_another_format_starts_from_the_stored_text(qapp) -> None:
    tv = _ts_viewer()
    _apply(tv, 2, "unix_s")   # out of range -> cells flagged
    _apply(tv, 2, "unix_ms")  # now valid: flags must be gone, values decoded
    assert _texts(tv, 2) == [_TS_DECODED] * 3
    assert not any(_cell(tv, r, 2, Qt.ItemDataRole.ToolTipRole) for r in range(3))
    assert _htext(tv, 2) == "txt [unix ms]"


def test_ts_decode_in_sql_result_view(qapp) -> None:
    tv = _ts_viewer()
    tv._load_table_from_query({"columns": ["n", "txt", "mixed"], "rows": [
        [_TS, str(_TS), "n/a"], [_TS, "x", None],
    ]})
    assert tv._query_results_active
    model = tv._proxy_model

    def cell(r: int, c: int, role=Qt.ItemDataRole.DisplayRole):
        return model.data(model.index(r, c), role)

    _apply(tv, 2, "unix_ms")  # TEXT column: one numeric string, one not
    assert cell(0, 2) == _TS_DECODED
    assert cell(1, 2) == "x"
    assert cell(1, 2, Qt.ItemDataRole.ForegroundRole) == _TS_UNDECODED_COLOR
    assert "not a number" in cell(1, 2, Qt.ItemDataRole.ToolTipRole)
    assert cell(0, 2, Qt.ItemDataRole.ToolTipRole) is None
    assert cell(0, 2, Qt.ItemDataRole.UserRole) == str(_TS)  # raw value untouched
    assert model.headerData(2, Qt.Orientation.Horizontal) == "txt [unix ms]"
    assert "1 of 2" in model.headerData(2, Qt.Orientation.Horizontal, Qt.ItemDataRole.ToolTipRole)

    _apply(tv, 3, "unix_ms")  # only a non-numeric string and a NULL
    assert model.headerData(3, Qt.Orientation.Horizontal) == "mixed [unix ms: none decodable]"

    _revert(tv, 2)
    assert cell(0, 2) == str(_TS)
    assert model.headerData(2, Qt.Orientation.Horizontal) == "txt"
