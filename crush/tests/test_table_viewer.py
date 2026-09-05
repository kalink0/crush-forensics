# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for TableViewer's virtual blob-tab path/metadata (crush/viewers/table_viewer.py)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt

from crush.viewers.table_viewer import TableViewer


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
