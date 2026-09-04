# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the Multi-Log Studio backing SQLite database."""
from __future__ import annotations

from crush.core.log_db import LogDatabase
from crush.viewers.multi_log_viewer import _COL_PID, _SQL_SORT_COL


def test_pid_sort_column_is_numeric_cast() -> None:
    """Regression test companion for #61: pid is stored as TEXT (log_db._SCHEMA),
    so a plain `ORDER BY pid` sorts "1", "10", "100", "2", "20" as text instead of
    by numeric value — the sort column must be wrapped in CAST(... AS INTEGER)."""
    assert _SQL_SORT_COL[_COL_PID] == "CAST(pid AS INTEGER)"


def test_pid_orders_numerically_not_as_text() -> None:
    db = LogDatabase()
    try:
        db.insert_batch(1, [
            {"pid": pid, "message": f"m{pid}"} for pid in ("1", "10", "100", "2", "20")
        ])
        con = LogDatabase.open_worker_connection(db.path)
        try:
            order_col = _SQL_SORT_COL[_COL_PID]
            rows = con.execute(f"SELECT pid FROM entries ORDER BY {order_col} ASC").fetchall()  # noqa: S608
        finally:
            con.close()
        assert [r[0] for r in rows] == ["1", "2", "10", "20", "100"]
    finally:
        db.close()
