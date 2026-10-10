# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the LevelDB viewer's Records table sorting."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItemModel

from crush.viewers.leveldb_viewer import (
    _COLUMNS,
    LevelDbRecordsWidget,
    _StateFilterProxy,
    _make_item,
)


def test_seq_column_sorts_numerically_not_as_text(qapp) -> None:
    """Regression test for #61: QSortFilterProxyModel has its own independent
    sortRole (default DisplayRole), separate from the source model's — setting
    only the source model's sortRole doesn't propagate to it, so the Records
    table's Seq column previously sorted "1", "10", "100", "2", "20" as text
    instead of by numeric value."""
    model = QStandardItemModel(0, len(_COLUMNS))
    model.setHorizontalHeaderLabels(_COLUMNS)
    model.setSortRole(Qt.ItemDataRole.UserRole)

    for seq in (1, 10, 100, 2, 20):
        row = [_make_item(str(seq), seq)] + [_make_item("") for _ in range(len(_COLUMNS) - 1)]
        model.appendRow(row)

    proxy = _StateFilterProxy()
    proxy.setSourceModel(model)
    proxy.setSortRole(Qt.ItemDataRole.UserRole)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)

    result = [proxy.index(r, 0).data() for r in range(proxy.rowCount())]
    assert result == ["1", "2", "10", "20", "100"]


def _record(seq: int, value_text: str | None, value: bytes) -> dict:
    return {
        "seq": seq, "state": "Live", "file": "000003.log", "offset": seq,
        "user_key_text": f"k{seq}", "user_key_bytes": f"k{seq}".encode(),
        "value_text": value_text, "value_bytes": value,
        "internal_key_bytes": b"", "compressed": False, "checksum_ok": True,
    }


def test_value_text_column_sorts_binary_placeholders_by_size(qapp, widgets) -> None:
    """The "<binary N B>" placeholders sort by N (not as text, which put
    1042 B before 326 B), grouped apart from the text values."""
    records = [
        _record(1, None, b"\x00" * 1042),
        _record(2, "beta", b"beta"),
        _record(3, None, b"\x00" * 326),
        _record(4, "alpha", b"alpha"),
        _record(5, None, b"\x00" * 9),
    ]
    widget = widgets(LevelDbRecordsWidget(records))
    col = _COLUMNS.index("Value (text)")
    widget._proxy.sort(col, Qt.SortOrder.AscendingOrder)
    result = [widget._proxy.index(r, col).data() for r in range(widget._proxy.rowCount())]
    assert result == [
        "<binary 9 B>", "<binary 326 B>", "<binary 1042 B>", "alpha", "beta",
    ]
