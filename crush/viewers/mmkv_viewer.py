# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""MMKV key-value store viewer — Overview + Records tabs, same family as LevelDB."""
from __future__ import annotations

import csv
from typing import Any

from PySide6.QtCore import Qt, QSortFilterProxyModel
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from crush.viewers.hex_viewer import HexViewer
from crush.viewers.table_viewer import BlobInspector
from crush.viewers.tree_viewer import TreeViewer
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

_RAW_ROLE = Qt.ItemDataRole.UserRole + 1
_FULLTEXT_ROLE = Qt.ItemDataRole.UserRole + 2
_VALUE_BYTES_ROLE = Qt.ItemDataRole.UserRole + 3
_ENTRY_RANGE_ROLE = Qt.ItemDataRole.UserRole + 4
_VALUE_RANGE_ROLE = Qt.ItemDataRole.UserRole + 5

_STATE_COLORS: dict[str, QColor] = {
    "Removed": QColor("#cc3333"),
    "Superseded": QColor("#b8860b"),
}

_COLUMNS = ["Index", "Key", "State", "Type", "Size (B)", "Value"]
_VALUE_COL = _COLUMNS.index("Value")
_HEX_PREVIEW_BYTES = 64
# Real MMKV stores can hold multi-megabyte values (e.g. a cached GraphQL/JSON
# blob) — putting that directly into a table cell's display text makes Qt's
# text layout/paint noticeably slow on every repaint, not just once. Only the
# on-screen preview is capped; the full value stays reachable via the value's
# own _FULLTEXT_ROLE (search, Copy Value), CSV export, and Inspect Value's
# raw bytes (via _RAW_ROLE) — nothing is actually discarded.
_TEXT_PREVIEW_LEN = 256


def _make_item(display: str, sort_val: Any = None) -> QStandardItem:
    item = QStandardItem(display)
    item.setEditable(False)
    item.setData(display if sort_val is None else sort_val, Qt.ItemDataRole.UserRole)
    return item


def _full_value_text(decoded: Any, raw: bytes) -> str:
    if decoded is None:
        return "<empty / removed>" if not raw else "<empty>"
    if isinstance(decoded, bytes):
        return decoded.hex(" ")
    return str(decoded)


def _display_value(decoded: Any, raw: bytes) -> str:
    if decoded is None:
        return "<empty / removed>" if not raw else "<empty>"
    if isinstance(decoded, bytes):
        preview = decoded[:_HEX_PREVIEW_BYTES].hex(" ")
        return f"<{preview}{' …' if len(decoded) > _HEX_PREVIEW_BYTES else ''}>"
    text = str(decoded)
    if len(text) > _TEXT_PREVIEW_LEN:
        return f"{text[:_TEXT_PREVIEW_LEN]}… ({len(text):,} chars total)"
    return text


class _StateFilterProxy(QSortFilterProxyModel):
    """Filters rows by State column and optional free-text search."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._state: str | None = None
        self._text: str = ""

    def set_state(self, state: str | None) -> None:
        self._state = state
        self.invalidateFilter()

    def set_text(self, text: str) -> None:
        self._text = text.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # type: ignore[override]
        model = self.sourceModel()
        if self._state:
            idx = model.index(source_row, _COLUMNS.index("State"), source_parent)
            if model.data(idx) != self._state:
                return False
        if self._text:
            for col in range(model.columnCount()):
                idx = model.index(source_row, col, source_parent)
                if col == _VALUE_COL:
                    # Search the full value, not the truncated preview text —
                    # a match past the display cutoff must still be findable.
                    text = model.data(idx, _FULLTEXT_ROLE) or model.data(idx) or ""
                else:
                    text = model.data(idx) or ""
                if self._text in text.lower():
                    return True
            return False
        return True


class MMKVRecordsWidget(QWidget):
    """Records table (top) + HexViewer of the selected row's bytes in context (bottom).

    When *file_bytes* (the real, complete .mmkv file) and a row's own real
    on-disk span are both available, the pane shows the whole file with that
    span highlighted -- true byte provenance, not just the value's own bytes
    in isolation. Falls back to the old isolated-value-bytes behavior when
    offsets couldn't be computed (e.g. an encrypted store opened before
    Crush added offset tracking, or a walk that lost alignment) -- never a
    guess, never blank.
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        parent: QWidget | None = None,
        file_bytes: bytes | None = None,
    ) -> None:
        super().__init__(parent)
        self._records = records
        self._file_bytes = file_bytes
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.addWidget(QLabel("  Show: "))
        self._filter_buttons: dict[str | None, QPushButton] = {}
        for label, state in [("All", None), ("Live", "Live"), ("Superseded", "Superseded"), ("Removed", "Removed")]:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFlat(True)
            btn.clicked.connect(lambda checked, s=state: self._apply_filter(s))
            toolbar.addWidget(btn)
            self._filter_buttons[state] = btn
        self._filter_buttons[None].setChecked(True)

        toolbar.addSeparator()
        toolbar.addWidget(QLabel("  Search: "))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rows…")
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(220)
        self._search.textChanged.connect(lambda t: self._proxy.set_text(t))
        toolbar.addWidget(self._search)

        toolbar.addSeparator()
        export_btn = QPushButton("Export CSV…")
        export_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(export_btn)
        layout.addWidget(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._model = QStandardItemModel(0, len(_COLUMNS))
        self._model.setHorizontalHeaderLabels(_COLUMNS)
        self._model.setSortRole(Qt.ItemDataRole.UserRole)
        self._populate_model()

        self._proxy = _StateFilterProxy()
        self._proxy.setSourceModel(self._model)
        # QSortFilterProxyModel has its own independent sortRole (defaults to
        # DisplayRole) — setting it only on the source model doesn't propagate
        # here, so Index would sort as text without this (see #61).
        self._proxy.setSortRole(Qt.ItemDataRole.UserRole)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        install_horizontal_wheel_scroll(self._table)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.resizeColumnsToContents()
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        splitter.addWidget(self._table)

        self._hex_val = HexViewer(self._file_bytes or b"")
        splitter.addWidget(self._hex_val)
        splitter.setSizes([400, 150])

        layout.addWidget(splitter)

        value_bar = QWidget()
        vb_layout = QHBoxLayout(value_bar)
        vb_layout.setContentsMargins(8, 4, 8, 4)
        vb_layout.setSpacing(8)
        vb_layout.addWidget(QLabel("Value:"))
        self._value_field = QLineEdit()
        self._value_field.setReadOnly(True)
        vb_layout.addWidget(self._value_field, 1)
        layout.addWidget(value_bar)

    def _populate_model(self) -> None:
        for rec in self._records:
            state = rec["state"]
            color = _STATE_COLORS.get(state)
            display_val = _display_value(rec["decoded"], rec["raw"])
            size = len(rec["raw"])
            cells: list[tuple[str, Any]] = [
                (str(rec["index"]), rec["index"]),
                (rec["key"], None),
                (state, None),
                (rec["type"], None),
                (f"{size:,}", size),
                (display_val, None),
            ]
            items = [_make_item(d, s) for d, s in cells]
            if color:
                for item in items:
                    item.setForeground(color)
            items[0].setData(rec["raw"], _RAW_ROLE)
            items[0].setData(rec["value_bytes"], _VALUE_BYTES_ROLE)
            if "entry_range" in rec:
                items[0].setData(rec["entry_range"], _ENTRY_RANGE_ROLE)
            if "value_range" in rec:
                items[0].setData(rec["value_range"], _VALUE_RANGE_ROLE)
            items[_VALUE_COL].setData(_full_value_text(rec["decoded"], rec["raw"]), _FULLTEXT_ROLE)
            self._model.appendRow(items)

    def _apply_filter(self, state: str | None) -> None:
        self._proxy.set_state(state)
        for s, btn in self._filter_buttons.items():
            btn.setChecked(s == state)

    def _source_row(self, proxy_index) -> int:
        return self._proxy.mapToSource(proxy_index).row()

    def _on_row_changed(self, current, _previous) -> None:
        row = self._source_row(current)
        if 0 <= row < self._model.rowCount():
            item = self._model.item(row, 0)
            entry_range = item.data(_ENTRY_RANGE_ROLE)
            value_range = item.data(_VALUE_RANGE_ROLE)
            if self._file_bytes is not None and entry_range is not None:
                ranges = [entry_range]
                if value_range is not None and value_range[1] > value_range[0]:
                    ranges.append(value_range)
                self._hex_val.highlight_byte_ranges(ranges)
            else:
                # No real on-disk span available (offset walk lost alignment,
                # or this data predates offset tracking) -- fall back to the
                # value's own bytes in isolation rather than showing nothing.
                self._hex_val.set_data(item.data(_RAW_ROLE) or b"")
            value_item = self._model.item(row, _VALUE_COL)
            # QLineEdit.setText() silently truncates at its 32,767-char maxLength —
            # use the already-bounded display text (with its own explicit "(N chars
            # total)" note when truncated) rather than the untruncated full text,
            # which risks a *silent* cut with no indication anything was lost.
            # The complete value is still reachable via Copy Value / Inspect Value.
            self._value_field.setText(value_item.text() if value_item else "")
            self._value_field.setCursorPosition(0)

    def _on_context_menu(self, pos) -> None:
        proxy_index = self._table.indexAt(pos)
        if not proxy_index.isValid():
            return
        row = self._source_row(proxy_index)
        if row < 0 or row >= self._model.rowCount():
            return
        key = self._model.item(row, 1).text()
        value_bytes: bytes = self._model.item(row, 0).data(_VALUE_BYTES_ROLE) or b""
        full_value = self._model.item(row, _VALUE_COL).data(_FULLTEXT_ROLE) or ""

        menu = QMenu(self)
        inspect_val = menu.addAction(f"Inspect Value… ({len(value_bytes)} B)")
        inspect_val.setEnabled(bool(value_bytes))
        menu.addSeparator()
        copy_key = menu.addAction("Copy Key")
        copy_value = menu.addAction("Copy Value")
        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == inspect_val:
            # Inspects the value's own bytes (MMKV's internal length-prefix
            # already stripped, see _content_bytes()) — never the full raw
            # container, so this can actually be re-parsed as e.g. JSON.
            # "raw" itself (the complete, untouched container) stays available
            # unmodified in the hex pane above and CSV export. Defaults to the
            # already-decoded content (a scalar's bytes are just a varint, not
            # human-readable on their own) — same "Decoded (from table)"
            # pattern already used for SEGB.
            BlobInspector(value_bytes, self, display_text=full_value).show()
        elif action == copy_key:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(key)
        elif action == copy_value:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(full_value)

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([*_COLUMNS, "Raw value (hex)"])
            for proxy_row in range(self._proxy.rowCount()):
                src_row = self._proxy.mapToSource(self._proxy.index(proxy_row, 0)).row()
                if src_row < 0 or src_row >= len(self._records):
                    continue
                rec = self._records[src_row]
                writer.writerow([
                    rec["index"],
                    rec["key"],
                    rec["state"],
                    rec["type"],
                    len(rec["raw"]),
                    _full_value_text(rec["decoded"], rec["raw"]),
                    rec["raw"].hex(),
                ])


class MMKVViewer(QWidget):
    """MMKV viewer with tabs: Overview | Records."""

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()

        records: list[dict[str, Any]] = self._data.get("records", [])
        meta_info: dict[str, Any] | None = self._data.get("meta_info")

        overview: dict[str, Any] = {}
        if meta_info is not None:
            overview["Meta version"] = meta_info["version"]
            overview["Sequence (full write-backs)"] = meta_info["sequence"]
            overview["CRC-32 (data region, as recorded)"] = f"0x{meta_info['crc']:08x}"
            encrypted = "yes" if meta_info["encrypted"] else "no"
            note = meta_info.get("encrypted_note")
            overview["Encrypted"] = f"{encrypted} — {note}" if note else encrypted
            if meta_info["actual_size"] is not None:
                overview["Recorded data region size"] = f"{meta_info['actual_size']:,} B"
        else:
            overview["Meta file"] = "not found (.crc companion missing)"
        overview["Total entries"] = len(records)
        overview["Live"] = sum(1 for r in records if r["state"] == "Live")
        overview["Superseded"] = sum(1 for r in records if r["state"] == "Superseded")
        overview["Removed"] = sum(1 for r in records if r["state"] == "Removed")
        tabs.addTab(TreeViewer(overview, tabs), "Overview")

        if records:
            file_bytes = self._data.get("__mmkv_file_bytes")
            tabs.addTab(
                MMKVRecordsWidget(records, tabs, file_bytes=file_bytes),
                f"Records ({len(records):,})",
            )
        else:
            lbl = QLabel("No entries found.")
            lbl.setWordWrap(True)
            tabs.addTab(lbl, "Records")

        layout.addWidget(tabs)
