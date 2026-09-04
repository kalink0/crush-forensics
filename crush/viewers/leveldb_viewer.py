# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""LevelDB viewer — overview, files, records (all + deleted)."""
from __future__ import annotations

import csv
from typing import Any

from PySide6.QtCore import Qt, QSortFilterProxyModel
from PySide6.QtGui import QColor, QFont, QStandardItem, QStandardItemModel, QTextCursor
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
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

# Raw bytes stored alongside display text via custom item data roles
_KEY_BYTES_ROLE = Qt.ItemDataRole.UserRole + 1
_VAL_BYTES_ROLE = Qt.ItemDataRole.UserRole + 2
_IKEY_BYTES_ROLE = Qt.ItemDataRole.UserRole + 3  # full internal key (LDB: includes seq/type suffix)

_STATE_COLORS: dict[str, QColor] = {
    "Deleted": QColor("#cc3333"),
    "Unknown": QColor("#888888"),
}

_COLUMNS = [
    "Seq",
    "State",
    "File",
    "Offset",
    "User Key (text)",
    "User Key (hex)",
    "Value (text)",
    "Value (hex)",
    "Compressed",
]

# Number of bytes shown as hex preview in the table columns
_HEX_PREVIEW_BYTES = 16


def _hex_preview(raw: bytes) -> str:
    if not raw:
        return ""
    preview = raw[:_HEX_PREVIEW_BYTES].hex(" ")
    if len(raw) > _HEX_PREVIEW_BYTES:
        preview += f"  ({len(raw)} B)"
    return preview


def _text_preview(text: str | None, raw: bytes) -> str:
    if text is not None:
        if len(text) > 120:
            return text[:120] + "…"
        return text
    return f"<binary {len(raw)} B>"


def _make_item(display: str, sort_val: Any = None) -> QStandardItem:
    item = QStandardItem(display)
    item.setEditable(False)
    item.setData(display if sort_val is None else sort_val, Qt.ItemDataRole.UserRole)
    return item


class _StateFilterProxy(QSortFilterProxyModel):
    """Filters rows by State column and optional full-text search."""

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

    def filterAcceptsRow(self, source_row: int, source_parent: Any) -> bool:
        model = self.sourceModel()
        if self._state is not None:
            idx = model.index(source_row, 1, source_parent)
            if model.data(idx) != self._state:
                return False
        if self._text:
            for col in range(model.columnCount()):
                idx = model.index(source_row, col, source_parent)
                if self._text in (model.data(idx) or "").lower():
                    return True
            return False
        return True


class LevelDbRecordsWidget(QWidget):
    """Reusable splitter: records table (top) + HexViewer of selected row (bottom).

    initial_filter: "Live" | "Deleted" | "Unknown" | None (show all)
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        initial_filter: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._records = records
        self._initial_filter = initial_filter
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- filter toolbar ---
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.addWidget(QLabel("  Show: "))

        self._filter_buttons: dict[str | None, QPushButton] = {}
        for label, state in [("All", None), ("Live", "Live"), ("Deleted", "Deleted"), ("Unknown", "Unknown")]:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFlat(True)
            btn.clicked.connect(lambda checked, s=state: self._apply_filter(s))
            toolbar.addWidget(btn)
            self._filter_buttons[state] = btn

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

        # --- splitter: table + hex ---
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._model = QStandardItemModel(0, len(_COLUMNS))
        self._model.setHorizontalHeaderLabels(_COLUMNS)
        self._model.setSortRole(Qt.ItemDataRole.UserRole)
        self._populate_model()

        self._proxy = _StateFilterProxy()
        self._proxy.setSourceModel(self._model)
        # QSortFilterProxyModel has its own independent sortRole (defaults to
        # DisplayRole) — setting it only on the source model above doesn't propagate
        # here, so the table would sort Seq/Offset as text without this.
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

        hex_tabs = QTabWidget()
        self._hex_key = HexViewer(b"")
        self._hex_val = HexViewer(b"")
        self._hex_ikey = HexViewer(b"")
        hex_tabs.addTab(self._hex_key, "Key")
        hex_tabs.addTab(self._hex_val, "Value")
        hex_tabs.addTab(self._hex_ikey, "Internal Key")
        splitter.addWidget(hex_tabs)
        splitter.setSizes([400, 200])

        layout.addWidget(splitter)

        # activate initial filter
        self._apply_filter(self._initial_filter)

    def _populate_model(self) -> None:
        for rec in self._records:
            state = rec["state"]
            color = _STATE_COLORS.get(state)

            uk_bytes: bytes = rec.get("user_key_bytes") or b""
            val_bytes: bytes = rec.get("value_bytes") or b""
            ik_bytes: bytes = rec.get("internal_key_bytes") or b""

            seq = rec.get("seq", 0)
            offset = rec.get("offset", 0)
            cells: list[tuple[str, Any]] = [
                (str(seq), seq),
                (state, None),
                (rec.get("file", ""), None),
                (f"0x{offset:08x}", offset),
                (_text_preview(rec.get("user_key_text"), uk_bytes), None),
                (_hex_preview(uk_bytes), None),
                (_text_preview(rec.get("value_text"), val_bytes), None),
                (_hex_preview(val_bytes), None),
                ("yes" if rec.get("compressed") else "no", None),
            ]

            items = []
            for display, sort_val in cells:
                item = _make_item(display, sort_val)
                if color:
                    item.setForeground(color)
                items.append(item)

            # Store raw bytes for hex pane and inspector
            items[0].setData(uk_bytes, _KEY_BYTES_ROLE)
            items[0].setData(val_bytes, _VAL_BYTES_ROLE)
            items[0].setData(ik_bytes, _IKEY_BYTES_ROLE)

            self._model.appendRow(items)

    def _apply_filter(self, state: str | None) -> None:
        self._proxy.set_state(state)
        for s, btn in self._filter_buttons.items():
            btn.setChecked(s == state)

        # update label to show visible / total
        total = self._model.rowCount()
        for s, btn in self._filter_buttons.items():
            if s is None:
                btn.setText(f"All ({total})")
            else:
                count = sum(1 for r in self._records if r["state"] == s)
                btn.setText(f"{s} ({count})")

    def _source_row(self, proxy_index) -> int:
        return self._proxy.mapToSource(proxy_index).row()

    def _on_row_changed(self, current, _previous) -> None:
        row = self._source_row(current)
        if 0 <= row < self._model.rowCount():
            item = self._model.item(row, 0)
            uk = item.data(_KEY_BYTES_ROLE) or b""
            val = item.data(_VAL_BYTES_ROLE) or b""
            ik = item.data(_IKEY_BYTES_ROLE) or b""
            self._hex_key.set_data(uk)
            self._hex_val.set_data(val)
            self._hex_ikey.set_data(ik)

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if not path:
            return
        headers = [
            "Seq", "State", "File", "Offset",
            "User Key (text)", "User Key (hex)",
            "Internal Key (hex)",
            "Value (text)", "Value (hex)",
            "Compressed",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for proxy_row in range(self._proxy.rowCount()):
                src_row = self._proxy.mapToSource(
                    self._proxy.index(proxy_row, 0)
                ).row()
                if src_row < 0 or src_row >= len(self._records):
                    continue
                rec = self._records[src_row]
                uk: bytes = rec.get("user_key_bytes") or b""
                val: bytes = rec.get("value_bytes") or b""
                ik: bytes = rec.get("internal_key_bytes") or b""
                writer.writerow([
                    rec.get("seq", 0),
                    rec.get("state", ""),
                    rec.get("file", ""),
                    f"0x{rec.get('offset', 0):08x}",
                    rec.get("user_key_text") or "",
                    uk.hex(),
                    ik.hex(),
                    rec.get("value_text") or "",
                    val.hex(),
                    "yes" if rec.get("compressed") else "no",
                ])

    def _on_context_menu(self, pos) -> None:
        proxy_index = self._table.indexAt(pos)
        if not proxy_index.isValid():
            return
        row = self._source_row(proxy_index)
        if row < 0 or row >= self._model.rowCount():
            return
        item = self._model.item(row, 0)
        uk: bytes = item.data(_KEY_BYTES_ROLE) or b""
        val: bytes = item.data(_VAL_BYTES_ROLE) or b""
        ik: bytes = item.data(_IKEY_BYTES_ROLE) or b""

        menu = QMenu(self)
        inspect_key = menu.addAction(f"Inspect Key… ({len(uk)} B)")
        inspect_val = menu.addAction(f"Inspect Value… ({len(val)} B)")
        inspect_ikey = menu.addAction(f"Inspect Internal Key… ({len(ik)} B)")
        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == inspect_key and uk:
            BlobInspector(uk, self).show()
        elif action == inspect_val and val:
            BlobInspector(val, self).show()
        elif action == inspect_ikey and ik:
            BlobInspector(ik, self).show()


class LevelDbViewer(QWidget):
    """LevelDB viewer with tabs: Overview | Files | Records | Deleted Records."""

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()

        records: list[dict[str, Any]] = self._data.get("records", [])
        files: list[dict[str, Any]] = self._data.get("files", [])
        manifests: dict[str, Any] = self._data.get("manifests", {})

        # --- Overview ---
        if manifests:
            tabs.addTab(TreeViewer(manifests, tabs), "Overview")
        else:
            lbl = QLabel("No MANIFEST file found.")
            lbl.setWordWrap(True)
            tabs.addTab(lbl, "Overview")

        # --- Files ---
        if files:
            tabs.addTab(self._build_files_tab(files, tabs), "Files")

        # --- Records (all, with filter toolbar) ---
        if records:
            total = len(records)
            tabs.addTab(
                LevelDbRecordsWidget(records, initial_filter=None, parent=tabs),
                f"Records ({total:,})",
            )

        # --- LOG / LOG.old (full content, own tab each) ---
        log_files: dict[str, str] = self._data.get("log_files", {})
        for log_name, content in log_files.items():
            if content:
                tabs.addTab(self._build_log_tab(content, tabs), log_name)

        layout.addWidget(tabs)

    def _build_files_tab(self, files: list[dict[str, Any]], parent: QWidget) -> QWidget:
        columns = ["File", "Type", "Level", "Size (B)", "Total", "Live", "Deleted", "Unknown", "Smallest Key", "Largest Key"]
        model = QStandardItemModel(0, len(columns))
        model.setHorizontalHeaderLabels(columns)

        for f in files:
            level = f.get("level", -1)
            level_str = str(level) if level >= 0 else "—"
            size = f.get("size")
            size_str = f"{size:,}" if size is not None else "—"
            row = [
                _make_item(f.get("name", "")),
                _make_item(f.get("type", "")),
                _make_item(level_str, level),
                _make_item(size_str, size if size is not None else -1),
                _make_item(str(f.get("total", 0)), f.get("total", 0)),
                _make_item(str(f.get("live", 0)), f.get("live", 0)),
                _make_item(str(f.get("deleted", 0)), f.get("deleted", 0)),
                _make_item(str(f.get("unknown", 0)), f.get("unknown", 0)),
                _make_item(f.get("smallest_key", "")),
                _make_item(f.get("largest_key", "")),
            ]
            # Color files that contain deleted records
            if f.get("deleted", 0) > 0:
                for item in row:
                    item.setForeground(_STATE_COLORS["Deleted"])
            model.appendRow(row)

        table = QTableView()
        model.setSortRole(Qt.ItemDataRole.UserRole)
        table.setModel(model)
        table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        install_horizontal_wheel_scroll(table)
        table.horizontalHeader().setStretchLastSection(True)
        table.resizeColumnsToContents()

        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(table)
        return widget

    def _build_log_tab(self, content: str, parent: QWidget) -> QWidget:
        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        line_count = len(content.splitlines())
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.addWidget(QLabel(f"  {line_count:,} lines   "))
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("  Find: "))
        search = QLineEdit()
        search.setPlaceholderText("Find in log…")
        search.setClearButtonEnabled(True)
        search.setFixedWidth(240)
        toolbar.addWidget(search)
        find_next_btn = QPushButton("Next")
        toolbar.addWidget(find_next_btn)
        layout.addWidget(toolbar)

        text_view = QPlainTextEdit()
        text_view.setReadOnly(True)
        text_view.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        text_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(text_view, smooth_item_scroll=False)
        text_view.document().setDefaultFont(QFont("Monospace", 9))
        text_view.setPlainText(content)
        layout.addWidget(text_view)

        def find_next() -> None:
            term = search.text()
            if not term:
                return
            if not text_view.find(term):
                text_view.moveCursor(QTextCursor.MoveOperation.Start)
                text_view.find(term)

        search.returnPressed.connect(find_next)
        find_next_btn.clicked.connect(find_next)
        return widget
