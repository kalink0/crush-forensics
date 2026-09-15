# SPDX-License-Identifier: Apache-2.0
"""Generic result viewer for crush-analyze contract v1 output — one "view
kind" (typed columns + rows) reused by every analyzer module instead of a
bespoke viewer per module. See docs/design/analyzer-runner.md.
"""
from __future__ import annotations

import csv
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

_ROW_STATUS_COLORS = {
    "error": QColor(255, 205, 205),
    "partial": QColor(255, 235, 190),
}


class _AnalyzerResultModel(QAbstractTableModel):
    def __init__(
        self,
        columns: list[dict[str, str]],
        rows: list[dict[str, Any]],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._keys = [c["key"] for c in columns]
        self._labels = [c["label"] for c in columns]
        self._types = [c.get("type", "string") for c in columns]
        self._rows = rows

    def column_type(self, column: int) -> str:
        return self._types[column]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._keys)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation != Qt.Orientation.Horizontal or role != Qt.ItemDataRole.DisplayRole:
            return None
        return self._labels[section]

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        key = self._keys[index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            value = row.get(key)
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.UserRole:
            # The raw, untyped value (not stringified) -- lets the sort
            # proxy compare int/float columns numerically instead of
            # lexicographically ("100" sorting before "42" otherwise).
            return row.get(key)
        if role == Qt.ItemDataRole.BackgroundRole:
            return _ROW_STATUS_COLORS.get(row.get("_row_status", "ok"))
        if role == Qt.ItemDataRole.ToolTipRole:
            return row.get("_row_warning")
        return None


class _AnalyzerResultSortProxy(QSortFilterProxyModel):
    """Sorts int/float columns numerically using the model's UserRole
    (contract v1's `columns[].type`), not lexicographically on the
    display string -- string columns/bool/datetime fall through to Qt's
    default DisplayRole comparison, which is already correct for those
    (ISO 8601 datetimes sort correctly as plain strings)."""

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # type: ignore[override]
        source = self.sourceModel()
        if source.column_type(left.column()) in ("int", "float"):
            left_val = source.data(left, Qt.ItemDataRole.UserRole)
            right_val = source.data(right, Qt.ItemDataRole.UserRole)
            try:
                return float(left_val) < float(right_val)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass
        return super().lessThan(left, right)


class AnalyzerResultViewer(QWidget):
    """Displays one crush-analyze contract v1 result. A banner appears
    whenever the run wasn't a clean "ok" with no warnings — a failed or
    partial run must never look like an ordinary clean result table.

    Includes search/filter (all columns), click-to-sort per column
    (numeric for int/float columns via _AnalyzerResultSortProxy, plain
    string comparison otherwise -- already correct for datetime, since
    contract v1 mandates ISO 8601), a right-click copy menu, and CSV
    export of whatever's currently visible (i.e. filtered by the
    search box, mirroring mmkv_viewer.py's own CSV export) — the same
    baseline interactions Crush's other table-shaped viewers already
    offer, absent from the first cut of this one.
    """

    def __init__(self, result: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        banner_text, is_error = _banner(result)
        if banner_text:
            banner = QLabel(banner_text)
            banner.setObjectName("analyzer_banner")
            banner.setWordWrap(True)
            colors = "background: #f8d7da; color: #58151c;" if is_error else \
                "background: #fff3cd; color: #664500;"
            banner.setStyleSheet(f"padding: 6px; {colors}")
            layout.addWidget(banner)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rows…")
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(220)
        self._search.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self._search)
        toolbar.addStretch()
        export_btn = QPushButton("Export…")
        export_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(export_btn)
        layout.addLayout(toolbar)

        self._source_model = _AnalyzerResultModel(
            result.get("columns", []), result.get("rows", [])
        )
        self._proxy_model = _AnalyzerResultSortProxy(self)
        self._proxy_model.setSourceModel(self._source_model)
        self._proxy_model.setFilterKeyColumn(-1)  # match if any column matches

        self._table = QTableView(self)
        self._table.setModel(self._proxy_model)
        self._table.setSortingEnabled(True)
        # setSortingEnabled(True) alone leaves the header showing a sort
        # indicator on column 0 (descending) and the rows already sorted
        # by it -- clear that back to the module's own original row order
        # until the user actually clicks a header.
        self._table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        self._table.selectionModel().currentChanged.connect(self._on_current_changed)
        layout.addWidget(self._table)

        value_bar = QHBoxLayout()
        value_bar.addWidget(QLabel("Value:"))
        self._value_field = QLineEdit()
        self._value_field.setReadOnly(True)
        value_bar.addWidget(self._value_field, 1)
        layout.addLayout(value_bar)

    def _on_current_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        # A plain read-only QLineEdit, not a QLabel -- lets the user select
        # and copy just part of a long cell value (e.g. one path segment
        # out of a full app bundle path), which the row-level copy actions
        # above can't do since they always copy the whole cell/row.
        self._value_field.setText(str(current.data() or "") if current.isValid() else "")

    def _apply_filter(self, text: str) -> None:
        self._proxy_model.setFilterFixedString(text)

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if not path:
            return
        headers = [
            self._source_model.headerData(col, Qt.Orientation.Horizontal)
            for col in range(self._proxy_model.columnCount())
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for row in range(self._proxy_model.rowCount()):
                writer.writerow(
                    [
                        self._proxy_model.index(row, col).data() or ""
                        for col in range(self._proxy_model.columnCount())
                    ]
                )

    def _on_context_menu(self, pos: Any) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        menu = QMenu(self)
        copy_cell = menu.addAction("Copy cell")
        copy_row = menu.addAction("Copy row (TSV)")
        copy_selection = menu.addAction("Copy selection (TSV)")
        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == copy_cell:
            QApplication.clipboard().setText(str(index.data() or ""))
        elif action == copy_row:
            values = [
                str(self._proxy_model.index(index.row(), col).data() or "")
                for col in range(self._proxy_model.columnCount())
            ]
            QApplication.clipboard().setText("\t".join(values))
        elif action == copy_selection:
            self._copy_selection()

    def _copy_selection(self) -> None:
        indexes = self._table.selectionModel().selectedIndexes()
        if not indexes:
            return
        rows = sorted({i.row() for i in indexes})
        cols = sorted({i.column() for i in indexes})
        lines = []
        for row in rows:
            lines.append(
                "\t".join(
                    str(self._proxy_model.index(row, col).data() or "") for col in cols
                )
            )
        QApplication.clipboard().setText("\n".join(lines))


def _banner(result: dict[str, Any]) -> tuple[str, bool]:
    lines = []
    status = result.get("status", "ok")
    is_error = status == "error"
    if status != "ok":
        error = result.get("error") or {}
        message = error.get("message", "")
        lines.append(f"Status: {status}" + (f" — {message}" if message else ""))
    lines.extend(result.get("warnings", []))
    return "\n".join(lines), is_error
