# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Format Reference dialog — browsable table of all known forensic formats."""
from __future__ import annotations

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from crush.core.format_db import FormatDatabase
from crush.ui.format_info_dialog import FormatInfoDialog
from crush.ui.i18n import translate

_COL_NAME = 0
_COL_CAT = 1
_COL_PLAT = 2
_COL_PARSER = 3
_COL_RELEVANCE = 4


class FormatReferenceDialog(QDialog):
    """Searchable table of all formats known to Crush."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(translate("FormatReferenceDialog", "Format Reference"))
        self.resize(1000, 600)
        self._build_ui()
        self._populate()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Search bar
        search_bar = QWidget()
        sb = QHBoxLayout(search_bar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.addWidget(QLabel(translate("FormatReferenceDialog", "Search:")))
        self._search = QLineEdit()
        self._search.setPlaceholderText(
            translate("FormatReferenceDialog", "Filter by name, category, platform…")
        )
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)
        sb.addWidget(self._search, 1)
        layout.addWidget(search_bar)

        # Table
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels([
            translate("FormatReferenceDialog", "Name"),
            translate("FormatReferenceDialog", "Category"),
            translate("FormatReferenceDialog", "Platforms"),
            translate("FormatReferenceDialog", "Parser"),
            translate("FormatReferenceDialog", "Forensic Relevance"),
        ])

        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(_COL_NAME, 240)
        self._table.setColumnWidth(_COL_CAT, 100)
        self._table.setColumnWidth(_COL_PLAT, 140)
        self._table.setColumnWidth(_COL_PARSER, 120)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        self._table.doubleClicked.connect(self._open_details)
        layout.addWidget(self._table)

        # Status + details button
        bottom = QWidget()
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        self._count_label = QLabel("")
        bl.addWidget(self._count_label)
        bl.addStretch()
        self._details_btn = QPushButton(translate("FormatReferenceDialog", "View Details…"))
        self._details_btn.setEnabled(False)
        self._details_btn.clicked.connect(self._open_details)
        bl.addWidget(self._details_btn)
        layout.addWidget(bottom)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate(self) -> None:
        formats = FormatDatabase.get().all_formats()
        for fmt in formats:
            parser_text = fmt.parser_class or "—"
            items = [
                QStandardItem(fmt.name),
                QStandardItem(fmt.category),
                QStandardItem(fmt.platforms.replace(",", ", ")),
                QStandardItem(parser_text),
                QStandardItem(fmt.forensic_relevance),
            ]
            for item in items:
                item.setEditable(False)
            # Grey out unsupported formats slightly
            if not fmt.parser_class:
                for item in items:
                    item.setForeground(Qt.GlobalColor.gray)
            items[0].setData(fmt, Qt.ItemDataRole.UserRole)
            self._model.appendRow(items)

        self._update_count()

    def _apply_filter(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)
        self._update_count()

    def _update_count(self) -> None:
        visible = self._proxy.rowCount()
        total = self._model.rowCount()
        if visible == total:
            self._count_label.setText(
                translate("FormatReferenceDialog", "{total} formats").format(total=total)
            )
        else:
            self._count_label.setText(
                translate("FormatReferenceDialog", "{visible} of {total} formats").format(
                    visible=visible, total=total
                )
            )

    def _on_selection(self) -> None:
        indexes = self._table.selectionModel().selectedRows()
        self._details_btn.setEnabled(bool(indexes))

    def _open_details(self) -> None:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            return
        source = self._proxy.mapToSource(indexes[0])
        item = self._model.item(source.row(), _COL_NAME)
        fmt = item.data(Qt.ItemDataRole.UserRole) if item else None
        if fmt:
            dlg = FormatInfoDialog(None, fmt, self)
            dlg.exec()
