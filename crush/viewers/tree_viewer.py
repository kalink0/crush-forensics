# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tree viewer — displays plist, XML, and other hierarchical data."""
from __future__ import annotations

import plistlib
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

_USER_ROLE = Qt.ItemDataRole.UserRole


class TreeViewer(QWidget):
    """Viewer for plist / XML / any nested dict/list structure."""

    def __init__(self, data: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()
        self._load(data)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setFixedHeight(36)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)
        self._expand_all_btn = QPushButton("Expand All")
        self._expand_all_btn.clicked.connect(self._expand_all)
        tb_layout.addWidget(self._expand_all_btn)
        self._collapse_all_btn = QPushButton("Collapse All")
        self._collapse_all_btn.clicked.connect(self._collapse_all)
        tb_layout.addWidget(self._collapse_all_btn)
        tb_layout.addStretch()
        tb_layout.addWidget(QLabel("Search:"))

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter keys / values…")
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        tb_layout.addWidget(self._search)
        layout.addWidget(toolbar)

        # Tree view
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Key / Index", "Value", "Type"])

        self._tree = QTreeView()
        self._tree.setModel(self._model)
        self._tree.setAlternatingRowColors(True)
        self._tree.setAnimated(True)
        install_horizontal_wheel_scroll(self._tree)
        self._tree.header().setStretchLastSection(False)
        self._tree.setColumnWidth(0, 220)
        self._tree.setColumnWidth(1, 300)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)
        self._tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        layout.addWidget(self._tree)

    def _expand_all(self) -> None:
        self._tree.expandAll()

    def _collapse_all(self) -> None:
        self._tree.collapseAll()

    def _load(self, data: Any) -> None:
        self._model.removeRows(0, self._model.rowCount())
        root = self._model.invisibleRootItem()
        if isinstance(data, dict):
            for key, value in data.items():
                self._build_items(root, value, str(key))
        elif isinstance(data, (list, tuple)):
            for i, value in enumerate(data):
                self._build_items(root, value, str(i))
        else:
            self._build_items(root, data, "value")
        self._tree.expandToDepth(1)

    def _build_items(self, parent: QStandardItem, obj: Any, key: str) -> None:
        type_name = type(obj).__name__

        if isinstance(obj, dict):
            # Strip NSKeyedArchiver class metadata; surface classname in Type column
            class_meta = obj.get("$class")
            classname = (
                class_meta.get("$classname", "") if isinstance(class_meta, dict) else ""
            )
            display_obj = {k: v for k, v in obj.items() if k not in ("$class", "$classes", "$classname")}
            key_item = QStandardItem(str(key))
            val_item = QStandardItem(f"({len(display_obj)} keys)")
            type_item = QStandardItem(classname if classname else "dict")
            key_item.setData(obj, _USER_ROLE)
            key_item.setEditable(False)
            val_item.setEditable(False)
            type_item.setEditable(False)
            parent.appendRow([key_item, val_item, type_item])
            for k, v in display_obj.items():
                self._build_items(key_item, v, str(k))

        elif isinstance(obj, (list, tuple)):
            key_item = QStandardItem(str(key))
            val_item = QStandardItem(f"({len(obj)} items)")
            type_item = QStandardItem(type_name)
            key_item.setData(obj, _USER_ROLE)
            key_item.setEditable(False)
            val_item.setEditable(False)
            type_item.setEditable(False)
            parent.appendRow([key_item, val_item, type_item])
            for i, v in enumerate(obj):
                self._build_items(key_item, v, str(i))

        elif isinstance(obj, bytes):
            key_item = QStandardItem(str(key))
            val_item = QStandardItem(f"<BLOB {len(obj):,} B>")
            type_item = QStandardItem("bytes")
            key_item.setData(obj, _USER_ROLE)
            key_item.setEditable(False)
            val_item.setEditable(False)
            type_item.setEditable(False)
            parent.appendRow([key_item, val_item, type_item])

        else:
            key_item = QStandardItem(str(key))
            val_item = QStandardItem(str(obj))
            type_item = QStandardItem(type_name)
            key_item.setData(obj, _USER_ROLE)
            key_item.setEditable(False)
            val_item.setEditable(False)
            type_item.setEditable(False)
            parent.appendRow([key_item, val_item, type_item])

    @staticmethod
    def _make_blob(obj: Any) -> bytes:
        if isinstance(obj, bytes):
            return obj
        if isinstance(obj, str):
            return obj.encode("utf-8", errors="replace")
        try:
            return plistlib.dumps(obj, fmt=plistlib.FMT_XML)
        except Exception:
            if isinstance(obj, (list, tuple)):
                return "\n".join(str(item) for item in obj).encode("utf-8", errors="replace")
            return str(obj).encode("utf-8", errors="replace")

    def _apply_filter(self, text: str) -> None:
        """Show/hide rows whose key or value contains the search text."""
        self._filter_items(self._model.invisibleRootItem(), text.lower())

    def _filter_items(self, parent: QStandardItem, text: str) -> bool:
        any_visible = False
        for row in range(parent.rowCount()):
            key_item = parent.child(row, 0)
            val_item = parent.child(row, 1)
            if key_item is None:
                continue
            child_visible = self._filter_items(key_item, text)
            key_match = not text or text in key_item.text().lower()
            val_match = val_item and text in val_item.text().lower()
            visible = key_match or bool(val_match) or child_visible
            self._tree.setRowHidden(
                row,
                self._model.indexFromItem(parent),
                not visible,
            )
            any_visible = any_visible or visible
        return any_visible

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "matches"):
            if event.matches(QKeySequence.StandardKey.Copy):
                key, val = self._current_key_value()
                if key == "" and val == "":
                    return
                if val:
                    QApplication.clipboard().setText(val)
                else:
                    QApplication.clipboard().setText(key)
                return
        super().keyPressEvent(event)  # type: ignore[arg-type]

    def _current_key_value(self) -> tuple[str, str]:
        index = self._tree.currentIndex()
        if not index.isValid():
            return "", ""
        row = index.row()
        parent_index = index.parent()
        key_item = self._model.itemFromIndex(self._model.index(row, 0, parent_index))
        val_item = self._model.itemFromIndex(self._model.index(row, 1, parent_index))
        if key_item is None:
            return "", ""
        key = key_item.text()
        val = val_item.text() if val_item is not None else ""
        return key, val

    def _current_obj_and_key(self) -> tuple[Any, str]:
        index = self._tree.currentIndex()
        if not index.isValid():
            return None, ""
        row = index.row()
        parent_index = index.parent()
        key_item = self._model.itemFromIndex(self._model.index(row, 0, parent_index))
        if key_item is None:
            return None, ""
        return key_item.data(_USER_ROLE), key_item.text()

    def _on_context_menu(self, pos: object) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return
        self._tree.setCurrentIndex(index)
        key, val = self._current_key_value()
        if not key and not val:
            return
        obj, _ = self._current_obj_and_key()
        menu = QMenu(self)
        inspect_action = menu.addAction("Inspect BLOB…")
        menu.addSeparator()
        copy_key = menu.addAction("Copy key")
        copy_value = menu.addAction("Copy value")
        copy_pair = menu.addAction("Copy key = value")
        action = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if action == inspect_action:
            from crush.viewers.table_viewer import BlobInspector
            BlobInspector(self._make_blob(obj), self).show()
        elif action == copy_key:
            QApplication.clipboard().setText(key)
        elif action == copy_value:
            QApplication.clipboard().setText(val)
        elif action == copy_pair:
            QApplication.clipboard().setText(f"{key} = {val}")
