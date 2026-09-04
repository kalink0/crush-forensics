# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Protobuf viewer — schema-less decode with optional schema-based decoding."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QComboBox,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from crush.parsers.protobuf_schema import (
    SchemaLoadError,
    decode_message_with_schema,
    load_descriptor_set,
)
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.tree_viewer import TreeViewer


class ProtobufViewer(QWidget):
    """Viewer for Protobuf data.

    data shape:
      {"raw": bytes, "decoded": {"entries": [...]}}
    """

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw = data.get("raw", b"") if isinstance(data, dict) else b""
        self._decoded = data.get("decoded", {}) if isinstance(data, dict) else {}
        self._pool = None
        self._descriptor_set = None
        self._message_names: list[str] = []
        self._build_ui()
        self._show_schema_less()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QWidget()
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)

        tb_layout.addWidget(QLabel("Schema:"))
        self._schema_label = QLabel("None")
        self._schema_label.setStyleSheet("color: gray;")
        tb_layout.addWidget(self._schema_label)

        self._load_btn = QPushButton("Load .proto / descriptor…")
        self._load_btn.clicked.connect(self._on_load_schema)
        tb_layout.addWidget(self._load_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._clear_schema)
        self._clear_btn.setEnabled(False)
        tb_layout.addWidget(self._clear_btn)

        tb_layout.addSpacing(12)
        tb_layout.addWidget(QLabel("Message:"))
        self._msg_combo = QComboBox()
        self._msg_combo.setEnabled(False)
        tb_layout.addWidget(self._msg_combo)

        self._decode_btn = QPushButton("Decode")
        self._decode_btn.clicked.connect(self._decode_with_schema)
        self._decode_btn.setEnabled(False)
        tb_layout.addWidget(self._decode_btn)

        self._raw_btn = QPushButton("Show Raw Decode")
        self._raw_btn.clicked.connect(self._show_schema_less)
        tb_layout.addWidget(self._raw_btn)

        tb_layout.addStretch()

        self._status = QLabel("")
        tb_layout.addWidget(self._status)

        layout.addWidget(toolbar)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(0)
        layout.addWidget(self._content)

    def _replace_view(self, widget: QWidget) -> None:
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._content_layout.addWidget(widget)

    def _show_schema_less(self) -> None:
        self._status.setText("Schema-less decode")
        self._replace_view(ProtobufTreeWidget(self._decoded, self))

    def _clear_schema(self) -> None:
        self._pool = None
        self._descriptor_set = None
        self._message_names = []
        self._schema_label.setText("None")
        self._schema_label.setStyleSheet("color: gray;")
        self._msg_combo.clear()
        self._msg_combo.setEnabled(False)
        self._decode_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        self._status.setText("Schema cleared")

    def _on_load_schema(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Protobuf schema",
            "",
            "Protobuf schema (*.proto *.pb *.desc *.fds);;All files (*)",
        )
        if not path:
            return
        try:
            loaded = load_descriptor_set(Path(path))
        except SchemaLoadError as exc:
            self._status.setText(str(exc))
            return
        self._descriptor_set = loaded
        self._pool = loaded["pool"]
        self._message_names = loaded["message_names"]
        self._msg_combo.clear()
        self._msg_combo.addItems(self._message_names)
        self._msg_combo.setEnabled(bool(self._message_names))
        self._decode_btn.setEnabled(bool(self._message_names))
        self._clear_btn.setEnabled(True)
        self._schema_label.setText(Path(path).name)
        self._schema_label.setStyleSheet("color: palette(text);")
        self._status.setText(f"Loaded {len(self._message_names)} message types")

    def _decode_with_schema(self) -> None:
        if self._pool is None:
            self._status.setText("Load a schema first")
            return
        name = self._msg_combo.currentText().strip()
        if not name:
            self._status.setText("Select a message type")
            return
        try:
            from google.protobuf import json_format
            msg = decode_message_with_schema(self._pool, name, self._raw)
            decoded = json_format.MessageToDict(
                msg,
                preserving_proto_field_name=True,
                always_print_fields_with_no_presence=True,
            )
        except Exception as exc:
            self._status.setText(f"Decode failed: {exc}")
            return

        self._status.setText(f"Decoded as {name}")
        self._replace_view(TreeViewer(decoded, self))


# ---------------------------------------------------------------------------
# Protobuf-specific tree widget
# ---------------------------------------------------------------------------

_GRAY = QColor(130, 130, 130)
_INTERP_FONT_SIZE_DELTA = -1  # points smaller than parent
_RAW_ROLE = Qt.ItemDataRole.UserRole
_FULLTEXT_ROLE = Qt.ItemDataRole.UserRole + 1


class ProtobufTreeWidget(QWidget):
    """Tree view tailored for schema-less protobuf entries.

    Each field is a top-level row; its interpretations appear as dimmed child
    rows so analysts can immediately see all candidate type readings.
    Nested messages expand recursively.
    """

    def __init__(self, decoded: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Field", "Value", "Wire type"])

        self._tree = QTreeView()
        self._tree.setModel(self._model)
        self._tree.setAlternatingRowColors(True)
        self._tree.setAnimated(True)
        install_horizontal_wheel_scroll(self._tree)
        self._tree.header().setStretchLastSection(False)
        self._tree.setColumnWidth(0, 140)
        self._tree.setColumnWidth(1, 340)
        self._tree.setColumnWidth(2, 120)
        self._tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._tree)

        value_bar = QWidget()
        vb_layout = QHBoxLayout(value_bar)
        vb_layout.setContentsMargins(8, 4, 8, 4)
        vb_layout.setSpacing(8)
        vb_layout.addWidget(QLabel("Value:"))
        self._value_field = QLineEdit()
        self._value_field.setReadOnly(True)
        vb_layout.addWidget(self._value_field, 1)
        layout.addWidget(value_bar)

        self._populate(decoded.get("entries", []), self._model.invisibleRootItem())
        self._tree.expandToDepth(1)
        self._tree.selectionModel().selectionChanged.connect(self._update_value_field)

    def _populate(self, entries: list[dict[str, Any]], parent: QStandardItem) -> None:
        for entry in entries:
            field = entry.get("field", "?")
            wire_type = entry.get("wire_type", "?")
            val = entry.get("value")
            interpretations = entry.get("interpretations", [])

            # Primary value display
            raw_bytes = entry.get("raw")  # full payload; only set for length-delimited entries
            if isinstance(val, dict):
                vtype = val.get("type")
                if vtype == "message":
                    label = f"{{ {len(val.get('entries', []))} field(s) }}"
                    full_text = label
                elif vtype == "string":
                    text = val.get("text", "")
                    label = f'"{text}"'
                    full_text = text
                else:
                    label = f'<{val.get("hex_preview", "")}>'
                    # hex_preview is capped at 64 bytes by the parser — show the complete
                    # payload here instead of repeating that truncated preview.
                    full_text = raw_bytes.hex(" ") if raw_bytes else label
            else:
                label = str(val) if val is not None else ""
                full_text = label

            field_item = QStandardItem(f"field {field}")
            val_item = QStandardItem(label)
            wt_item = QStandardItem(wire_type)
            val_item.setData(raw_bytes, _RAW_ROLE)
            val_item.setData(full_text, _FULLTEXT_ROLE)
            for item in (field_item, val_item, wt_item):
                item.setEditable(False)
            parent.appendRow([field_item, val_item, wt_item])

            # Interpretations as dimmed child rows
            if interpretations:
                interp_font = field_item.font()
                interp_font.setPointSize(max(7, interp_font.pointSize() + _INTERP_FONT_SIZE_DELTA))
                for interp in interpretations:
                    lbl_item = QStandardItem(f"  {interp.label}")
                    lbl_item.setForeground(_GRAY)
                    lbl_item.setFont(interp_font)
                    lbl_item.setEditable(False)
                    v_item = QStandardItem(interp.value)
                    v_item.setForeground(_GRAY)
                    v_item.setFont(interp_font)
                    v_item.setEditable(False)
                    if interp.label == "raw bytes" and raw_bytes:
                        # interp.value is the same 64-byte-capped preview as the field's
                        # own hex_preview — point the value box / Inspect BLOB at the
                        # full payload instead of repeating that truncated text.
                        v_item.setData(raw_bytes, _RAW_ROLE)
                        v_item.setData(raw_bytes.hex(" "), _FULLTEXT_ROLE)
                    empty = QStandardItem("")
                    empty.setEditable(False)
                    field_item.appendRow([lbl_item, v_item, empty])

            # Recurse into nested messages
            if isinstance(val, dict) and val.get("type") == "message":
                self._populate(val.get("entries", []), field_item)

    def _current_row_items(self) -> tuple[QStandardItem, QStandardItem] | None:
        index = self._tree.currentIndex()
        if not index.isValid():
            return None
        row, parent_index = index.row(), index.parent()
        key_item = self._model.itemFromIndex(self._model.index(row, 0, parent_index))
        val_item = self._model.itemFromIndex(self._model.index(row, 1, parent_index))
        if key_item is None or val_item is None:
            return None
        return key_item, val_item

    def _update_value_field(self) -> None:
        items = self._current_row_items()
        if items is None:
            self._value_field.clear()
            return
        _, val_item = items
        full_text = val_item.data(_FULLTEXT_ROLE)
        self._value_field.setText(full_text if full_text is not None else val_item.text())
        self._value_field.setCursorPosition(0)

    def _on_context_menu(self, pos: object) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return
        self._tree.setCurrentIndex(index)
        items = self._current_row_items()
        if items is None:
            return
        key_item, val_item = items
        key = key_item.text()
        value = val_item.data(_FULLTEXT_ROLE)
        value = value if value is not None else val_item.text()
        raw_bytes = val_item.data(_RAW_ROLE)

        menu = QMenu(self)
        inspect_action = menu.addAction("Inspect BLOB…")
        inspect_action.setEnabled(bool(raw_bytes))
        menu.addSeparator()
        copy_key = menu.addAction("Copy key")
        copy_value = menu.addAction("Copy value")
        copy_pair = menu.addAction("Copy key = value")
        action = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if action == inspect_action:
            from crush.viewers.table_viewer import BlobInspector
            BlobInspector(raw_bytes, self).show()
        elif action == copy_key:
            QApplication.clipboard().setText(key)
        elif action == copy_value:
            QApplication.clipboard().setText(value)
        elif action == copy_pair:
            QApplication.clipboard().setText(f"{key} = {value}")
