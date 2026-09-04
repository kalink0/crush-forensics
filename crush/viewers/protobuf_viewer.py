# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Protobuf viewer — schema-less decode with optional schema-based decoding."""
from __future__ import annotations

import json
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
_ENTRY_ROLE = Qt.ItemDataRole.UserRole + 2  # the field's original decoded entry dict


def _entry_to_jsonable(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert one decoded protobuf entry to a JSON-safe dict.

    Uses the entry's full raw payload for a bytes field's value (not the parser's
    64-byte-capped hex_preview, per #60) so an export never contains less than the
    field actually holds.
    """
    from crush.viewers.blob_inspector import _PROTOBUF_INTERP_SKIP

    out: dict[str, Any] = {"field": entry.get("field"), "wire_type": entry.get("wire_type")}
    val = entry.get("value")
    raw = entry.get("raw")
    if isinstance(val, dict):
        vtype = val.get("type")
        if vtype == "message":
            out["type"] = "message"
            out["entries"] = [_entry_to_jsonable(e) for e in val.get("entries", [])]
        elif vtype == "string":
            out["type"] = "string"
            out["value"] = val.get("text", "")
        else:
            out["type"] = "bytes"
            out["length"] = val.get("length")
            out["value_hex"] = raw.hex() if raw else val.get("hex_preview", "")
    else:
        out["type"] = "scalar"
        out["value"] = val
    interpretations = [
        i for i in entry.get("interpretations", [])
        if i.label not in _PROTOBUF_INTERP_SKIP
    ]
    if interpretations:
        out["interpretations"] = {i.label: i.value for i in interpretations}
    return out


def _entries_to_json(entries: list[dict[str, Any]]) -> str:
    return json.dumps([_entry_to_jsonable(e) for e in entries], indent=2, ensure_ascii=False)


class ProtobufTreeWidget(QWidget):
    """Tree view tailored for schema-less protobuf entries.

    Each field is a top-level row; its interpretations appear as dimmed child
    rows so analysts can immediately see all candidate type readings.
    Nested messages expand recursively.
    """

    def __init__(self, decoded: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._decoded = decoded
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QWidget()
        toolbar.setFixedHeight(36)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)
        self._expand_all_btn = QPushButton("Expand All")
        self._expand_all_btn.clicked.connect(self._tree_expand_all)
        tb_layout.addWidget(self._expand_all_btn)
        self._collapse_all_btn = QPushButton("Collapse All")
        self._collapse_all_btn.clicked.connect(self._tree_collapse_all)
        tb_layout.addWidget(self._collapse_all_btn)
        self._export_btn = QPushButton("Export…")
        self._export_btn.clicked.connect(self._show_export_menu)
        tb_layout.addWidget(self._export_btn)
        tb_layout.addStretch()
        tb_layout.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter fields / values…")
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        tb_layout.addWidget(self._search)
        layout.addWidget(toolbar)

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
            field_item.setData(entry, _ENTRY_ROLE)
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

    def _tree_expand_all(self) -> None:
        self._tree.expandAll()

    def _tree_collapse_all(self) -> None:
        self._tree.collapseAll()

    def _apply_filter(self, text: str) -> None:
        """Show/hide rows whose field name or value contains the search text."""
        self._filter_items(self._model.invisibleRootItem(), text.lower())

    def _filter_items(self, parent: QStandardItem, text: str) -> bool:
        any_visible = False
        for row in range(parent.rowCount()):
            key_item = parent.child(row, 0)
            val_item = parent.child(row, 1)
            if key_item is None:
                continue
            child_visible = self._filter_items(key_item, text)
            # Match against the full (untruncated) value where available, so a search
            # can find text even in a value the tree cell itself shows truncated.
            full_text = val_item.data(_FULLTEXT_ROLE) if val_item else None
            val_text = full_text if full_text is not None else (val_item.text() if val_item else "")
            key_match = not text or text in key_item.text().lower()
            val_match = text in val_text.lower()
            visible = key_match or val_match or child_visible
            self._tree.setRowHidden(
                row,
                self._model.indexFromItem(parent),
                not visible,
            )
            any_visible = any_visible or visible
        return any_visible

    def _show_export_menu(self) -> None:
        menu = QMenu(self)
        export_text = menu.addAction("Export All as Text…")
        export_json = menu.addAction("Export All as JSON…")
        action = menu.exec(self._export_btn.mapToGlobal(self._export_btn.rect().bottomLeft()))
        entries = self._decoded.get("entries", [])
        if action == export_text:
            self._export_entries(entries, "text", "protobuf.txt")
        elif action == export_json:
            self._export_entries(entries, "json", "protobuf.json")

    def _export_entries(self, entries: list[dict[str, Any]], fmt: str, default_name: str) -> None:
        if fmt == "json":
            content = _entries_to_json(entries)
            name_filter = "JSON (*.json)"
        else:
            from crush.viewers.blob_inspector import _render_protobuf
            content = _render_protobuf(entries)
            name_filter = "Text (*.txt)"
        path, _ = QFileDialog.getSaveFileName(self, "Export Protobuf", default_name, name_filter)
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

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
        subtree_entry = key_item.data(_ENTRY_ROLE)  # None for interpretation hint rows

        menu = QMenu(self)
        inspect_action = menu.addAction("Inspect BLOB…")
        inspect_action.setEnabled(bool(raw_bytes))
        menu.addSeparator()
        copy_key = menu.addAction("Copy key")
        copy_value = menu.addAction("Copy value")
        copy_pair = menu.addAction("Copy key = value")
        menu.addSeparator()
        export_text = menu.addAction("Export Subtree as Text…")
        export_text.setEnabled(subtree_entry is not None)
        export_json = menu.addAction("Export Subtree as JSON…")
        export_json.setEnabled(subtree_entry is not None)
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
        elif action == export_text:
            self._export_entries([subtree_entry], "text", f"{key.replace(' ', '_')}.txt")
        elif action == export_json:
            self._export_entries([subtree_entry], "json", f"{key.replace(' ', '_')}.json")
