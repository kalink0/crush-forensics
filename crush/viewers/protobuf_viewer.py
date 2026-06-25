# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Protobuf viewer — schema-less decode with optional schema-based decoding."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QTreeView,
    QVBoxLayout,
    QWidget,
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
        loaded = self._load_descriptor_set(Path(path))
        if loaded is None:
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

    def _load_descriptor_set(self, path: Path) -> dict[str, Any] | None:
        try:
            from google.protobuf import descriptor_pb2, descriptor_pool
        except Exception:
            self._status.setText("Install protobuf to use schema decoding")
            return None

        if path.suffix.lower() == ".proto":
            compiled = _compile_proto(path)
            if compiled is None:
                self._status.setText(".proto requires grpcio-tools or a .pb descriptor set")
                return None
            data = compiled
        else:
            data = path.read_bytes()

        fds = descriptor_pb2.FileDescriptorSet()
        try:
            fds.ParseFromString(data)
        except Exception:
            self._status.setText("Invalid descriptor set")
            return None

        pool = descriptor_pool.DescriptorPool()
        for fd in fds.file:
            pool.Add(fd)

        message_names = _collect_message_names(fds)
        if not message_names:
            self._status.setText("No message types found")
            return None
        return {"pool": pool, "message_names": message_names}

    def _decode_with_schema(self) -> None:
        if self._pool is None:
            self._status.setText("Load a schema first")
            return
        name = self._msg_combo.currentText().strip()
        if not name:
            self._status.setText("Select a message type")
            return
        try:
            from google.protobuf import json_format, message_factory
            descriptor = self._pool.FindMessageTypeByName(name)
            cls = message_factory.MessageFactory(self._pool).GetPrototype(descriptor)
            msg = cls()
            msg.ParseFromString(self._raw)
            decoded = json_format.MessageToDict(
                msg,
                preserving_proto_field_name=True,
                including_default_value_fields=True,
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

        layout.addWidget(self._tree)
        self._populate(decoded.get("entries", []), self._model.invisibleRootItem())
        self._tree.expandToDepth(1)

    def _populate(self, entries: list[dict[str, Any]], parent: QStandardItem) -> None:
        for entry in entries:
            field = entry.get("field", "?")
            wire_type = entry.get("wire_type", "?")
            val = entry.get("value")
            interpretations = entry.get("interpretations", [])

            # Primary value display
            if isinstance(val, dict):
                vtype = val.get("type")
                if vtype == "message":
                    label = f"{{ {len(val.get('entries', []))} field(s) }}"
                elif vtype == "string":
                    label = f'"{val.get("text", "")}"'
                else:
                    label = f'<{val.get("hex_preview", "")}>'
            else:
                label = str(val) if val is not None else ""

            field_item = QStandardItem(f"field {field}")
            val_item = QStandardItem(label)
            wt_item = QStandardItem(wire_type)
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
                    empty = QStandardItem("")
                    empty.setEditable(False)
                    field_item.appendRow([lbl_item, v_item, empty])

            # Recurse into nested messages
            if isinstance(val, dict) and val.get("type") == "message":
                self._populate(val.get("entries", []), field_item)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compile_proto(path: Path) -> bytes | None:
    """Compile a .proto file to a FileDescriptorSet using grpcio-tools if available."""
    try:
        from grpc_tools import protoc
    except Exception:
        return None

    import tempfile

    out_path = Path(tempfile.mkdtemp()) / "descriptor.fds"
    args = [
        "protoc",
        f"-I{path.parent}",
        f"--descriptor_set_out={out_path}",
        "--include_imports",
        str(path),
    ]
    try:
        rc = protoc.main(args)
        if rc != 0 or not out_path.exists():
            return None
        return out_path.read_bytes()
    except Exception:
        return None


def _collect_message_names(fds: Any) -> list[str]:
    names: list[str] = []

    def walk(prefix: str, msg: Any) -> None:
        full = f"{prefix}.{msg.name}" if prefix else msg.name
        names.append(full)
        for nested in msg.nested_type:
            walk(full, nested)

    for fd in fds.file:
        pkg = fd.package or ""
        for msg in fd.message_type:
            walk(pkg, msg)

    names.sort()
    return names
