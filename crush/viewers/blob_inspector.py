# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""BLOB Inspector dialog with a chainable decode pipeline and multi-view panel."""
from __future__ import annotations

import base64
import gzip
import json as _json
import zlib
from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QContextMenuEvent, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from crush.core.formatters import (
    bytes_to_hexview,
    try_plist_text,
    try_xml_text,
)
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

# Column layout of bytes_to_hexview output, e.g. "0000000a: 48 65 6c  Hel"
_BLOB_HEX_START = 10
_BLOB_HEX_END = 57
_BLOB_ASCII_START = 59

_PROTOBUF_INTERP_SKIP = {"uint64", "uint32"}


# ---------------------------------------------------------------------------
# Decode functions — intermediate (bytes → bytes)
# ---------------------------------------------------------------------------

def _decode_base64(data: bytes) -> bytes | None:
    try:
        return base64.b64decode(data.strip())
    except Exception:
        return None


def _decode_hex(data: bytes) -> bytes | None:
    try:
        text = data.decode("ascii", errors="ignore")
        cleaned = "".join(text.split()).replace(":", "")
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def _decode_zlib(data: bytes) -> bytes | None:
    try:
        return zlib.decompress(data)
    except Exception:
        return None


def _decode_gzip(data: bytes) -> bytes | None:
    try:
        return gzip.decompress(data)
    except Exception:
        return None


def _decode_base64url(data: bytes) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(data.strip() + b"==")
    except Exception:
        return None


def _decode_lzfse(data: bytes) -> bytes | None:
    try:
        import lzfse
        return lzfse.decompress(data)  # type: ignore[attr-defined]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Render functions — terminal (bytes → str)
# ---------------------------------------------------------------------------

def _try_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except Exception:
        return ""


def _try_latin1(data: bytes) -> str:
    try:
        return data.decode("latin-1")
    except Exception:
        return ""


def _try_json(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except Exception:
        return ""
    unescaped = text.replace('\\"', '"')
    for candidate in (text, unescaped):
        try:
            return _json.dumps(_json.loads(candidate), indent=2, ensure_ascii=False)
        except Exception:
            pass
    candidate = unescaped if '\\"' in text else text
    if candidate.lstrip().startswith(("{", "[")):
        return "[partial / truncated JSON — pretty-print not possible]\n\n" + candidate
    return ""


def _try_plist(data: bytes) -> str:
    return try_plist_text(data) or ""


def _try_xml(data: bytes) -> str:
    return try_xml_text(data) or ""


def _try_protobuf(data: bytes) -> str:
    try:
        from crush.parsers.protobuf_parser import _decode_message
        decoded, warning, _text = _decode_message(data)
        result = _render_protobuf(decoded.get("entries", []))
        if warning:
            result = f"# Warning: {warning}\n\n{result}"
        return result
    except Exception:
        return ""


def _try_abx(data: bytes) -> str:
    try:
        from crush.parsers.abx_decoder import decode_abx
        return decode_abx(data).xml
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Format registries — add a new format by adding one entry here
# ---------------------------------------------------------------------------

# bytes → bytes; None on failure
_INTERMEDIATE: dict[str, Callable[[bytes], bytes | None]] = {
    "Base64 (decode)":   _decode_base64,
    "Base64url (decode)": _decode_base64url,
    "Hex → Bytes":       _decode_hex,
    "zlib decompress":   _decode_zlib,
    "gzip decompress":   _decode_gzip,
    "lzfse decompress":  _decode_lzfse,
}

# bytes → str; tuple is (render_fn, error_label_on_failure)
_TERMINAL_TEXT: dict[str, tuple[Callable[[bytes], str], str]] = {
    "UTF-8 text":               (_try_utf8,     "[decode error]"),
    "Latin-1 text":             (_try_latin1,   "[decode error]"),
    "JSON":                     (_try_json,     "[parse error]"),
    "Plist / bplist":           (_try_plist,    "[parse error]"),
    "XML":                      (_try_xml,      "[parse error]"),
    "Protobuf (schema-less)":   (_try_protobuf, "[parse error]"),
    "Android Binary XML (ABX)": (_try_abx,      "[parse error]"),
}

# Subset of _TERMINAL_TEXT keys tried by auto-detection, in priority order
_AUTO_ORDER: tuple[str, ...] = (
    "Plist / bplist",
    "XML",
    "JSON",
    "UTF-8 text",
    "Latin-1 text",
)

# Formats that always (or almost always) produce output — not a strong recognition signal
_PERMISSIVE: frozenset[str] = frozenset({"Latin-1 text", "Protobuf (schema-less)"})

_INTERMEDIATE_FORMATS: tuple[str, ...] = tuple(_INTERMEDIATE)


def _is_image(data: bytes) -> bool:
    return (
        data[:8] == b"\x89PNG\r\n\x1a\n"
        or data[:3] == b"\xff\xd8\xff"
        or data[:6] in (b"GIF87a", b"GIF89a")
    )


def _render_protobuf(entries: list, indent: int = 0) -> str:
    lines: list[str] = []
    pad = "  " * indent
    ipad = pad + "    "
    for entry in entries:
        field = entry.get("field", "?")
        wt = entry.get("wire_type", "?")
        val = entry.get("value")
        interpretations = [
            i for i in entry.get("interpretations", [])
            if i.label not in _PROTOBUF_INTERP_SKIP
        ]
        if isinstance(val, dict):
            vtype = val.get("type")
            if vtype == "message":
                lines.append(f"{pad}{field} {{")
                lines.append(_render_protobuf(val.get("entries", []), indent + 1))
                lines.append(f"{pad}}}")
            elif vtype == "string":
                lines.append(f'{pad}{field}: "{val.get("text", "")}"')
            else:
                lines.append(f"{pad}{field}: <{val.get('hex_preview', '')}>")
        elif isinstance(val, bytes):
            lines.append(f"{pad}{field}: {val[:32].hex()}" + ("…" if len(val) > 32 else ""))
        else:
            lines.append(f"{pad}{field} [{wt}]: {val}")
        for interp in interpretations:
            lines.append(f"{ipad}# {interp.label}: {interp.value}")
    return "\n".join(lines)


class _BlobViewerEdit(QPlainTextEdit):
    """QPlainTextEdit with a hex-aware context menu."""

    def __init__(self, panel: "_BlobPanel") -> None:
        super().__init__()
        self._panel = panel

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = self.createStandardContextMenu()
        cursor = self.textCursor()
        if cursor.hasSelection() and self._panel._is_hex_mode():
            menu.addSeparator()
            menu.addAction("Copy Selected Hex").triggered.connect(
                self._panel._copy_selected_hex
            )
            menu.addAction("Copy Selected ASCII").triggered.connect(
                self._panel._copy_selected_ascii
            )
        menu.addSeparator()
        menu.addAction("Copy All").triggered.connect(self._panel._copy_all)
        menu.exec(event.globalPos())


_STEP_LIST_MAX_VISIBLE = 5


class _StepRow(QWidget):
    """One transform step in the decode pipeline: label + format list + size hint."""

    def __init__(self, number: int, inspector: "_BlobPanel") -> None:
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(2)

        header = QHBoxLayout()
        self._num_label = QLabel(f"Step {number}:")
        header.addWidget(self._num_label)
        header.addStretch()
        remove_btn = QPushButton("✕")
        remove_btn.setFixedSize(22, 22)
        remove_btn.setToolTip("Remove this step")
        remove_btn.clicked.connect(lambda: inspector._remove_step(self))
        header.addWidget(remove_btn)
        layout.addLayout(header)

        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._list.addItems(_INTERMEDIATE_FORMATS)
        self._list.setCurrentRow(0)
        visible = min(len(_INTERMEDIATE_FORMATS), _STEP_LIST_MAX_VISIBLE)
        row_h = self._list.sizeHintForRow(0)
        self._list.setFixedHeight(visible * row_h + 4)
        self._list.currentItemChanged.connect(lambda *_: inspector._recompute())
        layout.addWidget(self._list)

        self._hint = QLabel("")
        self._hint.setStyleSheet("color: gray;")
        layout.addWidget(self._hint)

    def format(self) -> str:
        item = self._list.currentItem()
        return item.text() if item else ""

    def set_number(self, n: int) -> None:
        self._num_label.setText(f"Step {n}:")

    def set_hint(self, text: str) -> None:
        self._hint.setText(text)


class _BlobPanel(QWidget):
    """Three-column BLOB inspection panel reused by BlobInspector and PasteDecodeDialog."""

    def __init__(
        self,
        blob: bytes,
        parent: QWidget | None = None,
        *,
        display_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._blob = blob
        self._display_text = display_text
        self._steps: list[_StepRow] = []
        self._cached_results: dict[str, str] = {}
        self._cached_image_data: bytes | None = None
        self._hex_mode = False
        self._build_panel()
        self._recompute()

    def update_blob(self, blob: bytes) -> None:
        """Replace the inspected bytes and refresh all interpretations."""
        self._blob = blob
        for step in self._steps:
            step.set_hint("")
        self._recompute()

    def _build_panel(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # --- Column 1: Decode pipeline ---
        pipeline_widget = QWidget()
        pipeline_col = QVBoxLayout(pipeline_widget)
        pipeline_col.setContentsMargins(0, 0, 4, 0)
        pipeline_col.setSpacing(4)

        lbl_pipeline = QLabel("Decode pipeline")
        lbl_pipeline.setStyleSheet("font-weight: bold;")
        pipeline_col.addWidget(lbl_pipeline)

        steps_container = QWidget()
        self._pipeline_layout = QVBoxLayout(steps_container)
        self._pipeline_layout.setContentsMargins(0, 0, 0, 0)
        self._pipeline_layout.setSpacing(0)
        pipeline_col.addWidget(steps_container)
        pipeline_col.addStretch()

        self._add_btn = QPushButton("＋  Add step")
        self._add_btn.clicked.connect(self._push_step)
        pipeline_col.addWidget(self._add_btn)

        splitter.addWidget(pipeline_widget)

        # --- Column 2: Interpretations ---
        interp_widget = QWidget()
        interp_col = QVBoxLayout(interp_widget)
        interp_col.setContentsMargins(4, 0, 4, 0)
        interp_col.setSpacing(4)

        lbl_interp = QLabel("Interpretations")
        lbl_interp.setStyleSheet("font-weight: bold;")
        interp_col.addWidget(lbl_interp)

        self._format_list = QListWidget()
        self._format_list.currentItemChanged.connect(self._on_item_changed)
        interp_col.addWidget(self._format_list)

        splitter.addWidget(interp_widget)

        # --- Column 3: Content view ---
        content_widget = QWidget()
        content_col = QVBoxLayout(content_widget)
        content_col.setContentsMargins(4, 0, 0, 0)
        content_col.setSpacing(4)

        self._stack = QStackedWidget()

        self._viewer = _BlobViewerEdit(self)
        self._viewer.setReadOnly(True)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._viewer, smooth_item_scroll=False)
        self._stack.addWidget(self._viewer)

        self._img_scroll = QScrollArea()
        self._img_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img_scroll.setWidgetResizable(False)
        install_horizontal_wheel_scroll(self._img_scroll, smooth_item_scroll=False)
        self._img_label = QLabel()
        self._img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img_scroll.setWidget(self._img_label)
        self._stack.addWidget(self._img_scroll)

        content_col.addWidget(self._stack, stretch=1)

        copy_row = QHBoxLayout()
        self._copy_btn = QPushButton("Copy")
        self._copy_btn.clicked.connect(self._copy_current)
        copy_row.addWidget(self._copy_btn)
        copy_row.addStretch()
        content_col.addLayout(copy_row)

        splitter.addWidget(content_widget)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 0)
        splitter.setStretchFactor(2, 1)
        splitter.setSizes([185, 170, 505])

        outer.addWidget(splitter, stretch=1)

    def _push_step(self) -> None:
        number = len(self._steps) + 1
        step = _StepRow(number, self)
        self._steps.append(step)
        self._pipeline_layout.addWidget(step)
        self._recompute()

    def _remove_step(self, step: _StepRow) -> None:
        idx = self._steps.index(step)
        self._steps.pop(idx)
        self._pipeline_layout.removeWidget(step)
        step.deleteLater()
        for i, s in enumerate(self._steps):
            s.set_number(i + 1)
        self._recompute()

    def _recompute(self) -> None:
        current = self._blob

        for i, step in enumerate(self._steps):
            fmt = step.format()
            result = _INTERMEDIATE[fmt](current)
            if result is None:
                step.set_hint("→ [error]")
                for s in self._steps[i + 1:]:
                    s.set_hint("")
                self._format_list.blockSignals(True)
                self._format_list.clear()
                self._format_list.blockSignals(False)
                self._viewer.setPlainText(f"[step {i + 1}: {fmt!r} failed]")
                self._stack.setCurrentIndex(0)
                self._hex_mode = False
                self._copy_btn.setEnabled(False)
                return
            step.set_hint(f"→ {len(result):,} B")
            current = result

        self._populate_format_list(current)

    def _populate_format_list(self, data: bytes) -> None:
        self._cached_results = {}
        self._cached_image_data = None

        confident: list[str] = []
        uncertain: list[str] = []
        failed: list[str] = []

        if self._display_text is not None:
            confident.append("Decoded (from table)")
            self._cached_results["Decoded (from table)"] = self._display_text

        if _is_image(data):
            confident.append("Image")
            self._cached_image_data = data
        else:
            failed.append("Image")

        ordered_keys = list(_AUTO_ORDER) + [k for k in _TERMINAL_TEXT if k not in set(_AUTO_ORDER)]
        for key in ordered_keys:
            render_fn, _ = _TERMINAL_TEXT[key]
            result = render_fn(data)
            if result:
                self._cached_results[key] = result
                if key in _PERMISSIVE:
                    uncertain.append(key)
                else:
                    confident.append(key)
            else:
                failed.append(key)

        self._cached_results["Hex view"] = bytes_to_hexview(data, max_bytes=200_000)

        prev = self._format_list.currentItem()
        prev_name: str | None = prev.data(Qt.ItemDataRole.UserRole) if prev else None

        muted = QColor(128, 128, 128)

        self._format_list.blockSignals(True)
        self._format_list.clear()

        def _sep() -> None:
            s = QListWidgetItem("─" * 18)
            s.setFlags(Qt.ItemFlag.NoItemFlags)
            s.setForeground(muted)
            self._format_list.addItem(s)

        hex_item = QListWidgetItem("Hex view")
        hex_item.setData(Qt.ItemDataRole.UserRole, "Hex view")
        self._format_list.addItem(hex_item)

        if confident:
            _sep()
            for name in confident:
                item = QListWidgetItem(f"✓  {name}")
                item.setData(Qt.ItemDataRole.UserRole, name)
                self._format_list.addItem(item)

        if uncertain:
            _sep()
            for name in uncertain:
                item = QListWidgetItem(f"~  {name}")
                item.setData(Qt.ItemDataRole.UserRole, name)
                item.setForeground(muted)
                self._format_list.addItem(item)

        if failed:
            _sep()
            for name in failed:
                item = QListWidgetItem(f"    {name}")
                item.setData(Qt.ItemDataRole.UserRole, name)
                item.setForeground(muted)
                self._format_list.addItem(item)

        to_select: str
        prev_still_valid = prev_name is not None and (
            prev_name in self._cached_results
            or (prev_name == "Image" and self._cached_image_data is not None)
        )
        if prev_still_valid:
            to_select = prev_name  # type: ignore[assignment]
        elif self._display_text is not None:
            to_select = "Decoded (from table)"
        elif self._cached_image_data is not None:
            to_select = "Image"
        else:
            to_select = next((k for k in _AUTO_ORDER if k in self._cached_results and k not in _PERMISSIVE), "Hex view")

        for i in range(self._format_list.count()):
            item = self._format_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == to_select:
                self._format_list.setCurrentItem(item)
                break

        self._format_list.blockSignals(False)

        current_item = self._format_list.currentItem()
        self._on_format_selected(current_item.data(Qt.ItemDataRole.UserRole) if current_item else "")

    def _on_item_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            return
        name: str = current.data(Qt.ItemDataRole.UserRole)
        if not name:
            return
        self._on_format_selected(name)

    def _on_format_selected(self, name: str) -> None:
        if not name:
            return

        if name == "Image":
            if self._cached_image_data is not None:
                self._show_image(self._cached_image_data)
            else:
                self._stack.setCurrentIndex(0)
                self._copy_btn.setEnabled(False)
                self._viewer.setPlainText("[not recognised as image]")
            return

        self._stack.setCurrentIndex(0)
        self._hex_mode = name == "Hex view"

        if name in self._cached_results:
            self._copy_btn.setEnabled(True)
            self._viewer.setPlainText(self._cached_results[name][:500_000])
        else:
            self._copy_btn.setEnabled(False)
            self._viewer.setPlainText(f"[{name}: not recognised]")

    def _show_image(self, data: bytes) -> None:
        from PySide6.QtCore import QByteArray
        px = QPixmap()
        if px.loadFromData(QByteArray(data)):
            self._img_label.setPixmap(px)
            self._img_label.resize(px.size())
            self._stack.setCurrentIndex(1)
            self._copy_btn.setEnabled(False)
        else:
            self._stack.setCurrentIndex(0)
            self._copy_btn.setEnabled(True)
            self._viewer.setPlainText("[not a recognised image format]")

    def _is_hex_mode(self) -> bool:
        return self._hex_mode

    def _copy_current(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())

    def _copy_all(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())

    def _copy_selected_hex(self) -> None:
        cursor = self._viewer.textCursor()
        if not cursor.hasSelection():
            return
        tokens: list[str] = []
        for line in cursor.selectedText().split(" "):
            hex_section = line[_BLOB_HEX_START:_BLOB_HEX_END]
            for part in hex_section.split():
                if len(part) == 2 and all(c in "0123456789ABCDEFabcdef" for c in part):
                    tokens.append(part.upper())
        QApplication.clipboard().setText(" ".join(tokens))

    def _copy_selected_ascii(self) -> None:
        cursor = self._viewer.textCursor()
        if not cursor.hasSelection():
            return
        parts: list[str] = []
        for line in cursor.selectedText().split(" "):
            if len(line) > _BLOB_ASCII_START:
                parts.append(line[_BLOB_ASCII_START:])
        QApplication.clipboard().setText("".join(parts))


class BlobInspector(QDialog):
    """Non-modal dialog wrapping _BlobPanel for inspecting a single binary BLOB."""

    def __init__(
        self,
        blob: bytes,
        parent: QWidget | None = None,
        *,
        display_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"BLOB Inspector ({len(blob):,} B)")
        self.resize(900, 560)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        outer.addWidget(_BlobPanel(blob, self, display_text=display_text), stretch=1)

        bottom = QHBoxLayout()
        bottom.addStretch()
        close_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_box.rejected.connect(self.reject)
        bottom.addWidget(close_box)
        outer.addLayout(bottom)
