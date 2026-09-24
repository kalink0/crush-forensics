# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Paste & Decode dialog — paste hex/base64/text and inspect the decoded bytes inline."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from crush.core.paste_decode import (
    ENCODING_AUTO,
    ENCODING_BASE64,
    ENCODING_HEX,
    ENCODING_UTF8,
)
from crush.core.paste_decode import try_decode_input as _try_decode_input
from crush.viewers.blob_inspector import _BlobPanel

# (display text, stable encoding key) — item text is translatable later,
# the key passed to try_decode_input() never changes with the UI language.
_INPUT_ENCODINGS = [
    ("Auto", ENCODING_AUTO),
    ("Hex", ENCODING_HEX),
    ("Base64", ENCODING_BASE64),
    ("UTF-8 text", ENCODING_UTF8),
]

_EMPTY = b""


class PasteDecodeDialog(QDialog):
    """Dialog that lets the user paste hex/base64/text and inspect the decoded bytes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Paste & Decode")
        self.resize(900, 640)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(200)
        self._debounce.timeout.connect(self._decode_and_update)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 8)

        # --- Input area ---
        root.addWidget(QLabel("Paste data (hex, base64, or plain text):"))

        self._paste_area = QPlainTextEdit()
        self._paste_area.setPlaceholderText(
            "62706c6973743030…   (hex)\n"
            "YnBsaXN0MDA…       (base64)\n"
            "<?xml version…     (text)"
        )
        self._paste_area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._paste_area.setFixedHeight(80)
        self._paste_area.textChanged.connect(self._debounce.start)
        root.addWidget(self._paste_area)

        # --- Encoding row + status ---
        enc_row = QHBoxLayout()
        enc_row.addWidget(QLabel("Input encoding:"))
        self._encoding_combo = QComboBox()
        for label, key in _INPUT_ENCODINGS:
            self._encoding_combo.addItem(label, key)
        self._encoding_combo.currentIndexChanged.connect(self._decode_and_update)
        enc_row.addWidget(self._encoding_combo)
        enc_row.addSpacing(16)
        self._status_label = QLabel("Paste data above")
        self._status_label.setStyleSheet("color: gray;")
        enc_row.addWidget(self._status_label)
        enc_row.addStretch()
        root.addLayout(enc_row)

        # --- Blob panel (always visible, starts with empty bytes) ---
        self._blob_panel = _BlobPanel(_EMPTY, self)
        root.addWidget(self._blob_panel, stretch=1)

        # --- Close button ---
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_box.rejected.connect(self.reject)
        btn_row.addWidget(close_box)
        root.addLayout(btn_row)

    def _decode_and_update(self) -> None:
        text = self._paste_area.toPlainText()
        encoding = self._encoding_combo.currentData()
        data, msg = _try_decode_input(text, encoding)
        if data is None:
            self._status_label.setText(msg)
            self._status_label.setStyleSheet("color: gray;")
            self._blob_panel.update_blob(_EMPTY)
        else:
            self._status_label.setText(msg)
            self._status_label.setStyleSheet("color: green;")
            self._blob_panel.update_blob(data)
