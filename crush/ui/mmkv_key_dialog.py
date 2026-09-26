# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""MMKV encryption key dialog.

MMKV's key (unlike Realm's, always a raw binary key) can genuinely be either a
short human-typable passphrase or a raw/derived binary key depending on the
app, so this asks explicitly which one it is rather than guessing from the
text's shape — a passphrase that happens to look like hex would otherwise be
silently misinterpreted as one.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)
from crush.ui.i18n import translate


class MMKVKeyDialog(QDialog):
    """Prompt for an MMKV AES key. Call exec(); on QDialog.Accepted, read
    .key_bytes() — already hex-decoded if the Hex checkbox was ticked."""

    def __init__(
        self, parent: QWidget | None = None, wrong_reason: str | None = None,
    ) -> None:
        # wrong_reason: None on the first prompt, else why the previous
        # attempt was rejected ("" if the source gave no reason).
        was_wrong = wrong_reason is not None
        super().__init__(parent)
        self.setWindowTitle(
            translate("MMKVKeyDialog", "Incorrect Key")
            if was_wrong
            else translate("MMKVKeyDialog", "MMKV Encryption Key")
        )
        self._build_ui(wrong_reason)

    def _build_ui(self, wrong_reason: str | None) -> None:
        root = QVBoxLayout(self)

        if wrong_reason is not None:
            retry = translate(
                "MMKVKeyDialog", "Incorrect key, or not a valid hex string. Try again:"
            )
            warn = QLabel(
                f"{wrong_reason}\n\n{retry}"  # i18n: keep -- layout of translated parts
                if wrong_reason
                else retry
            )
            warn.setTextFormat(Qt.TextFormat.PlainText)
            warn.setStyleSheet("color: #b33;")
            warn.setWordWrap(True)
            root.addWidget(warn)

        form = QFormLayout()
        self._key_edit = QLineEdit()
        self._key_edit.setPlaceholderText(translate("MMKVKeyDialog", "Key MMKV was given"))
        form.addRow(translate("MMKVKeyDialog", "Key:"), self._key_edit)

        self._hex_cb = QCheckBox(
            translate("MMKVKeyDialog", "Hex (raw/derived binary key, not typed text)")
        )
        form.addRow("", self._hex_cb)

        self._aes256_cb = QCheckBox(
            translate("MMKVKeyDialog", "AES-256 (MMKV's default is AES-128)")
        )
        form.addRow("", self._aes256_cb)

        root.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def key_text(self) -> str:
        return self._key_edit.text().strip()

    def is_hex(self) -> bool:
        return self._hex_cb.isChecked()

    def is_aes256(self) -> bool:
        return self._aes256_cb.isChecked()

    def key_bytes(self) -> bytes | None:
        """Return the entered key as bytes, or None if hex was requested but invalid."""
        text = self.key_text()
        if not text:
            return None
        if not self.is_hex():
            return text.encode("utf-8")
        cleaned = text.strip()
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace(" ", "").replace(":", "").replace("-", "")
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None
