# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""What opens an encrypted volume inside a disk image: a BitLocker volume's
password, recovery password or startup key file (.BEK), an APFS volume's
password or personal recovery key, a LUKS container's passphrase.

Every secret given in a source is tried on every locked volume in it, so one
entry can open several. Nothing typed or chosen here is stored.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from crush.ui.i18n import translate

_MIN_WIDTH_CHARS = 90


class UnlockVolumeDialog(QDialog):
    """Ask for a secret for the locked volume *volume*. Call exec(); on
    QDialog.Accepted, read .password() and .key_file() -- at least one is
    set. *reason* is the reader's note on why the volume is not read; the
    key file field is offered for a BitLocker volume (*kind* "bitlocker")."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        volume: str,
        kind: str,
        reason: str = "",
    ) -> None:
        super().__init__(parent)
        self._with_key_file = kind == "bitlocker"
        self.setWindowTitle(translate("UnlockVolumeDialog", "Unlock Volume"))
        self._build_ui(volume, reason)
        self.setMinimumWidth(self.fontMetrics().averageCharWidth() * _MIN_WIDTH_CHARS)
        self.adjustSize()

    def _build_ui(self, volume: str, reason: str) -> None:
        root = QVBoxLayout(self)

        heading = QLabel(volume)
        heading.setTextFormat(Qt.TextFormat.PlainText)
        heading.setStyleSheet("font-weight: bold;")
        root.addWidget(heading)

        if reason:
            why = QLabel(reason)
            why.setTextFormat(Qt.TextFormat.PlainText)
            why.setWordWrap(True)
            root.addWidget(why)

        prompt = QLabel(
            translate(
                "UnlockVolumeDialog",
                "Enter a password or recovery password, or choose a startup key file "
                "(.BEK). It is tried on every locked volume of this image, together "
                "with what was given before; it is not stored.",
            )
            if self._with_key_file
            else translate(
                "UnlockVolumeDialog",
                "Enter a password, passphrase or recovery key. It is tried on every "
                "locked volume of this image, together with what was given before; it "
                "is not stored.",
            )
        )
        prompt.setWordWrap(True)
        root.addWidget(prompt)

        form = QFormLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(translate("UnlockVolumeDialog", "Password:"), self._password_edit)

        self._key_edit = QLineEdit()
        if self._with_key_file:
            key_row = QHBoxLayout()
            self._key_edit.setPlaceholderText(
                translate("UnlockVolumeDialog", "Startup key file (.BEK)")
            )
            browse = QPushButton(translate("UnlockVolumeDialog", "Browse…"))
            browse.clicked.connect(self._browse_key)
            key_row.addWidget(self._key_edit)
            key_row.addWidget(browse)
            form.addRow(translate("UnlockVolumeDialog", "Startup key:"), key_row)
        root.addLayout(form)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.accepted.connect(self._accept_if_readable)
        self._buttons.rejected.connect(self.reject)
        root.addWidget(self._buttons)

        self._password_edit.textChanged.connect(self._update_ok)
        self._key_edit.textChanged.connect(self._update_ok)
        self._update_ok()

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            translate("UnlockVolumeDialog", "Startup key file (.BEK)"),
            "",
            translate("UnlockVolumeDialog", "All files") + " (*)",  # i18n: keep -- file filter pattern
        )
        if path:
            self._key_edit.setText(path)

    def _update_ok(self) -> None:
        ok = bool(self.password()) or bool(self.key_file())
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    def _accept_if_readable(self) -> None:
        # The reader passes over a key file it cannot read without a word, so
        # the volume would only stay locked: say it here instead.
        key = self.key_file()
        if key:
            try:
                Path(key).read_bytes()
            except OSError as exc:
                QMessageBox.warning(
                    self,
                    translate("UnlockVolumeDialog", "Unlock Volume"),
                    translate(
                        "UnlockVolumeDialog", "The startup key file cannot be read: {reason}"
                    ).format(reason=exc.strerror or exc),
                )
                return
        self.accept()

    def password(self) -> str:
        """The secret as typed (not trimmed: spaces can be part of it)."""
        return self._password_edit.text()

    def key_file(self) -> str:
        return self._key_edit.text().strip() if self._with_key_file else ""
