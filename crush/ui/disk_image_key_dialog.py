# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""What opens an encrypted disk image container: its password, or the
private key of a certificate it is sealed to.

An encrypted AFF, Apple disk image or AD-encrypted set can be sealed to a
password, to a certificate, or to both, and the reader's reason says which.
A container that opens with a password is offered both fields, since one
sealed to both opens with either; one sealed only to a certificate is
offered only the key file.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from crush.ui.i18n import translate

_MIN_WIDTH_CHARS = 90


class DiskImageKeyDialog(QDialog):
    """Ask for a disk image's password or private key file. Call exec(); on
    QDialog.Accepted, read .password() and .private_key() -- one of them is
    set."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        reason: str = "",
        was_wrong: bool = False,
        needs: str = "password",
    ) -> None:
        super().__init__(parent)
        self._by_key_only = needs == "private key"
        if was_wrong:
            title = (translate("DiskImageKeyDialog", "Incorrect Private Key")
                     if self._by_key_only else
                     translate("DiskImageKeyDialog", "Incorrect Password or Key"))
        else:
            title = translate("DiskImageKeyDialog", "Encrypted Disk Image")
        self.setWindowTitle(title)
        self._build_ui(reason, was_wrong)
        # Word-wrapped labels let Qt pick the narrowest width, which breaks
        # the reader's reason (often with a path in it) into many short
        # lines; wide enough for it, in the font's own units (HiDPI, longer
        # translations).
        self.setMinimumWidth(self.fontMetrics().averageCharWidth() * _MIN_WIDTH_CHARS)
        self.adjustSize()

    def _build_ui(self, reason: str, was_wrong: bool) -> None:
        root = QVBoxLayout(self)

        if reason:
            why = QLabel(reason)
            why.setTextFormat(Qt.TextFormat.PlainText)
            why.setWordWrap(True)
            if was_wrong:
                why.setStyleSheet("color: #b33;")
            root.addWidget(why)

        prompt = QLabel(
            translate(
                "DiskImageKeyDialog",
                "Choose the private key file (PEM or DER, unencrypted RSA key) of the "
                "certificate this image is sealed to:",
            )
            if self._by_key_only
            else translate(
                "DiskImageKeyDialog",
                "Enter the image's password, or choose the private key file (PEM or DER, "
                "unencrypted RSA key) of a certificate it is sealed to:",
            )
        )
        prompt.setWordWrap(True)
        root.addWidget(prompt)

        form = QFormLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        if not self._by_key_only:
            form.addRow(translate("DiskImageKeyDialog", "Password:"), self._password_edit)

        key_row = QHBoxLayout()
        self._key_edit = QLineEdit()
        self._key_edit.setPlaceholderText(translate("DiskImageKeyDialog", "Private key file"))
        browse = QPushButton(translate("DiskImageKeyDialog", "Browse…"))
        browse.clicked.connect(self._browse_key)
        key_row.addWidget(self._key_edit)
        key_row.addWidget(browse)
        form.addRow(translate("DiskImageKeyDialog", "Private key:"), key_row)
        root.addLayout(form)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        root.addWidget(self._buttons)

        self._password_edit.textChanged.connect(self._update_ok)
        self._key_edit.textChanged.connect(self._update_ok)
        self._update_ok()

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            translate("DiskImageKeyDialog", "Private key file"),
            "",
            translate("DiskImageKeyDialog", "All files") + " (*)",  # i18n: keep -- file filter pattern
        )
        if path:
            self._key_edit.setText(path)

    def _update_ok(self) -> None:
        # Exactly one of the two: the reader is given what the analyst chose,
        # so a rejection says which one did not open the image.
        ok = bool(self.password()) != bool(self.private_key())
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    def password(self) -> str:
        """The password as typed (not trimmed: spaces can be part of it)."""
        return "" if self._by_key_only else self._password_edit.text()

    def private_key(self) -> str:
        return self._key_edit.text().strip()
