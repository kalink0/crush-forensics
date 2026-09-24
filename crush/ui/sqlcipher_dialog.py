# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SQLCipher credentials dialog — password/raw key plus optional advanced
cipher parameters, for the cases the standard cipher_compatibility preset
auto-try (SQLiteParser._connect_sqlcipher) can't cover, e.g. Signal and its
forks (Session, Molly), which set kdf_iter=1 to skip the passphrase KDF
since their key is already high-entropy (managed via the platform keystore)
rather than a low-entropy user password.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from crush.parsers.sqlite_parser import SQLCipherParams

_DIGEST_CHOICES = ["SHA1", "SHA256", "SHA512"]


class SQLCipherCredentialsDialog(QDialog):
    """Prompt for a SQLCipher password/key, with an optional "Advanced"
    section for explicit cipher parameters (page size, KDF iterations, KDF
    and HMAC digest) when the standard version-preset auto-try can't open
    the file. Call exec(); on QDialog.Accepted, read .key_text() and
    .cipher_params() (None unless Advanced was used)."""

    def __init__(
        self, parent: QWidget | None = None, wrong_reason: str | None = None,
    ) -> None:
        # wrong_reason: None on the first prompt, else why the previous
        # attempt was rejected ("" if the source gave no reason).
        was_wrong = wrong_reason is not None
        super().__init__(parent)
        self.setWindowTitle("Incorrect Key" if was_wrong else "SQLCipher Credentials")
        self._build_ui(wrong_reason)

    def _build_ui(self, wrong_reason: str | None) -> None:
        root = QVBoxLayout(self)

        if wrong_reason is not None:
            retry = "Incorrect password/key, or unsupported parameters. Try again:"
            warn = QLabel(f"{wrong_reason}\n\n{retry}" if wrong_reason else retry)
            warn.setTextFormat(Qt.TextFormat.PlainText)
            warn.setStyleSheet("color: #b33;")
            warn.setWordWrap(True)
            root.addWidget(warn)

        form = QFormLayout()
        self._key_edit = QLineEdit()
        self._key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_edit.setPlaceholderText("Database password")
        form.addRow("Password:", self._key_edit)

        self._raw_key_cb = QCheckBox("Raw key (64 hex chars / 32 bytes, not a passphrase)")
        self._raw_key_cb.toggled.connect(self._on_raw_key_toggled)
        form.addRow("", self._raw_key_cb)
        root.addLayout(form)

        self._advanced_cb = QCheckBox(
            "Use custom cipher parameters (skip auto-detecting the SQLCipher version)"
        )
        self._advanced_cb.toggled.connect(self._on_advanced_toggled)
        root.addWidget(self._advanced_cb)

        self._advanced_group = QGroupBox("Advanced cipher parameters")
        self._advanced_group.setVisible(False)
        adv_form = QFormLayout(self._advanced_group)

        self._page_size_combo = QComboBox()
        self._page_size_combo.setEditable(True)
        self._page_size_combo.addItems(["1024", "4096"])
        self._page_size_combo.setCurrentText("4096")
        adv_form.addRow("Page size:", self._page_size_combo)

        self._kdf_iter_spin = QSpinBox()
        self._kdf_iter_spin.setRange(1, 10_000_000)
        self._kdf_iter_spin.setValue(256_000)
        self._kdf_iter_spin.setToolTip(
            "Signal and its forks (Session, Molly) set this to 1 -- their key\n"
            "is already high-entropy (from the platform keystore), so the\n"
            "passphrase-stretching KDF is pointless overhead for them."
        )
        adv_form.addRow("KDF iterations:", self._kdf_iter_spin)

        self._kdf_algo_combo = QComboBox()
        self._kdf_algo_combo.addItems(_DIGEST_CHOICES)
        self._kdf_algo_combo.setCurrentText("SHA512")
        adv_form.addRow("KDF algorithm:", self._kdf_algo_combo)

        self._hmac_algo_combo = QComboBox()
        self._hmac_algo_combo.addItems(_DIGEST_CHOICES)
        self._hmac_algo_combo.setCurrentText("SHA512")
        adv_form.addRow("HMAC algorithm:", self._hmac_algo_combo)

        self._header_size_spin = QSpinBox()
        self._header_size_spin.setRange(0, 4096)
        self._header_size_spin.setValue(0)
        adv_form.addRow("Plaintext header size:", self._header_size_spin)

        root.addWidget(self._advanced_group)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self._key_edit.setFocus()

    def _on_raw_key_toggled(self, checked: bool) -> None:
        self._key_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self._key_edit.setPlaceholderText(
            "Raw key as a hex string" if checked else "Database password"
        )

    def _on_advanced_toggled(self, checked: bool) -> None:
        self._advanced_group.setVisible(checked)
        self.adjustSize()

    def key_text(self) -> str:
        return self._key_edit.text()

    def is_raw_key(self) -> bool:
        """Independent of cipher_params()/Advanced -- page_size and
        cipher_hmac_algorithm still matter for a raw key, so this stays in
        effect during the compatibility-preset auto-try too, not only when
        Advanced is also checked."""
        return self._raw_key_cb.isChecked()

    def cipher_params(self) -> SQLCipherParams | None:
        if not self._advanced_cb.isChecked():
            return None
        try:
            page_size = int(self._page_size_combo.currentText())
        except ValueError:
            page_size = 4096
        return SQLCipherParams(
            page_size=page_size,
            kdf_iter=self._kdf_iter_spin.value(),
            kdf_algorithm=self._kdf_algo_combo.currentText(),
            hmac_algorithm=self._hmac_algo_combo.currentText(),
            plaintext_header_size=self._header_size_spin.value(),
        )
