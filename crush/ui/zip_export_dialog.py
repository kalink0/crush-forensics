# SPDX-License-Identifier: Apache-2.0
"""The dialog behind "Export to ZIP…": where the archive goes, and how it is
written -- compression method and level, an AES-256 password, and splitting
it into parts of a fixed size (crush.core.zip_writer)."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from crush.core.zip_writer import LEVELS, MIN_SPLIT_SIZE, ZipMethod, ZipOptions
from crush.ui.i18n import translate

# Decimal units, as drive and disc sizes are given: "4 GB" fits on FAT32
# (at most 4 GiB - 1 B per file) and a 4.7 GB DVD holds two such parts.
_UNITS = {"MB": 1_000_000, "GB": 1_000_000_000}


def with_zip_suffix(path: str) -> Path:
    target = Path(path)
    if target.suffix.lower() != ".zip":
        target = target.with_name(f"{target.name}.zip")
    return target


class ZipExportDialog(QDialog):
    """Ask for the archive and its options. *options* preset the fields
    (the last ones used, say); their password is never shown."""

    def __init__(
        self,
        parent: QWidget | None,
        default_path: str,
        options: ZipOptions | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate("ZipExportDialog", "Export to ZIP archive"))
        self.setMinimumWidth(600)
        options = options or ZipOptions()

        self._path = QLineEdit(default_path)
        browse = QPushButton(translate("ZipExportDialog", "Browse…"))
        browse.clicked.connect(self._browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self._path, 1)
        path_row.addWidget(browse)

        self._method = QComboBox()
        for label, method in (
            (translate("ZipExportDialog", "Deflate (standard, opens everywhere)"), "deflate"),
            (translate("ZipExportDialog", "No compression (store)"), "stored"),
            (translate("ZipExportDialog", "BZIP2 (smaller; not in Windows Explorer)"), "bzip2"),
            (translate("ZipExportDialog", "LZMA (smallest; not in Windows Explorer)"), "lzma"),
        ):
            self._method.addItem(label, method)
        self._method.setCurrentIndex(max(0, self._method.findData(options.method)))
        self._level = QSpinBox()
        self._level_label = QLabel(translate("ZipExportDialog", "Level:"))
        self._level_hint = QLabel(translate("ZipExportDialog", "1 = fastest, 9 = smallest"))
        self._method.currentIndexChanged.connect(self._method_changed)
        self._method_changed()
        if options.effective_level is not None:
            self._level.setValue(options.effective_level)

        self._encrypt = QCheckBox(translate("ZipExportDialog", "Encrypt with a password (AES-256)"))
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText(translate("ZipExportDialog", "Password"))
        self._confirm = QLineEdit()
        self._confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm.setPlaceholderText(translate("ZipExportDialog", "Repeat password"))
        encrypt_note = QLabel(translate(
            "ZipExportDialog",
            "The contents are encrypted, not the names of files and folders. Opens in "
            "7-Zip, WinRAR, WinZip and others; Windows Explorer can't reliably open "
            "AES-encrypted ZIP archives.",
        ))
        encrypt_note.setWordWrap(True)
        self._encrypt.toggled.connect(self._password.setEnabled)
        self._encrypt.toggled.connect(self._confirm.setEnabled)
        self._encrypt.setChecked(False)
        self._password.setEnabled(False)
        self._confirm.setEnabled(False)

        self._split = QCheckBox(translate("ZipExportDialog", "Split into parts of"))
        self._split_size = QSpinBox()
        self._split_size.setRange(1, 999_999)
        self._split_unit = QComboBox()
        for unit in _UNITS:
            self._split_unit.addItem(unit, unit)  # i18n: keep -- unit symbol
        split_note = QLabel(translate(
            "ZipExportDialog",
            "Parts are named {name}.001, .002 …, cut byte for byte (1 MB = 1,000,000 bytes). "
            "7-Zip opens .001 directly; other tools need the parts joined first "
            "(copy /b, cat). A split archive can't be added to later.",
        ).format(name="export.zip"))  # i18n: keep -- example file name
        split_note.setWordWrap(True)
        self._split_size.setValue(4)
        self._split_unit.setCurrentIndex(self._split_unit.findData("GB"))
        if options.split_size:
            unit = "GB" if options.split_size % _UNITS["GB"] == 0 else "MB"
            self._split_size.setValue(max(1, options.split_size // _UNITS[unit]))
            self._split_unit.setCurrentIndex(self._split_unit.findData(unit))
        self._split.toggled.connect(self._split_size.setEnabled)
        self._split.toggled.connect(self._split_unit.setEnabled)
        self._split.setChecked(bool(options.split_size))
        self._split_size.setEnabled(bool(options.split_size))
        self._split_unit.setEnabled(bool(options.split_size))
        split_row = QHBoxLayout()
        split_row.addWidget(self._split)
        split_row.addWidget(self._split_size)
        split_row.addWidget(self._split_unit)
        split_row.addStretch(1)

        form = QFormLayout()
        form.addRow(translate("ZipExportDialog", "Archive:"), path_row)
        form.addRow(translate("ZipExportDialog", "Compression:"), self._method)
        level_row = QHBoxLayout()
        level_row.addWidget(self._level)
        level_row.addWidget(self._level_hint)
        level_row.addStretch(1)
        form.addRow(self._level_label, level_row)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addSpacing(8)
        layout.addWidget(self._encrypt)
        layout.addWidget(self._password)
        layout.addWidget(self._confirm)
        layout.addWidget(encrypt_note)
        layout.addSpacing(8)
        layout.addLayout(split_row)
        layout.addWidget(split_note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(
            translate("ZipExportDialog", "Export")
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -- results --

    def archive_path(self) -> Path:
        return with_zip_suffix(self._path.text().strip())

    def options(self) -> ZipOptions:
        method: ZipMethod = self._method.currentData()
        split_size = None
        if self._split.isChecked():
            split_size = self._split_size.value() * _UNITS[self._split_unit.currentData()]
        return ZipOptions(
            method=method,
            level=self._level.value() if method in LEVELS else None,
            password=self._password.text() if self._encrypt.isChecked() else None,
            split_size=split_size,
        )

    @staticmethod
    def remembered(options: ZipOptions) -> ZipOptions:
        """*options* to preset the next time: all but the password."""
        return replace(options, password=None)

    # -- behaviour --

    def _method_changed(self) -> None:
        method = self._method.currentData()
        if method in LEVELS:
            low, high, default = LEVELS[method]
            self._level.setRange(low, high)
            self._level.setValue(default)
        self._level.setEnabled(method in LEVELS)
        self._level_label.setEnabled(method in LEVELS)
        self._level_hint.setEnabled(method in LEVELS)

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            translate("ZipExportDialog", "Export to ZIP archive"),
            self._path.text(),
            translate("ZipExportDialog", "ZIP archives (*.zip)"),
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if path:
            self._path.setText(str(with_zip_suffix(path)))

    def _accept(self) -> None:
        title = translate("ZipExportDialog", "Export to ZIP archive")
        if not self._path.text().strip():
            QMessageBox.warning(self, title, translate("ZipExportDialog", "Choose where the archive goes."))
            return
        if not self.archive_path().parent.is_dir():
            QMessageBox.warning(
                self, title,
                translate("ZipExportDialog", "The folder {folder} doesn't exist.").format(
                    folder=self.archive_path().parent
                ),
            )
            return
        if self._encrypt.isChecked():
            if not self._password.text():
                QMessageBox.warning(self, title, translate("ZipExportDialog", "Enter a password."))
                return
            if self._password.text() != self._confirm.text():
                QMessageBox.warning(
                    self, title, translate("ZipExportDialog", "The passwords don't match.")
                )
                return
        if self._split.isChecked():
            size = self._split_size.value() * _UNITS[self._split_unit.currentData()]
            if size < MIN_SPLIT_SIZE:  # pragma: no cover -- 1 MB is the smallest choice
                return
        self.accept()
