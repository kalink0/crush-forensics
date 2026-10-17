# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Loading dialog with lightweight ASCII art."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLabel, QVBoxLayout, QWidget
from crush.ui.i18n import translate


class LoadingDialog(QDialog):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate("LoadingDialog", "Loading"))
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowTitleHint
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self._label = QLabel(text)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._label)
        # How far the load got: a running count, never a percentage (the
        # total isn't known while a source is listed).
        self._progress = QLabel("")
        self._progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress.setStyleSheet("color: gray;")
        layout.addWidget(self._progress)

        self.setFixedSize(320, 120)

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def set_phase(self, phase: str) -> None:
        """Show the phase a load reported (a crush.core.load_phase key);
        a key with no text of its own leaves the text as it is."""
        text = load_phase_text(phase)
        if text:
            self._label.setText(text)

    def set_progress(self, entries: int, step: int, steps: int) -> None:
        """Show how far the load got (crush.core.load_phase progress)."""
        parts = []
        if steps:
            parts.append(translate("LoadingDialog", "volume {step} of {steps}").format(
                step=step, steps=steps
            ))
        if entries:
            parts.append(translate("LoadingDialog", "{count:,} entries listed").format(count=entries))
        self._progress.setText(" — ".join(parts))


def load_phase_text(phase: str) -> str:
    """The wait dialog's text for a crush.core.load_phase key, "" for none."""
    from crush.core import load_phase

    texts = {
        load_phase.PHASE_OPEN_IMAGE: translate("LoadingDialog", "Opening disk image…"),
        load_phase.PHASE_UNLOCK_VOLUMES: translate("LoadingDialog", "Unlocking volumes…"),
        load_phase.PHASE_SEARCH_VOLUMES: translate("LoadingDialog", "Searching volumes…"),
        load_phase.PHASE_READ_FILESYSTEMS: translate("LoadingDialog", "Reading filesystems…"),
        load_phase.PHASE_DELETED_FILES: translate("LoadingDialog", "Listing deleted files…"),
        load_phase.PHASE_HASH_SOURCE: translate("LoadingDialog", "Hashing the source…"),
    }
    return texts.get(phase, "")


_ASCII_FRAMES: list[str] = []
