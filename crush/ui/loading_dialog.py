# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Loading dialog with lightweight ASCII art."""
from __future__ import annotations

import threading

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget
from crush.ui.i18n import translate


class LoadingDialog(QDialog):
    """A "please wait" dialog. With *cancellable*, it has a Cancel button
    that sets cancel_event; the work behind it stops at its next checkpoint
    (crush.core.load_phase), so until then the dialog says it is stopping."""

    def __init__(
        self, text: str, parent: QWidget | None = None, *, cancellable: bool = False,
    ) -> None:
        super().__init__(parent)
        self.cancel_event = threading.Event()
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

        self._cancel_button: QPushButton | None = None
        if cancellable:
            row = QHBoxLayout()
            row.addStretch(1)
            self._cancel_button = QPushButton(translate("LoadingDialog", "Cancel"))
            self._cancel_button.setAutoDefault(False)
            self._cancel_button.clicked.connect(self.request_cancel)
            row.addWidget(self._cancel_button)
            row.addStretch(1)
            layout.addLayout(row)
            self.setFixedSize(320, 150)
        else:
            self.setFixedSize(320, 120)

    def request_cancel(self) -> None:
        """Ask the work behind the dialog to stop."""
        if (
            self._cancel_button is None or self._cancel_button.isHidden()
            or self.cancel_event.is_set()
        ):
            return
        self.cancel_event.set()
        self._cancel_button.setEnabled(False)
        self._label.setText(translate("LoadingDialog", "Cancelling…"))

    def is_cancel_requested(self) -> bool:
        return self.cancel_event.is_set()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        # Escape would close (reject) the dialog while the work runs on;
        # with a Cancel button it asks the work to stop instead.
        if self._cancel_button is not None and event.key() == Qt.Key.Key_Escape:
            # Escape never closes it while work runs, Cancel button shown or not.
            self.request_cancel()
            event.accept()
            return
        super().keyPressEvent(event)

    def end_cancellable(self) -> None:
        """The work that could be stopped is over (what follows, building
        the tree, cannot be): no Cancel button any more."""
        if self._cancel_button is not None:
            self._cancel_button.hide()

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def set_phase(self, phase: str) -> None:
        """Show the phase a load reported (a crush.core.load_phase key);
        a key with no text of its own leaves the text as it is."""
        if self.cancel_event.is_set():
            return  # "Cancelling…" until the work stops
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
