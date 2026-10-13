# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""A one-line label that gives way first when a row runs out of room."""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import QLabel, QWidget


class ElidedLabel(QLabel):
    """Takes its full text width when there is room; when there isn't, it
    shrinks before its neighbours and shows the text cut with "…" -- never
    silently clipped, so a cut count or size can't be read as a different
    number. The whole text is always its tooltip; text() returns it."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full_text = ""
        self.setText(text)

    def setText(self, text: str) -> None:  # type: ignore[override]
        self._full_text = text
        self.setToolTip(text)
        self._show_fitting()
        self.updateGeometry()

    def text(self) -> str:  # type: ignore[override]
        return self._full_text

    def sizeHint(self) -> QSize:
        hint = super().sizeHint()
        margins = self.contentsMargins()
        width = (
            self.fontMetrics().horizontalAdvance(self._full_text)
            + margins.left() + margins.right() + 2 * self.margin()
        )
        return QSize(width, hint.height())

    def minimumSizeHint(self) -> QSize:
        return QSize(1, super().minimumSizeHint().height())

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._show_fitting()

    def _show_fitting(self) -> None:
        available = self.contentsRect().width() - 2 * self.margin()
        shown = self.fontMetrics().elidedText(
            self._full_text, Qt.TextElideMode.ElideRight, max(available, 0)
        )
        super().setText(shown)
