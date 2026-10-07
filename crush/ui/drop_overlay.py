# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The drop zones shown over a window while files are dragged onto it.

Two zones, one per way of opening: **Open** takes what Open File… and Open
Folder… take (files, folders, archives, backups -- recognised by content),
**Open as Disk Image** takes what Open Disk Image… takes: one file. The
reader joins the other parts of a set (E01/E02…, .001/.002…, a VMDK's
extents, a sparse bundle's bands) from any one of them, as from the picker,
so a drop of several files or of a folder is refused there, with the reason
shown in the zone and in the status bar -- never opened in part.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from PySide6.QtCore import QEvent, QMimeData, QObject, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QPainter,
    QPaintEvent,
    QPalette,
    QPen,
)
from PySide6.QtWidgets import QWidget

from crush.ui.i18n import translate

DropZone = Literal["open", "disk_image"]

_MARGIN = 24
_GAP = 16


def local_paths(mime: QMimeData) -> list[str]:
    """The local files and folders a drag carries, in its order."""
    if not mime.hasUrls():
        return []
    return [url.toLocalFile() for url in mime.urls() if url.isLocalFile()]


def zone_at(width: int, x: float) -> DropZone:
    """The zone under *x* in a window *width* wide: Open on the left half,
    Open as Disk Image on the right."""
    return "open" if x < width / 2 else "disk_image"


def disk_image_drop_refusal(paths: list[str]) -> str:
    """Why *paths* can't be dropped on Open as Disk Image, or "" when they
    can: exactly one file, as Open Disk Image… picks."""
    if len(paths) != 1:
        return translate(
            "DropOverlay",
            "One file at a time: drop one file of the image; the other parts of a set "
            "are found beside it.",
        )
    if not Path(paths[0]).is_file():
        return translate(
            "DropOverlay",
            "Only a file opens as a disk image, not a folder. For a sparse bundle, drop "
            "any file in it.",
        )
    return ""


class DropOverlay(QWidget):
    """Covers its window while local files are dragged over it.

    It turns itself on from the window's own drag events (watch_window), so
    a viewer under the cursor that takes drops itself (a text field) never
    gets them first, and off when the drag leaves or drops.
    """

    open_requested = Signal(list)
    disk_image_requested = Signal(str)
    refused = Signal(str)

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._paths: list[str] = []
        self._refusal = ""
        self._hover: DropZone | None = None
        self.hide()
        parent.installEventFilter(self)

    def watch_window(self, window: QObject) -> None:
        """Turn on as soon as a drag enters *window* (the parent's
        QWindow), before Qt hands the event to the widget under it."""
        window.installEventFilter(self)

    def activate(self, paths: list[str]) -> None:
        self._paths = list(paths)
        self._refusal = disk_image_drop_refusal(self._paths)
        self._hover = None
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.show()
        self.raise_()
        self.update()

    def deactivate(self) -> None:
        self._paths = []
        self._refusal = ""
        self._hover = None
        self.hide()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        kind = event.type()
        if kind == QEvent.Type.Resize and watched is self.parentWidget():
            self.setGeometry(self.parentWidget().rect())
        elif (
            kind in (QEvent.Type.DragEnter, QEvent.Type.DragMove)
            and not self.isVisible()
            and isinstance(event, QDragMoveEvent)
        ):
            paths = local_paths(event.mimeData())
            if paths:
                self.activate(paths)
        return False

    # -- drag & drop -----------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        paths = local_paths(event.mimeData())
        if not paths:
            event.ignore()
            return
        if paths != self._paths:
            self.activate(paths)
        self._track(event)

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        self._track(event)

    def dragLeaveEvent(self, event: QEvent) -> None:
        self.deactivate()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = local_paths(event.mimeData())
        zone = zone_at(self.width(), event.position().x())
        refusal = disk_image_drop_refusal(paths)
        self.deactivate()
        if not paths:
            event.ignore()
            return
        if zone == "open":
            event.acceptProposedAction()
            self.open_requested.emit(paths)
        elif refusal:
            event.ignore()
            self.refused.emit(refusal)
        else:
            event.acceptProposedAction()
            self.disk_image_requested.emit(paths[0])

    def _track(self, event: QDragMoveEvent) -> None:
        zone = zone_at(self.width(), event.position().x())
        if zone != self._hover:
            self._hover = zone
            self.update()
        if zone == "disk_image" and self._refusal:
            event.ignore()
        else:
            event.acceptProposedAction()

    # -- painting --------------------------------------------------------------

    def _zone_rects(self) -> tuple[QRectF, QRectF]:
        half = (self.width() - 2 * _MARGIN - _GAP) / 2
        height = self.height() - 2 * _MARGIN
        left = QRectF(_MARGIN, _MARGIN, half, height)
        right = QRectF(_MARGIN + half + _GAP, _MARGIN, half, height)
        return left, right

    def paintEvent(self, event: QPaintEvent) -> None:
        palette = self.palette()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        veil = QColor(palette.color(QPalette.ColorRole.Window))
        veil.setAlpha(240)
        painter.fillRect(self.rect(), veil)

        left, right = self._zone_rects()
        self._paint_zone(
            painter, left, "open",
            translate("DropOverlay", "Open"),
            translate(
                "DropOverlay",
                "Files, folders, archives and backups, as Open File… and Open Folder… "
                "open them",
            ),
            refused=False,
        )
        self._paint_zone(
            painter, right, "disk_image",
            translate("DropOverlay", "Open as Disk Image"),
            self._refusal or translate(
                "DropOverlay",
                "One file: a raw/dd image, an acquisition, an Apple or virtual machine "
                "disk, or a flash dump, as Open Disk Image… opens it. The other parts of "
                "a set are found beside it.",
            ),
            refused=bool(self._refusal),
        )
        painter.end()

    def _paint_zone(
        self, painter: QPainter, rect: QRectF, zone: DropZone, title: str, text: str,
        *, refused: bool,
    ) -> None:
        palette = self.palette()
        # A refused zone never lights up: grey, dashed, its reason as text.
        hovered = self._hover == zone and not refused
        accent = palette.color(QPalette.ColorRole.Highlight)
        # The text colour half seen: grey on every theme, light or dark.
        muted = QColor(palette.color(QPalette.ColorRole.WindowText))
        muted.setAlpha(130)
        fill = QColor(accent if not refused else muted)
        fill.setAlpha(60 if hovered else 12 if refused else 20)
        pen = QPen(accent if hovered else muted)
        pen.setWidth(3 if hovered else 2)
        pen.setStyle(Qt.PenStyle.SolidLine if hovered else Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(fill)
        painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 12, 12)

        text_color = palette.color(QPalette.ColorRole.WindowText)
        painter.setPen(muted if refused else text_color)
        title_font = self.font()
        title_font.setPointSize(title_font.pointSize() + 8)
        title_font.setBold(True)
        painter.setFont(title_font)
        middle = rect.center().y()
        title_rect = QRectF(rect.left() + 24, middle - 60, rect.width() - 48, 50)
        painter.drawText(
            title_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom, title
        )
        painter.setFont(self.font())
        painter.setPen(text_color)
        text_rect = QRectF(rect.left() + 24, middle + 4, rect.width() - 48, rect.height() / 2 - 28)
        painter.drawText(
            text_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
            text,
        )
