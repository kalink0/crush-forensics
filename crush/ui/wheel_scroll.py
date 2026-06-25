# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Wheel scrolling helpers shared by Qt scroll areas."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QAbstractItemView, QAbstractScrollArea


_FILTER_ATTR = "_crush_horizontal_wheel_scroll_filter"


def handle_shift_wheel_horizontal_scroll(
    scroll_area: QAbstractScrollArea, event: object
) -> bool:
    """Map Shift + vertical wheel events to horizontal scrollbar movement."""
    if not (hasattr(event, "modifiers") and hasattr(event, "angleDelta")):
        return False
    if not event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
        return False

    hbar = scroll_area.horizontalScrollBar()
    if hbar.minimum() == hbar.maximum():
        return False

    delta = 0
    if hasattr(event, "pixelDelta"):
        pixel_delta = event.pixelDelta()
        delta = pixel_delta.x() or pixel_delta.y()
    if not delta:
        angle_delta = event.angleDelta()
        delta = (angle_delta.x() or angle_delta.y()) // 2
    if not delta:
        return False

    hbar.setValue(hbar.value() - delta)
    if hasattr(event, "accept"):
        event.accept()
    return True


class _HorizontalWheelScrollFilter(QObject):
    def __init__(
        self,
        scroll_area: QAbstractScrollArea,
        on_wheel: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(scroll_area)
        self._scroll_area = scroll_area
        self._on_wheel = on_wheel

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Wheel:
            if self._on_wheel is not None:
                self._on_wheel()
            if handle_shift_wheel_horizontal_scroll(self._scroll_area, event):
                return True
        return super().eventFilter(watched, event)


def install_horizontal_wheel_scroll(
    scroll_area: QAbstractScrollArea,
    *,
    on_wheel: Callable[[], None] | None = None,
    smooth_item_scroll: bool = True,
) -> None:
    """Enable cross-platform Shift-wheel horizontal scrolling for a scroll area."""
    existing = getattr(scroll_area, _FILTER_ATTR, None)
    if existing is not None:
        return

    if smooth_item_scroll and isinstance(scroll_area, QAbstractItemView):
        scroll_area.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    event_filter = _HorizontalWheelScrollFilter(scroll_area, on_wheel)
    scroll_area.installEventFilter(event_filter)
    scroll_area.viewport().installEventFilter(event_filter)
    setattr(scroll_area, _FILTER_ATTR, event_filter)
