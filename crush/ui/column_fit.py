# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Fit a tree view's text columns to their content.

The fitted columns grow to what their visible entries need, but only into the
room the other columns leave in the viewport, so those stay in view. What still
doesn't fit is elided by the view (the caller picks the elide mode) and stays
readable through the item tooltip or by dragging the column wider.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QTreeView

# Coalesces the bursts of triggers a folder load or a scroll produces into one fit.
_FIT_DELAY_MS = 50


def distribute_widths(
    wanted: dict[int, int], minimum: dict[int, int], available: int
) -> dict[int, int]:
    """Width per column: what it wants, but together no more than *available*.

    When the wanted widths don't fit, the room is shared: a column that wants
    less than an even share keeps its width, the rest split what is left. No
    column goes below its minimum, even if that overflows *available* (the view
    then scrolls horizontally).
    """
    target = {col: max(minimum[col], wanted.get(col, 0)) for col in minimum}
    if sum(target.values()) <= available:
        return target
    result: dict[int, int] = {}
    remaining = sorted(target, key=lambda col: target[col])
    room = available
    while remaining:
        share = room // len(remaining)
        col = remaining[0]
        if target[col] > share:
            for col in remaining:
                result[col] = max(minimum[col], share)
            break
        result[col] = target[col]
        room -= target[col]
        remaining.pop(0)
    return result


class ColumnFitter(QObject):
    """Keeps *columns* of *view* fitted to their content (see module docstring).

    A column only grows while the same content is shown: collapsing a folder or
    scrolling away from a long name doesn't shrink it, so the layout doesn't jump.
    :meth:`clear_content` starts over for new content, :meth:`reset` also gives
    control back after the analyst sized a column by hand -- from then on the
    fitter leaves that view's columns alone.
    """

    def __init__(self, view: QTreeView, minimum_widths: dict[int, int]) -> None:
        super().__init__(view)
        self._view = view
        self._minimum = dict(minimum_widths)
        self._wanted: dict[int, int] = {}
        self._manual = False
        self._applying = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(_FIT_DELAY_MS)
        self._timer.timeout.connect(self._fit)

        header = view.header()
        # The free room goes to the fitted columns, not to the last column.
        header.setStretchLastSection(False)
        header.sectionResized.connect(self._on_section_resized)
        header.sectionHandleDoubleClicked.connect(self._on_handle_double_clicked)
        for col, width in self._minimum.items():
            view.setColumnWidth(col, width)

        model = view.model()
        model.rowsInserted.connect(self.schedule)
        model.modelReset.connect(self.schedule)
        model.layoutChanged.connect(self.schedule)
        view.expanded.connect(self.schedule)
        view.verticalScrollBar().valueChanged.connect(self.schedule)
        view.viewport().installEventFilter(self)

    def schedule(self, *_: object) -> None:
        """Fit soon; repeated calls before then fold into one fit."""
        if not self._manual and not self._timer.isActive():
            self._timer.start()

    def clear_content(self) -> None:
        """Forget the widths the previous content needed (new content is shown)."""
        self._wanted.clear()
        if not self._manual:
            self._apply(dict(self._minimum))
            self.schedule()

    def reset(self) -> None:
        """Start over: forget the content widths and any manual column sizing."""
        self._manual = False
        self.clear_content()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.Resize:
            self.schedule()
        return super().eventFilter(watched, event)

    def _on_section_resized(self, logical: int, _old: int, _new: int) -> None:
        if self._applying:
            return
        if logical in self._minimum:
            # Only a drag by the analyst (button held on the header handle);
            # Qt's own resizes don't count as manual sizing.
            if QGuiApplication.mouseButtons() & Qt.MouseButton.LeftButton:
                self._manual = True
                self._timer.stop()
        else:
            self.schedule()  # another column changed the room left for ours

    def _on_handle_double_clicked(self, logical: int) -> None:
        if logical in self._minimum:
            self._manual = True
            self._timer.stop()

    def _fit(self) -> None:
        if self._manual:
            return
        view = self._view
        header = view.header()
        for col in self._minimum:
            content = max(view.sizeHintForColumn(col), header.sectionSizeHint(col))
            self._wanted[col] = max(self._wanted.get(col, 0), content)
        others = sum(
            header.sectionSize(col)
            for col in range(header.count())
            if col not in self._minimum and not header.isSectionHidden(col)
        )
        available = view.viewport().width() - others
        self._apply(distribute_widths(self._wanted, self._minimum, available))

    def _apply(self, widths: dict[int, int]) -> None:
        self._applying = True
        try:
            for col, width in widths.items():
                if self._view.columnWidth(col) != width:
                    self._view.setColumnWidth(col, width)
        finally:
            self._applying = False
