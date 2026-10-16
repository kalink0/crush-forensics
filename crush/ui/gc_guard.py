# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Python's cyclic garbage collection, on the GUI thread only.

The automatic collector runs on whichever thread happens to allocate when a
generation's threshold is passed -- often a worker (the type pre-scan, a
busy_call job). Unreachable cycles that hold PySide objects (a closed window,
a replaced model, a dropped viewer) are then destroyed there, their C++
destructors running off the GUI thread while it touches Qt itself: a
segmentation fault. With the automatic collector off, this collects on the
GUI thread instead, from a timer, by the same generation thresholds the
automatic one uses.
"""
from __future__ import annotations

import gc
import threading

from PySide6.QtCore import QObject, QTimer
from PySide6.QtWidgets import QApplication

# How often the GUI thread checks whether a collection is due. Cycles made in
# between wait at most this long; nothing else does.
_INTERVAL_MS = 500


class GuiThreadGarbageCollector(QObject):
    """Turns the automatic collector off and collects from a GUI-thread timer.
    Create it once, on the GUI thread (install_gui_thread_gc)."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        gc.disable()
        self._timer = QTimer(self)
        self._timer.setInterval(_INTERVAL_MS)
        self._timer.timeout.connect(self.collect_if_due)
        self._timer.start()

    def collect_if_due(self) -> int:
        """Collect the oldest generation whose count passed its threshold, as
        the automatic collector would; 0 when none did. Only on the main
        thread. Returns what gc.collect() returns (objects found unreachable)."""
        if threading.current_thread() is not threading.main_thread():
            return 0
        thresholds = gc.get_threshold()
        counts = gc.get_count()
        due = [gen for gen in range(len(counts)) if counts[gen] > thresholds[gen]]
        if not due:
            return 0
        return gc.collect(max(due))


def install_gui_thread_gc(app: QApplication) -> GuiThreadGarbageCollector:
    """The application's collector, made on first call (then the same one)."""
    existing = app.findChild(GuiThreadGarbageCollector)
    if isinstance(existing, GuiThreadGarbageCollector):
        return existing
    return GuiThreadGarbageCollector(app)
