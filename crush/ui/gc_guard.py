# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Python's cyclic garbage collection, on the GUI thread only.

The automatic collector runs on whichever thread happens to allocate when a
generation's threshold is passed -- often a worker (the type pre-scan, a
busy_call job). Unreachable cycles that hold PySide objects (a closed window,
a replaced model, a dropped viewer) are then destroyed there, their C++
destructors running off the GUI thread while it touches Qt itself: a
segmentation fault. With the automatic collector off, this collects on the
GUI thread instead, from a timer.

Which generation it collects follows CPython's generational collector (3.11
to 3.13, Modules/gcmodule.c gc_collect_generations): the oldest generation
whose count passed its threshold, except that a full collection waits until
the objects that reached the oldest generation since the last one are a
quarter of those it held then. CPython keeps those two numbers to itself;
this keeps its own: the objects a collection of the middle generation leaves
alive, and the size of the oldest after a full collection. Python 3.14's
incremental collector has other thresholds and counts; there this still
collects every cycle, but not on that collector's schedule. Crush's builds use
Python 3.11.

Garbage that is not part of a cycle is freed by reference counting the moment
it is dropped, on any thread, as before. Only cycles wait for a collection:
until a generation is due, then until the next tick of the timer, and while
the GUI thread runs something without returning to its event loop.
"""
from __future__ import annotations

import gc
import threading

from PySide6.QtCore import QObject, QTimer
from PySide6.QtWidgets import QApplication

# How often the GUI thread checks whether a collection is due.
_INTERVAL_MS = 500
_OLDEST = 2


class GuiThreadGarbageCollector(QObject):
    """Turns the automatic collector off and collects from a GUI-thread timer.
    Create it once, on the GUI thread (install_gui_thread_gc)."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        gc.disable()
        # CPython's long_lived_pending / long_lived_total, from its start
        # values: the objects that reached the oldest generation since the
        # last full collection, and the oldest generation's size after it.
        self._long_lived_pending = 0
        self._long_lived_total = 0
        self._timer = QTimer(self)
        self._timer.setInterval(_INTERVAL_MS)
        self._timer.timeout.connect(self.collect_if_due)
        self._timer.start()

    def collect_if_due(self) -> int | None:
        """Collect the generation the automatic collector would collect now,
        and return it; None when none is due, or off the main thread."""
        if threading.current_thread() is not threading.main_thread():
            return None
        thresholds, counts = gc.get_threshold(), gc.get_count()
        for gen in range(_OLDEST, -1, -1):
            if counts[gen] <= thresholds[gen]:
                continue
            if gen == _OLDEST and self._long_lived_pending < self._long_lived_total // 4:
                continue
            self._collect(gen)
            return gen
        return None

    def _collect(self, gen: int) -> None:
        if gen == _OLDEST:
            gc.collect(gen)
            self._long_lived_pending = 0
            self._long_lived_total = len(gc.get_objects(generation=_OLDEST))
            return
        if gen == _OLDEST - 1:
            # What this collection leaves alive moves to the oldest generation.
            young = len(gc.get_objects(generation=0)) + len(gc.get_objects(generation=1))
            unreachable = gc.collect(gen)
            self._long_lived_pending += max(young - unreachable, 0)
            return
        gc.collect(gen)


def install_gui_thread_gc(app: QApplication) -> GuiThreadGarbageCollector:
    """The application's collector, made on first call (then the same one)."""
    existing = app.findChild(GuiThreadGarbageCollector)
    if isinstance(existing, GuiThreadGarbageCollector):
        return existing
    return GuiThreadGarbageCollector(app)
