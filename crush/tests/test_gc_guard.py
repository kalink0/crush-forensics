# SPDX-License-Identifier: Apache-2.0
"""Cyclic garbage is collected on the GUI thread, never on a worker that
happens to allocate: there, destroying Qt objects held in a cycle crashes."""
from __future__ import annotations

import gc
import threading
from typing import Any

from PySide6.QtWidgets import QApplication

from crush.ui.gc_guard import GuiThreadGarbageCollector, install_gui_thread_gc


class _Cycle:
    """Part of a reference cycle; records the thread it is finalized on."""

    finalized_on: list[str] = []

    def __init__(self) -> None:
        self.me = self

    def __del__(self) -> None:
        _Cycle.finalized_on.append(threading.current_thread().name)


def test_installing_turns_the_automatic_collector_off_once(qapp: QApplication) -> None:
    collector = install_gui_thread_gc(qapp)
    assert isinstance(collector, GuiThreadGarbageCollector)
    assert not gc.isenabled()
    assert install_gui_thread_gc(qapp) is collector


def test_garbage_made_while_a_worker_allocates_is_collected_on_the_gui_thread(
    qapp: QApplication,
) -> None:
    collector = install_gui_thread_gc(qapp)
    gc.collect()
    _Cycle.finalized_on.clear()
    _Cycle()  # unreachable at once, kept only by its own cycle

    kept: list[Any] = []

    def allocate() -> None:
        # Far past the youngest generation's threshold: the automatic
        # collector would run here, on this thread.
        for _ in range(gc.get_threshold()[0] * 20):
            kept.append([])
        assert collector.collect_if_due() == 0  # never on a worker

    worker = threading.Thread(target=allocate, name="worker")
    worker.start()
    worker.join()
    assert _Cycle.finalized_on == []

    while not _Cycle.finalized_on and collector.collect_if_due():
        pass
    if not _Cycle.finalized_on:  # the cycle sits in an older generation
        gc.collect()
    assert _Cycle.finalized_on == [threading.main_thread().name]
