# SPDX-License-Identifier: Apache-2.0
"""Cyclic garbage is collected on the GUI thread, never on a worker that
happens to allocate: there, destroying Qt objects held in a cycle crashes.
Which generation is collected follows CPython's generational collector."""
from __future__ import annotations

import gc
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from crush.ui.gc_guard import GuiThreadGarbageCollector, install_gui_thread_gc


class _Cycle:
    """Part of a reference cycle; records the thread it is finalized on."""

    finalized_on: list[str] = []

    def __init__(self) -> None:
        self.me = self

    def __del__(self) -> None:
        _Cycle.finalized_on.append(threading.current_thread().name)


@pytest.fixture
def collector(qapp: QApplication) -> Iterator[GuiThreadGarbageCollector]:
    collector = install_gui_thread_gc(qapp)
    thresholds = gc.get_threshold()
    pending, total = collector._long_lived_pending, collector._long_lived_total
    try:
        yield collector
    finally:
        gc.set_threshold(*thresholds)
        collector._long_lived_pending, collector._long_lived_total = pending, total


def test_installing_turns_the_automatic_collector_off_once(qapp: QApplication) -> None:
    collector = install_gui_thread_gc(qapp)
    assert not gc.isenabled()
    assert install_gui_thread_gc(qapp) is collector


def test_a_generation_due_after_a_worker_allocated_is_collected_on_the_gui_thread(
    collector: GuiThreadGarbageCollector,
) -> None:
    gc.collect()  # every generation's count back to 0
    _Cycle.finalized_on.clear()
    _Cycle()  # unreachable at once, in the youngest generation

    kept: list[Any] = []
    on_worker: list[int | None] = []

    def allocate() -> None:
        # Past the youngest generation's threshold: the automatic collector
        # would collect it here, on this thread.
        for _ in range(gc.get_threshold()[0] * 2):
            kept.append([])
        on_worker.append(collector.collect_if_due())

    worker = threading.Thread(target=allocate, name="worker")
    worker.start()
    worker.join()
    assert on_worker == [None]
    assert _Cycle.finalized_on == []

    assert collector.collect_if_due() == 0
    assert _Cycle.finalized_on == [threading.main_thread().name]
    assert collector.collect_if_due() is None  # nothing due any more


def test_a_full_collection_waits_for_a_quarter_of_new_long_lived_objects(
    collector: GuiThreadGarbageCollector,
) -> None:
    gc.set_threshold(1, 1, 1)
    gc.collect()
    gc.collect(1)
    gc.collect(1)  # the oldest generation's count past its threshold
    kept = [[] for _ in range(5)]  # and the youngest's
    collector._long_lived_total, collector._long_lived_pending = 1_000_000, 0
    assert collector.collect_if_due() == 0  # not the full one: too few new
    kept += [[] for _ in range(5)]
    collector._long_lived_pending = 250_000
    assert collector.collect_if_due() == 2
    assert collector._long_lived_pending == 0
    assert kept
