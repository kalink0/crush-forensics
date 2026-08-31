# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Generic background-thread + "please wait" dialog helper.

Any operation whose cost scales with evidence size (walks every page of a
file, hashes a whole source, decrypts page-by-page, ...) must not run
straight on the Qt UI thread: past a few seconds the OS flags the window as
unresponsive, on top of the app just freezing. Wrapping such a call in
run_with_busy_dialog() moves the actual work to a QThread so the UI thread
keeps pumping events (window stays responsive, no OS "not responding"
warning) while a LoadingDialog gives the user visible feedback.

This generalizes the QThread + LoadingDialog pattern MainWindow._load_source
already used for opening a source (see _LoadSourceWorker) so any call site,
not just that one, can opt in with a single call instead of hand-rolling its
own worker class.
"""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QWidget

from crush.ui.loading_dialog import LoadingDialog

# Strong references to in-flight (dialog, thread, worker) tuples, keyed by
# the owning widget's id(). QThread/QObject don't keep themselves alive --
# without this, Python could garbage-collect them mid-run since nothing in
# the caller's local scope holds on to them after run_with_busy_dialog()
# returns (it's fire-and-forget, not blocking).
_inflight: dict[int, set[tuple[Any, ...]]] = {}


class _BusyWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, work_fn: Callable[[], object]) -> None:
        super().__init__()
        self._work_fn = work_fn

    def run(self) -> None:
        try:
            result = self._work_fn()
        except Exception as exc:  # noqa: BLE001 - reported to caller, not swallowed
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)


class _BusyController(QObject):
    """Lives on the UI thread (parented to *owner*) so worker.finished/failed
    -- connected to its bound methods below -- are reliably delivered via
    the UI thread's event loop (queued connection), not invoked directly on
    the worker's thread. Plain Python closures don't have thread affinity
    of their own, so connecting straight to them isn't a reliable substitute
    for this."""

    def __init__(
        self,
        owner: QWidget,
        dialog: LoadingDialog,
        thread: QThread,
        worker: _BusyWorker,
        on_done: Callable[[Any], None],
        on_error: Callable[[str], None] | None,
        cleanup: Callable[[], None],
    ) -> None:
        super().__init__(owner)
        self._dialog = dialog
        self._thread = thread
        self._worker = worker
        self._on_done = on_done
        self._on_error = on_error
        self._cleanup = cleanup

    def on_finished(self, result: object) -> None:
        self._cleanup()
        self._on_done(result)

    def on_failed(self, message: str) -> None:
        self._cleanup()
        if self._on_error is not None:
            self._on_error(message)


def run_with_busy_dialog(
    owner: QWidget,
    text: str,
    work_fn: Callable[[], object],
    on_done: Callable[[Any], None],
    on_error: Callable[[str], None] | None = None,
) -> None:
    """Run *work_fn* on a background thread while showing a "please wait"
    dialog parented to *owner*, instead of blocking the UI thread outright.

    Fire-and-forget: returns immediately. *on_done*/*on_error* are called
    back on the UI thread once the worker finishes -- structure the caller
    around that callback, not around this function returning a result.
    """
    dialog = LoadingDialog(text, owner)
    thread = QThread(owner)
    worker = _BusyWorker(work_fn)
    worker.moveToThread(thread)

    key = id(owner)

    def _cleanup() -> None:
        dialog.close()
        thread.quit()
        thread.wait()
        bucket = _inflight.get(key)
        if bucket is not None:
            bucket.discard(entry)
            if not bucket:
                _inflight.pop(key, None)

    # controller lives on the UI thread (parented to owner), so connecting
    # worker.finished/failed to its bound methods gets a reliable queued
    # delivery back to the UI thread -- see _BusyController's docstring.
    controller = _BusyController(owner, dialog, thread, worker, on_done, on_error, _cleanup)
    entry = (dialog, thread, worker, controller)
    _inflight.setdefault(key, set()).add(entry)

    thread.started.connect(worker.run)
    worker.finished.connect(controller.on_finished)
    worker.failed.connect(controller.on_failed)
    thread.finished.connect(worker.deleteLater)

    thread.start()
    dialog.show()
