# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Per-window log attribution for running more than one MainWindow at once.

Crush logs through `logging.getLogger("crush")`, one process-wide logger
shared by every open MainWindow. For each window's on-screen log pane to
show only its own activity, every record needs to carry which window it
came from. This is the shared, ownership-free home for that bookkeeping so
main_window.py and any module with its own background threads (fs_panel's
type pre-scan, the Multi-Log Studio viewer's loader/sort workers, ...) can
all tag their log output the same way without importing from each other.
"""
from __future__ import annotations

from contextlib import contextmanager
import logging
import threading

# Maps a thread id (a worker thread, or the single GUI thread while it is
# inside one window's action handler) to a stack of window ids. A stack
# rather than a single value because the GUI thread's handlers can re-enter
# (e.g. MainWindow._open_node_mode falling back to _open_node) and must
# restore the outer window's id, not just clear it, when the inner call
# returns.
_THREAD_WINDOW_STACK: dict[int, list[str]] = {}
_THREAD_WINDOW_LOCK = threading.Lock()


def _push(window_id: str | None) -> None:
    with _THREAD_WINDOW_LOCK:
        _THREAD_WINDOW_STACK.setdefault(threading.get_ident(), []).append(window_id)


def _pop() -> None:
    ident = threading.get_ident()
    with _THREAD_WINDOW_LOCK:
        stack = _THREAD_WINDOW_STACK.get(ident)
        if stack:
            stack.pop()
            if not stack:
                del _THREAD_WINDOW_STACK[ident]


def current_window_id() -> str | None:
    with _THREAD_WINDOW_LOCK:
        stack = _THREAD_WINDOW_STACK.get(threading.get_ident())
        return stack[-1] if stack else None


@contextmanager
def window_log_scope(window_id: str | None):
    """Attribute every log record emitted by the current thread to window_id.

    Safe to nest (on the same or a different thread): the previous value, if
    any, is restored when the inner scope exits.
    """
    _push(window_id)
    try:
        yield
    finally:
        _pop()


class WindowStampFilter(logging.Filter):
    """Tags a log record with the id of the window it originated from.

    Idempotent so it can be attached to every window's handler: whichever
    handler processes the record first performs the lookup, later handlers
    see `window_id` already set and leave it alone.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "window_id"):
            # None (no tracked scope for the current thread) is a deliberate,
            # visible "couldn't attribute this" outcome -- the record is
            # shown in every window's pane rather than being guessed into
            # one specific window's, which could otherwise hide it from the
            # window it actually belongs to.
            record.window_id = current_window_id()
        return True


class WindowLogFilter(logging.Filter):
    """Only lets records through that belong to this window, or to no window."""

    def __init__(self, window_id: str) -> None:
        super().__init__()
        self._window_id = window_id

    def filter(self, record: logging.LogRecord) -> bool:
        window_id = getattr(record, "window_id", None)
        return window_id is None or window_id == self._window_id
