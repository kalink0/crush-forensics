# SPDX-License-Identifier: Apache-2.0
"""The phase a long source load is in, and how far it got, for a wait dialog
to show.

Opening a source runs on a worker thread through open_vfs() and the VFS
constructors, which know nothing of the window. A caller that shows progress
installs a reporter for its thread with phase_reporter(); the code doing the
work calls report_phase() with one of the PHASE_* keys below, which is a no-op
when nobody listens. The keys stay English; the UI maps them to its own text.

Progress is a running count, never a percentage: how many entries have been
listed so far (count_entry(), called for every VFSNode made on the thread, so
every source type counts the same way), and, where the load goes through a
known number of steps, which step it is on (report_step(), e.g. volume 2 of
5). Counts are passed on at most every _MIN_INTERVAL seconds.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

# A disk image or acquisition: opening its file(s) and joining segments.
PHASE_OPEN_IMAGE = "open_image"
# Trying the secrets given on the encrypted volumes inside a disk image.
PHASE_UNLOCK_VOLUMES = "unlock_volumes"
# Reading partition tables and LVM metadata, and scanning for filesystems.
PHASE_SEARCH_VOLUMES = "search_volumes"
# Listing every folder of every readable volume.
PHASE_READ_FILESYSTEMS = "read_filesystems"
# Listing a volume's deleted files (into $Recovered).
PHASE_DELETED_FILES = "deleted_files"
# Hashing the source as loaded (integrity mode).
PHASE_HASH_SOURCE = "hash_source"

# (entries listed so far, step, steps); step and steps are 0 with no steps.
ProgressCallback = Callable[[int, int, int], None]

_MIN_INTERVAL = 0.1

_local = threading.local()


@contextmanager
def phase_reporter(
    callback: Callable[[str], None], progress: ProgressCallback | None = None,
) -> Iterator[None]:
    """Send every report_phase() on this thread to *callback*, and the
    counts to *progress*, while active."""
    previous = (
        getattr(_local, "callback", None), getattr(_local, "progress", None),
        getattr(_local, "entries", 0), getattr(_local, "step", (0, 0)),
        getattr(_local, "last", 0.0),
    )
    _local.callback, _local.progress = callback, progress
    _local.entries, _local.step, _local.last = 0, (0, 0), 0.0
    try:
        yield
    finally:
        (_local.callback, _local.progress, _local.entries, _local.step,
         _local.last) = previous


def report_phase(phase: str) -> None:
    """Say that the load on this thread entered *phase* (a PHASE_* key)."""
    callback = getattr(_local, "callback", None)
    if callback is not None:
        callback(phase)


def report_step(step: int, steps: int) -> None:
    """Say that the load on this thread is on *step* of *steps* (1-based)."""
    if getattr(_local, "progress", None) is None:
        return
    _local.step = (step, steps)
    _emit()


@contextmanager
def not_counted() -> Iterator[None]:
    """VFSNodes made inside are not counted: copies of entries already
    listed (a mounted source holding another source's tree)."""
    _local.paused = getattr(_local, "paused", 0) + 1
    try:
        yield
    finally:
        _local.paused -= 1


def count_entry() -> None:
    """One more entry listed on this thread (VFSNode.__post_init__)."""
    progress = getattr(_local, "progress", None)
    if progress is None or getattr(_local, "paused", 0) > 0:
        return
    _local.entries += 1
    if time.monotonic() - _local.last >= _MIN_INTERVAL:
        _emit()


def _emit() -> None:
    _local.last = time.monotonic()
    step, steps = _local.step
    _local.progress(_local.entries, step, steps)
