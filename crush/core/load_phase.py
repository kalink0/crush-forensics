# SPDX-License-Identifier: Apache-2.0
"""The phase a long source load is in, for a wait dialog to show.

Opening a source runs on a worker thread through open_vfs() and the VFS
constructors, which know nothing of the window. A caller that shows progress
installs a reporter for its thread with phase_reporter(); the code doing the
work calls report_phase() with one of the PHASE_* keys below, which is a no-op
when nobody listens. The keys stay English; the UI maps them to its own text.
"""
from __future__ import annotations

import threading
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

_local = threading.local()


@contextmanager
def phase_reporter(callback: Callable[[str], None]) -> Iterator[None]:
    """Send every report_phase() on this thread to *callback* while active."""
    previous = getattr(_local, "callback", None)
    _local.callback = callback
    try:
        yield
    finally:
        _local.callback = previous


def report_phase(phase: str) -> None:
    """Say that the load on this thread entered *phase* (a PHASE_* key)."""
    callback = getattr(_local, "callback", None)
    if callback is not None:
        callback(phase)
