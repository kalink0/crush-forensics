# SPDX-License-Identifier: Apache-2.0
"""SQLite in-page freeblock carving.

Deleting a single row rarely frees a whole page — SQLite instead splices the
cell into the page's freeblock list (a linked list threaded through the page
itself, starting at the 2-byte pointer at header offset 1) and only reclaims
the space on a later compaction. The deleted cell's payload is still sitting
in that freeblock, byte-for-byte, until something overwrites it — this is
the far more common counterpart to `sqlite_freelist.py`'s whole-page
recovery, since most real-world deletes (a single message, a single row)
never free an entire page.

The freeblock's own 4-byte header (next-pointer + size) overwrites the first
4 bytes of whatever cell used to start there, so the leftover bytes can't be
re-parsed as a structured record (payload-size/rowid varints, serial-type
header) — this module returns the raw bytes instead, the same "carve what's
still legible" approach as `sqlite_freelist.py`.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from crush.core.sqlite_wal import PAGE_TYPE_TABLE_LEAF

_MIN_FREEBLOCK_SIZE = 4  # next-pointer (2) + size (2)


def extract_freeblocks(page: bytes) -> list[dict[str, Any]]:
    """Return every freeblock on a table-leaf page as ``{"offset", "size", "data"}``.

    Only table-leaf pages (type 0x0D) are scanned — that's where deleted row
    payloads actually live. A corrupt or cyclic freeblock chain is stopped
    defensively (bounded by page size / minimum freeblock size) rather than
    looping forever.
    """
    if len(page) < 8 or page[0] != PAGE_TYPE_TABLE_LEAF:
        return []

    freeblocks: list[dict[str, Any]] = []
    visited: set[int] = set()
    ptr = struct.unpack_from(">H", page, 1)[0]
    budget = len(page) // _MIN_FREEBLOCK_SIZE + 1

    while ptr and ptr not in visited and budget > 0:
        if ptr + _MIN_FREEBLOCK_SIZE > len(page):
            break
        visited.add(ptr)
        budget -= 1

        next_ptr = struct.unpack_from(">H", page, ptr)[0]
        size = struct.unpack_from(">H", page, ptr + 2)[0]
        if size < _MIN_FREEBLOCK_SIZE:
            break

        end = min(ptr + size, len(page))
        content = bytes(page[ptr + _MIN_FREEBLOCK_SIZE:end])
        freeblocks.append({"offset": ptr, "size": size, "data": content})

        ptr = next_ptr

    return freeblocks


def scan_database_freeblocks(
    db_path: Path, page_size: int, wal_pages: dict[int, bytes] | None = None
) -> list[dict[str, Any]]:
    """Scan every page in *db_path* for freeblocks.

    Returns one entry per freeblock: ``{"page": int, "offset": int, "size":
    int, "data": bytes}``. Table-leaf pages are checked regardless of
    whether they currently belong to a live table or sit on the freelist —
    a freelist leaf page can still carry both intact cells (see
    ``sqlite_freelist.py``) and, separately, its own freeblock leftovers
    from before it was freed.

    *wal_pages* (see sqlite_wal.build_wal_page_overlay()) is checked before
    the base file for each page number — on a live WAL-mode database, a
    page's most recent freeblock layout can sit only in a not-yet-
    checkpointed -wal frame, and scanning the base file alone would show a
    stale (or entirely wrong) freeblock list for that page.
    """
    try:
        page_count = db_path.stat().st_size // page_size if page_size else 0
    except OSError:
        return []
    if wal_pages:
        page_count = max(page_count, max(wal_pages, default=0))

    results: list[dict[str, Any]] = []
    try:
        with open(db_path, "rb") as fh:
            for page_num in range(1, page_count + 1):
                if wal_pages and page_num in wal_pages:
                    page = wal_pages[page_num]
                else:
                    fh.seek((page_num - 1) * page_size)
                    page = fh.read(page_size)
                if len(page) != page_size:
                    continue
                for fb in extract_freeblocks(page):
                    results.append({"page": page_num, **fb})
    except OSError:
        return results

    return results
