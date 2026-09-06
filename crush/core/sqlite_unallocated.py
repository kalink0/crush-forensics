# SPDX-License-Identifier: Apache-2.0
"""SQLite intra-page unallocated-space carving.

Every table-leaf page has a gap between where its cell-pointer array ends
and where its cell-content area begins. That gap shrinks as more cells are
added and can grow again — immediately when a cell is deleted (its pointer
slot is dropped, shrinking the array) and, less often, when the page is
compacted (SQLite consolidates scattered freeblocks into one contiguous run,
which can move the content-area boundary and expose previously-live space).

Unlike `sqlite_freeblocks.py`, this space isn't a maintained structure with
guaranteed content — it's simply whatever bytes happen to be sitting there,
and empirically (verified against SQLite 3.53.4) it is *usually* all-zero or
holds leftover 2-byte pointer values from a shrunk cell-pointer array, not
reconstructable row text. This module makes no claim about what's in that
gap; it returns the raw non-zero bytes, if any, for a human to judge —
matching the "no heuristics without disclosure" rule for this codebase: no
attempt is made here to guess whether a given gap holds real evidence.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from crush.core.sqlite_wal import PAGE_TYPE_TABLE_LEAF


def extract_unallocated_space(page: bytes) -> dict[str, Any] | None:
    """Return the gap between a table-leaf page's pointer array and its
    cell-content area as ``{"offset", "size", "data"}``, or None if the page
    isn't a table-leaf page, has no such gap, or the gap is all-zero.
    """
    if len(page) < 8 or page[0] != PAGE_TYPE_TABLE_LEAF:
        return None

    cell_count = struct.unpack_from(">H", page, 3)[0]
    content_start_raw = struct.unpack_from(">H", page, 5)[0]
    content_start = content_start_raw if content_start_raw != 0 else 65536
    pointer_array_end = 8 + cell_count * 2

    if pointer_array_end >= content_start or content_start > len(page):
        return None

    data = bytes(page[pointer_array_end:content_start])
    if not any(data):
        return None

    return {"offset": pointer_array_end, "size": len(data), "data": data}


def scan_database_unallocated(
    db_path: Path, page_size: int, wal_pages: dict[int, bytes] | None = None
) -> list[dict[str, Any]]:
    """Scan every table-leaf page in *db_path* for non-empty unallocated gaps.

    Returns one entry per page with a non-zero gap: ``{"page", "offset",
    "size", "data"}``. Applies to live-allocated and freelist leaf pages
    alike, same as `sqlite_freeblocks.scan_database_freeblocks`.

    *wal_pages* (see sqlite_wal.build_wal_page_overlay()) is checked before
    the base file for each page number, same reasoning as in
    scan_database_freeblocks: a page's current gap can exist only in a
    not-yet-checkpointed -wal frame on a live WAL-mode database.
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
                entry = extract_unallocated_space(page)
                if entry is not None:
                    results.append({"page": page_num, **entry})
    except OSError:
        return results

    return results
