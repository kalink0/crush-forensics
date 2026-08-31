# SPDX-License-Identifier: Apache-2.0
"""SQLite freelist walker and leftover-cell carving.

SQLite does not zero a page's contents when it is moved onto the freelist —
a freed page can still carry its old table-leaf B-tree structure and cells
until the space is reused by a later allocation. This module walks the
freelist trunk chain recorded in the database header to enumerate every
freed page, then reuses ``parse_table_leaf_page`` to carve any leftover rows
still present.

This only recovers data when ``secure_delete`` was OFF at write time (the
official SQLite default, and what iOS/Android apps bundling their own SQLite
typically ship with) — a handful of Linux distro packages default it ON,
which zeroes freed pages immediately and leaves nothing to carve.

A freed page is, by definition, no longer referenced by any table's B-tree,
so which table a carved row originally belonged to cannot be recovered from
the page itself — callers that want a candidate-table hint must match on
other signals (e.g. column count) themselves.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from crush.core.sqlite_wal import parse_table_leaf_page

_HEADER_FIRST_TRUNK_OFFSET = 32
_HEADER_FREELIST_COUNT_OFFSET = 36


def read_raw_page(db_path: Path, page_num: int, page_size: int) -> bytes | None:
    """Return raw bytes for 1-indexed *page_num*, or None if unreadable."""
    if page_num < 1 or page_size <= 0:
        return None
    offset = (page_num - 1) * page_size
    try:
        with open(db_path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(page_size)
    except OSError:
        return None
    return data if len(data) == page_size else None


def _read_page_via_handle(fh: Any, page_num: int, page_size: int) -> bytes | None:
    """Like read_raw_page(), but reuses an already-open file handle instead
    of opening the file fresh — avoids one open()/close() per page when
    walking many pages in a loop."""
    if page_num < 1 or page_size <= 0:
        return None
    try:
        fh.seek((page_num - 1) * page_size)
        data = fh.read(page_size)
    except OSError:
        return None
    return data if len(data) == page_size else None


def walk_freelist_pages(db_path: Path, page_size: int) -> list[dict[str, Any]]:
    """Walk the freelist trunk chain, returning one entry per freed page.

    Each entry is ``{"page": int, "kind": "trunk" | "leaf"}``.  The walk is
    bounded by the freelist page count declared in the database header, so a
    corrupt or cyclic chain is stopped defensively rather than looping.
    """
    try:
        fh = open(db_path, "rb")
    except OSError:
        return []

    try:
        header = _read_page_via_handle(fh, 1, page_size)
        if header is None or len(header) < _HEADER_FREELIST_COUNT_OFFSET + 4:
            return []

        first_trunk = struct.unpack_from(">I", header, _HEADER_FIRST_TRUNK_OFFSET)[0]
        declared_count = struct.unpack_from(">I", header, _HEADER_FREELIST_COUNT_OFFSET)[0]
        if first_trunk == 0 or declared_count == 0:
            return []

        entries: list[dict[str, Any]] = []
        visited: set[int] = set()
        trunk_num = first_trunk
        budget = declared_count + 1  # +1: trunk pages aren't counted separately in some builds

        while trunk_num and trunk_num not in visited and budget > 0:
            visited.add(trunk_num)
            budget -= 1
            trunk = _read_page_via_handle(fh, trunk_num, page_size)
            if trunk is None or len(trunk) < 8:
                break
            entries.append({"page": trunk_num, "kind": "trunk"})

            next_trunk = struct.unpack_from(">I", trunk, 0)[0]
            leaf_count = struct.unpack_from(">I", trunk, 4)[0]
            max_leaves = (page_size - 8) // 4
            leaf_count = min(leaf_count, max_leaves)

            for i in range(leaf_count):
                if budget <= 0:
                    break
                leaf_off = 8 + i * 4
                if leaf_off + 4 > len(trunk):
                    break
                leaf_num = struct.unpack_from(">I", trunk, leaf_off)[0]
                if leaf_num == 0 or leaf_num in visited:
                    continue
                visited.add(leaf_num)
                budget -= 1
                entries.append({"page": leaf_num, "kind": "leaf"})

            trunk_num = next_trunk

        return entries
    finally:
        fh.close()


def carve_freelist_rows(
    db_path: Path,
    page_size: int,
    entries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Carve leftover table-leaf rows out of freed pages.

    For each freed page whose raw bytes still form a valid table-leaf B-tree
    page (type 0x0D), returns ``{"page": int, "kind": str, "rows": [(rowid,
    values), ...]}``.  Pages that are zeroed, reused for something else, or
    no longer resemble a table-leaf page are omitted.

    Values whose payload spills onto overflow pages are reconstructed by
    following the overflow chain — but *only* through freelist *leaf*
    entries. A chain that steps onto any other page is treated as broken
    at that point (rest marked with the existing '<OVERFLOW>' sentinel),
    for two reasons: a page outside the freelist has, by definition, been
    reused for something else since the row was deleted, so splicing its
    current content in would misattribute live data as part of a deleted
    record; and freelist *trunk* pages are unconditionally overwritten with
    the freelist's own bookkeeping (next-trunk pointer + leaf array) the
    moment they become a trunk, so even though they're still "on the
    freelist," their content is guaranteed to no longer be the original
    overflow bytes. Only leaf-kind freelist pages are never touched by
    SQLite once freed (per [[feedback_no_heuristics_in_parsers]] — only
    reconstruct what can be verified).
    """
    if entries is None:
        entries = walk_freelist_pages(db_path, page_size)

    freelist_page_set = {e["page"] for e in entries if e["kind"] == "leaf"}

    try:
        fh = open(db_path, "rb")
    except OSError:
        return []

    def _overflow_reader(page_num: int) -> bytes | None:
        if page_num not in freelist_page_set:
            return None
        return _read_page_via_handle(fh, page_num, page_size)

    try:
        carved: list[dict[str, Any]] = []
        for entry in entries:
            page = _read_page_via_handle(fh, entry["page"], page_size)
            if page is None:
                continue
            rows = parse_table_leaf_page(
                page, page_size=page_size, overflow_reader=_overflow_reader
            )
            if not rows:
                continue
            carved.append({"page": entry["page"], "kind": entry["kind"], "rows": rows})

        return carved
    finally:
        fh.close()


_AFFINITY_TEXT = "TEXT"
_AFFINITY_NUMERIC = "NUMERIC"
_AFFINITY_INTEGER = "INTEGER"
_AFFINITY_REAL = "REAL"
_AFFINITY_BLOB = "BLOB"


def column_affinity(declared_type: str | None) -> str:
    """Map a declared column type to its SQLite type affinity.

    Follows the rules in https://www.sqlite.org/datatype3.html
    ("Determination Of Column Affinity"), applied in the order the spec
    lists them.
    """
    t = (declared_type or "").upper()
    if "INT" in t:
        return _AFFINITY_INTEGER
    if "CHAR" in t or "CLOB" in t or "TEXT" in t:
        return _AFFINITY_TEXT
    if "BLOB" in t or not t:
        return _AFFINITY_BLOB
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return _AFFINITY_REAL
    return _AFFINITY_NUMERIC


def value_matches_affinity(value: Any, affinity: str) -> bool:
    """Whether a decoded value's storage class is possible for *affinity*.

    Type affinity only governs what an INSERT coerces a value *into* — once
    stored, SQLite does not re-check it — so most affinities give no usable
    signal here: NUMERIC/INTEGER/REAL affinity columns keep unparseable text
    as TEXT and store BLOB literals unconverted, so any storage class is
    possible for them. TEXT affinity is the one case the spec makes a hard
    guarantee for: "If numerical data is inserted into a column with TEXT
    affinity it is converted into text form before being stored" — so a
    TEXT-affinity column can only ever hold NULL, TEXT or BLOB, never a raw
    INTEGER/REAL storage class. NULL always matches, since nullability
    constraints aren't visible from a freed page's row header.
    """
    if value is None or affinity != _AFFINITY_TEXT:
        return True
    return isinstance(value, (str, bytes))
