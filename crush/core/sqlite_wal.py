# SPDX-License-Identifier: Apache-2.0
"""SQLite WAL page parser and B-tree attribution utilities.

Implements:
  - SQLite varint decoder
  - Record-format row extractor (serial-type decoder, optional overflow chasing)
  - Table-leaf page parser (page type 0x0D)
  - Page→table attribution map built by walking B-tree interior pages
"""
from __future__ import annotations

import sqlite3
import struct
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Varint
# ---------------------------------------------------------------------------

def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, bytes_consumed) for the SQLite varint at *offset*."""
    result = 0
    for i in range(9):
        byte = data[offset + i]
        if i < 8:
            result = (result << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                return result, i + 1
        else:
            # 9th byte: all 8 bits contribute
            result = (result << 8) | byte
            return result, 9
    return result, 9  # unreachable but satisfies type checker


# ---------------------------------------------------------------------------
# Record format
# ---------------------------------------------------------------------------

_NULL    = object()  # sentinel for NULL cells


def _decode_record(payload: bytes) -> list[Any]:
    """Decode a SQLite record payload into a list of Python values.

    Overflow payloads are not followed — values that would require an
    overflow page are returned as the sentinel string '<OVERFLOW>'.
    """
    if not payload:
        return []

    hdr_size, consumed = _read_varint(payload, 0)
    pos = consumed
    serial_types: list[int] = []
    while pos < hdr_size:
        stype, n = _read_varint(payload, pos)
        serial_types.append(stype)
        pos += n

    values: list[Any] = []
    body_pos = hdr_size
    for stype in serial_types:
        if stype == 0:
            values.append(None)
        elif stype == 1:
            if body_pos + 1 > len(payload):
                values.append("<TRUNCATED>")
            else:
                values.append(struct.unpack_from(">b", payload, body_pos)[0])
            body_pos += 1
        elif stype == 2:
            if body_pos + 2 > len(payload):
                values.append("<TRUNCATED>")
            else:
                values.append(struct.unpack_from(">h", payload, body_pos)[0])
            body_pos += 2
        elif stype == 3:
            if body_pos + 3 > len(payload):
                values.append("<TRUNCATED>")
            else:
                raw = payload[body_pos:body_pos + 3]
                v = int.from_bytes(raw, "big", signed=True)
                values.append(v)
            body_pos += 3
        elif stype == 4:
            if body_pos + 4 > len(payload):
                values.append("<TRUNCATED>")
            else:
                values.append(struct.unpack_from(">i", payload, body_pos)[0])
            body_pos += 4
        elif stype == 5:
            if body_pos + 6 > len(payload):
                values.append("<TRUNCATED>")
            else:
                raw = payload[body_pos:body_pos + 6]
                v = int.from_bytes(raw, "big", signed=True)
                values.append(v)
            body_pos += 6
        elif stype == 6:
            if body_pos + 8 > len(payload):
                values.append("<TRUNCATED>")
            else:
                values.append(struct.unpack_from(">q", payload, body_pos)[0])
            body_pos += 8
        elif stype == 7:
            if body_pos + 8 > len(payload):
                values.append("<TRUNCATED>")
            else:
                values.append(struct.unpack_from(">d", payload, body_pos)[0])
            body_pos += 8
        elif stype == 8:
            values.append(0)
        elif stype == 9:
            values.append(1)
        elif stype >= 12 and stype % 2 == 0:
            length = (stype - 12) // 2
            if length == 0:
                values.append(b"")
            elif body_pos + length > len(payload):
                values.append("<OVERFLOW>")
            else:
                values.append(bytes(payload[body_pos:body_pos + length]))
            body_pos += length
        elif stype >= 13 and stype % 2 == 1:
            length = (stype - 13) // 2
            if length == 0:
                values.append("")
            elif body_pos + length > len(payload):
                values.append("<OVERFLOW>")
            else:
                try:
                    values.append(payload[body_pos:body_pos + length].decode("utf-8", errors="replace"))
                except Exception:
                    values.append(bytes(payload[body_pos:body_pos + length]))
            body_pos += length
        else:
            values.append(None)  # reserved serial types 10, 11

    return values


# ---------------------------------------------------------------------------
# Table leaf page parser
# ---------------------------------------------------------------------------

PAGE_TYPE_TABLE_LEAF     = 0x0D
PAGE_TYPE_TABLE_INTERIOR = 0x05
PAGE_TYPE_INDEX_LEAF     = 0x0A
PAGE_TYPE_INDEX_INTERIOR = 0x02


def _payload_inline_size(payload_size: int, usable_size: int) -> int:
    """Return how many payload bytes SQLite stores inline on the leaf page
    itself; any remainder spills into the overflow page chain. Formula per
    the SQLite file format spec (section 1.5), same as SQLite's own
    `btreeParseCellPtr()`.
    """
    U = usable_size
    P = payload_size
    X = U - 35
    if P <= X:
        return P
    M = ((U - 12) * 32) // 255 - 23
    K = M + (P - M) % (U - 4)
    return K if K <= X else M


def _follow_overflow_chain(
    first_page: int,
    remaining: int,
    usable_size: int,
    overflow_reader: Callable[[int], bytes | None],
    max_pages: int = 10_000,
) -> bytes:
    """Follow an overflow page chain, collecting up to *remaining* bytes.

    Stops early — returning whatever was collected so far — if the chain
    breaks: a page can't be read, or a cycle is detected. *overflow_reader*
    decides what counts as "readable"; callers that can only trust specific
    pages (e.g. other pages still confirmed on the freelist) should return
    None for anything else rather than risk splicing in unrelated live data.
    """
    collected = bytearray()
    page_num = first_page
    visited: set[int] = set()
    per_page_capacity = usable_size - 4

    while page_num and remaining > 0 and page_num not in visited and len(visited) < max_pages:
        visited.add(page_num)
        page = overflow_reader(page_num)
        if page is None or len(page) < 4:
            break
        next_page = struct.unpack_from(">I", page, 0)[0]
        take = min(remaining, per_page_capacity, len(page) - 4)
        collected.extend(page[4:4 + take])
        remaining -= take
        page_num = next_page

    return bytes(collected)


def parse_table_leaf_page(
    page: bytes,
    *,
    page_size: int = 0,
    overflow_reader: Callable[[int], bytes | None] | None = None,
) -> list[tuple[int, list[Any]]] | None:
    """Parse a SQLite table-leaf page (type 0x0D).

    Returns a list of (rowid, [values]) tuples, or None if the page is not a
    table-leaf page or is corrupt. Values whose payload extends beyond what
    could be recovered are returned as the string '<OVERFLOW>'. By default
    overflow pages are not followed (matching prior behavior); pass
    *page_size* and *overflow_reader* to reconstruct values that spill onto
    overflow pages — *overflow_reader(page_num)* should return that page's
    raw bytes, or None if it can't be trusted/read.
    """
    if len(page) < 8:
        return None
    page_type = page[0]
    if page_type != PAGE_TYPE_TABLE_LEAF:
        return None

    # cell_count at offset 3 (2 bytes)
    cell_count = struct.unpack_from(">H", page, 3)[0]
    if cell_count == 0:
        return []

    # Cell pointer array starts at offset 8 (table-leaf has no rightmost-pointer)
    ptr_area_start = 8
    rows: list[tuple[int, list[Any]]] = []
    usable_size = page_size or len(page)

    for i in range(cell_count):
        ptr_off = ptr_area_start + i * 2
        if ptr_off + 2 > len(page):
            break
        cell_offset = struct.unpack_from(">H", page, ptr_off)[0]
        if cell_offset == 0 or cell_offset >= len(page):
            continue
        try:
            pos = cell_offset
            payload_size, n = _read_varint(page, pos)
            pos += n
            rowid, n = _read_varint(page, pos)
            pos += n

            inline_size = _payload_inline_size(payload_size, usable_size)
            inline_size = min(inline_size, len(page) - pos)  # never read past the page
            payload = bytearray(page[pos:pos + inline_size])

            remaining = payload_size - inline_size
            if remaining > 0 and overflow_reader is not None:
                overflow_ptr_off = pos + inline_size
                if overflow_ptr_off + 4 <= len(page):
                    next_page = struct.unpack_from(">I", page, overflow_ptr_off)[0]
                    payload.extend(
                        _follow_overflow_chain(next_page, remaining, usable_size, overflow_reader)
                    )

            values = _decode_record(bytes(payload))
            rows.append((rowid, values))
        except Exception:
            continue

    return rows


def get_page_type(page: bytes) -> int | None:
    """Return the page-type byte, or None if the page is too short."""
    return page[0] if page else None


# ---------------------------------------------------------------------------
# Page → table attribution
# ---------------------------------------------------------------------------

# Same magic pair the WAL frame classifier in table_viewer.py's _get_wal_frames
# checks (_WAL_MAGIC there) -- kept local here since this module has no
# dependency on the viewer.
_WAL_MAGIC = (0x377F0682, 0x377F0683)


def build_wal_page_overlay(wal_data: bytes | None, page_size: int) -> dict[int, bytes]:
    """Return {page_num: latest committed page bytes} from a WAL file's
    salt-valid frames.

    A page's *logical* current content is its base-file copy unless a later,
    not-yet-checkpointed WAL frame overrides it -- which is exactly what a
    live SQLite connection already returns transparently for any query, WAL
    or no WAL. Any code that instead reads a database file's raw bytes
    directly (as every recovery scanner in sqlite_freelist.py,
    sqlite_freeblocks.py and sqlite_unallocated.py does, since none of them
    go through sqlite3) sees only the frozen base-file state and silently
    misses -- or reports as still-live -- whatever the WAL has since
    changed. Passing this overlay's bytes for a page number, falling back to
    the base file otherwise, closes that gap without needing sqlite3 at all.
    """
    wal_pages: dict[int, bytes] = {}
    if not wal_data or not page_size or len(wal_data) < 32:
        return wal_pages
    magic = struct.unpack_from(">I", wal_data, 0)[0]
    if magic not in _WAL_MAGIC:
        return wal_pages
    salt1 = struct.unpack_from(">I", wal_data, 16)[0]
    salt2 = struct.unpack_from(">I", wal_data, 20)[0]
    frame_size = 24 + page_size
    offset = 32
    # Collect last valid frame per page (active)
    while offset + frame_size <= len(wal_data):
        pn  = struct.unpack_from(">I", wal_data, offset)[0]
        fs1 = struct.unpack_from(">I", wal_data, offset + 8)[0]
        fs2 = struct.unpack_from(">I", wal_data, offset + 12)[0]
        if fs1 == salt1 and fs2 == salt2:
            wal_pages[pn] = wal_data[offset + 24: offset + 24 + page_size]
        offset += frame_size
    return wal_pages


def build_page_table_map(
    conn: sqlite3.Connection,
    wal_data: bytes | None = None,
    page_size: int = 0,
) -> dict[int, str]:
    """Return a mapping of {page_number: table_name} for every page reachable
    from a table's B-tree root.

    Works by reading sqlite_master root pages, then walking interior pages
    (from the DB connection or from WAL frames) to collect all child page
    numbers.  Index pages and non-table objects are excluded.
    """
    mapping: dict[int, str] = {}
    wal_pages = build_wal_page_overlay(wal_data, page_size)

    # Read sqlite_master for table root pages and schemas
    try:
        rows = conn.execute(
            "SELECT name, rootpage FROM sqlite_master WHERE type='table'"
        ).fetchall()
    except Exception:
        return mapping

    # Resolve the DB file path and page count once up front, and keep a single
    # file handle open for the whole walk — _read_page used to run a
    # `SELECT ... FROM dbstat` (a full B-tree scan of the whole database) and
    # re-open the file, per page visited, which made this walk cost
    # O(pages x interior_pages) on any real-sized database.
    db_file: Any = None
    page_count = 0
    try:
        db_path_row = conn.execute("PRAGMA database_list").fetchone()
        if db_path_row is not None and page_size:
            db_path = Path(db_path_row[2])
            if db_path.is_file():
                page_count = db_path.stat().st_size // page_size
                db_file = open(db_path, "rb")
    except Exception:
        db_file = None

    try:
        # For each root page, BFS-walk interior pages to collect all child pages
        for name, rootpage in rows:
            if rootpage is None:
                continue
            mapping[rootpage] = name
            _walk_interior(
                rootpage, name, mapping, wal_pages, page_size, set(), db_file, page_count
            )
    finally:
        if db_file is not None:
            db_file.close()

    return mapping


def _walk_interior(
    page_num: int,
    table_name: str,
    mapping: dict[int, str],
    wal_pages: dict[int, bytes],
    page_size: int,
    visited: set[int],
    db_file: Any,
    page_count: int,
) -> None:
    """Recursively collect all child pages of *page_num* into *mapping*."""
    if page_num in visited:
        return
    visited.add(page_num)

    page = _read_page(page_num, wal_pages, page_size, db_file, page_count)
    if page is None or len(page) < 1:
        return
    page_type = page[0]
    if page_type not in (PAGE_TYPE_TABLE_INTERIOR, PAGE_TYPE_TABLE_LEAF):
        return
    if page_type != PAGE_TYPE_TABLE_INTERIOR:
        return  # leaf — no children to walk

    # Interior page header: type(1) + freeblock(2) + cell_count(2) +
    #                       content_start(2) + fragmented(1) + rightmost(4) = 12
    if len(page) < 12:
        return
    cell_count = struct.unpack_from(">H", page, 3)[0]
    rightmost  = struct.unpack_from(">I", page, 8)[0]
    mapping[rightmost] = table_name
    _walk_interior(
        rightmost, table_name, mapping, wal_pages, page_size, visited, db_file, page_count
    )

    ptr_area_start = 12
    for i in range(cell_count):
        ptr_off = ptr_area_start + i * 2
        if ptr_off + 2 > len(page):
            break
        cell_offset = struct.unpack_from(">H", page, ptr_off)[0]
        if cell_offset + 4 > len(page):
            continue
        child_page = struct.unpack_from(">I", page, cell_offset)[0]
        if child_page and child_page not in mapping:
            mapping[child_page] = table_name
            _walk_interior(
                child_page, table_name, mapping, wal_pages, page_size, visited, db_file, page_count
            )


def _read_page(
    page_num: int,
    wal_pages: dict[int, bytes],
    page_size: int,
    db_file: Any,
    page_count: int,
) -> bytes | None:
    """Return raw page bytes for *page_num*, preferring WAL over DB file."""
    if page_num in wal_pages:
        return wal_pages[page_num]
    if db_file is None or page_size == 0 or not (1 <= page_num <= page_count):
        return None
    try:
        db_file.seek((page_num - 1) * page_size)
        data = db_file.read(page_size)
        return data if len(data) == page_size else None
    except Exception:
        return None
