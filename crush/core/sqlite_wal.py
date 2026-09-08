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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, overload

from crush.core.cell_locator import CellLocation


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


def _serial_type_len(stype: int) -> int:
    """Return the on-disk byte length of a SQLite record serial type.

    A standalone length table, not reused *by* _decode_record() itself (that
    function's per-branch unpacking is left untouched to avoid any risk of
    changing its already-shipped decoding behavior) -- kept here purely so
    _record_field_ranges() below can locate each column's bytes without
    re-decoding its value. Must stay in sync with _decode_record()'s branches
    (see https://www.sqlite.org/fileformat2.html#record_format).
    """
    if stype in (0, 8, 9):
        return 0
    if stype == 1:
        return 1
    if stype == 2:
        return 2
    if stype == 3:
        return 3
    if stype == 4:
        return 4
    if stype == 5:
        return 6
    if stype in (6, 7):
        return 8
    if stype >= 12 and stype % 2 == 0:
        return (stype - 12) // 2
    if stype >= 13 and stype % 2 == 1:
        return (stype - 13) // 2
    return 0  # reserved serial types 10, 11


def _record_field_ranges(payload: bytes) -> list[tuple[int, int]]:
    """Return each column's (start, end) byte range *within payload* --
    companion to _decode_record(), which returns values but discards where
    each field's bytes actually live. Used by locate_cell() (below) to
    highlight one specific column's on-disk bytes.
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

    ranges: list[tuple[int, int]] = []
    body_pos = hdr_size
    for stype in serial_types:
        length = _serial_type_len(stype)
        ranges.append((body_pos, body_pos + length))
        body_pos += length
    return ranges


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


def _follow_overflow_chain_ex(
    first_page: int,
    remaining: int,
    usable_size: int,
    overflow_reader: Callable[[int], bytes | None],
    max_pages: int = 10_000,
) -> tuple[bytes, list[tuple[int, int]]]:
    """Like _follow_overflow_chain(), but also returns the (page_num,
    bytes_taken) for each overflow page actually visited, in chain order --
    needed to map a reconstructed payload's logical byte positions back to
    their physical page/offset (see locate_cell()).
    """
    collected = bytearray()
    segments: list[tuple[int, int]] = []
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
        segments.append((page_num, take))
        remaining -= take
        page_num = next_page

    return bytes(collected), segments


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
    data, _segments = _follow_overflow_chain_ex(
        first_page, remaining, usable_size, overflow_reader, max_pages
    )
    return data


@dataclass
class RowByteLayout:
    """Physical layout of one table-leaf cell, describing where its bytes
    actually live so a decoded row/column can be mapped back to exact
    on-disk ranges (see locate_cell()). All positions except
    *overflow_segments* (page_num, bytes_taken) are relative to the page
    passed to parse_table_leaf_page(); overflow pages are looked up
    separately by the caller, which is the only one that knows whether a
    given page number currently lives in the base file or a -wal frame.
    """
    page_local_range: tuple[int, int]        # (cell_offset, end-of-inline-payload) within `page`
    payload_start_in_page: int               # where the inline payload itself begins, within `page`
    inline_payload_size: int
    overflow_segments: list[tuple[int, int]]  # (overflow_page_num, bytes_taken), in chain order
    column_logical_ranges: list[tuple[int, int]]  # per column, within the logical (inline+overflow) payload


@overload
def parse_table_leaf_page(
    page: bytes,
    *,
    page_size: int = 0,
    overflow_reader: Callable[[int], bytes | None] | None = None,
    want_ranges: Literal[False] = False,
) -> list[tuple[int, list[Any]]] | None: ...
@overload
def parse_table_leaf_page(
    page: bytes,
    *,
    page_size: int = 0,
    overflow_reader: Callable[[int], bytes | None] | None = None,
    want_ranges: Literal[True],
) -> list[tuple[int, list[Any], RowByteLayout]] | None: ...
def parse_table_leaf_page(
    page: bytes,
    *,
    page_size: int = 0,
    overflow_reader: Callable[[int], bytes | None] | None = None,
    want_ranges: bool = False,
) -> list[tuple[int, list[Any]]] | list[tuple[int, list[Any], RowByteLayout]] | None:
    """Parse a SQLite table-leaf page (type 0x0D).

    Returns a list of (rowid, [values]) tuples, or None if the page is not a
    table-leaf page or is corrupt. Values whose payload extends beyond what
    could be recovered are returned as the string '<OVERFLOW>'. By default
    overflow pages are not followed (matching prior behavior); pass
    *page_size* and *overflow_reader* to reconstruct values that spill onto
    overflow pages — *overflow_reader(page_num)* should return that page's
    raw bytes, or None if it can't be trusted/read.

    Pass *want_ranges=True* to additionally get each row's on-disk byte
    layout back — returns (rowid, values, RowByteLayout) tuples instead.
    Existing callers that don't pass it are unaffected.
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
    row_layouts: list[RowByteLayout] = []
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
            overflow_segments: list[tuple[int, int]] = []
            if remaining > 0 and overflow_reader is not None:
                overflow_ptr_off = pos + inline_size
                if overflow_ptr_off + 4 <= len(page):
                    next_page = struct.unpack_from(">I", page, overflow_ptr_off)[0]
                    overflow_bytes, overflow_segments = _follow_overflow_chain_ex(
                        next_page, remaining, usable_size, overflow_reader
                    )
                    payload.extend(overflow_bytes)

            values = _decode_record(bytes(payload))
            rows.append((rowid, values))
            if want_ranges:
                row_layouts.append(RowByteLayout(
                    page_local_range=(cell_offset, pos + inline_size),
                    payload_start_in_page=pos,
                    inline_payload_size=inline_size,
                    overflow_segments=overflow_segments,
                    column_logical_ranges=_record_field_ranges(bytes(payload)),
                ))
        except Exception:
            continue

    if want_ranges:
        return [
            (row_rowid, row_values, layout)
            for (row_rowid, row_values), layout in zip(rows, row_layouts)
        ]
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


def build_wal_page_index(wal_data: bytes | None, page_size: int) -> dict[int, tuple[int, bytes]]:
    """Return {page_num: (data_offset, latest committed page bytes)} from a
    WAL file's salt-valid frames -- like build_wal_page_overlay() below, but
    also keeps each page's absolute byte offset *within wal_data* (the
    frame's data section, right after its 24-byte header). locate_cell()
    needs that offset to open the -wal file's own Hex view at the right
    spot, not just to know a page's current content.
    """
    index: dict[int, tuple[int, bytes]] = {}
    if not wal_data or not page_size or len(wal_data) < 32:
        return index
    magic = struct.unpack_from(">I", wal_data, 0)[0]
    if magic not in _WAL_MAGIC:
        return index
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
            data_offset = offset + 24
            index[pn] = (data_offset, wal_data[data_offset: data_offset + page_size])
        offset += frame_size
    return index


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
    return {pn: data for pn, (_offset, data) in build_wal_page_index(wal_data, page_size).items()}


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


# ---------------------------------------------------------------------------
# Live row/cell → exact on-disk byte range ("Locate in Hex")
# ---------------------------------------------------------------------------

def _read_db_page(db_path: Path, page_num: int, page_size: int) -> bytes | None:
    """Read one page directly from the base file. A small local copy of
    sqlite_freelist.read_raw_page()'s logic rather than importing it --
    sqlite_freelist.py already imports from this module, so importing back
    would be circular.
    """
    if page_num < 1 or page_size <= 0:
        return None
    try:
        with open(db_path, "rb") as fh:
            fh.seek((page_num - 1) * page_size)
            data = fh.read(page_size)
    except OSError:
        return None
    return data if len(data) == page_size else None


def _decompose_logical_range(
    start: int, end: int, inline_size: int, overflow_segments: list[tuple[int, int]]
) -> list[tuple[str, int, int, int]]:
    """Split a payload-logical [start, end) range into physical pieces.

    Each piece is either ("page", local_start, local_end, 0) -- bytes in the
    inline portion, at the given offset *within the inline payload itself*
    (callers add RowByteLayout.payload_start_in_page) -- or ("overflow",
    local_start, local_end, page_num) -- bytes on one overflow page, local to
    that page's own content area (i.e. already past its 4-byte next-pointer
    header).
    """
    pieces: list[tuple[str, int, int, int]] = []
    if start < end and start < inline_size:
        seg_end = min(end, inline_size)
        pieces.append(("page", start, seg_end, 0))
    cursor = inline_size
    for page_num, taken in overflow_segments:
        seg_start = max(start, cursor)
        seg_end = min(end, cursor + taken)
        if seg_start < seg_end:
            pieces.append(("overflow", seg_start - cursor, seg_end - cursor, page_num))
        cursor += taken
    return pieces


def _resolve_pieces(
    pieces: list[tuple[str, int, int, int]],
    *,
    payload_start_in_page: int,
    page_file_offset: int,
    home_file_kind: str,
    page_locator: Callable[[int], tuple[str, int] | None],
) -> list[tuple[int, int]]:
    """Resolve decomposed pieces (see _decompose_logical_range) to absolute
    file byte ranges, dropping any overflow piece that lives in a different
    file (base vs -wal) than *home_file_kind* -- never splice bytes from the
    wrong file into a single highlighted view.
    """
    out: list[tuple[int, int]] = []
    for kind, seg_start, seg_end, page_num in pieces:
        if kind == "page":
            base = page_file_offset + payload_start_in_page
            out.append((base + seg_start, base + seg_end))
        else:
            located = page_locator(page_num)
            if located is None:
                continue
            file_kind, overflow_page_offset = located
            if file_kind != home_file_kind:
                continue
            base = overflow_page_offset + 4  # skip the overflow page's next-pointer header
            out.append((base + seg_start, base + seg_end))
    return out


def _page_accessors(
    db_path: Path, page_size: int, wal_index: dict[int, tuple[int, bytes]]
) -> tuple[Callable[[int], tuple[str, int] | None], Callable[[int], bytes | None]]:
    """Shared (page_locator, read_page) pair, preferring a page's -wal
    version when one exists (i.e. resolving each page's *current* content)
    -- used by locate_cell() and by locate_offset()'s "wal" mode."""

    def page_locator(page_num: int) -> tuple[str, int] | None:
        if page_num in wal_index:
            offset, _data = wal_index[page_num]
            return "wal", offset
        if page_num >= 1:
            return "base", (page_num - 1) * page_size
        return None

    def read_page(page_num: int) -> bytes | None:
        if page_num in wal_index:
            return wal_index[page_num][1]
        return _read_db_page(db_path, page_num, page_size)

    return page_locator, read_page


def _raw_base_accessors(
    db_path: Path, page_size: int
) -> tuple[Callable[[int], tuple[str, int] | None], Callable[[int], bytes | None]]:
    """Like _page_accessors(), but never consults the -wal file at all --
    for locate_offset()'s "base" mode, where the caller (a Hex pane showing
    the base file's own raw bytes, unmerged with any WAL frame) needs
    ranges decoded strictly from what's actually at those offsets in the
    base file, not from whichever version SQLite would currently prefer.
    """

    def page_locator(page_num: int) -> tuple[str, int] | None:
        if page_num >= 1:
            return "base", (page_num - 1) * page_size
        return None

    def read_page(page_num: int) -> bytes | None:
        return _read_db_page(db_path, page_num, page_size)

    return page_locator, read_page


def _row_ranges_from_layout(
    layout: RowByteLayout,
    page_file_offset: int,
    home_file_kind: str,
    page_locator: Callable[[int], tuple[str, int] | None],
) -> list[tuple[int, int]]:
    cell_start, cell_end = layout.page_local_range
    row_ranges = [(page_file_offset + cell_start, page_file_offset + cell_end)]
    for seg_page_num, seg_len in layout.overflow_segments:
        seg_located = page_locator(seg_page_num)
        if seg_located is None:
            continue
        seg_file_kind, seg_file_offset = seg_located
        if seg_file_kind != home_file_kind:
            continue
        row_ranges.append((seg_file_offset + 4, seg_file_offset + 4 + seg_len))
    return row_ranges


def _column_ranges_from_layout(
    layout: RowByteLayout,
    column_index: int,
    page_file_offset: int,
    home_file_kind: str,
    page_locator: Callable[[int], tuple[str, int] | None],
) -> list[tuple[int, int]] | None:
    if not (0 <= column_index < len(layout.column_logical_ranges)):
        return None
    lstart, lend = layout.column_logical_ranges[column_index]
    pieces = _decompose_logical_range(
        lstart, lend, layout.inline_payload_size, layout.overflow_segments
    )
    return _resolve_pieces(
        pieces,
        payload_start_in_page=layout.payload_start_in_page,
        page_file_offset=page_file_offset,
        home_file_kind=home_file_kind,
        page_locator=page_locator,
    )


def locate_cell(
    db_path: Path,
    table_name: str,
    rowid: int,
    column_index: int | None,
    page_size: int,
    page_table_map: dict[int, str],
    wal_data: bytes | None,
) -> CellLocation | None:
    """Find a live row's (and optionally one column's) exact on-disk byte
    range(s).

    The row may currently live in the base file or, if not yet
    checkpointed, only in a committed -wal frame; whichever it is, ranges
    are returned against *that* file (CellLocation.file_kind), never
    guessed against the other one. Returns None if the row can't be found
    on any page *page_table_map* attributes to *table_name* (e.g. the map
    is stale, or the table has no rowid).
    """
    if db_path is None or page_size <= 0:
        return None

    wal_index = build_wal_page_index(wal_data, page_size)
    page_locator, read_page = _page_accessors(db_path, page_size, wal_index)

    table_pages = [pn for pn, name in page_table_map.items() if name == table_name]

    for page_num in table_pages:
        page = read_page(page_num)
        if page is None or get_page_type(page) != PAGE_TYPE_TABLE_LEAF:
            continue
        located = page_locator(page_num)
        if located is None:
            continue
        home_file_kind, page_file_offset = located

        parsed = parse_table_leaf_page(
            page, page_size=page_size, overflow_reader=read_page, want_ranges=True
        )
        if not parsed:
            continue

        for entry_rowid, _values, layout in parsed:
            if entry_rowid != rowid:
                continue

            row_ranges = _row_ranges_from_layout(layout, page_file_offset, home_file_kind, page_locator)
            column_ranges = (
                _column_ranges_from_layout(
                    layout, column_index, page_file_offset, home_file_kind, page_locator
                )
                if column_index is not None
                else None
            )

            return CellLocation(
                file_kind=home_file_kind, row_ranges=row_ranges, column_ranges=column_ranges
            )

    return None


def locate_offset(
    db_path: Path,
    table_name: str,
    offset: int,
    file_kind: str,
    page_size: int,
    page_table_map: dict[int, str],
    wal_data: bytes | None,
) -> tuple[int, int | None] | None:
    """Reverse of locate_cell(): given a byte *offset* the caller knows is
    relative to *file_kind* ("base" or "wal" -- whichever file a Hex pane
    is currently displaying raw, unmerged bytes of), find which row -- and,
    if the offset falls inside one specific column's own bytes, which
    column -- of *table_name* it belongs to.

    Cheaper than locate_cell(): resolves the one page the offset falls on
    directly, rather than scanning every page of the table. Returns None if
    the offset doesn't land on a table-leaf page *page_table_map*
    attributes to *table_name* -- never guesses a nearby/likely row.

    "base" mode reads strictly from the base file (see _raw_base_accessors)
    -- what the Hex pane shows there is the base file's own bytes, so
    decoding must never silently substitute a -wal-overridden version of a
    page, which could have different field lengths and shift every range.
    "wal" mode resolves the specific frame *offset* falls in (a page can
    have multiple frames across a WAL file's history; only the latest is
    resolvable here, same "current version" semantics as locate_cell()) and
    otherwise reads like locate_cell() (preferring -wal versions of any
    overflow pages visited too), since a WAL frame's payload can legitimately
    reference not-yet-superseded overflow pages either way.
    """
    if db_path is None or page_size <= 0:
        return None

    wal_index = build_wal_page_index(wal_data, page_size)

    page_num: int | None = None
    page_file_offset = 0
    if file_kind == "wal":
        for pn, (frame_offset, _data) in wal_index.items():
            if frame_offset <= offset < frame_offset + page_size:
                page_num = pn
                page_file_offset = frame_offset
                break
        page_locator, read_page = _page_accessors(db_path, page_size, wal_index)
    else:
        candidate = offset // page_size + 1
        page_num = candidate
        page_file_offset = (candidate - 1) * page_size
        page_locator, read_page = _raw_base_accessors(db_path, page_size)

    if page_num is None or page_table_map.get(page_num) != table_name:
        return None

    page = read_page(page_num)
    if page is None or get_page_type(page) != PAGE_TYPE_TABLE_LEAF:
        return None

    parsed = parse_table_leaf_page(
        page, page_size=page_size, overflow_reader=read_page, want_ranges=True
    )
    if not parsed:
        return None

    for entry_rowid, _values, layout in parsed:
        row_ranges = _row_ranges_from_layout(layout, page_file_offset, file_kind, page_locator)
        if not any(start <= offset < end for start, end in row_ranges):
            continue

        column_index: int | None = None
        for idx in range(len(layout.column_logical_ranges)):
            col_ranges = _column_ranges_from_layout(
                layout, idx, page_file_offset, file_kind, page_locator
            )
            if col_ranges and any(s <= offset < e for s, e in col_ranges):
                column_index = idx
                break

        return entry_rowid, column_index

    return None


@dataclass
class SqliteCellLocator:
    """CellLocator (crush/core/cell_locator.py) implementation for a real
    SQLite file, backing TableViewer's embedded Hex pane.

    Wraps locate_cell()/locate_offset() with the page_size/page_table_map/
    wal_data they need. Those are supplied as callables rather than plain
    values so this can be constructed once, eagerly, in TableViewer.__init__
    without forcing an early sqlite3 connection or B-tree walk -- the
    callables are TableViewer's own already-lazy, already-cached
    _get_page_size()/_ensure_page_table_map()/_get_wal_data(), so nothing
    about their timing or caching changes versus calling locate_cell()/
    locate_offset() directly the way the hex-pane methods used to.
    """
    db_path: Path
    page_size_provider: Callable[[], int]
    page_table_map_provider: Callable[[], dict[int, str]]
    wal_data_provider: Callable[[], bytes | None]

    def default_file_kind(self) -> str:
        return "base"

    def read_file(self, file_kind: str) -> bytes | None:
        path = Path(str(self.db_path) + "-wal") if file_kind == "wal" else self.db_path
        try:
            return path.read_bytes()
        except OSError:
            return None

    def label_for(self, file_kind: str) -> str:
        return "-wal file" if file_kind == "wal" else "db file"

    def locate_cell(
        self, table_name: str, row_key: Any, col_idx: int | None
    ) -> CellLocation | None:
        page_size = self.page_size_provider()
        if page_size == 0:
            return None
        return locate_cell(
            self.db_path, table_name, int(row_key), col_idx, page_size,
            self.page_table_map_provider(), self.wal_data_provider(),
        )

    def locate_offset(
        self, table_name: str, file_kind: str, offset: int
    ) -> tuple[Any, int | None] | None:
        page_size = self.page_size_provider()
        if page_size == 0:
            return None
        return locate_offset(
            self.db_path, table_name, offset, file_kind, page_size,
            self.page_table_map_provider(), self.wal_data_provider(),
        )
