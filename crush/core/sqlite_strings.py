# SPDX-License-Identifier: Apache-2.0
"""Strings in a SQLite database and its -wal / -journal companions, each
attributed to the structure its bytes sit in.

The string search itself is ``byte_strings.scan_strings`` (one rule for every
Strings view). This module splits each file into regions -- database
header, b-tree page areas, freelist/overflow/pointer-map pages, WAL frame
headers, journal record fields -- and lists every region a string's bytes
fall into.

Where regions come from (all from the file format, no guessing):

- Base file: the b-trees are walked from page 1 and every root page listed in
  sqlite_master; overflow pages are the chains the cells on those pages
  point to; the freelist is the trunk chain from the header; pointer-map
  pages and the lock-byte page follow from the header and the page size.
  Only the base file's own bytes are used here, so a page whose newer copy
  sits in the -wal is attributed as the base file itself describes it.
- -wal: header, frame headers and frame pages. The frame whose page is the
  current one (the same frame the rest of Crush reads that page from) gets
  the role of the base file walked with the -wal applied.
- Any page copy without that context -- an older WAL frame, a journal
  record, a base page no walk reaches -- is classified by its own b-tree
  type byte only, and says so (``attribution == "type byte"``).

On b-tree pages the areas are the spec's: database header (page 1), page
header, cell pointer array, unallocated space (between pointer array and
cell content area), freeblocks, cell content area and the reserved bytes at
the page end.
"""
from __future__ import annotations

import bisect
import mmap
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crush.core.byte_strings import DEFAULT_MIN_CHARS, StringHit, scan_strings
from crush.core.issues import ParseIssue
from crush.core.sqlite_freelist import walk_freelist_pages
from crush.core.sqlite_journal import parse_rollback_journal
from crush.core.sqlite_wal import (
    PAGE_TYPE_INDEX_INTERIOR,
    PAGE_TYPE_INDEX_LEAF,
    PAGE_TYPE_TABLE_INTERIOR,
    PAGE_TYPE_TABLE_LEAF,
    build_wal_page_index,
    classify_wal_frames,
    parse_table_leaf_page,
)

FILE_BASE = "base"
FILE_WAL = "wal"
FILE_JOURNAL = "journal"

# Region kinds (what a page or file part is).
KIND_TABLE_LEAF = "table leaf"
KIND_TABLE_INTERIOR = "table interior"
KIND_INDEX_LEAF = "index leaf"
KIND_INDEX_INTERIOR = "index interior"
KIND_OVERFLOW = "overflow"
KIND_FREELIST_TRUNK = "freelist trunk"
KIND_FREELIST_LEAF = "freelist leaf"
KIND_POINTER_MAP = "pointer map"
KIND_LOCK_BYTE = "lock-byte page"
KIND_UNATTRIBUTED = "unattributed page"
KIND_PARTIAL_PAGE = "partial page"
KIND_WAL_HEADER = "WAL header"
KIND_WAL_FRAME_HEADER = "WAL frame header"
KIND_WAL_TAIL = "after last WAL frame"
KIND_JOURNAL_HEADER = "journal header"
KIND_JOURNAL_PAGE_NUMBER = "journal record page number"
KIND_JOURNAL_CHECKSUM = "journal record checksum"
KIND_JOURNAL_TAIL = "after last journal record"
KIND_NO_STRUCTURE = "no structure read"

# Areas within a b-tree page.
AREA_DB_HEADER = "database header"
AREA_PAGE_HEADER = "page header"
AREA_CELL_POINTERS = "cell pointer array"
AREA_UNALLOCATED = "unallocated"
AREA_FREEBLOCK = "freeblock"
AREA_CELL_CONTENT = "cell content area"
AREA_RESERVED = "reserved bytes"
AREA_INCONSISTENT = "page body (header values inconsistent)"

ATTRIBUTION_WALK = "walk"
ATTRIBUTION_TYPE_BYTE = "type byte"

_BTREE_KINDS = {
    PAGE_TYPE_TABLE_LEAF: KIND_TABLE_LEAF,
    PAGE_TYPE_TABLE_INTERIOR: KIND_TABLE_INTERIOR,
    PAGE_TYPE_INDEX_LEAF: KIND_INDEX_LEAF,
    PAGE_TYPE_INDEX_INTERIOR: KIND_INDEX_INTERIOR,
}
_INTERIOR_TYPES = (PAGE_TYPE_TABLE_INTERIOR, PAGE_TYPE_INDEX_INTERIOR)
_PENDING_BYTE = 0x40000000  # SQLite's lock-byte offset (1 GiB)
_WAL_HEADER_SIZE = 32
_WAL_FRAME_HEADER_SIZE = 24

FILE_LABELS = {FILE_BASE: "db file", FILE_WAL: "-wal file", FILE_JOURNAL: "-journal file"}


@dataclass(frozen=True, slots=True)
class Region:
    start: int
    end: int
    kind: str
    area: str = ""
    page: int | None = None          # database page number
    frame: int | None = None         # WAL frame number (1-based)
    frame_status: str = ""           # classify_wal_frames() status of that frame
    record: tuple[int, int] | None = None  # journal (segment, record)
    attribution: str = ""            # ATTRIBUTION_* for page kinds


@dataclass(slots=True)
class FileStrings:
    file_kind: str
    size: int
    hits: list[StringHit] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    # Per hit: indices into *regions* of every region the hit's bytes touch.
    hit_regions: list[tuple[int, ...]] = field(default_factory=list)


@dataclass(slots=True)
class SqliteStringsResult:
    min_chars: int
    files: list[FileStrings] = field(default_factory=list)
    problems: list[ParseIssue] = field(default_factory=list)


def _u16(data: Any, offset: int) -> int:
    return int(struct.unpack_from(">H", data, offset)[0])


def _u32(data: Any, offset: int) -> int:
    return int(struct.unpack_from(">I", data, offset)[0])


def _varint(data: Any, offset: int, limit: int) -> tuple[int, int] | None:
    """(value, length) of the varint at *offset*, None if it runs past *limit*."""
    value = 0
    for i in range(9):
        if offset + i >= limit:
            return None
        byte = data[offset + i]
        if i == 8:
            return (value << 8) | byte, 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, i + 1
    return None


def _page_size_from_header(header: Any) -> int:
    """Page size from database header offset 16 (1 means 65536); 0 if invalid."""
    if len(header) < 100 or header[:16] != b"SQLite format 3\x00":
        return 0
    raw = _u16(header, 16)
    size = 65536 if raw == 1 else raw
    if size < 512 or size > 65536 or size & (size - 1):
        return 0
    return size


# ---------------------------------------------------------------------------
# Page roles from the file format
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _Roles:
    btree: dict[int, int] = field(default_factory=dict)   # page -> b-tree type byte
    overflow: set[int] = field(default_factory=set)
    freelist: dict[int, str] = field(default_factory=dict)  # page -> "trunk"/"leaf"
    pointer_map: set[int] = field(default_factory=set)
    lock_byte: int | None = None


def _local_payload(payload: int, usable: int, page_type: int) -> int:
    """Bytes of a cell's payload stored on the page itself (file format 1.6)."""
    if page_type == PAGE_TYPE_TABLE_LEAF:
        max_local = usable - 35
    else:
        max_local = ((usable - 12) * 64) // 255 - 23
    if payload <= max_local:
        return payload
    min_local = ((usable - 12) * 32) // 255 - 23
    k = min_local + (payload - min_local) % (usable - 4)
    return k if k <= max_local else min_local


def _cell_overflow_head(
    page: bytes, cell: int, page_type: int, usable: int,
) -> tuple[int, int] | None:
    """(first overflow page, overflow byte count) of the cell at *cell*, or
    None if it has no overflow or the cell can't be read."""
    if page_type == PAGE_TYPE_TABLE_INTERIOR:
        return None
    pos = cell + (4 if page_type == PAGE_TYPE_INDEX_INTERIOR else 0)
    vi = _varint(page, pos, usable)
    if vi is None:
        return None
    payload, n = vi
    pos += n
    if page_type == PAGE_TYPE_TABLE_LEAF:
        vi = _varint(page, pos, usable)
        if vi is None:
            return None
        pos += vi[1]
    local = _local_payload(payload, usable, page_type)
    if local >= payload or pos + local + 4 > usable:
        return None
    return _u32(page, pos + local), payload - local


def _btree_header(page: bytes, btree_offset: int) -> tuple[int, int, int] | None:
    """(type, header size, cell count) of a b-tree page, None if not one."""
    if len(page) < btree_offset + 8:
        return None
    page_type = page[btree_offset]
    if page_type not in _BTREE_KINDS:
        return None
    header_size = 12 if page_type in _INTERIOR_TYPES else 8
    if len(page) < btree_offset + header_size:
        return None
    return page_type, header_size, _u16(page, btree_offset + 3)


def _cell_offsets(page: bytes, btree_offset: int, header_size: int, count: int, usable: int) -> list[int]:
    start = btree_offset + header_size
    if start + count * 2 > usable:
        return []
    offsets = []
    for i in range(count):
        cell = _u16(page, start + i * 2)
        if 0 < cell < usable:
            offsets.append(cell)
    return offsets


def _walk_roles(
    read_page: Callable[[int], bytes | None],
    page_count: int,
    page_size: int,
    usable: int,
    file_label: str,
    problems: list[ParseIssue],
) -> _Roles:
    """Every page the schema's b-trees, their overflow chains, the pointer
    map and the lock-byte page account for."""
    roles = _Roles()
    header = read_page(1)
    if header is None:
        return roles

    # Roots: sqlite_master (page 1) and every rootpage it lists.
    roots = [1]
    pending = [1]
    seen_master: set[int] = set()
    while pending:
        pn = pending.pop()
        if pn in seen_master or not 1 <= pn <= page_count:
            continue
        seen_master.add(pn)
        page = read_page(pn)
        if page is None:
            continue
        bo = 100 if pn == 1 else 0
        hdr = _btree_header(page, bo)
        if hdr is None:
            continue
        page_type, header_size, count = hdr
        if page_type == PAGE_TYPE_TABLE_INTERIOR:
            for cell in _cell_offsets(page, bo, header_size, count, usable):
                if cell + 4 <= usable:
                    pending.append(_u32(page, cell))
            pending.append(_u32(page, bo + 8))
        elif page_type == PAGE_TYPE_TABLE_LEAF:
            rows = parse_table_leaf_page(
                page, page_size=usable, overflow_reader=read_page, btree_offset=bo,
            ) or []
            for _rowid, values in rows:
                if len(values) >= 4 and isinstance(values[3], int) and values[3] > 0:
                    roots.append(values[3])

    # Walk every b-tree from its root.
    pending = list(dict.fromkeys(roots))
    while pending:
        pn = pending.pop()
        if pn in roles.btree:
            continue
        if not 1 <= pn <= page_count:
            problems.append(ParseIssue("strings.child_out_of_range", {
                "file": file_label, "page": pn, "pages": page_count,
            }))
            continue
        page = read_page(pn)
        if page is None:
            continue
        bo = 100 if pn == 1 else 0
        hdr = _btree_header(page, bo)
        if hdr is None:
            continue
        page_type, header_size, count = hdr
        roles.btree[pn] = page_type
        for cell in _cell_offsets(page, bo, header_size, count, usable):
            if page_type in _INTERIOR_TYPES and cell + 4 <= usable:
                pending.append(_u32(page, cell))
            head = _cell_overflow_head(page, cell, page_type, usable)
            if head is not None:
                _follow_overflow(head[0], head[1], pn, read_page, page_count, usable,
                                 roles, file_label, problems)
        if page_type in _INTERIOR_TYPES:
            pending.append(_u32(page, bo + 8))

    # Pointer-map pages (auto-vacuum databases) and the lock-byte page.
    if len(header) >= 56 and _u32(header, 52):
        per_map = usable // 5 + 1
        pending_page = _PENDING_BYTE // page_size + 1
        pn = 2
        while pn <= page_count:
            map_page = pn if pn != pending_page else pn + 1
            if map_page <= page_count:
                roles.pointer_map.add(map_page)
            pn += per_map
    if page_count * page_size > _PENDING_BYTE:
        roles.lock_byte = _PENDING_BYTE // page_size + 1
    return roles


def _follow_overflow(
    first: int,
    remaining: int,
    from_page: int,
    read_page: Callable[[int], bytes | None],
    page_count: int,
    usable: int,
    roles: _Roles,
    file_label: str,
    problems: list[ParseIssue],
) -> None:
    pn = first
    while remaining > 0:
        if not 1 <= pn <= page_count or pn in roles.overflow:
            problems.append(ParseIssue("strings.overflow_chain_stopped", {
                "file": file_label, "page": from_page, "target": pn,
            }))
            return
        page = read_page(pn)
        if page is None:
            return
        roles.overflow.add(pn)
        remaining -= usable - 4
        pn = _u32(page, 0)


# ---------------------------------------------------------------------------
# Regions
# ---------------------------------------------------------------------------

def _btree_areas(
    page: bytes, base: int, page_num: int, usable: int, kind_fields: dict[str, Any],
    file_label: str, problems: list[ParseIssue],
) -> list[Region]:
    """The spec's areas of one b-tree page whose bytes start at file offset *base*."""
    size = len(page)
    bo = 100 if page_num == 1 else 0
    regions: list[Region] = []

    def add(start: int, end: int, area: str) -> None:
        if end > start:
            regions.append(Region(base + start, base + end, area=area, page=page_num, **kind_fields))

    if bo:
        add(0, min(100, size), AREA_DB_HEADER)
    hdr = _btree_header(page, bo)
    if hdr is None:
        add(bo, size, AREA_INCONSISTENT)
        return regions
    _page_type, header_size, count = hdr
    ptr_end = bo + header_size + count * 2
    content = _u16(page, bo + 5) or 65536
    add(bo, bo + header_size, AREA_PAGE_HEADER)
    if not (ptr_end <= content <= usable):
        add(bo + header_size, usable, AREA_INCONSISTENT)
        add(usable, size, AREA_RESERVED)
        return regions
    add(bo + header_size, ptr_end, AREA_CELL_POINTERS)
    add(ptr_end, content, AREA_UNALLOCATED)

    # Cell content area with the freeblock chain carved out.
    freeblocks: list[tuple[int, int]] = []
    seen: set[int] = set()
    ptr = _u16(page, bo + 1)
    while ptr:
        if ptr in seen or ptr < content or ptr + 4 > usable:
            problems.append(ParseIssue("strings.freeblock_chain_stopped", {
                "file": file_label, "page": page_num, "offset": ptr,
            }))
            break
        seen.add(ptr)
        fb_size = _u16(page, ptr + 2)
        if fb_size < 4:
            problems.append(ParseIssue("strings.freeblock_chain_stopped", {
                "file": file_label, "page": page_num, "offset": ptr,
            }))
            break
        freeblocks.append((ptr, min(ptr + fb_size, usable)))
        ptr = _u16(page, ptr)
    pos = content
    for fb_start, fb_end in sorted(freeblocks):
        if fb_start < pos:
            # Overlaps the previous freeblock: the chain is inconsistent.
            problems.append(ParseIssue("strings.freeblock_chain_stopped", {
                "file": file_label, "page": page_num, "offset": fb_start,
            }))
            break
        add(pos, fb_start, AREA_CELL_CONTENT)
        add(fb_start, fb_end, AREA_FREEBLOCK)
        pos = fb_end
    add(pos, usable, AREA_CELL_CONTENT)
    add(usable, size, AREA_RESERVED)
    return regions


def _page_regions(
    page: bytes,
    base: int,
    page_num: int,
    usable: int,
    roles: _Roles | None,
    extra: dict[str, Any],
    file_label: str,
    problems: list[ParseIssue],
) -> list[Region]:
    """Regions of one page copy. *roles* (from a walk) is used when this
    copy is the one the walk read; otherwise only the type byte counts."""
    end = base + len(page)
    kind = ""
    if roles is not None:
        if page_num in roles.freelist:
            kind = KIND_FREELIST_TRUNK if roles.freelist[page_num] == "trunk" else KIND_FREELIST_LEAF
        elif page_num in roles.overflow:
            kind = KIND_OVERFLOW
        elif page_num in roles.pointer_map:
            kind = KIND_POINTER_MAP
        elif page_num == roles.lock_byte:
            kind = KIND_LOCK_BYTE
        elif page_num in roles.btree:
            fields = {"kind": _BTREE_KINDS[roles.btree[page_num]],
                      "attribution": ATTRIBUTION_WALK, **extra}
            return _btree_areas(page, base, page_num, usable, fields, file_label, problems)
        if kind:
            return [Region(base, end, kind, page=page_num, attribution=ATTRIBUTION_WALK, **extra)]
    bo = 100 if page_num == 1 else 0
    if len(page) > bo and page[bo] in _BTREE_KINDS:
        fields = {"kind": _BTREE_KINDS[page[bo]], "attribution": ATTRIBUTION_TYPE_BYTE, **extra}
        return _btree_areas(page, base, page_num, usable, fields, file_label, problems)
    return [Region(base, end, KIND_UNATTRIBUTED, page=page_num, **extra)]


def _base_regions(
    data: Any, size: int, page_size: int, usable: int, roles: _Roles,
) -> tuple[list[Region], list[ParseIssue]]:
    problems: list[ParseIssue] = []
    regions: list[Region] = []
    page_count = size // page_size
    for pn in range(1, page_count + 1):
        start = (pn - 1) * page_size
        regions.extend(_page_regions(
            bytes(data[start:start + page_size]), start, pn, usable, roles, {},
            FILE_LABELS[FILE_BASE], problems,
        ))
    if page_count * page_size < size:
        regions.append(Region(page_count * page_size, size, KIND_PARTIAL_PAGE, page=page_count + 1))
    return regions, problems


def _wal_regions(
    data: Any, size: int, db_usable_reserved: int, effective: _Roles | None,
    current_offsets: dict[int, int],
) -> tuple[list[Region], list[ParseIssue]]:
    problems: list[ParseIssue] = []
    classified = classify_wal_frames(bytes(data[:size])) if size >= _WAL_HEADER_SIZE else None
    if classified is None:
        problems.append(ParseIssue("strings.wal_no_header"))
        return [Region(0, size, KIND_NO_STRUCTURE)], problems
    page_size, frames = classified
    usable = page_size - db_usable_reserved
    regions = [Region(0, _WAL_HEADER_SIZE, KIND_WAL_HEADER)]
    end = _WAL_HEADER_SIZE
    for f in frames:
        off = f["offset"]
        extra = {"frame": f["frame"], "frame_status": f["status"]}
        regions.append(Region(off, off + _WAL_FRAME_HEADER_SIZE, KIND_WAL_FRAME_HEADER,
                              page=f["page"], **extra))
        page_off = off + _WAL_FRAME_HEADER_SIZE
        page = bytes(data[page_off:page_off + page_size])
        roles = effective if current_offsets.get(f["page"]) == page_off else None
        regions.extend(_page_regions(page, page_off, f["page"], usable, roles, extra,
                                     FILE_LABELS[FILE_WAL], problems))
        end = page_off + page_size
    if end < size:
        regions.append(Region(end, size, KIND_WAL_TAIL))
    return regions, problems


def _journal_regions(data: Any, size: int, reserved: int) -> tuple[list[Region], list[ParseIssue]]:
    problems: list[ParseIssue] = []
    result = parse_rollback_journal(bytes(data[:size]))
    if not result.segments:
        problems.append(ParseIssue("strings.journal_no_header", {
            "reason": result.error or "",
        }))
        return [Region(0, size, KIND_NO_STRUCTURE)], problems
    regions: list[Region] = []
    for seg in result.segments:
        regions.append(Region(seg.header.offset, seg.header.records_start, KIND_JOURNAL_HEADER))
        for rec in seg.records:
            extra: dict[str, Any] = {"record": (seg.index, rec.record_index)}
            regions.append(Region(rec.page_offset - 4, rec.page_offset, KIND_JOURNAL_PAGE_NUMBER,
                                  page=rec.page_num, **extra))
            regions.extend(_page_regions(rec.data, rec.page_offset, rec.page_num,
                                         rec.page_size - reserved, None, extra,
                                         FILE_LABELS[FILE_JOURNAL], problems))
            regions.append(Region(rec.checksum_offset, rec.checksum_offset + 4,
                                  KIND_JOURNAL_CHECKSUM, page=rec.page_num, **extra))
    if result.trailing_offset < size:
        regions.append(Region(result.trailing_offset, size, KIND_JOURNAL_TAIL))
    return regions, problems


def attach_regions(fs: FileStrings, gap_kind: str = KIND_NO_STRUCTURE) -> None:
    """Fill fs.hit_regions. Regions don't overlap; bytes no region covers
    (e.g. between two journal segments) become *gap_kind* regions, so every
    byte of a hit is attributed to something. Shared by every Strings view
    that attributes regions (also realm_strings)."""
    regions = sorted(fs.regions, key=lambda r: r.start)
    filled: list[Region] = []
    pos = 0
    for region in regions:
        if region.start > pos:
            filled.append(Region(pos, region.start, gap_kind))
        filled.append(region)
        pos = max(pos, region.end)
    if pos < fs.size:
        filled.append(Region(pos, fs.size, gap_kind))
    fs.regions = filled
    starts = [r.start for r in fs.regions]
    out: list[tuple[int, ...]] = []
    for hit in fs.hits:
        i = max(bisect.bisect_right(starts, hit.offset) - 1, 0)
        touched = []
        while i < len(fs.regions) and fs.regions[i].start < hit.end:
            if fs.regions[i].end > hit.offset:
                touched.append(i)
            i += 1
        out.append(tuple(touched))
    fs.hit_regions = out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _open_map(path: Path, label: str, problems: list[ParseIssue]) -> tuple[Any, int] | None:
    """(read-only mapping, size) of *path*; None (reason in *problems*) if
    it can't be read. An empty file maps to (b"", 0)."""
    try:
        with open(path, "rb") as fh:
            size = path.stat().st_size
            if size == 0:
                problems.append(ParseIssue("strings.file_empty", {"file": label}))
                return b"", 0
            return mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ), size
    except (OSError, ValueError) as exc:
        problems.append(ParseIssue("strings.file_unreadable", {"file": label}, detail=str(exc)))
        return None


def scan_sqlite_strings(
    db_path: Path,
    wal_path: Path | None = None,
    journal_path: Path | None = None,
    min_chars: int = DEFAULT_MIN_CHARS,
) -> SqliteStringsResult:
    """Strings in *db_path* and, when given, its -wal and -journal file,
    each hit with the regions its bytes fall into. Files are only read.
    Why something is missing (a file unreadable, no page size, a chain that
    couldn't be followed) is in ``problems``."""
    result = SqliteStringsResult(min_chars=min_chars)
    problems = result.problems

    base_map = _open_map(db_path, FILE_LABELS[FILE_BASE], problems)
    wal_map = _open_map(wal_path, FILE_LABELS[FILE_WAL], problems) if wal_path else None
    journal_map = (
        _open_map(journal_path, FILE_LABELS[FILE_JOURNAL], problems) if journal_path else None
    )
    try:
        page_size = usable = reserved = 0
        base_data: Any = b""
        base_size = 0
        if base_map is not None:
            base_data, base_size = base_map
            page_size = _page_size_from_header(base_data[:100])
            if page_size:
                reserved = base_data[20]
                usable = page_size - reserved
            elif base_size:
                problems.append(ParseIssue("strings.no_page_size"))

        page_count = base_size // page_size if page_size else 0

        def read_base(pn: int) -> bytes | None:
            if not 1 <= pn <= page_count:
                return None
            return bytes(base_data[(pn - 1) * page_size:pn * page_size])

        # --- base file -----------------------------------------------------
        if base_map is not None:
            fs = FileStrings(FILE_BASE, base_size, scan_strings(base_data, min_chars))
            if page_size:
                walk_problems: list[ParseIssue] = []
                roles = _walk_roles(read_base, page_count, page_size, usable,
                                    FILE_LABELS[FILE_BASE], walk_problems)
                roles.freelist = _freelist(db_path, page_size, None, walk_problems)
                fs.regions, region_problems = _base_regions(base_data, base_size, page_size,
                                                            usable, roles)
                problems.extend(walk_problems + region_problems)
            elif base_size:
                fs.regions = [Region(0, base_size, KIND_NO_STRUCTURE)]
            attach_regions(fs)
            result.files.append(fs)

        # --- -wal ----------------------------------------------------------
        if wal_map is not None:
            wal_data, wal_size = wal_map
            fs = FileStrings(FILE_WAL, wal_size, scan_strings(wal_data, min_chars))
            if wal_size:
                effective: _Roles | None = None
                current_offsets: dict[int, int] = {}
                if page_size:
                    wal_bytes = bytes(wal_data[:wal_size])
                    index = build_wal_page_index(wal_bytes, page_size)
                    current_offsets = {pn: off for pn, (off, _b) in index.items()}
                    eff_count = max(page_count, max(index, default=0))

                    def read_effective(pn: int) -> bytes | None:
                        if pn in index:
                            return index[pn][1]
                        return read_base(pn)

                    eff_problems: list[ParseIssue] = []
                    effective = _walk_roles(read_effective, eff_count, page_size, usable,
                                            FILE_LABELS[FILE_WAL], eff_problems)
                    effective.freelist = _freelist(
                        db_path, page_size, {pn: b for pn, (_o, b) in index.items()}, eff_problems,
                    )
                    problems.extend(eff_problems)
                fs.regions, wal_problems = _wal_regions(wal_data, wal_size, reserved,
                                                        effective, current_offsets)
                problems.extend(wal_problems)
            attach_regions(fs)
            result.files.append(fs)

        # --- -journal ------------------------------------------------------
        if journal_map is not None:
            journal_data, journal_size = journal_map
            fs = FileStrings(FILE_JOURNAL, journal_size, scan_strings(journal_data, min_chars))
            if journal_size:
                fs.regions, journal_problems = _journal_regions(journal_data, journal_size, reserved)
                problems.extend(journal_problems)
            attach_regions(fs)
            result.files.append(fs)
    finally:
        for opened in (base_map, wal_map, journal_map):
            if opened is not None and isinstance(opened[0], mmap.mmap):
                opened[0].close()
    return result


def _freelist(
    db_path: Path, page_size: int, wal_pages: dict[int, bytes] | None, problems: list[ParseIssue],
) -> dict[int, str]:
    found: list[ParseIssue] = []
    entries = walk_freelist_pages(db_path, page_size, wal_pages, found)
    # "No freelist" is a fact about the file, not a reason anything is missing.
    problems.extend(p for p in found if p.code != "freelist.none")
    return {int(e["page"]): str(e["kind"]) for e in entries}
