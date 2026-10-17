# SPDX-License-Identifier: Apache-2.0
"""Strings in a Realm file, each attributed to the structure its bytes sit in.

The string search itself is ``byte_strings.scan_strings`` (one rule for every
Strings view); the regions are attached the way ``sqlite_strings`` does it.

Where regions come from (all from the file format, no guessing):

- The file header (24 bytes) and, for a file in streaming form, the 16-byte
  footer that holds its top reference.
- Every array reachable from a top reference. The walk follows Realm Core's
  own rule for what a reference is (``Array::destroy_deep``): in an array
  with the has_refs flag, an element that is not 0 and even is the offset
  of another array; an odd one is a tagged integer. Both top references are
  walked; an array the inactive one reaches and the active one doesn't is
  the previous snapshot's.
- Freed blocks: the positions and sizes in the active snapshot's free list
  (what is free now). An array lying in one says so; bytes of a freed block
  no array covers are the freed block's. Bytes only the inactive
  snapshot's free list names (space the latest commit may have used since)
  are freed-block bytes too, and say whose list names them.
- Every other byte: not reached from either top reference.

Offsets are into the bytes Crush reads the Realm from -- for an encrypted
Realm, the decrypted file.
"""
from __future__ import annotations

import bisect
from typing import Any

from crush.core.byte_strings import DEFAULT_MIN_CHARS, scan_strings
from crush.core.issues import ParseIssue
from crush.core.sqlite_strings import FileStrings, Region, SqliteStringsResult, attach_regions
from crush.parsers.realm_parser import (
    REALM_HEADER_SIZE,
    array_elem_bytes,
    extract_free_list,
    parse_array_header,
    parse_realm_header,
    read_array_ref,
    resolve_streaming_form,
)

FILE_REALM = "realm"

KIND_HEADER = "Realm file header"
KIND_FOOTER = "streaming form footer"
KIND_ACTIVE = "array (active snapshot)"
KIND_INACTIVE = "array (inactive snapshot only)"
KIND_FREED = "freed block"
KIND_UNREACHED = "not reached from either top reference"
AREA_IN_FREED = "in a freed block"
AREA_INACTIVE_FREE_LIST = "in the inactive snapshot's free list only"

_FOOTER_SIZE = 16


def _walk_arrays(data: Any, top: int, size: int) -> tuple[dict[int, int], int]:
    """({offset: end} of every array reachable from *top*, refs that point at
    no array header). Iterative, each array once, so a loop in a damaged file
    ends."""
    arrays: dict[int, int] = {}
    unreadable = 0
    stack = [top]
    while stack:
        off = stack.pop()
        if off in arrays:
            continue
        hdr = parse_array_header(data, off)
        if hdr is None:
            unreadable += 1
            continue
        arrays[off] = min(off + int(hdr["Total array bytes"]), size)
        if not hdr["has_refs"]:
            continue
        eb = array_elem_bytes(hdr)
        if eb < 1:
            # Elements narrower than a byte hold at most 15: no array can
            # start there (a ref is 8-aligned and past the file header).
            continue
        for i in range(int(hdr["Element count (size)"])):
            value = read_array_ref(data, off + 8, i, eb)
            if value <= 0 or value & 1:
                continue  # null, or a tagged integer
            if value % 8 or value < REALM_HEADER_SIZE or value >= size:
                unreadable += 1
                continue
            stack.append(value)
    return arrays, unreadable


def _top_refs(data: Any, size: int, problems: list[ParseIssue]) -> tuple[int | None, int | None, bool]:
    """(active top ref, inactive top ref, streaming form) from the header."""
    top0 = int.from_bytes(data[0:8], "little")
    top1 = int.from_bytes(data[8:16], "little")
    active_idx = 1 if data[23] & 0x01 else 0
    streaming = resolve_streaming_form(data, top0, active_idx)
    if streaming is not None:
        if not streaming["footer_valid"]:
            problems.append(ParseIssue("realm_strings.footer_invalid"))
            return None, None, True
        return streaming["top_ref"], None, True
    active = top1 if active_idx else top0
    inactive = top0 if active_idx else top1

    def usable(ref: int) -> int | None:
        return ref if REALM_HEADER_SIZE <= ref < size else None

    return usable(active), usable(inactive), False


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def _overlaps(merged: list[tuple[int, int]], start: int, end: int) -> bool:
    i = bisect.bisect_right(merged, (start, float("inf"))) - 1
    for j in (i, i + 1):
        if 0 <= j < len(merged) and merged[j][0] < end and merged[j][1] > start:
            return True
    return False


def realm_regions(data: Any, problems: list[ParseIssue]) -> list[Region]:
    """The regions of a Realm file's bytes, not overlapping, in offset order."""
    size = len(data)
    if parse_realm_header(data) is None:
        problems.append(ParseIssue("realm_strings.header_not_detected"))
        return []
    primary: list[Region] = [Region(0, min(REALM_HEADER_SIZE, size), KIND_HEADER)]
    active, inactive, streaming = _top_refs(data, size, problems)
    if streaming and size >= REALM_HEADER_SIZE + _FOOTER_SIZE:
        primary.append(Region(size - _FOOTER_SIZE, size, KIND_FOOTER))

    unreadable = 0
    active_arrays: dict[int, int] = {}
    inactive_arrays: dict[int, int] = {}
    free_lists: dict[str, list[tuple[int, int]]] = {"active": [], "inactive": []}
    for top, target, which in (
        (active, active_arrays, "active"), (inactive, inactive_arrays, "inactive"),
    ):
        if top is None:
            continue
        arrays, bad = _walk_arrays(data, top, size)
        target.update(arrays)
        unreadable += bad
        free_lists[which] = _merge([
            (blk["offset"], blk["offset"] + blk["size"])
            for blk in extract_free_list(data, top, size)
        ])
    if unreadable:
        problems.append(ParseIssue("realm_strings.refs_not_followed", {"count": f"{unreadable:,}"}))
    # The active snapshot's free list is what is free now; the inactive
    # one's may name space the latest commit has used since.
    freed = free_lists["active"]

    for off, end in active_arrays.items():
        area = AREA_IN_FREED if _overlaps(freed, off, end) else ""
        primary.append(Region(off, end, KIND_ACTIVE, area))
    for off, end in inactive_arrays.items():
        if off not in active_arrays:
            area = AREA_IN_FREED if _overlaps(freed, off, end) else ""
            primary.append(Region(off, end, KIND_INACTIVE, area))

    # Placed in offset order; a damaged file's overlapping arrays keep the
    # bytes for the one starting first.
    placed: list[Region] = []
    pos = 0
    for region in sorted(primary, key=lambda r: (r.start, r.end)):
        start = max(region.start, pos)
        if start >= region.end:
            continue
        placed.append(Region(start, region.end, region.kind, region.area))
        pos = region.end

    # Freed-block bytes no array or header covers: the active free list's
    # first, then what only the inactive one names.
    placed = _fill_gaps(placed, freed, KIND_FREED, "")
    return _fill_gaps(placed, free_lists["inactive"], KIND_FREED, AREA_INACTIVE_FREE_LIST)


def _fill_gaps(
    placed: list[Region], intervals: list[tuple[int, int]], kind: str, area: str
) -> list[Region]:
    """*placed* (sorted, not overlapping) plus a *kind* region for every
    part of *intervals* (merged) that no placed region covers."""
    out = list(placed)
    ends = [r.end for r in placed]
    for f_start, f_end in intervals:
        cursor = f_start
        i = bisect.bisect_right(ends, f_start)  # first placed region ending past f_start
        while cursor < f_end:
            nxt = placed[i] if i < len(placed) else None
            if nxt is None or nxt.start >= f_end:
                out.append(Region(cursor, f_end, kind, area))
                break
            if nxt.start > cursor:
                out.append(Region(cursor, nxt.start, kind, area))
            cursor = max(cursor, nxt.end)
            i += 1
    return sorted(out, key=lambda r: r.start)


def scan_realm_strings(data: Any, min_chars: int = DEFAULT_MIN_CHARS) -> SqliteStringsResult:
    """Strings in a Realm file's bytes, each hit with the regions its bytes
    fall into. Why regions are missing (no header, a footer that doesn't
    resolve, references that lead nowhere) is in ``problems``."""
    result = SqliteStringsResult(min_chars=min_chars)
    fs = FileStrings(file_kind=FILE_REALM, size=len(data))
    fs.hits = scan_strings(data, min_chars)
    fs.regions = realm_regions(data, result.problems)
    attach_regions(fs, KIND_UNREACHED)
    result.files.append(fs)
    return result
