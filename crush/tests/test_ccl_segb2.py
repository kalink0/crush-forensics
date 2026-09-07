# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the vendored SEGB v2 reader (crush/third_party/ccl_segb/ccl_segb2.py).

Buffers are built by hand to the on-disk SEGB v2 layout (magic + entries_count +
creation timestamp + padding header, a data area of CRC-prefixed entries each
followed by 0-3 alignment padding bytes, and a trailer of fixed-size (end_offset,
state, timestamp) records at the end of the file, where end_offset marks the
*unpadded* end of an entry's content) rather than taken from a real device, per
this project's synthetic-fixtures-only rule for forensic tests.

These three cases were found to crash or silently corrupt data on real device
captures during a gap-check against iLEAPP's copy of the same module, which
had already picked up the fix -- traced back to the actual upstream source
(github.com/cclgroupltd/ccl-segb, commit e218d7e9e5266b833d345ba4be9cf1f7e2ea1b57,
2026-07-11) and re-vendored from there rather than hand-porting a diff.
"""
from __future__ import annotations

import struct
import zlib
from io import BytesIO

from crush.third_party.ccl_segb.ccl_segb2 import MAGIC, read_segb2_stream
from crush.third_party.ccl_segb.ccl_segb_common import EntryState


def _build_segb2(entries: list[tuple[bytes, int]]) -> bytes:
    """entries: list of (payload, state_raw), written to the data area in this
    order with real on-disk alignment padding between them; end_offset in the
    trailer is the *unpadded* boundary, matching the real format (the reader
    skips the padding itself via a post-read seek keyed off end_offset % 4)."""
    data_area = bytearray()
    trailer_entries: list[tuple[int, int]] = []
    for payload, state_raw in entries:
        crc = zlib.crc32(payload)
        data_area.extend(struct.pack("<Ii", crc, 0) + payload)
        end_offset = len(data_area)
        trailer_entries.append((end_offset, state_raw))
        remainder = end_offset % 4
        if remainder != 0:
            data_area.extend(b"\x00" * (4 - remainder))

    header = struct.pack("<4sid16s", MAGIC, len(trailer_entries), 0.0, b"\x00" * 16)
    trailer = b"".join(
        struct.pack("<iid", end_offset, state_raw, 0.0)
        for end_offset, state_raw in trailer_entries
    )
    return header + bytes(data_area) + trailer


def test_invalid_trailer_state_is_skipped_not_raised() -> None:
    """A trailer slot whose state doesn't map to a known EntryState (e.g. a
    zeroed/unused slot) must be silently skipped, not crash the whole parse."""
    segb_bytes = _build_segb2([
        (b"hello world!", int(EntryState.Written)),
        (b"junk", 99),  # invalid state -- not in EntryState at all
    ])

    entries = list(read_segb2_stream(BytesIO(segb_bytes)))

    assert len(entries) == 1
    assert entries[0].data == b"hello world!"
    assert entries[0].crc_passed


def test_duplicate_end_offset_reuses_previous_entry_data() -> None:
    """Two trailer entries sharing the same end_offset (e.g. a record written
    and later marked deleted) reference the same already-consumed data region
    -- the second must reuse the first's data rather than re-reading the
    stream (which would either read garbage from past the entry or crash on
    a too-short read)."""
    payload = b"shared-entry-data"
    crc = zlib.crc32(payload)
    entry_bytes = struct.pack("<Ii", crc, 0) + payload
    end_offset = len(entry_bytes)
    remainder = end_offset % 4
    data_area = entry_bytes + (b"\x00" * (4 - remainder) if remainder else b"")

    header = struct.pack("<4sid16s", MAGIC, 2, 0.0, b"\x00" * 16)
    trailer = struct.pack("<iid", end_offset, int(EntryState.Written), 0.0)
    trailer += struct.pack("<iid", end_offset, int(EntryState.Deleted), 0.0)
    segb_bytes = header + data_area + trailer

    entries = list(read_segb2_stream(BytesIO(segb_bytes)))

    assert len(entries) == 2
    assert entries[0].data == payload
    assert entries[1].data == payload
    assert entries[0].crc_passed
    assert entries[1].crc_passed
    states = {e.state for e in entries}
    assert states == {EntryState.Written, EntryState.Deleted}


def test_stale_trailer_entry_with_too_small_length_is_skipped() -> None:
    """A trailer entry whose computed length is smaller than the 8-byte entry
    header (a leftover/stale slot pointing into already-consumed data) must be
    skipped, not fed to struct.unpack() with too few bytes (crash) or read
    with a negative length (which reads to EOF and desyncs everything after
    it)."""
    payload = b"first-real-entry"
    entry_bytes = struct.pack("<Ii", zlib.crc32(payload), 0) + payload
    assert len(entry_bytes) == 24  # 8-byte header + 16-byte payload, already 4-aligned
    data_area = entry_bytes

    # entry1 ends at offset 24 (stream position 56 = HEADER_LENGTH 32 + 24); a
    # stale trailer slot at offset 27 computes to length 27 - 56 + 32 = 3,
    # below the 8-byte entry-header minimum.
    header = struct.pack("<4sid16s", MAGIC, 2, 0.0, b"\x00" * 16)
    trailer = struct.pack("<iid", 24, int(EntryState.Written), 0.0)
    trailer += struct.pack("<iid", 27, int(EntryState.Written), 0.0)
    segb_bytes = header + data_area + trailer

    entries = list(read_segb2_stream(BytesIO(segb_bytes)))

    assert len(entries) == 1
    assert entries[0].data == payload


def test_well_formed_file_still_parses_normally() -> None:
    """Regression guard: the fixes above must not change behavior for an
    ordinary file with no edge cases."""
    segb_bytes = _build_segb2([
        (b"first", int(EntryState.Written)),
        (b"second-entry", int(EntryState.Written)),
    ])

    entries = list(read_segb2_stream(BytesIO(segb_bytes)))

    assert [e.data for e in entries] == [b"first", b"second-entry"]
    assert all(e.crc_passed for e in entries)
