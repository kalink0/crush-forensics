# SPDX-License-Identifier: Apache-2.0
"""Regression coverage for crush/core/sqlite_wal.py's low-level table-leaf
page parsing (shared by the WAL Frames, Rollback Journal, Freeblocks,
Unallocated Space, and File Structure tabs, plus the standalone WAL/journal
parsers -- every consumer of parse_table_leaf_page())."""
from __future__ import annotations

import struct

from crush.core.sqlite_wal import PAGE_TYPE_TABLE_LEAF, parse_table_leaf_page


def _build_table_leaf_page(rowid_varint: bytes, page_size: int = 512) -> bytes:
    """A minimal, single-cell table-leaf page with the given raw rowid
    varint bytes and an empty (zero-length) record payload."""
    page = bytearray(page_size)
    page[0] = PAGE_TYPE_TABLE_LEAF
    struct.pack_into(">H", page, 3, 1)       # cell_count = 1
    struct.pack_into(">H", page, 8, 100)     # cell pointer -> offset 100
    page[100] = 0x00                          # payload_size varint = 0
    page[101:101 + len(rowid_varint)] = rowid_varint
    return bytes(page)


def test_parse_table_leaf_page_rowid_reinterpreted_as_signed_64bit() -> None:
    """A rowid whose full 9-byte varint sets the top bit is SQLite's signed
    64-bit encoding of a negative rowid -- the on-disk format defines the
    rowid as signed (see btreeParseCellPtr's (i64)(u64)x cast), so decoding
    it as a plain unsigned accumulator instead produces a value up to
    2**64-1, larger than any real 64-bit integer. That previously reached
    Qt's setData() as a value too big for a signed 64-bit qlonglong,
    raising "OverflowError: int too big to convert" / a libshiboken
    RuntimeWarning instead of showing the (perfectly valid, if unusual)
    negative rowid.
    """
    page = _build_table_leaf_page(bytes([0xFF] * 9))
    rows = parse_table_leaf_page(page, page_size=512, btree_offset=0)
    assert rows == [(-1, [])]
    rowid = rows[0][0]
    assert -(1 << 63) <= rowid < (1 << 63)


def test_parse_table_leaf_page_rowid_small_positive_unaffected() -> None:
    """An ordinary small rowid (single-byte varint, well below the sign
    bit) must decode exactly as before -- the signed reinterpretation must
    only ever change values that were already outside the valid signed
    64-bit range, never a normal rowid."""
    page = _build_table_leaf_page(bytes([42]))
    rows = parse_table_leaf_page(page, page_size=512, btree_offset=0)
    assert rows == [(42, [])]
