# SPDX-License-Identifier: Apache-2.0
"""Tests for built-in parsers."""
from __future__ import annotations

import plistlib
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


from crush.core.vfs import DirectoryVFS
from crush.parsers.sqlite_parser import SQLiteParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.abx_parser import AbxParser
from crush.parsers.abx_decoder import decode_abx
from crush.parsers.hex_fallback import HexFallbackParser
from crush.parsers.image_parser import ImageParser
from crush.parsers.realm_parser import RealmParser
from crush.core.encodings import detect_encoding as _detect_encoding


def _make_sqlite(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)")
    conn.execute("INSERT INTO messages (text) VALUES ('hello')")
    conn.commit()
    conn.close()


def test_sqlite_parser_can_parse(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    _make_sqlite(db_path)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.db")

    parser = SQLiteParser()
    assert parser.can_parse(node.path, vfs.peek(node))


def test_sqlite_parser_parse(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    _make_sqlite(db_path)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.db")

    parser = SQLiteParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "table"
    assert "messages" in result.data
    assert result.data["messages"]["columns"][1] == "text"
    assert result.data["messages"]["rows"][0][1] == "hello"


def test_plist_parser_binary(tmp_path: Path) -> None:
    data = {"key": "value", "number": 42}
    plist_path = tmp_path / "test.plist"
    plist_path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_BINARY))

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.plist")

    parser = PlistParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "tree"
    assert result.data["key"] == "value"
    assert result.metadata["Format"] == "binary"


def test_hex_fallback_always_matches() -> None:
    parser = HexFallbackParser()
    assert parser.can_parse("anything.xyz", b"\x00\x01\x02\x03")


def test_hex_fallback_parse(tmp_path: Path) -> None:
    raw = bytes(range(64))
    (tmp_path / "blob.bin").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "blob.bin")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)
    assert result.viewer_type == "hex"
    assert result.data == raw


def _make_realm_header(
    top_ref0: int = 212880,
    top_ref1: int = 211736,
    fmt0: int = 24,
    fmt1: int = 24,
    reserved: int = 0,
    flag: int = 0,
) -> bytes:
    return (
        top_ref0.to_bytes(8, "little") +
        top_ref1.to_bytes(8, "little") +
        b"T-DB" +
        bytes([fmt0, fmt1, reserved, flag])
    )


def test_realm_parser_header(tmp_path: Path) -> None:
    realm_path = tmp_path / "default.realm"
    realm_path.write_bytes(_make_realm_header() + b"\x00" * 512)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "default.realm")

    parser = RealmParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "realm"
    assert "header" in result.data
    header = result.data["header"]
    assert header["Mnemonic"] == "T-DB"
    assert header["File format (top ref 0)"] == 24

    # New data structure: top_refs and schema
    assert "top_refs" in result.data
    assert "schema" in result.data
    # top_ref entries exist even when array headers are not reachable (synthetic file)
    top_refs = result.data["top_refs"]
    assert "top_ref_0" in top_refs
    assert "top_ref_1" in top_refs
    assert "active_index" in top_refs


def _make_realm_array_header(
    flags: int = 0x0E,
    size: int = 0,
) -> bytes:
    """Build an 8-byte Realm array header for tests."""
    return b"\x41\x41\x41\x41" + bytes([flags]) + size.to_bytes(3, "big")


def test_realm_array_header_decoding(tmp_path: Path) -> None:
    """_parse_array_header correctly decodes flags and computes payload size."""
    from crush.parsers.realm_parser import _parse_array_header

    # Example from PDF: flags=0x0E, size=5 → width_scheme=1, width=32 bytes → 160 bytes payload
    raw = _make_realm_array_header(flags=0x0E, size=5)
    hdr = _parse_array_header(raw, 0)
    assert hdr is not None
    assert hdr["is_inner_bptree_node"] is False
    assert hdr["has_refs"] is False
    assert hdr["width_scheme"] == 1
    assert hdr["width"] == 32
    assert hdr["Element count (size)"] == 5
    assert hdr["Payload bytes (raw)"] == 160   # 32 * 5
    assert hdr["Total array bytes"] == 168      # 8 header + 160

    # flags=0x46: has_refs=True, scheme=0, width=32 bits (4 bytes/elem), size=11 → 44 raw → 48 aligned
    raw2 = _make_realm_array_header(flags=0x46, size=11)
    hdr2 = _parse_array_header(raw2, 0)
    assert hdr2 is not None
    assert hdr2["has_refs"] is True
    assert hdr2["width_scheme"] == 0
    assert hdr2["width"] == 32
    assert hdr2["Element count (size)"] == 11
    assert hdr2["Payload bytes (raw)"] == 44    # ceil(32*11/8)
    assert hdr2["Payload bytes (aligned)"] == 48
    assert hdr2["Total array bytes"] == 56


def test_realm_schema_extraction(tmp_path: Path) -> None:
    """Schema extraction follows the B+ tree path and returns class names."""
    # Build a minimal realm file: file header + schema array + root ref array
    # Offsets (all computed to avoid overlap):
    #   0x00 (0):  24-byte file header  (top_ref1 → ROOT_OFFSET, flags=0x01)
    #   0x18 (24): schema data array    (flags=0x0E, size=2, width=32 bytes → 72 total)
    #   0x60 (96): root ref array       (flags=0x46, size=1, 4-byte ref → SCHEMA_OFFSET)

    SCHEMA_OFFSET = 24   # right after file header
    # schema array = 8-byte header + 2 × 32-byte entries = 72 bytes
    ROOT_OFFSET = SCHEMA_OFFSET + 72  # = 96

    # Two 32-byte schema entries
    entry0 = b"metadata\x00" + b"\x00" * 23
    entry1 = b"class_Task\x00" + b"\x00" * 21
    schema_hdr = b"\x41\x41\x41\x41\x0E" + (2).to_bytes(3, "big")  # flags=0x0E, size=2
    schema_array = schema_hdr + entry0 + entry1  # 8 + 32 + 32 = 72 bytes

    # Root ref array: flags=0x46, size=1, width_scheme=0, width=32bits → 4-byte LE ref
    # payload_bytes = ceil(32*1/8)=4, aligned=8
    root_hdr_bytes = b"\x41\x41\x41\x41\x46" + (1).to_bytes(3, "big")
    ref_payload = SCHEMA_OFFSET.to_bytes(4, "little") + b"\x00" * 4  # padded to 8
    root_array = root_hdr_bytes + ref_payload  # 16 bytes

    # File header: top_ref1=ROOT_OFFSET, flags=0x01 (top_ref1 active)
    file_hdr = (
        (0).to_bytes(8, "little")               # top_ref0 = 0 (unused)
        + ROOT_OFFSET.to_bytes(8, "little")     # top_ref1 = 96
        + b"T-DB"                               # mnemonic
        + bytes([24, 24, 0, 0x01])              # fmt0, fmt1, reserved, flags
    )

    realm_bytes = file_hdr + schema_array + root_array

    realm_path = tmp_path / "test.realm"
    realm_path.write_bytes(realm_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.realm")

    parser = RealmParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "realm"
    schema = result.data["schema"]
    assert "metadata" in schema
    assert "class_Task" in schema
    assert result.metadata.get("Tables found") == "2"


def test_extract_table_data_flags_estimated_row_count_on_corrupt_key_slot() -> None:
    """When a leaf's key slot (child[0]) is unreadable (e.g. corruption),
    row_count falls back to _derive_row_count and the table is flagged
    row_count_estimated=True so the UI never shows a guessed count as if it
    were authoritative — same failure shape as the original RealmDB bug
    (silently-wrong row count), just surfaced instead of hidden."""
    from crush.parsers.realm_parser import _extract_table_data

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- leaf: key slot (child[0]) is corrupt (ref=0), column has 2 rows --
    col1_ref = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (10, 20))
    ))
    cluster_root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + col1_ref.to_bytes(4, "little")
    ))

    names_ref = emit(_array_hdr(0x0C, 1) + _pad8(b"n\x00\x00\x00\x00\x00\x00\x00"))
    colkey = 0
    colkeys_ref = emit(_array_hdr(0x0C, 1) + _pad8(colkey.to_bytes(8, "little", signed=True)))
    spec_ref = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little")
        + names_ref.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + colkeys_ref.to_bytes(4, "little")
    ))

    table_ref = emit(_array_hdr(0x46, 3) + _pad8(
        spec_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") + cluster_root_ref.to_bytes(4, "little")
    ))
    table_refs_ref = emit(_array_hdr(0x46, 1) + _pad8(table_ref.to_bytes(4, "little")))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    tables = _extract_table_data(data, root_ref, ["class_Foo"], len(data))

    assert len(tables) == 1
    t = tables[0]
    assert t["row_count_estimated"] is True
    assert t["row_count"] == 2  # recovered via the column-element-count vote
    assert t["columns"][0] == [10, 20]


def _array_hdr(flags: int, size: int) -> bytes:
    return bytes([0x41, 0x41, 0x41, 0x41, flags]) + size.to_bytes(3, "big")


def _pad8(b: bytes) -> bytes:
    rem = len(b) % 8
    return b if rem == 0 else b + b"\x00" * (8 - rem)


def test_walk_cluster_leaves_resolves_inner_node() -> None:
    """_walk_cluster_leaves recurses a ClusterNodeInner's fixed layout
    ([key_ref_or_0, tagged_depth, tagged_tree_size, child_refs...]) and
    skips the 3 bookkeeping slots, matching cluster_tree.cpp's
    ClusterNodeInner (s_key_ref_index=0, s_sub_tree_depth_index=1,
    s_sub_tree_size=2, s_first_node_index=3).
    """
    from crush.parsers.realm_parser import _walk_cluster_leaves

    def leaf_bytes() -> bytes:
        return _array_hdr(0x46, 1) + _pad8((0).to_bytes(4, "little"))

    # A ref of 0 conventionally means "null" in Realm, so no real array ever
    # sits at file offset 0 (the 24-byte file header always precedes it) —
    # an 8-byte prefix here keeps every offset below realistic and nonzero.
    PREFIX = b"\x00" * 8
    ROOT_OFFSET = len(PREFIX)
    leaf_a = leaf_bytes()
    leaf_b = leaf_bytes()
    LEAF_A_OFFSET = ROOT_OFFSET + 32
    LEAF_B_OFFSET = ROOT_OFFSET + 48

    inner_payload = _pad8(
        (0).to_bytes(4, "little")                    # child[0]: key ref = 0 (compact form)
        + (((1 << 1) | 1)).to_bytes(4, "little")      # child[1]: tagged sub_tree_depth = 1
        + (((2 << 1) | 1)).to_bytes(4, "little")      # child[2]: tagged sub_tree_size = 2
        + LEAF_A_OFFSET.to_bytes(4, "little")         # child[3]: leaf A
        + LEAF_B_OFFSET.to_bytes(4, "little")         # child[4]: leaf B
    )
    inner = _array_hdr(0xC6, 5) + inner_payload  # is_inner=1, has_refs=1

    raw = PREFIX + inner + leaf_a + leaf_b
    leaves = _walk_cluster_leaves(raw, ROOT_OFFSET, len(raw))
    assert [ref for ref, _off in leaves] == [LEAF_A_OFFSET, LEAF_B_OFFSET]
    # compact form: child_idx << (sub_tree_depth * 8) = 0<<8=0, 1<<8=256
    assert [off for _ref, off in leaves] == [0, 256]


def test_read_array_int_null_reads_sentinel_from_slot_zero() -> None:
    """_read_array_int_null: slot[0] holds the file's own null sentinel
    (not an assumed INT_MAX-style constant); value == sentinel -> NULL
    (array_integer.hpp: null_value() reads slot 0 directly)."""
    from crush.parsers.realm_parser import _read_array_int_null

    sentinel = 999
    raw = _array_hdr(0x0C, 4) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (sentinel, 10, sentinel, 30)
    )
    assert _read_array_int_null(raw, 0, len(raw)) == [10, None, 30]


def test_read_array_bool_null_is_exactly_three() -> None:
    """_read_array_bool: nullable Bool is NULL iff the stored value is
    exactly 3, not "any value >= 2" (array_bool.hpp: null_value = 3)."""
    from crush.parsers.realm_parser import _read_array_bool

    # 4 values, 2 bits each: 0, 1, 3, 1 -> byte = 0b01_11_01_00 = 0x74
    raw = _array_hdr(0x02, 4) + _pad8(bytes([0b01110100]))
    assert _read_array_bool(raw, 0, len(raw), nullable=True) == [False, True, None, True]
    assert _read_array_bool(raw, 0, len(raw), nullable=False) == [False, True, True, True]


def test_read_array_string_short_inline() -> None:
    """ArrayStringShort: pad byte == width -> NULL; else content length is
    (width-1)-pad (array_string_short.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    entry0 = b"hello\x00\x00" + bytes([2])   # length = 7-2 = 5
    entry1 = b"\x00" * 7 + bytes([8])        # pad == width(8) -> NULL
    raw = _array_hdr(0x0C, 2) + entry0 + entry1
    result = _read_array_string_or_binary(raw, 0, len(raw), is_string=True, nullable=True)
    assert result == ["hello", None]


def test_read_array_small_blobs_cumulative_end_offsets() -> None:
    """ArraySmallBlobs: offsets[i] is the cumulative END position (begin =
    offsets[i-1] or 0), not a start-offset scanned for a NUL terminator;
    String rows carry a trailing '\\0' in blob that is stripped
    (array_blobs_small.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    OFFS_OFF, BLOB_OFF, NULL_OFF = 0, 16, 32
    # row0="ab" (stored "ab\0", end=3), row1="" (stored "\0", end=4), row2=NULL
    offs_array = _array_hdr(0x05, 3) + _pad8(
        (3).to_bytes(2, "little") + (4).to_bytes(2, "little") + (4).to_bytes(2, "little")
    )
    blob_array = _array_hdr(0x10, 4) + _pad8(b"ab\x00\x00")
    null_array = _array_hdr(0x01, 3) + _pad8(bytes([0b100]))
    COL_OFF = 48
    col_array = _array_hdr(0x46, 3) + _pad8(
        OFFS_OFF.to_bytes(4, "little") + BLOB_OFF.to_bytes(4, "little") + NULL_OFF.to_bytes(4, "little")
    )
    raw = offs_array + blob_array + null_array + col_array
    result = _read_array_string_or_binary(raw, COL_OFF, len(raw), is_string=True, nullable=True)
    assert result == ["ab", "", None]


def test_read_array_big_blobs_per_row_ref() -> None:
    """ArrayBigBlobs: each element is a ref to a standalone blob elsewhere
    in the file, or 0 for NULL (array_blobs_big.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    # A ref of 0 means "null" in Realm, so the target blob must not sit at
    # file offset 0 (a small prefix keeps it, and every other offset, nonzero).
    PREFIX = b"\x00" * 8
    BLOB_OFF = len(PREFIX)
    blob_array = _array_hdr(0x10, 3) + _pad8(b"XYZ")
    OUTER_OFF = BLOB_OFF + 16
    outer_array = _array_hdr(0x66, 2) + _pad8(  # has_refs=1, context_flag=1
        BLOB_OFF.to_bytes(4, "little") + (0).to_bytes(4, "little")
    )
    raw = PREFIX + blob_array + outer_array
    result = _read_array_string_or_binary(raw, OUTER_OFF, len(raw), is_string=False, nullable=True)
    assert result == [b"XYZ", None]


def test_decode_timestamp_negative_seconds_before_1970() -> None:
    """A negative Timestamp (a valid pre-1970 date, not a guessed unit) must
    still decode to a date instead of silently falling back to the raw int —
    array_timestamp.hpp's seconds field is signed and pre-1970 dates are
    ordinary data, not an edge case to special-case away."""
    from crush.parsers.realm_parser import _decode_timestamp

    # -100_000 seconds before epoch = 1969-12-30 20:13:20 UTC.
    result = _decode_timestamp(-100_000)
    assert result == "1969-12-30 20:13:20 UTC"


def test_decode_timestamp_does_not_guess_unit_from_magnitude() -> None:
    """A value that would look like plausible milliseconds under the old
    magnitude-based guess must still be decoded as whole seconds, since
    that's the only unit array_timestamp.hpp ever stores."""
    from crush.parsers.realm_parser import _decode_timestamp

    # Old code's magnitude guess would have treated this as milliseconds
    # (dividing by 1000, landing on 1971); it's actually whole seconds.
    # Expected value computed via epoch + timedelta, not fromtimestamp():
    # fromtimestamp() delegates to the platform C library, and this value
    # is beyond what Windows' CRT accepts (though within glibc's range).
    result = _decode_timestamp(50_000_000_000)
    expected = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=50_000_000_000))
    assert result == expected.strftime("%Y-%m-%d %H:%M:%S UTC")
    assert "1971" not in result


def test_read_array_timestamp_nested_int_null() -> None:
    """ArrayTimestamp: [seconds_ref, nanos_ref], seconds is itself an
    ArrayIntNull (array_timestamp.cpp)."""
    from crush.parsers.realm_parser import _decode_timestamp, _read_array_timestamp

    SECS_OFF = 0
    sentinel = 777
    secs_array = _array_hdr(0x0C, 3) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (sentinel, 1_700_000_000, sentinel)
    )
    NANOS_OFF = 32
    nanos_array = _array_hdr(0x0C, 2) + b"".join(v.to_bytes(8, "little", signed=True) for v in (0, 0))
    OUTER_OFF = 56
    outer_array = _array_hdr(0x46, 2) + _pad8(
        SECS_OFF.to_bytes(4, "little") + NANOS_OFF.to_bytes(4, "little")
    )
    raw = secs_array + nanos_array + outer_array
    result = _read_array_timestamp(raw, OUTER_OFF, len(raw))
    assert result == [_decode_timestamp(1_700_000_000), None]


def test_read_array_fixed_bytes_block_bitvector() -> None:
    """ArrayFixedBytes[Null]: elements packed in blocks of 8, with 1
    null-bitvector byte prefixing each block (array_fixed_bytes.hpp)."""
    from crush.parsers.realm_parser import _read_array_fixed_bytes

    bitvec = bytes([0b00000010])  # element index 1 is NULL
    elem0 = b"\xAA\xBB\xCC\xDD"
    elem1 = b"\x00\x00\x00\x00"
    raw = _array_hdr(0x10, 9) + bitvec + elem0 + elem1  # total_bytes=9 (scheme=2, raw bytes)
    result = _read_array_fixed_bytes(raw, 0, len(raw), elem_size=4)
    assert result == [b"\xAA\xBB\xCC\xDD", None]


def test_read_array_link_stores_target_plus_one() -> None:
    """ArrayKey (single Link column): stored value = target ObjKey + 1, so
    that 0 represents NULL (array_key.hpp: ArrayKeyBase<1>)."""
    from crush.parsers.realm_parser import _read_array_link

    raw = _array_hdr(0x0C, 3) + b"".join(v.to_bytes(8, "little", signed=True) for v in (0, 6, 1))
    assert _read_array_link(raw, 0, len(raw)) == [None, 5, 0]


def test_extract_table_data_multi_leaf_concatenates_rows() -> None:
    """End-to-end: a table whose ClusterTree spans 2 leaves has its column
    values concatenated across leaves in key order, and row_count is the
    true sum — the scenario that was silently truncated before the
    ClusterNodeInner traversal fix."""
    from crush.parsers.realm_parser import _extract_table_data

    # A ref of 0 means "null" in Realm, so no real array may sit at file
    # offset 0 — an 8-byte prefix keeps every emitted offset nonzero.
    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- leaf 1: rows [10, 20] (compact keys) --
    col1_ref = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (10, 20))
    ))
    leaf1_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((2 << 1) | 1)).to_bytes(4, "little") + col1_ref.to_bytes(4, "little")
    ))

    # -- leaf 2: rows [30, 40, 50] (compact keys) --
    col2_ref = emit(_array_hdr(0x0C, 3) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (30, 40, 50))
    ))
    leaf2_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((3 << 1) | 1)).to_bytes(4, "little") + col2_ref.to_bytes(4, "little")
    ))

    # -- ClusterNodeInner: [key_ref=0, tagged_depth=1, tagged_tree_size=5, leaf1, leaf2] --
    cluster_root_ref = emit(_array_hdr(0xC6, 5) + _pad8(
        (0).to_bytes(4, "little")
        + (((1 << 1) | 1)).to_bytes(4, "little")
        + (((5 << 1) | 1)).to_bytes(4, "little")
        + leaf1_ref.to_bytes(4, "little")
        + leaf2_ref.to_bytes(4, "little")
    ))

    # -- spec: one column "n", Int, non-nullable --
    names_ref = emit(_array_hdr(0x0C, 1) + _pad8(b"n\x00\x00\x00\x00\x00\x00\x00"))
    colkey = 0  # index=0, type=Int(0), attrs=0
    colkeys_ref = emit(_array_hdr(0x0C, 1) + _pad8(colkey.to_bytes(8, "little", signed=True)))
    spec_ref = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little")            # child[0] types: unused by dispatch (colkey carries type)
        + names_ref.to_bytes(4, "little")    # child[1] names
        + (0).to_bytes(4, "little")          # child[2] attrs: unused (colkey carries attrs)
        + (0).to_bytes(4, "little")          # child[3] vacant
        + (0).to_bytes(4, "little")          # child[4] enum keys: unused
        + colkeys_ref.to_bytes(4, "little")  # child[5] colkeys
    ))

    # -- table node: [spec_ref, 0(unused), cluster_root_ref] --
    table_ref = emit(_array_hdr(0x46, 3) + _pad8(
        spec_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") + cluster_root_ref.to_bytes(4, "little")
    ))

    # -- table refs + root --
    table_refs_ref = emit(_array_hdr(0x46, 1) + _pad8(table_ref.to_bytes(4, "little")))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    tables = _extract_table_data(data, root_ref, ["class_Foo"], len(data))

    assert len(tables) == 1
    t = tables[0]
    assert t["name"] == "class_Foo"
    assert t["row_count"] == 5
    assert t["column_names"] == ["n"]
    assert t["column_types"] == ["int"]
    assert t["columns"][0] == [10, 20, 30, 40, 50]


def test_walk_bplustree_leaves_compact_form() -> None:
    """_walk_bplustree_leaves: BPlusTreeInner has a *different* layout from
    ClusterNodeInner — [elem0, child_1..child_N, tagged_tree_size(last)],
    only 2 bookkeeping slots (not 3), and elem0 uses the RefOrTagged tag
    bit (not zero/nonzero) to distinguish compact vs. general form
    (bplustree.cpp: BPlusTreeInner::get_node_size/get_bp_node_ref)."""
    from crush.parsers.realm_parser import _walk_bplustree_leaves

    # Children must be emitted (and their real offsets known) before the
    # inner node that references them, since the inner node's fixed size
    # depends on its own element count, not the children's.
    buf = bytearray(b"\x00" * 8)  # ref 0 means "null" in Realm; keep offsets nonzero

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    def leaf_bytes() -> bytes:
        return _array_hdr(0x05, 1) + _pad8((0).to_bytes(2, "little"))

    leaf_a_off = emit(leaf_bytes())
    leaf_b_off = emit(leaf_bytes())

    elems_per_child = 3
    inner_payload = _pad8(
        (((elems_per_child << 1) | 1)).to_bytes(4, "little")  # elem[0]: tagged compact marker
        + leaf_a_off.to_bytes(4, "little")                    # elem[1]: child A
        + leaf_b_off.to_bytes(4, "little")                    # elem[2]: child B
        + (((5 << 1) | 1)).to_bytes(4, "little")               # elem[3] (last): tagged tree_size
    )
    root_off = emit(_array_hdr(0xC6, 4) + inner_payload)

    raw = bytes(buf)
    leaves = _walk_bplustree_leaves(raw, root_off, len(raw))
    assert [ref for ref, _off in leaves] == [leaf_a_off, leaf_b_off]
    # compact form: child_idx * elems_per_child = 0*3=0, 1*3=3
    assert [off for _ref, off in leaves] == [0, 3]


def test_read_collection_column_list_of_int() -> None:
    """_read_collection_column: each row's ref points to its own
    BPlusTree<T> root — 0 means an empty collection, a non-inner ref means
    the tree root is itself already a leaf (small lists)."""
    from crush.parsers.realm_parser import _read_collection_column

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # row0's list tree root is a single leaf holding [7, 8]; row1 is empty.
    row0_leaf = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (7, 8))
    ))
    col_ref = emit(_array_hdr(0x46, 2) + _pad8(
        row0_leaf.to_bytes(4, "little") + (0).to_bytes(4, "little")
    ))

    data = bytes(buf)
    result = _read_collection_column(data, col_ref, len(data), element_type=0, nullable=False)
    assert result == [[7, 8], []]


def test_read_array_typed_link_pairs() -> None:
    """ArrayTypedLink: flat (table_key+1, obj_key+1) int64 pairs;
    table_key==0 means NULL (array_typed_link.hpp)."""
    from crush.parsers.realm_parser import _read_array_typed_link

    raw = _array_hdr(0x0C, 4) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (4, 11, 0, 0)
    )
    assert _read_array_typed_link(raw, 0, len(raw)) == ["Obj(table_key=3, key=10)", None]


def test_read_array_mixed_basic_types() -> None:
    """ArrayMixed: each composite entry packs
    (payload_or_inline_value << 8) | (payload_idx << 5) | (data_type + 1);
    Int/Bool can be stored inline, String goes through the shared
    m_strings (ArrayString-shaped) payload array (array_mixed.cpp: get())."""
    from crush.parsers.realm_parser import _read_array_mixed

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # m_strings: 1 short-inline entry "hi" (width=8, pad=5)
    strings_ref = emit(_array_hdr(0x0C, 1) + (b"hi" + b"\x00" * 5 + bytes([5])))

    DT_INT, DT_BOOL, DT_STRING = 1, 2, 3  # data_type + 1 (Int=0, Bool=1, String=2)
    composite_vals = [
        (42 << 8) | (0 << 5) | DT_INT,     # inline Int
        (1 << 8) | (0 << 5) | DT_BOOL,     # inline Bool (True)
        (0 << 8) | (3 << 5) | DT_STRING,   # String at m_strings[0]
        0,                                  # NULL
    ]
    composite_ref = emit(_array_hdr(0x0C, 4) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in composite_vals)
    ))

    # outer ArrayMixed: [composite_ref, ints_ref=0, pairs_ref=0, strings_ref]
    outer_ref = emit(_array_hdr(0x46, 4) + _pad8(
        composite_ref.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + strings_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    result = _read_array_mixed(data, outer_ref, len(data))
    assert result == [42, True, "hi", None]


def test_link_column_resolves_target_table_name() -> None:
    """A Link column's target table is resolved via table.hpp's
    top_position_for_key (=3, this table's own TableKey) and
    top_position_for_opposite_table (=7, one TableKey per column) —
    table.hpp: Table::get_key_direct / Table::get_opposite_table_key.
    TableKeys are stable IDs, not necessarily equal to the table's
    physical index, so class_B (schema index 1) deliberately gets the
    larger TableKey (9) and class_A (schema index 0) the smaller one (5)."""
    from crush.parsers.realm_parser import _build_table_key_map, _extract_table_data

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- class_A: one Int column "x", own TableKey = 5 --
    names_ref_a = emit(_array_hdr(0x0C, 1) + (b"x" + b"\x00" * 6 + bytes([6])))
    colkeys_ref_a = emit(_array_hdr(0x0C, 1) + _pad8((0).to_bytes(8, "little", signed=True)))
    spec_ref_a = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little") + names_ref_a.to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + colkeys_ref_a.to_bytes(4, "little")
    ))
    col_a_data_ref = emit(_array_hdr(0x0C, 1) + _pad8((42).to_bytes(8, "little", signed=True)))
    leaf_a_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((1 << 1) | 1)).to_bytes(4, "little") + col_a_data_ref.to_bytes(4, "little")
    ))
    table_a_ref = emit(_array_hdr(0x46, 4) + _pad8(
        spec_ref_a.to_bytes(4, "little") + (0).to_bytes(4, "little")
        + leaf_a_ref.to_bytes(4, "little") + (((5 << 1) | 1)).to_bytes(4, "little")
    ))

    # -- class_B: one Link column "link_to_a" pointing at class_A, own TableKey = 9 --
    names_ref_b = emit(_array_hdr(0x0D, 1) + (b"link_to_a" + b"\x00" * 6 + bytes([6])))
    colkey_b = 12 << 16  # index=0, type=Link(12), attrs=0
    colkeys_ref_b = emit(_array_hdr(0x0C, 1) + _pad8(colkey_b.to_bytes(8, "little", signed=True)))
    spec_ref_b = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little") + names_ref_b.to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + colkeys_ref_b.to_bytes(4, "little")
    ))
    col_b_data_ref = emit(_array_hdr(0x0C, 1) + _pad8((1).to_bytes(8, "little", signed=True)))
    leaf_b_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((1 << 1) | 1)).to_bytes(4, "little") + col_b_data_ref.to_bytes(4, "little")
    ))
    opposite_ref_b = emit(_array_hdr(0x0C, 1) + _pad8((5).to_bytes(8, "little", signed=True)))
    table_b_ref = emit(_array_hdr(0x46, 8) + _pad8(
        spec_ref_b.to_bytes(4, "little") + (0).to_bytes(4, "little")
        + leaf_b_ref.to_bytes(4, "little") + (((9 << 1) | 1)).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + opposite_ref_b.to_bytes(4, "little")
    ))

    table_refs_ref = emit(_array_hdr(0x46, 2) + _pad8(
        table_a_ref.to_bytes(4, "little") + table_b_ref.to_bytes(4, "little")
    ))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    schema = ["class_A", "class_B"]
    table_key_map = _build_table_key_map(data, root_ref, schema, len(data))
    assert table_key_map == {5: "class_A", 9: "class_B"}

    tables = _extract_table_data(data, root_ref, schema, len(data), table_key_map)
    table_b = next(t for t in tables if t["name"] == "class_B")
    assert table_b["column_names"] == ["link_to_a"]
    assert table_b["column_target_tables"] == ["class_A"]


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _utf(s: str) -> bytes:
    data = s.encode("utf-8")
    return _u16(len(data)) + data


def _interned(s: str) -> bytes:
    return _u16(0xFFFF) + _utf(s)


def _make_abx_bytes() -> bytes:
    # Minimal ABX for: <root attr="value"/>
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")  # TYPE_STRING + START_TAG
    attr = bytes([0x2F]) + _interned("attr") + _utf("value")  # ATTRIBUTE token
    end_tag = bytes([0x23]) + _utf("root")  # TYPE_STRING + END_TAG
    end_doc = bytes([0x01])
    return magic + start_doc + start_tag + attr + end_tag + end_doc


def _make_atx_head_chunk(width: int = 32, height: int = 16) -> bytes:
    head = bytearray(0x54)
    struct.pack_into("<I", head, 0x18, width)
    struct.pack_into("<I", head, 0x1C, height)
    struct.pack_into("<I", head, 0x20, 1)
    struct.pack_into("<I", head, 0x28, 1)
    struct.pack_into("<I", head, 0x2C, 1)
    head[0x3C:0x4C] = bytes(range(16))
    struct.pack_into("<I", head, 0x4C, 3)
    struct.pack_into("<I", head, 0x50, 5)
    return struct.pack("<I4s", len(head), b"HEAD") + bytes(head)


def _make_atx_metadata_bytes() -> bytes:
    return b"AAPL\r\n\x1a\n" + _make_atx_head_chunk()


def _make_atx_lzfs_bytes() -> bytes:
    import liblzfse
    astc_block = bytes(16)
    compressed = liblzfse.compress(astc_block)
    lzfs_inner = struct.pack("<I", len(astc_block)) + compressed
    lzfs_chunk = struct.pack("<I4s", len(lzfs_inner), b"LZFS") + lzfs_inner
    return b"AAPL\r\n\x1a\n" + _make_atx_head_chunk(width=4, height=4) + lzfs_chunk


def test_abx_decode_unknown_value_type_reports_error() -> None:
    # START_TAG with an unassigned type nibble (0xE0) instead of a real ABX type.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    bad_start_tag = bytes([0xE2])  # token=START_TAG(2), dtype=0xE0 (unassigned)
    data = magic + start_doc + bad_start_tag

    result = decode_abx(data)

    assert any("Unknown ABX value type" in w for w in result.warnings)


def test_abx_decode_invalid_string_pool_reference_reports_error() -> None:
    # ATTRIBUTE with an interned-string reference pointing past the (empty) pool,
    # rather than the reserved 0xFFFF "new string" marker.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")
    bad_attr = bytes([0x2F]) + _u16(0) + _utf("value")  # ref=0, pool is empty
    data = magic + start_doc + start_tag + bad_attr

    result = decode_abx(data)

    assert any("Invalid ABX string pool reference" in w for w in result.warnings)


def test_abx_parser_parse(tmp_path: Path) -> None:
    abx_path = tmp_path / "binary.xml"
    abx_path.write_bytes(_make_abx_bytes())

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "binary.xml")

    parser = AbxParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "abx"
    assert "<root" in result.data["xml_str"]
    assert "attr" in result.data["xml_str"]
    tree = result.data["tree"]
    assert tree["@tag"] == "root"
    assert tree["@attribs"]["attr"] == "value"


def test_image_parser_can_parse_atx_magic(tmp_path: Path) -> None:
    atx_path = tmp_path / "poster.bin"
    atx_path.write_bytes(_make_atx_metadata_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.bin")

    assert ImageParser().can_parse(node.path, vfs.peek(node))


def test_image_parser_atx_metadata(tmp_path: Path) -> None:
    atx_path = tmp_path / "poster.atx"
    atx_path.write_bytes(_make_atx_metadata_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.atx")
    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "text"
    assert result.metadata["Format"] == "ATX"
    assert result.metadata["Width"] == 32
    assert result.metadata["Height"] == 16
    assert result.metadata["Pixel format"] == "ASTC 4x4"
    assert result.metadata["Chunks"] == "HEAD"
    assert result.metadata["Decode status"] == "ATX metadata parsed; image decode unavailable"


def test_image_parser_atx_image_decode(tmp_path: Path) -> None:
    pytest.importorskip("astc_decomp_faster")
    atx_path = tmp_path / "poster.atx"
    atx_path.write_bytes(_make_atx_lzfs_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.atx")
    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "image"
    assert result.metadata["Format"] == "ATX"
    assert result.metadata["Width"] == 4
    assert result.metadata["Height"] == 4
    assert result.metadata["Pixel format"] == "ASTC 4x4"
    assert result.metadata["Decode status"] == "Decoded ATX to PNG"

# ---------------------------------------------------------------------------
# HexFallbackParser — format identification via FormatDatabase
# ---------------------------------------------------------------------------

def test_hex_fallback_identifies_sqlite_format(tmp_path: Path) -> None:
    raw = b"SQLite format 3\x00" + b"\x00" * 512
    (tmp_path / "mystery.bin").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "mystery.bin")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "hex"
    assert "Format (identified)" in result.metadata
    assert "SQLite" in result.metadata["Format (identified)"]
    assert "Parser support" in result.metadata
    assert result.metadata["Parser support"] == "Supported"


def test_hex_fallback_unknown_has_no_format_key(tmp_path: Path) -> None:
    raw = b"\xDE\xAD\xBE\xEF" * 32
    (tmp_path / "random.xyz999").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "random.xyz999")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "hex"
    assert "Format (identified)" not in result.metadata


# ---------------------------------------------------------------------------
# _detect_encoding — text viewer encoding detection
# ---------------------------------------------------------------------------

def test_detect_utf8_bom() -> None:
    raw = b"\xef\xbb\xbf" + "hello".encode("utf-8")
    text, label = _detect_encoding(raw)
    assert text == "hello"
    assert label == "UTF-8 BOM"


def test_detect_utf16_le_bom() -> None:
    raw = b"\xff\xfe" + "hi".encode("utf-16-le")
    text, label = _detect_encoding(raw)
    assert text == "hi"
    assert label == "UTF-16 LE"


def test_detect_utf16_be_bom() -> None:
    raw = b"\xfe\xff" + "hi".encode("utf-16-be")
    text, label = _detect_encoding(raw)
    assert text == "hi"
    assert label == "UTF-16 BE"


def test_detect_plain_utf8() -> None:
    raw = "plain ascii".encode("utf-8")
    text, label = _detect_encoding(raw)
    assert text == "plain ascii"
    assert label == "UTF-8"


def test_detect_utf16_le_no_bom() -> None:
    # UTF-16 LE without BOM — non-ASCII chars put null bytes at odd positions
    # and make the raw bytes invalid as strict UTF-8, triggering the heuristic
    raw = "héllo wörld".encode("utf-16-le")
    text, label = _detect_encoding(raw)
    assert "h" in text
    assert "UTF-16 LE" in label


def test_detect_lossy_fallback() -> None:
    # Latin-1 bytes that are not valid UTF-8
    raw = b"\xff\xfe\xfd" * 10  # matches UTF-16 LE BOM — use something else
    # Use bytes that are invalid UTF-8 and won't trigger UTF-16 LE heuristic
    raw = bytes([0x80, 0x81, 0x82, 0x83] * 20)
    text, label = _detect_encoding(raw)
    assert isinstance(text, str)
    assert "lossy" in label.lower() or "UTF-8" in label


# ---------------------------------------------------------------------------
# LevelDB parser
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    out = []
    while n > 127:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _make_log_entry(key: bytes, value: bytes | None, seq: int) -> bytes:
    """Build one LevelDB log record (Full type). CRC is zeroed — ccl_leveldb doesn't validate it."""
    batch = struct.pack("<QI", seq, 1)
    if value is not None:
        batch += b"\x01" + _varint(len(key)) + key + _varint(len(value)) + value
    else:
        batch += b"\x00" + _varint(len(key)) + key
    header = struct.pack("<IHB", 0, len(batch), 1)  # CRC=0, length, type=Full
    return header + batch


def _make_minimal_leveldb(
    path: Path,
    records: list[tuple[bytes, bytes | None]],
) -> None:
    """Write a minimal LevelDB directory with one log file containing *records*."""
    path.mkdir(parents=True, exist_ok=True)
    log_data = b"".join(
        _make_log_entry(k, v, seq=i + 1) for i, (k, v) in enumerate(records)
    )
    (path / "000001.log").write_bytes(log_data)
    (path / "MANIFEST-000001").write_bytes(b"")  # empty manifest — parser handles gracefully


def test_leveldb_can_parse_dir_ldb(tmp_path: Path) -> None:
    (tmp_path / "000001.ldb").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_log(tmp_path: Path) -> None:
    (tmp_path / "000001.log").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_sst(tmp_path: Path) -> None:
    (tmp_path / "000001.sst").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_manifest(tmp_path: Path) -> None:
    (tmp_path / "MANIFEST-000001").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_negative(tmp_path: Path) -> None:
    (tmp_path / "README.txt").write_text("not a leveldb")
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert not LeveldbParser().can_parse_dir(node)


def test_leveldb_parse_viewer_type(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"key1", b"value1")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    assert result.viewer_type == "leveldb"


def test_leveldb_parse_live_records(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"hello", b"world")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    live = [r for r in records if r["state"] == "Live"]
    assert len(live) == 1
    assert live[0]["user_key_bytes"] == b"hello"
    assert live[0]["value_bytes"] == b"world"
    assert live[0]["user_key_text"] == "hello"
    assert live[0]["value_text"] == "world"


def test_leveldb_parse_deleted_records(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"gone", b"data"), (b"gone", None)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    deleted = [r for r in records if r["state"] == "Deleted"]
    assert len(deleted) >= 1
    assert deleted[0]["user_key_bytes"] == b"gone"


def test_leveldb_parse_file_stats(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"k", b"v"), (b"k2", None)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    files = result.data["files"]
    assert len(files) == 1
    assert files[0]["type"] == "Log"
    assert files[0]["total"] == 2
    assert files[0]["live"] == 1
    assert files[0]["deleted"] == 1


def test_leveldb_binary_key_value(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    binary_key = b"\x80\x81\x82\x83"   # invalid UTF-8 (continuation bytes without leader)
    binary_val = b"\xff\xfe\xfd"
    _make_minimal_leveldb(db, [(binary_key, binary_val)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    assert records[0]["user_key_bytes"] == binary_key
    assert records[0]["value_bytes"] == binary_val
    assert records[0]["user_key_text"] is None   # not valid UTF-8
    assert records[0]["value_text"] is None


def test_leveldb_parse_record_has_offset(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"key1", b"value1")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    assert len(records) >= 1
    assert "offset" in records[0]
    assert isinstance(records[0]["offset"], int)
    assert records[0]["offset"] >= 0


# ---------------------------------------------------------------------------
# BlobInspector helpers: _is_image, _render_protobuf
# ---------------------------------------------------------------------------

def test_is_image_png() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)


def test_is_image_jpeg() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"\xff\xd8\xff\xe0" + b"\x00" * 100)


def test_is_image_gif87() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"GIF87a" + b"\x00" * 100)


def test_is_image_gif89() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"GIF89a" + b"\x00" * 100)


def test_is_image_negative() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert not _is_image(b"SQLite format 3\x00" + b"\x00" * 100)
    assert not _is_image(b"")
    assert not _is_image(b"\x00\x01\x02\x03")


def test_render_protobuf_simple() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 1, "wire_type": "varint", "value": 42},
        {"field": 2, "wire_type": "varint", "value": 0},
    ]
    result = _render_protobuf(entries)
    assert "1 [varint]: 42" in result
    assert "2 [varint]: 0" in result


def test_render_protobuf_nested() -> None:
    # wire_type is "length-delimited" (as _decode_message produces);
    # value shape is {"type": "message", "entries": [...]}
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 1, "wire_type": "length-delimited", "value": {
            "type": "message",
            "entries": [{"field": 3, "wire_type": "varint", "value": 99}],
        }},
    ]
    result = _render_protobuf(entries)
    assert "1 {" in result
    assert "3 [varint]: 99" in result
    assert "}" in result


def test_render_protobuf_string_value() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 5, "wire_type": "length-delimited", "value": {"type": "string", "text": "hello"}},
    ]
    result = _render_protobuf(entries)
    assert '5: "hello"' in result


def test_render_protobuf_bytes_dict_value() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 3, "wire_type": "length-delimited", "value": {
            "type": "bytes", "length": 4, "hex_preview": "de ad be ef",
        }},
    ]
    result = _render_protobuf(entries)
    assert "3:" in result
    assert "de ad be ef" in result


def test_render_protobuf_bytes_value() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [{"field": 2, "wire_type": "bytes", "value": bytes(range(40))}]
    result = _render_protobuf(entries)
    assert "2:" in result           # field number present
    assert "…" in result            # truncation marker for > 32 bytes
    assert "00010203" in result     # hex content starts correctly


def test_render_protobuf_integration_nested() -> None:
    """End-to-end: real wire bytes with a nested message render as a block, not a raw dict."""
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # inner: field 1, varint 7  →  b'\x08\x07'
    inner = b"\x08\x07"
    # outer: field 1 varint 42, field 2 length-delimited (inner)
    outer = (
        b"\x08\x2a"                                        # field 1, varint 42
        + b"\x12" + bytes([len(inner)]) + inner            # field 2, length-delimited, inner
    )
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    result = _render_protobuf(decoded["entries"])
    assert "1 [varint]: 42" in result
    assert "2 {" in result            # nested message renders as block
    assert "1 [varint]: 7" in result  # inner field present
    assert "}" in result
    assert "type" not in result       # no raw dict repr leaking through


def test_decode_message_nested_field_also_shows_raw_bytes_interpretation() -> None:
    """Wire type 2 doesn't declare whether a payload is really a submessage —
    a short blob that happens to be grammatically valid protobuf (like a hash
    prefix or opaque token) would otherwise render as a confident nested
    message with no hint it might just be bytes. The raw-bytes reading must
    always be shown alongside it, like scalar fields' interpretations."""
    from crush.parsers.protobuf_parser import _decode_message

    # inner: field 1, varint 7  →  b'\x08\x07' (also happens to parse as a message)
    inner = b"\x08\x07"
    outer = b"\x12" + bytes([len(inner)]) + inner  # field 2, length-delimited
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "message"
    labels = [i.label for i in entry["interpretations"]]
    assert "raw bytes" in labels
    raw_hint = next(i for i in entry["interpretations"] if i.label == "raw bytes")
    assert raw_hint.value == inner.hex(" ")


def test_render_protobuf_shows_interpretations() -> None:
    """Interpretation hints appear as '# label: value' lines below the field."""
    from crush.parsers.proto_interp import Interpretation
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {
            "field": 1,
            "wire_type": "varint",
            "value": 42,
            "interpretations": [
                Interpretation("uint64", "42"),
                Interpretation("sint64 (zigzag)", "21"),
                Interpretation("bool", "false"),
            ],
        }
    ]
    result = _render_protobuf(entries)
    assert "1 [varint]: 42" in result
    assert "# sint64 (zigzag): 21" in result
    assert "# bool: false" in result
    # uint64 is redundant (same as primary value) — must be suppressed
    assert "# uint64" not in result


def test_render_protobuf_suppresses_uint32() -> None:
    """uint32 is also suppressed as it equals the primary fixed32 value."""
    from crush.parsers.proto_interp import Interpretation
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {
            "field": 2,
            "wire_type": "fixed32",
            "value": 99,
            "interpretations": [
                Interpretation("uint32", "99"),
                Interpretation("int32", "99"),
                Interpretation("float", "1.387e-43"),
            ],
        }
    ]
    result = _render_protobuf(entries)
    assert "# uint32" not in result
    assert "# int32: 99" in result
    assert "# float" in result


def test_render_protobuf_integration_with_interpretations() -> None:
    """End-to-end: _decode_message produces interpretations shown in text output."""
    import struct
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # field 1: fixed64 containing a Cocoa timestamp (694656000.0 = 2023-01-07 UTC)
    raw = b"\x09" + struct.pack("<d", 694_656_000.0)
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    result = _render_protobuf(decoded["entries"])
    assert "# double:" in result
    assert "# Cocoa timestamp:" in result
    assert "2023" in result


def test_try_protobuf_surfaces_warning() -> None:
    """Truncated protobuf shows a Warning header in BlobInspector output."""
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # field 1, wire_type 1 (64-bit) with only 4 bytes — truncated
    truncated = b"\x09\x00\x01\x02\x03"
    decoded, warning, _ = _decode_message(truncated)
    assert warning  # must have a warning

    result = _render_protobuf(decoded["entries"])
    # _try_protobuf prepends the warning — simulate that here
    if warning:
        result = f"# Warning: {warning}\n\n{result}"
    assert "# Warning:" in result
    assert "Truncated" in result


# ---------------------------------------------------------------------------
# _decode_message heuristic: nested-first, string/bytes fallback
# ---------------------------------------------------------------------------

def test_decode_message_prefers_nested_over_utf8() -> None:
    """A length-delimited payload that is valid protobuf AND printable UTF-8 is decoded
    as a nested message, not a string."""
    from crush.parsers.protobuf_parser import _decode_message, _looks_like_utf8

    # tag 0x20 = field 4, wire_type 0 (varint); 0x41 = 65 — both are printable ASCII
    inner = b"\x20\x41"
    assert _looks_like_utf8(inner), "precondition: inner passes UTF-8 heuristic"

    # wrap as field 1, length-delimited
    outer = b"\x0a" + bytes([len(inner)]) + inner
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "message", (
        "valid nested protobuf should be decoded as message, not string"
    )


def test_decode_message_falls_back_to_string() -> None:
    """When nested parse yields no entries, UTF-8 payload is decoded as string."""
    from crush.parsers.protobuf_parser import _decode_message

    # b'\x07' is BEL — not parseable as a valid protobuf field (wire_type 7 is unknown)
    # and not printable (< 0x20), so this will fall through to bytes preview.
    # Use a clean printable string that cannot parse as protobuf:
    # 0xff starts an invalid varint sequence (never terminates within 1 byte as a tag)
    # → use pure ASCII text wrapped to trigger string fallback

    # "hello" as a payload: tag attempts fail quickly on 'h'=0x68 → field 13, wire_type 0
    # then 'e'=0x65 as varint value → succeeds → gives entries → would be nested!
    # We need something that fails nested parse but passes UTF-8.
    # Best approach: a payload that has a valid tag but truncated value.
    # field 1, wire_type 1 (64-bit) needs exactly 8 bytes — give it only 4.
    # tag 0x09 (field 1, wire_type 1) + 4 bytes "aaaa" → nested fails (truncated), payload IS UTF-8.
    payload = b"\x09aaaa"  # truncated 64-bit field → nested_warn set → falls back
    outer = b"\x0a" + bytes([len(payload)]) + payload
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "string", (
        "when nested parse fails, UTF-8 payload should fall back to string"
    )


def test_decode_message_falls_back_to_bytes() -> None:
    """When nested parse fails and payload is not UTF-8, shown as bytes preview."""
    from crush.parsers.protobuf_parser import _decode_message

    # 0x09 = field 1, wire_type 1 (64-bit) — but only 3 bytes follow → truncated nested parse
    # 0x80 0x81 0x82 are non-UTF-8 bytes → not a string either
    payload = b"\x09\x80\x81\x82"
    outer = b"\x0a" + bytes([len(payload)]) + payload
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "bytes"


# ---------------------------------------------------------------------------
# proto_interp: multi-interpretation display
# ---------------------------------------------------------------------------

def test_interpret_varint_basic() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(42)}
    assert "uint64" in labels
    assert "sint64 (zigzag)" in labels


def test_interpret_varint_bool() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(1)}
    assert "bool" in labels
    val = {i.label: i.value for i in interpret_varint(1)}
    assert val["bool"] == "true"
    val0 = {i.label: i.value for i in interpret_varint(0)}
    assert val0["bool"] == "false"


def test_interpret_varint_no_bool_for_large() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(999)}
    assert "bool" not in labels


def test_interpret_varint_unix_ts() -> None:
    from crush.parsers.proto_interp import interpret_varint
    # 2023-01-07 00:00:00 UTC = 1673049600
    val = {i.label: i.value for i in interpret_varint(1_673_049_600)}
    assert "Unix timestamp (s)" in val
    assert "2023" in val["Unix timestamp (s)"]


def test_interpret_varint_signed() -> None:
    from crush.parsers.proto_interp import interpret_varint
    # max uint64 would be negative as int64
    big = (1 << 63)
    val = {i.label: i.value for i in interpret_varint(big)}
    assert "int64" in val


def test_interpret_fixed64_double_cocoa() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed64
    # Cocoa timestamp 694656000.0 = 2023-01-07 00:00:00 UTC
    raw = struct.pack("<d", 694_656_000.0)
    val = {i.label: i.value for i in interpret_fixed64(raw)}
    assert "double" in val
    assert "Cocoa timestamp" in val
    assert "2023" in val["Cocoa timestamp"]


def test_interpret_fixed64_uint64() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed64
    raw = struct.pack("<Q", 12345678)
    val = {i.label: i.value for i in interpret_fixed64(raw)}
    assert "uint64" in val


def test_interpret_fixed32_float() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed32
    raw = struct.pack("<f", 3.14)
    val = {i.label: i.value for i in interpret_fixed32(raw)}
    assert "float" in val


def test_interpret_fixed32_uint32() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed32
    raw = struct.pack("<I", 99)
    val = {i.label: i.value for i in interpret_fixed32(raw)}
    assert "uint32" in val


def test_decode_message_adds_interpretations() -> None:
    """_decode_message entries include an 'interpretations' list for numeric fields."""
    from crush.parsers.protobuf_parser import _decode_message
    # field 1, varint 42
    data = b"\x08\x2a"
    decoded, warning, _ = _decode_message(data)
    assert not warning
    entry = decoded["entries"][0]
    assert "interpretations" in entry
    assert any(i.label == "uint64" for i in entry["interpretations"])


# ---------------------------------------------------------------------------
# SEGB protobuf decoder tests
# ---------------------------------------------------------------------------

def _varint(v: int) -> bytes:
    """Encode a single unsigned varint."""
    out = []
    while v > 127:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _proto_field(field_num: int, wire_type: int, payload: bytes) -> bytes:
    return _varint((field_num << 3) | wire_type) + payload


def test_parse_protobuf_varint_field() -> None:
    """Basic varint field is decoded correctly."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(2, 0, _varint(42))
    result = _parse_protobuf(data)
    assert result[2] == 42


def test_parse_protobuf_string_field() -> None:
    """Length-delimited UTF-8 field is decoded as str."""
    from crush.parsers.segb_parser import _parse_protobuf
    s = b"com.apple.Preferences"
    data = _proto_field(2, 2, _varint(len(s)) + s)
    result = _parse_protobuf(data)
    assert result[2] == "com.apple.Preferences"


def test_parse_protobuf_repeated_fields() -> None:
    """Same field number appearing twice is collected into a list."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(1, 0, _varint(10)) + _proto_field(1, 0, _varint(20))
    result = _parse_protobuf(data)
    assert result[1] == [10, 20]


def test_parse_protobuf_high_field_number() -> None:
    """Field numbers above 200 (old hard limit) are now parsed correctly."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(750, 0, _varint(99))
    result = _parse_protobuf(data)
    assert 750 in result
    assert result[750] == 99


def test_parse_protobuf_multiple_fields() -> None:
    """Multiple different field numbers are all decoded."""
    from crush.parsers.segb_parser import _parse_protobuf
    s = b"hello"
    data = (
        _proto_field(1, 0, _varint(7))
        + _proto_field(2, 2, _varint(len(s)) + s)
        + _proto_field(300, 0, _varint(1))
    )
    result = _parse_protobuf(data)
    assert result[1] == 7
    assert result[2] == "hello"
    assert result[300] == 1


def test_proto_to_json_basic() -> None:
    """Simple protobuf payload serialises to valid JSON."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    s = b"com.apple.test"
    data = _proto_field(2, 2, _varint(len(s)) + s)
    j = _proto_to_json(data)
    obj = json.loads(j)
    assert obj["2"] == "com.apple.test"


def test_proto_to_json_repeated_fields_become_array() -> None:
    """Repeated fields are stored as JSON arrays."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    data = _proto_field(1, 0, _varint(10)) + _proto_field(1, 0, _varint(20))
    obj = json.loads(_proto_to_json(data))
    assert obj["1"] == [10, 20]


def test_proto_to_json_always_valid_json() -> None:
    """Garbage input always returns valid (empty) JSON, never raises."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    for bad in (b"", b"\xff\xff\xff", b"\x00" * 20):
        result = _proto_to_json(bad)
        obj = json.loads(result)   # must not raise
        assert isinstance(obj, dict)


def test_render_proto_payload_shows_undecodable_blobs_as_hex() -> None:
    """Binary blobs that cannot be sub-parsed still appear, as a size+hex preview."""
    from crush.parsers.segb_parser import _render_proto_payload
    binary = b"\xde\xad\xbe\xef"
    data = _proto_field(5, 2, _varint(len(binary)) + binary)
    result = _render_proto_payload(data)
    # field 5 must stay visible — no field silently vanishes from the rendered view.
    assert "5" in result
    assert "4 B" in result
    assert "deadbeef" in result


def test_render_proto_payload_double_field_gets_cocoa_hint_not_replaced() -> None:
    """A double in the plausible Cocoa range is shown as a labeled hint, raw value kept."""
    import struct
    from crush.parsers.segb_parser import _render_proto_payload
    # 694656000.0 = 2023-01-06 UTC as a Cocoa timestamp (2001-01-01 epoch + 8040 days).
    data = _proto_field(4, 1, struct.pack("<d", 694_656_000.0))
    result = _render_proto_payload(data)
    assert f"{694_656_000.0:.6g}" in result  # raw value still present, not replaced
    assert "possible Cocoa timestamp" in result
    assert "2023" in result


def test_proto_to_json_double_field_stays_a_json_number() -> None:
    """Payload JSON must never swap a plausible-Cocoa double for a date string,
    so json_extract() comparisons stay type-consistent regardless of value."""
    import json
    import struct
    from crush.parsers.segb_parser import _proto_to_json
    data = _proto_field(4, 1, struct.pack("<d", 694_656_000.0))
    obj = json.loads(_proto_to_json(data))
    assert isinstance(obj["4"], float)
    assert obj["4"] == pytest.approx(694_656_000.0)


def test_render_proto_payload_repeated_fields() -> None:
    """Repeated fields appear in the rendered output."""
    from crush.parsers.segb_parser import _render_proto_payload
    data = _proto_field(3, 0, _varint(1)) + _proto_field(3, 0, _varint(2))
    result = _render_proto_payload(data)
    assert result  # non-empty
    assert "3" in result


def test_render_proto_payload_nested_message_also_shows_raw_bytes() -> None:
    """A bytes field that decodes as a nested message must still show the raw
    bytes alongside it — wire type 2 doesn't declare that the payload really
    is a submessage, and a short blob can coincidentally parse as one (same
    convention as the standalone Protobuf Viewer's 'raw bytes' hint)."""
    from crush.parsers.segb_parser import _render_proto_payload
    # field 1, varint 200 -> b'\x08\xc8\x01': invalid UTF-8 (0xC8 needs a
    # continuation byte), but grammatically valid protobuf -> {1: 200}.
    inner = _proto_field(1, 0, _varint(200))
    data = _proto_field(5, 2, _varint(len(inner)) + inner)
    result = _render_proto_payload(data)
    assert "{1:200}" in result
    assert f"[raw: {len(inner)} B: {inner.hex()}]" in result


def test_create_segb_sqlite_payload_columns() -> None:
    """SQLite DB has both Payload (rendered text) and Payload JSON columns."""
    import json
    import sqlite3
    from crush.parsers.segb_parser import _create_segb_sqlite, _COLUMNS_V1
    s = b"com.apple.test"
    raw = _proto_field(2, 2, _varint(len(s)) + s)
    rendered = "2: \"com.apple.test\""
    rows = [
        [0, 0, "Current", "2024-01-01", "2024-01-01", 0, 0, True,
         len(raw), (rendered, raw)],
    ]
    path = _create_segb_sqlite(_COLUMNS_V1, rows)
    assert path is not None
    conn = sqlite3.connect(str(path))
    cols = [r[1] for r in conn.execute('PRAGMA table_info("SEGB")').fetchall()]
    assert "Payload" in cols
    assert "Payload JSON" in cols
    payload_val = conn.execute('SELECT "Payload" FROM SEGB').fetchone()[0]
    assert payload_val == rendered
    payload_json = conn.execute('SELECT "Payload JSON" FROM SEGB').fetchone()[0]
    obj = json.loads(payload_json)
    assert obj.get("2") == "com.apple.test"
    conn.close()
    path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Group wire-type (3/4) handling in _decode_message
# ---------------------------------------------------------------------------

def test_decode_message_skips_simple_group() -> None:
    """A group (wire_type=3) should be skipped; fields after it are decoded normally."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B), field 2 varint 99 inside (0x10 0x63),
    # field 1 end-group (0x0C), then field 3 varint 7 (0x18 0x07)
    raw = bytes([0x0B, 0x10, 0x63, 0x0C, 0x18, 0x07])
    decoded, warning, _ = _decode_message(raw)
    assert warning == ""
    entries = decoded["entries"]
    assert len(entries) == 1
    assert entries[0]["field"] == 3
    assert entries[0]["value"] == 7


def test_decode_message_skips_nested_group() -> None:
    """Nested groups (group inside a group) are skipped recursively."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B)
    #   field 3 start-group (0x1B)
    #     field 4 varint 5 (0x20 0x05)
    #   field 3 end-group (0x1C)
    # field 1 end-group (0x0C)
    # field 3 varint 7 (0x18 0x07)
    raw = bytes([0x0B, 0x1B, 0x20, 0x05, 0x1C, 0x0C, 0x18, 0x07])
    decoded, warning, _ = _decode_message(raw)
    assert warning == ""
    entries = decoded["entries"]
    assert len(entries) == 1
    assert entries[0]["field"] == 3
    assert entries[0]["value"] == 7


def test_decode_message_warns_on_truncated_group() -> None:
    """A group without a closing end-group tag produces a truncation warning."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B), field 2 varint 99 inside (0x10 0x63), then EOF
    raw = bytes([0x0B, 0x10, 0x63])
    decoded, warning, _ = _decode_message(raw)
    assert "Truncated" in warning or "truncated" in warning.lower()


def test_decode_message_warns_on_unexpected_end_group() -> None:
    """An end-group tag (wire_type=4) at the top level produces a warning."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 end-group (0x0C) at top level — no matching start-group
    raw = bytes([0x0C])
    decoded, warning, _ = _decode_message(raw)
    assert "end-group" in warning.lower() or "Unexpected" in warning


# ---------------------------------------------------------------------------
# blob_inspector — intermediate decode functions and registry
# ---------------------------------------------------------------------------

def test_decode_base64_valid() -> None:
    import base64
    from crush.viewers.blob_inspector import _decode_base64
    payload = b"hello world"
    assert _decode_base64(base64.b64encode(payload)) == payload


def test_decode_base64_invalid() -> None:
    from crush.viewers.blob_inspector import _decode_base64
    assert _decode_base64(b"!!!not-base64!!!") is None


def test_decode_hex_valid() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"deadbeef") == bytes.fromhex("deadbeef")


def test_decode_hex_with_spaces() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"de ad be ef") == bytes.fromhex("deadbeef")


def test_decode_hex_with_colons() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"de:ad:be:ef") == bytes.fromhex("deadbeef")


def test_decode_hex_invalid() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"zzzz") is None


def test_intermediate_registry_dispatches() -> None:
    import base64
    from crush.viewers.blob_inspector import _INTERMEDIATE
    payload = b"hello"
    assert _INTERMEDIATE["Base64 (decode)"](base64.b64encode(payload)) == payload
    assert _INTERMEDIATE["Hex → Bytes"](b"deadbeef") == bytes.fromhex("deadbeef")


def test_intermediate_registry_unknown_returns_none() -> None:
    from crush.viewers.blob_inspector import _INTERMEDIATE
    assert _INTERMEDIATE.get("UTF-8 text") is None


def test_decode_base64url_valid() -> None:
    import base64
    from crush.viewers.blob_inspector import _decode_base64url
    payload = b"\xfb\xfc\xfd"
    assert _decode_base64url(base64.urlsafe_b64encode(payload)) == payload


def test_decode_base64url_url_chars_accepted() -> None:
    """URL-safe alphabet (-_) must round-trip correctly."""
    from crush.viewers.blob_inspector import _decode_base64url
    # b"\xfb\xfc\xfd" encodes to "-_z9" in URL-safe b64 (contains - and _)
    import base64
    payload = b"\xfb\xfc\xfd"
    url_encoded = base64.urlsafe_b64encode(payload)
    assert _decode_base64url(url_encoded) == payload


def test_decode_base64url_no_padding_needed() -> None:
    """urlsafe_b64decode adds padding automatically — partial input must still decode."""
    import base64
    from crush.viewers.blob_inspector import _decode_base64url
    payload = b"hello"
    # strip trailing padding; function must restore it
    stripped = base64.urlsafe_b64encode(payload).rstrip(b"=")
    assert _decode_base64url(stripped) == payload


def test_decode_lzfse_invalid_returns_none() -> None:
    from crush.viewers.blob_inspector import _decode_lzfse
    assert _decode_lzfse(b"not lzfse data at all") is None


def test_intermediate_registry_has_new_steps() -> None:
    from crush.viewers.blob_inspector import _INTERMEDIATE
    assert "Base64url (decode)" in _INTERMEDIATE
    assert "lzfse decompress" in _INTERMEDIATE


def test_intermediate_registry_base64url_dispatches() -> None:
    import base64
    from crush.viewers.blob_inspector import _INTERMEDIATE
    payload = b"hello \xfb\xfc"
    assert _INTERMEDIATE["Base64url (decode)"](base64.urlsafe_b64encode(payload)) == payload
