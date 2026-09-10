# SPDX-License-Identifier: Apache-2.0
"""Unit coverage for realm_parser.py's byte-provenance decoders
(_decode_column_value_ranges and friends) against a real Cluster-format
fixture -- no Qt required, unlike test_realm_hex_provenance.py which
covers the same feature end-to-end through TableViewer/HexViewer.
"""
from __future__ import annotations

from pathlib import Path

from crush.core.vfs import DirectoryVFS
from crush.parsers.realm_parser import RealmParser

_FIXTURE = Path(__file__).parent / "fixtures" / "all_types_v24.realm"


def _parse_all_types() -> tuple[dict, bytes]:
    vfs = DirectoryVFS(_FIXTURE.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == _FIXTURE.name)
    result = RealmParser().parse(node, vfs)
    t = next(t for t in result.data["tables"] if t["name"] == "class_AllTypesRecord")
    return t, _FIXTURE.read_bytes()


def _cell(t: dict, raw: bytes, column: str, row: int) -> tuple[object, bytes | None]:
    i = t["column_names"].index(column)
    value = t["columns"][i][row]
    rng = t["byte_ranges"][i][row]
    if rng is None:
        return value, None
    ranges = rng if isinstance(rng, list) else [rng]
    return value, b"".join(raw[s:e] for s, e in ranges)


def test_string_column_range_is_the_actual_utf8_bytes() -> None:
    t, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "stringCol", 0)
    assert value == "hello world"
    assert highlighted is not None
    assert highlighted.rstrip(b"\x00").decode("utf-8") == "hello world"


def test_uuid_column_range_is_the_actual_16_bytes() -> None:
    t, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "uuidCol", 0)
    assert value == "550e8400-e29b-41d4-a716-446655440000"
    assert highlighted == bytes.fromhex("550e8400e29b41d4a716446655440000")


def test_decimal128_column_range_is_16_bytes_wide() -> None:
    t, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "decimalCol", 0)
    assert value == "12345.6789"
    assert highlighted is not None
    assert len(highlighted) == 16


def test_bit_packed_int_column_still_gets_a_range() -> None:
    """_id is a small sequential primary key -- Realm packs it into a
    sub-byte-width array (multiple rows sharing one byte). This must still
    resolve to a real, non-None range (the containing byte), not silently
    skip highlighting just because storage happens to be bit-packed."""
    t, raw = _parse_all_types()
    i = t["column_names"].index("_id")
    values = t["columns"][i]
    ranges = t["byte_ranges"][i]
    assert values == [1, 2, 3, 4]
    assert all(r is not None for r in ranges)
    # Adjacent rows packed into the same byte share the same range.
    assert ranges[0] == ranges[1]
    assert ranges[2] == ranges[3]


def test_link_list_column_range_covers_its_own_backing_array() -> None:
    """List/Set columns get a coarse "whole backing structure" range, not
    a per-element decomposition -- still a real, unambiguous location."""
    t, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "linkList", 0)
    assert value == [0, 1]
    assert highlighted is not None
    assert highlighted[:4] == b"AAAA"  # Realm array-header checksum


def test_mixed_string_column_range_covers_both_composite_and_payload() -> None:
    t, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "mixedCol", 0)
    assert value == "a plain mixed string"
    assert highlighted is not None
    assert b"a plain mixed string" in highlighted
