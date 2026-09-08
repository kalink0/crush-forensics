# SPDX-License-Identifier: Apache-2.0
"""Unit coverage for realm_parser.py's byte-provenance decoders on the
legacy pre-Cluster path (_decode_pre_cluster_column_value_ranges and
friends), against a real format-9 fixture. Mirrors
test_realm_byte_ranges.py, which covers the same feature for the modern
Cluster/ClusterTree path.
"""
from __future__ import annotations

from pathlib import Path

from crush.core.vfs import DirectoryVFS
from crush.parsers.realm_parser import RealmParser

_FIXTURE = Path(__file__).parent / "fixtures" / "format9_alltypes.realm"


def _parse_all_types() -> tuple[dict, dict, bytes]:
    vfs = DirectoryVFS(_FIXTURE.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == _FIXTURE.name)
    result = RealmParser().parse(node, vfs)
    all_types = next(t for t in result.data["tables"] if t["name"] == "class_AllTypes")
    enum_strings = next(t for t in result.data["tables"] if t["name"] == "class_EnumStrings")
    return all_types, enum_strings, _FIXTURE.read_bytes()


def _cell(t: dict, raw: bytes, column: str, row: int) -> tuple[object, bytes | None]:
    i = t["column_names"].index(column)
    value = t["columns"][i][row]
    rng = t["byte_ranges"][i][row]
    if rng is None:
        return value, None
    ranges = rng if isinstance(rng, list) else [rng]
    return value, b"".join(raw[s:e] for s, e in ranges)


def test_pre_cluster_string_columns_range_is_the_actual_bytes() -> None:
    t, _enum, raw = _parse_all_types()
    for column in ("col_string_short", "col_string_medium", "col_string_big"):
        value, highlighted = _cell(t, raw, column, 0)
        assert highlighted is not None, column
        assert highlighted.rstrip(b"\x00").decode("utf-8") == value, column


def test_pre_cluster_timestamp_range_covers_seconds_and_nanos() -> None:
    t, _enum, raw = _parse_all_types()
    i = t["column_names"].index("col_timestamp")
    rng = t["byte_ranges"][i][0]
    assert isinstance(rng, list) and len(rng) == 2


def test_pre_cluster_bit_packed_bool_column_still_gets_a_range() -> None:
    t, _enum, raw = _parse_all_types()
    i = t["column_names"].index("col_bool")
    ranges = t["byte_ranges"][i]
    assert all(r is not None for r in ranges)


def test_pre_cluster_linklist_range_covers_its_own_backing_array() -> None:
    t, _enum, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "col_linklist", 1)
    assert value == [0, 1]
    assert highlighted is not None
    assert highlighted[:4] == b"AAAA"


def test_pre_cluster_mixed_int_range_is_its_own_data_cell() -> None:
    t, _enum, raw = _parse_all_types()
    value, highlighted = _cell(t, raw, "col_mixed", 1)
    assert value == 123456789
    assert highlighted is not None
    assert len(highlighted) == 8


def test_pre_cluster_string_enum_range_is_the_row_own_index_cell_not_none() -> None:
    """Primary-only design: the row's own index cell, not the shared keys
    blob it resolves to (that's cross-row shared storage, not this row's
    own exclusive bytes)."""
    _all_types, enum_strings, raw = _parse_all_types()
    i = enum_strings["column_names"].index("enum_value")
    values = enum_strings["columns"][i]
    ranges = enum_strings["byte_ranges"][i]
    assert values == ["ALPHA", "BETA", "GAMMA"] * 4
    assert all(r is not None for r in ranges)
    # Rows sharing the same packed-index byte have identical ranges --
    # expected for bit-packed shared storage, not a bug.
    assert ranges[0] == ranges[1] == ranges[2] == ranges[3]
