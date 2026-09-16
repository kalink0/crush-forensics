# SPDX-License-Identifier: Apache-2.0
"""Byte-provenance coverage for segb_parser.py's SegbCellLocator
(crush/core/segb_offsets.py) -- both SEGB v1 and v2, end-to-end through
SegbParser.parse() against synthetic fixtures (this project's
synthetic-fixtures-only rule for forensic tests), mirroring
test_realm_byte_ranges.py's approach for Realm.
"""
from __future__ import annotations

import struct
import zlib

from crush.core.segb_offsets import SegbCellLocator
from crush.core.vfs import BytesVFS
from crush.parsers.segb_parser import SegbParser
from crush.third_party.ccl_segb.ccl_segb1 import HEADER_LENGTH as V1_HEADER_LENGTH
from crush.third_party.ccl_segb.ccl_segb1 import MAGIC as V1_MAGIC
from crush.third_party.ccl_segb.ccl_segb2 import MAGIC as V2_MAGIC
from crush.third_party.ccl_segb.ccl_segb_common import EntryState


def _build_segb1(entries: list[tuple[bytes, int]]) -> bytes:
    body = bytearray()
    for payload, state_raw in entries:
        crc = zlib.crc32(payload)
        body.extend(struct.pack("<iiddIi", len(payload), state_raw, 0.0, 0.0, crc, 0))
        body.extend(payload)
        remainder = len(body) % 8
        if remainder:
            body.extend(b"\x00" * (8 - remainder))
    end_of_data_offset = V1_HEADER_LENGTH + len(body)
    header = struct.pack("<I", end_of_data_offset) + b"\x00" * 48 + V1_MAGIC
    assert len(header) == V1_HEADER_LENGTH
    return header + bytes(body)


def _build_segb2(entries: list[tuple[bytes, int]]) -> bytes:
    data_area = bytearray()
    trailer_entries: list[tuple[int, int]] = []
    for payload, state_raw in entries:
        crc = zlib.crc32(payload)
        data_area.extend(struct.pack("<Ii", crc, 0) + payload)
        end_offset = len(data_area)
        trailer_entries.append((end_offset, state_raw))
        remainder = end_offset % 4
        if remainder:
            data_area.extend(b"\x00" * (4 - remainder))
    header = struct.pack("<4sid16s", V2_MAGIC, len(trailer_entries), 0.0, b"\x00" * 16)
    trailer = b"".join(
        struct.pack("<iid", end_offset, state_raw, 0.0)
        for end_offset, state_raw in trailer_entries
    )
    return header + bytes(data_area) + trailer


def _parse(raw: bytes, name: str) -> tuple[dict, bytes]:
    vfs = BytesVFS(raw, name=name)
    node = vfs.root()
    result = SegbParser().parse(node, vfs)
    return result.data, raw


def test_v1_wiring_has_rowids_and_locator() -> None:
    raw = _build_segb1([(b"hello world!", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb1")
    assert data["SEGB"]["rowids"] == [0]
    assert isinstance(data["__cell_locator"], SegbCellLocator)


def test_v1_payload_range_is_the_actual_payload_bytes() -> None:
    raw = _build_segb1([
        (b"first-entry", int(EntryState.Written)),
        (b"second-entry-longer", int(EntryState.Written)),
    ])
    data, _ = _parse(raw, "sample.segb1")
    columns = data["SEGB"]["columns"]
    payload_idx = columns.index("Payload")
    locator = data["__cell_locator"]

    for row_key, (payload, _state) in enumerate([
        (b"first-entry", 0), (b"second-entry-longer", 0),
    ]):
        location = locator.locate_cell("SEGB", row_key, payload_idx)
        assert location is not None
        assert location.column_ranges is not None
        (start, end), = location.column_ranges
        assert raw[start:end] == payload


def test_v1_state_column_range_matches_stored_state() -> None:
    raw = _build_segb1([(b"payload", int(EntryState.Deleted))])
    data, _ = _parse(raw, "sample.segb1")
    columns = data["SEGB"]["columns"]
    state_idx = columns.index("State")
    locator = data["__cell_locator"]

    location = locator.locate_cell("SEGB", 0, state_idx)
    assert location is not None
    (start, end), = location.column_ranges
    assert struct.unpack_from("<i", raw, start)[0] == int(EntryState.Deleted)
    assert end - start == 4


def test_v1_locate_offset_resolves_back_to_payload_cell() -> None:
    raw = _build_segb1([(b"hello world!", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb1")
    columns = data["SEGB"]["columns"]
    payload_idx = columns.index("Payload")
    locator = data["__cell_locator"]

    location = locator.locate_cell("SEGB", 0, payload_idx)
    (start, _end), = location.column_ranges

    result = locator.locate_offset("SEGB", "main", start)
    assert result == (0, payload_idx)


def test_v1_column_without_provenance_still_locates_the_row() -> None:
    """"Index"/"CRC Calc"/"CRC Passed" aren't stored fields with their own
    byte range -- clicking them must not lose the row-level highlight."""
    raw = _build_segb1([(b"payload", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb1")
    columns = data["SEGB"]["columns"]
    locator = data["__cell_locator"]

    for col_name in ("Index", "CRC Calc", "CRC Passed"):
        location = locator.locate_cell("SEGB", 0, columns.index(col_name))
        assert location is not None
        assert location.column_ranges is None
        assert location.row_ranges


def test_v2_payload_range_is_the_actual_payload_bytes() -> None:
    raw = _build_segb2([
        (b"first", int(EntryState.Written)),
        (b"second-entry", int(EntryState.Written)),
    ])
    data, _ = _parse(raw, "sample.segb2")
    columns = data["SEGB"]["columns"]
    payload_idx = columns.index("Payload")
    locator = data["__cell_locator"]

    for row_key, payload in enumerate([b"first", b"second-entry"]):
        location = locator.locate_cell("SEGB", row_key, payload_idx)
        assert location is not None
        (start, end), = location.column_ranges
        assert raw[start:end] == payload


def test_v2_row_ranges_cover_both_entry_and_trailer_regions() -> None:
    """v2's trailer lives at the end of the file, physically separate from
    the entry's own data area -- row_ranges must be the two disjoint
    regions, not one contiguous span."""
    raw = _build_segb2([(b"payload-bytes", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb2")
    locator = data["__cell_locator"]

    location = locator.locate_cell("SEGB", 0, None)
    assert location is not None
    assert len(location.row_ranges) == 2
    entry_range, trailer_range = location.row_ranges
    assert entry_range[1] <= trailer_range[0]  # entry area precedes trailer
    assert b"payload-bytes" in raw[entry_range[0]:entry_range[1]]


def test_v2_trailer_offset_and_entry_end_offset_columns() -> None:
    raw = _build_segb2([(b"abc", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb2")
    columns = data["SEGB"]["columns"]
    locator = data["__cell_locator"]

    end_offset_idx = columns.index("Entry End Offset")
    location = locator.locate_cell("SEGB", 0, end_offset_idx)
    (start, end), = location.column_ranges
    assert end - start == 4
    # 8-byte CRC/unknown header + 3-byte "abc" payload, no padding needed.
    assert struct.unpack_from("<i", raw, start)[0] == 11

    trailer_idx = columns.index("Trailer Offset")
    location = locator.locate_cell("SEGB", 0, trailer_idx)
    (start, end), = location.column_ranges
    assert end - start == 16  # whole 16-byte trailer entry


def test_locate_cell_unknown_table_returns_none() -> None:
    raw = _build_segb2([(b"abc", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb2")
    locator = data["__cell_locator"]
    assert locator.locate_cell("NOT-SEGB", 0, 0) is None


def test_locate_offset_outside_any_row_returns_none() -> None:
    raw = _build_segb1([(b"payload", int(EntryState.Written))])
    data, _ = _parse(raw, "sample.segb1")
    locator = data["__cell_locator"]
    assert locator.locate_offset("SEGB", "main", len(raw) + 100) is None


def test_out_of_bounds_offsets_are_dropped_not_wrong() -> None:
    """A corrupt/hand-edited data_start_offset pointing past the actual
    file content must never produce a highlight range that runs off the
    end of the real bytes -- drop it instead of guessing."""
    fake_row = [0, 10_000_000, "Written", "t1", "t2", 0, 0, True, 5, ("", b"xxxxx")]
    locator = SegbCellLocator(file_bytes=b"short file", version="v1", rows=[fake_row])
    assert locator.locate_cell("SEGB", 0, 0) is None
