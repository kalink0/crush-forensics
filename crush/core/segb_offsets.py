# SPDX-License-Identifier: Apache-2.0
"""CellLocator (crush/core/cell_locator.py) implementation for SEGB v1/v2
files, backing TableViewer's embedded Hex pane when opened from
segb_parser.py's generic table view.

Unlike Realm/SQLite, no live re-walk or eager parser-side range capture is
needed: every offset a per-cell range requires is already present, verbatim,
in the decoded row tuples segb_parser.py produces (data_start_offset,
payload size, and -- for v2 -- the trailer's own metadata_offset/end_offset).
This module just re-derives each column's exact byte range from those
values plus the vendored format's own fixed-layout constants (ccl_segb1/
ccl_segb2's HEADER_LENGTH/RECORD_HEADER_LENGTH/etc.), without touching the
vendored parsing code itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.cell_locator import CellLocation
from crush.third_party.ccl_segb import ccl_segb1, ccl_segb2

_MAIN = "main"  # SEGB has one physical file -- no base/WAL split to model.
_TABLE = "SEGB"

# Column indices, matching segb_parser.py's _COLUMNS_V1/_COLUMNS_V2 order.
_V1_STATE, _V1_TS1, _V1_TS2, _V1_CRC_STORED, _V1_PAYLOAD_SIZE, _V1_PAYLOAD = 2, 3, 4, 5, 8, 9
_V2_STATE, _V2_CREATION, _V2_TRAILER_OFFSET, _V2_ENTRY_END, _V2_CRC_STORED, _V2_PAYLOAD = 2, 3, 4, 5, 6, 10


def _clip(rng: tuple[int, int], limit: int) -> tuple[int, int] | None:
    """Clamp *rng* to [0, limit) and drop it if that leaves nothing --
    truncated/corrupt SEGB files can carry offsets past the bytes actually
    read, and a wrong-but-plausible-looking range is worse than none."""
    start, end = max(rng[0], 0), min(rng[1], limit)
    return (start, end) if end > start else None


def _v1_ranges(
    data_start_offset: int, payload_size: int, file_len: int
) -> tuple[list[tuple[int, int]], dict[int, tuple[int, int]]]:
    header_start = data_start_offset - ccl_segb1.RECORD_HEADER_LENGTH
    row = _clip((header_start, data_start_offset + payload_size), file_len)
    raw_columns = {
        _V1_STATE: (header_start + 4, header_start + 8),
        _V1_TS1: (header_start + 8, header_start + 16),
        _V1_TS2: (header_start + 16, header_start + 24),
        _V1_CRC_STORED: (header_start + 24, header_start + 28),
        _V1_PAYLOAD_SIZE: (header_start, header_start + 4),
        _V1_PAYLOAD: (data_start_offset, data_start_offset + payload_size),
    }
    columns = {idx: clipped for idx, rng in raw_columns.items() if (clipped := _clip(rng, file_len)) is not None}
    return ([row] if row is not None else []), columns


def _v2_ranges(
    data_start_offset: int,
    trailer_offset: int,
    entry_end_offset: int,
    payload_size: int,
    file_len: int,
) -> tuple[list[tuple[int, int]], dict[int, tuple[int, int]]]:
    entry_data_end = ccl_segb2.HEADER_LENGTH + entry_end_offset
    trailer_end = trailer_offset + ccl_segb2.TRAILER_ENTRY_LENGTH
    raw_rows = [(data_start_offset, entry_data_end), (trailer_offset, trailer_end)]
    rows = [clipped for rng in raw_rows if (clipped := _clip(rng, file_len)) is not None]
    raw_columns = {
        _V2_STATE: (trailer_offset + 4, trailer_offset + 8),
        _V2_CREATION: (trailer_offset + 8, trailer_offset + 16),
        _V2_TRAILER_OFFSET: (trailer_offset, trailer_end),
        _V2_ENTRY_END: (trailer_offset, trailer_offset + 4),
        _V2_CRC_STORED: (data_start_offset, data_start_offset + 4),
        _V2_PAYLOAD: (
            data_start_offset + ccl_segb2.ENTRY_HEADER_LENGTH,
            data_start_offset + ccl_segb2.ENTRY_HEADER_LENGTH + payload_size,
        ),
    }
    columns = {idx: clipped for idx, rng in raw_columns.items() if (clipped := _clip(rng, file_len)) is not None}
    return rows, columns


@dataclass
class SegbCellLocator:
    """Byte-provenance lookup for one open SEGB v1/v2 file's decoded rows.

    *rows* must be segb_parser.py's own row lists (same order as
    _COLUMNS_V1/_COLUMNS_V2), keyed here by their position (0-based) -- the
    same value segb_parser.py threads through data["SEGB"]["rowids"] so a
    TableViewer row's _ROWID_ROLE lines up with this locator's lookup key.
    """

    file_bytes: bytes
    version: str  # "v1" or "v2"
    rows: list[list[Any]]
    _row_ranges: dict[int, list[tuple[int, int]]] = field(default_factory=dict, init=False)
    _col_ranges: dict[int, dict[int, tuple[int, int]]] = field(default_factory=dict, init=False)
    # Rows whose offsets couldn't be read, with why (see why_not_located).
    _row_failures: dict[int, ParseIssue] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        file_len = len(self.file_bytes)
        for idx, row in enumerate(self.rows):
            try:
                if self.version == "v1":
                    row_ranges, columns = _v1_ranges(int(row[1]), int(row[8]), file_len)
                elif self.version == "v2":
                    row_ranges, columns = _v2_ranges(
                        int(row[1]), int(row[4]), int(row[5]), int(row[9]), file_len
                    )
                else:
                    continue
            except (TypeError, ValueError, IndexError) as exc:
                self._row_failures[idx] = ParseIssue("locate.segb_record_offsets", detail=str(exc))
                continue
            if not row_ranges:
                continue
            self._row_ranges[idx] = row_ranges
            self._col_ranges[idx] = columns

    def default_file_kind(self) -> str:
        return _MAIN

    def why_not_located(self, table_name: str, row_key: Any) -> ParseIssue | None:  # noqa: ARG002
        """Why locate_cell() has nothing for *row_key*, when known."""
        return self._row_failures.get(row_key) if isinstance(row_key, int) else None

    def read_file(self, file_kind: str) -> bytes | None:  # noqa: ARG002
        return self.file_bytes

    def label_for(self, file_kind: str) -> str:  # noqa: ARG002
        return "segb file"

    def locate_cell(
        self, table_name: str, row_key: Any, col_idx: int | None
    ) -> CellLocation | None:
        if table_name != _TABLE or not isinstance(row_key, int):
            return None
        row_ranges = self._row_ranges.get(row_key)
        if row_ranges is None:
            return None
        column_ranges = None
        if col_idx is not None:
            col_range = self._col_ranges.get(row_key, {}).get(col_idx)
            if col_range is not None:
                column_ranges = [col_range]
        return CellLocation(file_kind=_MAIN, row_ranges=row_ranges, column_ranges=column_ranges)

    def locate_offset(
        self, table_name: str, file_kind: str, offset: int  # noqa: ARG002
    ) -> tuple[Any, int | None] | None:
        if table_name != _TABLE:
            return None
        for row_key, ranges in self._row_ranges.items():
            if not any(start <= offset < end for start, end in ranges):
                continue
            for col_idx, col_range in self._col_ranges.get(row_key, {}).items():
                if col_range[0] <= offset < col_range[1]:
                    return row_key, col_idx
            return row_key, None
        return None
