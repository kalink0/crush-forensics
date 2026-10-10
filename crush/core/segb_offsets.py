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



def _clip(rng: tuple[int, int], limit: int) -> tuple[int, int] | None:
    """Clamp *rng* to [0, limit) and drop it if that leaves nothing --
    truncated/corrupt SEGB files can carry offsets past the bytes actually
    read, and a wrong-but-plausible-looking range is worse than none."""
    start, end = max(rng[0], 0), min(rng[1], limit)
    return (start, end) if end > start else None


def _v1_ranges(
    data_start_offset: int, payload_size: int, file_len: int
) -> tuple[list[tuple[int, int]], dict[str, tuple[int, int]]]:
    header_start = data_start_offset - ccl_segb1.RECORD_HEADER_LENGTH
    row = _clip((header_start, data_start_offset + payload_size), file_len)
    raw_columns = {
        "Payload Size": (header_start, header_start + 4),
        "State": (header_start + 4, header_start + 8),
        "Timestamp1": (header_start + 8, header_start + 16),
        "Timestamp2": (header_start + 16, header_start + 24),
        "CRC Stored": (header_start + 24, header_start + 28),
        "Payload": (data_start_offset, data_start_offset + payload_size),
    }
    columns = {name: clipped for name, rng in raw_columns.items() if (clipped := _clip(rng, file_len)) is not None}
    return ([row] if row is not None else []), columns


def _v2_ranges(
    data_start_offset: int,
    trailer_offset: int,
    entry_end_offset: int,
    payload_size: int,
    file_len: int,
) -> tuple[list[tuple[int, int]], dict[str, tuple[int, int]]]:
    entry_data_end = ccl_segb2.HEADER_LENGTH + entry_end_offset
    trailer_end = trailer_offset + ccl_segb2.TRAILER_ENTRY_LENGTH
    raw_rows = [(data_start_offset, entry_data_end), (trailer_offset, trailer_end)]
    rows = [clipped for rng in raw_rows if (clipped := _clip(rng, file_len)) is not None]
    raw_columns = {
        "CRC Stored": (data_start_offset, data_start_offset + 4),
        "Payload": (
            data_start_offset + ccl_segb2.ENTRY_HEADER_LENGTH,
            data_start_offset + ccl_segb2.ENTRY_HEADER_LENGTH + payload_size,
        ),
        "Trailer Offset": (trailer_offset, trailer_end),
        "Entry End Offset": (trailer_offset, trailer_offset + 4),
        "State": (trailer_offset + 4, trailer_offset + 8),
        "Creation": (trailer_offset + 8, trailer_offset + 16),
    }
    columns = {name: clipped for name, rng in raw_columns.items() if (clipped := _clip(rng, file_len)) is not None}
    return rows, columns


@dataclass
class SegbCellLocator:
    """Byte-provenance lookup for one open SEGB v1/v2 file's decoded rows.

    *rows* must be segb_parser.py's own row lists, *columns* their column
    names (_COLUMNS_V1/_COLUMNS_V2; each value is found by its name, not a
    fixed position). Rows are keyed here by their position (0-based) -- the
    same value segb_parser.py threads through data["SEGB"]["rowids"] so a
    TableViewer row's _ROWID_ROLE lines up with this locator's lookup key.
    """

    file_bytes: bytes
    version: str  # "v1" or "v2"
    rows: list[list[Any]]
    columns: list[str]
    _row_ranges: dict[int, list[tuple[int, int]]] = field(default_factory=dict, init=False)
    _col_ranges: dict[int, dict[int, tuple[int, int]]] = field(default_factory=dict, init=False)
    # Rows whose offsets couldn't be read, with why (see why_not_located).
    _row_failures: dict[int, ParseIssue] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        file_len = len(self.file_bytes)
        col_index = {name: i for i, name in enumerate(self.columns)}
        for idx, row in enumerate(self.rows):
            try:

                def value(name: str, row: list[Any] = row) -> int:
                    return int(row[col_index[name]])

                if self.version == "v1":
                    row_ranges, named = _v1_ranges(
                        value("Offset"), value("Payload Size"), file_len
                    )
                elif self.version == "v2":
                    row_ranges, named = _v2_ranges(
                        value("Offset"),
                        value("Trailer Offset"),
                        value("Entry End Offset"),
                        value("Payload Size"),
                        file_len,
                    )
                else:
                    continue
                columns = {col_index[name]: rng for name, rng in named.items()}
            except (TypeError, ValueError, IndexError, KeyError) as exc:
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
