# SPDX-License-Identifier: Apache-2.0
"""Shared byte-provenance abstraction for TableViewer's embedded Hex pane.

TableViewer's "Show Hex" pane needs to answer two questions for whichever
data source it's showing: "where do this row/column's bytes actually live
on disk" (table -> hex) and "which row/column does this byte belong to"
(hex -> table). SQLite answers those by walking B-tree pages and WAL
frames (crush/core/sqlite_wal.py); Realm answers them by looking up byte
ranges captured while walking its own Cluster/pre-Cluster arrays
(crush/core/realm_offsets.py). Neither format's specifics belong in
TableViewer itself -- this module is the common interface both implement,
so the widget's hex-pane methods can stay format-agnostic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class CellLocation:
    """Where a row (and, if requested, one of its columns) currently lives
    on disk.

    *file_kind* is a locator-defined tag identifying which physical file
    the ranges are relative to (SQLite: "base"/"wal"; Realm: a single
    "main") -- see CellLocator.path_for()/label_for().
    """
    file_kind: str
    row_ranges: list[tuple[int, int]]
    column_ranges: list[tuple[int, int]] | None


class CellLocator(Protocol):
    """Implemented once per data source backing a TableViewer's hex pane."""

    def default_file_kind(self) -> str:
        """The file_kind to load before any cell has been selected yet."""
        ...

    def read_file(self, file_kind: str) -> bytes | None:
        """The full bytes *file_kind*'s ranges/offsets are relative to, or
        None if unreadable. Deliberately bytes, not a Path -- a locator's
        backing data need not be plain-path-addressable (e.g. Realm's
        source file may live inside a VFS-only archive), and a locator that
        already holds decoded bytes in memory (e.g. Realm, decrypted at
        parse time) shouldn't have to round-trip them through a temp file
        just to satisfy this interface.
        """
        ...

    def label_for(self, file_kind: str) -> str:
        """Short human label for *file_kind*, shown above the hex pane."""
        ...

    def locate_cell(
        self, table_name: str, row_key: Any, col_idx: int | None
    ) -> CellLocation | None:
        """Find a row's (and optionally one column's) exact byte range(s).
        Returns None if the row can't be resolved -- never a guess."""
        ...

    def locate_offset(
        self, table_name: str, file_kind: str, offset: int
    ) -> tuple[Any, int | None] | None:
        """Reverse of locate_cell(): resolve a byte *offset* (relative to
        *file_kind*) back to (row_key, column_index). Returns None if the
        offset can't be attributed to a row of *table_name* -- never a
        guess at a nearby/likely row."""
        ...


@dataclass
class RawBytesCellLocator:
    """Minimal CellLocator for a file opened standalone, with no schema/
    companion database to resolve a row back to its exact bytes against --
    e.g. a -wal or -journal file opened on its own (see
    sqlite_wal_parser.py / sqlite_journal_parser.py). Backs the embedded Hex
    pane with the file's own raw bytes so "Show Hex" has something to
    display.

    *row_ranges*, if given, maps a row index (the "rowids" list a caller
    puts alongside its table data -- see TableViewer's generic row
    population) to that row's own (start, end) byte range in *file_bytes*,
    e.g. one WAL frame's or journal record's exact span -- several rows can
    share the same range (several decoded cells from the same page/frame).
    Left as None (the default) when no such mapping is available, so
    locate_cell() honestly returns "can't resolve" rather than guessing.
    """
    file_bytes: bytes
    label: str
    row_ranges: dict[int, tuple[int, int]] | None = None

    def default_file_kind(self) -> str:
        return "base"

    def read_file(self, file_kind: str) -> bytes | None:  # noqa: ARG002
        return self.file_bytes

    def label_for(self, file_kind: str) -> str:  # noqa: ARG002
        return self.label

    def locate_cell(
        self, table_name: str, row_key: Any, col_idx: int | None  # noqa: ARG002
    ) -> CellLocation | None:
        if self.row_ranges is None or not isinstance(row_key, int):
            return None
        row_range = self.row_ranges.get(row_key)
        if row_range is None:
            return None
        return CellLocation(file_kind="base", row_ranges=[row_range], column_ranges=None)

    def locate_offset(
        self, table_name: str, file_kind: str, offset: int  # noqa: ARG002
    ) -> tuple[Any, int | None] | None:
        return None
