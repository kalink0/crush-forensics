# SPDX-License-Identifier: Apache-2.0
"""CellLocator (crush/core/cell_locator.py) implementation for real .realm
files, backing TableViewer's embedded Hex pane when opened from RealmViewer.

Unlike SQLite there is no page/WAL split to resolve and no live re-walk
needed on each click: realm_parser.py already computes every cell's byte
range once, eagerly, while walking the file's own Cluster/pre-Cluster
arrays (see _decode_column_value_ranges and friends in realm_parser.py).
This module is just a lookup table over that already-computed data, keyed
the same way RealmViewer's TableViewer rows already are (ObjKey + the
displayed column position).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crush.core.cell_locator import CellLocation

_MAIN = "main"  # Realm has one physical file -- no base/WAL split to model.


def _normalize_ranges(value: Any) -> list[tuple[int, int]]:
    """A cell's stored range is either a single (start, end) tuple, a list
    of them (a value split across more than one physical array), or None."""
    if value is None:
        return []
    if isinstance(value, list):
        return [r for r in value if r is not None]
    return [value]


@dataclass
class RealmCellLocator:
    """Byte-provenance lookup for one open .realm file's decoded tables."""

    file_bytes: bytes
    _by_table: dict[str, dict[tuple[Any, int], list[tuple[int, int]]]] = field(
        default_factory=dict
    )

    def add_table(
        self, table_name: str, table: dict[str, Any], col_indices: list[int]
    ) -> None:
        """Register one parsed table's rows for lookup.

        *table* is the raw per-table dict realm_parser.py produced (with
        "obj_keys" and "byte_ranges"); *col_indices* is the same
        sorted(table["columns"].keys()) order realm_viewer.py's own
        _decode() helper uses to build the displayed grid, so a display
        column position here lines up with the TableViewer column the user
        actually clicks.
        """
        obj_keys: list[Any] = table.get("obj_keys") or []
        byte_ranges: dict[int, list[Any]] = table.get("byte_ranges") or {}
        lookup: dict[tuple[Any, int], list[tuple[int, int]]] = {}
        for row, obj_key in enumerate(obj_keys):
            if obj_key is None:
                continue
            for display_idx, real_idx in enumerate(col_indices):
                col_ranges = byte_ranges.get(real_idx)
                if col_ranges is None or row >= len(col_ranges):
                    continue
                ranges = _normalize_ranges(col_ranges[row])
                if ranges:
                    lookup[(obj_key, display_idx)] = ranges
        self._by_table[table_name] = lookup

    def default_file_kind(self) -> str:
        return _MAIN

    def read_file(self, file_kind: str) -> bytes | None:  # noqa: ARG002
        return self.file_bytes

    def label_for(self, file_kind: str) -> str:  # noqa: ARG002
        return "realm file"

    def locate_cell(
        self, table_name: str, row_key: Any, col_idx: int | None
    ) -> CellLocation | None:
        if col_idx is None:
            return None
        ranges = self._by_table.get(table_name, {}).get((row_key, col_idx))
        if not ranges:
            return None
        return CellLocation(file_kind=_MAIN, row_ranges=[], column_ranges=ranges)

    def locate_offset(
        self, table_name: str, file_kind: str, offset: int  # noqa: ARG002
    ) -> tuple[Any, int | None] | None:
        for (row_key, col_idx), ranges in self._by_table.get(table_name, {}).items():
            if any(start <= offset < end for start, end in ranges):
                return row_key, col_idx
        return None
