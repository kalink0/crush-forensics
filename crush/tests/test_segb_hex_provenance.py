# SPDX-License-Identifier: Apache-2.0
"""End-to-end regression coverage for SEGB's embedded Hex pane byte-
provenance, verifying the wiring through the actual TableViewer Qt widget
(not just crush/core/segb_offsets.py in isolation, see
test_segb_byte_ranges.py) -- mirrors test_realm_hex_provenance.py's
approach, including the lesson logged there: confirm the highlighted bytes
are the real source file's own bytes, not a synthetic re-encoding (SEGB
also carries a synthetic __db_path for SQL querying, which the Hex pane
must not fall back to now that __cell_locator is supplied).
"""
from __future__ import annotations

import struct
import zlib

from crush.core.segb_offsets import SegbCellLocator
from crush.core.vfs import BytesVFS
from crush.parsers.segb_parser import SegbParser
from crush.third_party.ccl_segb.ccl_segb2 import MAGIC as V2_MAGIC
from crush.third_party.ccl_segb.ccl_segb_common import EntryState
from crush.viewers.table_viewer import TableViewer


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


def _open_table_viewer(qapp, raw: bytes) -> tuple[TableViewer, bytes]:  # noqa: ARG001
    vfs = BytesVFS(raw, name="sample.segb2")
    node = vfs.root()
    result = SegbParser().parse(node, vfs)
    tv = TableViewer(result.data, source_name=node.name, **result.viewer_hints)
    tv.show()
    return tv, raw


def _select_cell(tv: TableViewer, row: int, column_name: str) -> None:
    headers = [
        tv._source_model.horizontalHeaderItem(c).text()
        for c in range(tv._source_model.columnCount())
    ]
    col_idx = headers.index(column_name)
    index = tv._proxy_model.mapFromSource(tv._source_model.index(row, col_idx))
    tv._table_view.setCurrentIndex(index)


def test_segb_table_viewer_uses_a_real_cell_locator(qapp) -> None:
    raw = _build_segb2([(b"hello world!", int(EntryState.Written))])
    tv, raw = _open_table_viewer(qapp, raw)

    assert isinstance(tv._cell_locator, SegbCellLocator)
    # Not the synthetic SQLite copy's path (__db_path, used only for SQL
    # querying) -- the previously-known footgun this closes, see
    # crush/core/segb_offsets.py and the corresponding fix for Realm.
    assert tv._cell_locator.file_bytes == raw


def test_segb_hex_pane_highlights_real_payload_bytes(qapp) -> None:
    raw = _build_segb2([(b"hello world!", int(EntryState.Written))])
    tv, raw = _open_table_viewer(qapp, raw)
    tv._toggle_hex_pane()
    _select_cell(tv, 0, "Payload")

    ranges = tv._hex_viewer._focus_ranges
    assert ranges
    highlighted = b"".join(raw[s:e] for s, e in ranges)
    assert b"hello world!" in highlighted


def test_segb_hex_offset_click_selects_matching_cell(qapp) -> None:
    raw = _build_segb2([(b"hello world!", int(EntryState.Written))])
    tv, raw = _open_table_viewer(qapp, raw)
    tv._toggle_hex_pane()
    _select_cell(tv, 0, "Payload")

    # The row's *combined* highlight (row_ranges + column_ranges) starts
    # earlier than the Payload column itself -- v2's row range includes the
    # entry's leading CRC header bytes. Click inside the Payload column's
    # own range specifically, not just the first highlighted byte overall.
    location = tv._cell_locator.locate_cell("SEGB", 0, tv._table_view.currentIndex().column() - 1)
    assert location is not None and location.column_ranges
    payload_offset = location.column_ranges[0][0]

    tv._on_hex_offset_focused(payload_offset)

    current = tv._table_view.currentIndex()
    headers = [
        tv._source_model.horizontalHeaderItem(c).text()
        for c in range(tv._source_model.columnCount())
    ]
    assert headers[current.column()] == "Payload"
