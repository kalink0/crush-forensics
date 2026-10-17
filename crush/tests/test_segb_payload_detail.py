# SPDX-License-Identifier: Apache-2.0
"""SEGB payload detail: the selected record's payload under the table,
decoded as the Protobuf viewer decodes a file -- every field with all its
candidate readings -- where the Payload column shows one reading per field
(marked as a heuristic)."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt

from crush.core.segb_offsets import SegbCellLocator
from crush.core.vfs import DirectoryVFS
from crush.parsers.segb_parser import SegbParser, SegbPayloadDetail
from crush.tests.conftest import FIXTURES_DIR


def _parse(tmp_path: Path) -> tuple[dict[str, Any], bytes]:
    shutil.copy(FIXTURES_DIR / "minimal.segb2", tmp_path / "minimal.segb2")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "minimal.segb2")
    return SegbParser().parse(node, vfs).data, (tmp_path / "minimal.segb2").read_bytes()


def test_detail_is_the_payload_bytes_with_every_reading(tmp_path: Path) -> None:
    data, raw = _parse(tmp_path)
    detail = data["__row_detail"].detail(0)
    start = detail["offset"]
    assert detail["raw"] == raw[start:start + len(detail["raw"])] and detail["raw"]
    (entry,) = detail["decoded"]["entries"]
    assert entry["field"] == 2 and "test" in str(entry["value"])
    assert detail["notes"] == []
    assert data["__row_detail"].detail(99) is None


def _with(data: dict[str, Any], raw: bytes, column: str, value: Any) -> SegbPayloadDetail:
    """The detail of record 0 with one of its row values replaced."""
    locator: SegbCellLocator = data["__cell_locator"]
    rows = [list(r) for r in locator.rows]
    rows[0][locator.columns.index(column)] = value
    return SegbPayloadDetail(SegbCellLocator(
        file_bytes=raw, version=locator.version, rows=rows, columns=locator.columns,
    ))


def test_a_payload_shorter_in_the_file_than_stated_says_so(tmp_path: Path) -> None:
    data, raw = _parse(tmp_path)
    size = int(data["__cell_locator"].rows[0][data["__cell_locator"].columns.index("Payload Size")])
    detail = _with(data, raw, "Payload Size", size + 1000).detail(0)
    # (the longer payload runs into the trailer's bytes, so the decode may
    # add its own warning beside this one)
    (note,) = [n for n in detail["notes"] if n.code == "segb.detail_payload_short"]
    assert note.params["stated"] == f"{size + 1000:,}"


def test_a_payload_wholly_past_the_file_end_says_none_is_there(tmp_path: Path) -> None:
    """Its offsets read fine: that is 0 bytes present, not unreadable offsets."""
    data, raw = _parse(tmp_path)
    detail = _with(data, raw, "Offset", len(raw) + 100).detail(0)
    assert detail["raw"] == b""
    (note,) = detail["notes"]
    assert note.code == "segb.detail_payload_short" and note.params["present"] == "0"


def test_a_payload_of_0_bytes_says_so(tmp_path: Path) -> None:
    data, raw = _parse(tmp_path)
    detail = _with(data, raw, "Payload Size", 0).detail(0)
    assert [n.code for n in detail["notes"]] == ["segb.detail_payload_empty"]


def test_unreadable_offsets_keep_their_reason(tmp_path: Path) -> None:
    data, raw = _parse(tmp_path)
    detail = _with(data, raw, "Offset", "not a number").detail(0)
    (note,) = detail["notes"]
    assert note.code == "segb.detail_no_payload"
    assert note.params["reason"].code == "locate.segb_record_offsets"


def test_selecting_a_row_shows_its_payload_tree(qapp: Any, widgets: Any, tmp_path: Path) -> None:
    from crush.viewers.protobuf_viewer import ProtobufTreeWidget
    from crush.viewers.table_viewer import TableViewer

    data, _raw = _parse(tmp_path)
    tv = widgets(TableViewer(data, show_db_tabs=False, source_name="minimal.segb2"))
    assert tv._row_detail_panel.isVisibleTo(tv)
    assert tv._row_detail_widget is None
    model = tv._table_view.model()
    col = next(c for c in range(model.columnCount())
               if model.headerData(c, Qt.Orientation.Horizontal) == "Payload")
    tv._table_view.setCurrentIndex(model.index(0, col))
    widget = tv._row_detail_widget
    assert isinstance(widget, ProtobufTreeWidget)
    assert widget._model.rowCount() == 1
    assert "at file offset" in tv._row_detail_label.text()

    # The same row again keeps the widget; no row clears it.
    tv._table_view.setCurrentIndex(model.index(0, 0))
    assert tv._row_detail_widget is widget


def test_viewers_without_row_detail_have_no_panel(qapp: Any, widgets: Any) -> None:
    from crush.viewers.table_viewer import TableViewer

    tv = widgets(TableViewer({"t": {"columns": ["a"], "rows": [[1]]}}))
    assert not tv._row_detail_panel.isVisibleTo(tv)
