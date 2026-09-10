# SPDX-License-Identifier: Apache-2.0
"""End-to-end regression coverage for Realm's embedded Hex pane byte-
provenance (crush/core/realm_offsets.py, realm_parser.py's
_decode_column_value_ranges and friends): the previously-false claim that
this "worked for Realm too" (corrected in CHANGELOG.md) is now real --
these tests verify the highlighted ranges point at the actual .realm
file's own bytes, not a synthetic re-encoding.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QTabWidget

from crush.core.vfs import DirectoryVFS
from crush.parsers.realm_parser import RealmParser
from crush.viewers.realm_viewer import RealmViewer
from crush.viewers.table_viewer import TableViewer

_FIXTURES = Path(__file__).parent / "fixtures"


def _open_all_types_table_viewer(qapp) -> TableViewer:  # noqa: ARG001 -- qapp starts the QApplication
    fixture = _FIXTURES / "all_types_v24.realm"
    vfs = DirectoryVFS(fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == fixture.name)
    result = RealmParser().parse(node, vfs)

    viewer = RealmViewer(result.data)
    tabs = viewer.findChild(QTabWidget)
    assert tabs is not None
    tables_tab = next(
        tabs.widget(i) for i in range(tabs.count()) if tabs.tabText(i) == "Tables"
    )
    assert isinstance(tables_tab, TableViewer)
    # _sync_hex_pane() is gated on the hex panel's real Qt visibility, which
    # requires the whole ancestor chain (including the tab actually being
    # the QTabWidget's current one) to be shown -- not just its own
    # setVisible(True) flag.
    tabs.setCurrentWidget(tables_tab)
    viewer.show()
    return tables_tab


def _select_cell(tv: TableViewer, table_name: str, row: int, column_name: str) -> None:
    tv._table_combo.setCurrentText(table_name)
    headers = [
        tv._source_model.horizontalHeaderItem(c).text()
        for c in range(tv._source_model.columnCount())
    ]
    col_idx = headers.index(column_name)
    index = tv._proxy_model.mapFromSource(tv._source_model.index(row, col_idx))
    tv._table_view.setCurrentIndex(index)


def test_realm_table_viewer_uses_a_real_cell_locator(qapp) -> None:
    tv = _open_all_types_table_viewer(qapp)
    from crush.core.realm_offsets import RealmCellLocator

    assert isinstance(tv._cell_locator, RealmCellLocator)
    # Not the synthetic SQLite copy's path -- that's __db_path, used only
    # for querying/sorting, never as the Hex pane's byte source anymore.
    assert tv._cell_locator.file_bytes == (_FIXTURES / "all_types_v24.realm").read_bytes()


def test_realm_hex_pane_highlights_real_string_bytes(qapp) -> None:
    tv = _open_all_types_table_viewer(qapp)
    tv._toggle_hex_pane()  # loads + shows the pane
    _select_cell(tv, "class_AllTypesRecord", 0, "stringCol")

    ranges = tv._hex_viewer._focus_ranges
    assert ranges
    raw_file = (_FIXTURES / "all_types_v24.realm").read_bytes()
    # Row range is empty for Realm (no whole-row concept the way SQLite has
    # one) -- every range here comes from column_ranges, so the highlighted
    # bytes must decode to exactly this cell's real string content.
    highlighted = b"".join(raw_file[s:e] for s, e in ranges)
    assert highlighted.rstrip(b"\x00").decode("utf-8") == "hello world"


def test_realm_hex_pane_highlights_real_uuid_bytes(qapp) -> None:
    tv = _open_all_types_table_viewer(qapp)
    tv._toggle_hex_pane()
    _select_cell(tv, "class_AllTypesRecord", 0, "uuidCol")

    ranges = tv._hex_viewer._focus_ranges
    assert ranges
    raw_file = (_FIXTURES / "all_types_v24.realm").read_bytes()
    highlighted = b"".join(raw_file[s:e] for s, e in ranges)
    assert highlighted.hex() == "550e8400e29b41d4a716446655440000"


def test_realm_hex_offset_click_selects_matching_cell(qapp) -> None:
    tv = _open_all_types_table_viewer(qapp)
    tv._toggle_hex_pane()
    _select_cell(tv, "class_AllTypesRecord", 0, "objectIdCol")
    ranges = tv._hex_viewer._focus_ranges
    assert ranges

    tv._on_hex_offset_focused(ranges[0][0])

    current = tv._table_view.currentIndex()
    headers = [
        tv._source_model.horizontalHeaderItem(c).text()
        for c in range(tv._source_model.columnCount())
    ]
    assert headers[current.column()] == "objectIdCol"
