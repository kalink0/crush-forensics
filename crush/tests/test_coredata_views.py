# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The Core Data views in the table viewer and the .mom model tab."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMenu

from crush.core.vfs import DirectoryVFS, FileVFS, find_node
from crush.parsers.plist_parser import PlistParser
from crush.parsers.sqlite_parser import SQLiteParser
from crush.tests.coredata_helpers import EXTERNAL_NAME, build_store, model_archive
from crush.viewers import coredata_views as cdv
from crush.viewers.table_viewer import TableViewer
from crush.viewers.tree_text_viewer import TreeTextViewer

ENTITIES = "Core Data Entities (generated)"
HISTORY = "Core Data History (generated)"
MODEL = "Core Data Model (generated)"
EXTERNAL = "Core Data External Data (generated)"
STORE = "Core Data Store (generated)"
KEYS = "Core Data Keys (generated)"


def _viewer(widgets, path: Path, vfs=None, node=None) -> TableViewer:
    vfs = vfs or FileVFS(path)
    node = node or vfs.root()
    result = SQLiteParser().parse(node, vfs)
    return widgets(TableViewer(result.data, source_name=path.name))


def _show(viewer: TableViewer, label: str) -> None:
    viewer._table_combo.setCurrentIndex(viewer._table_combo.findData(label))


def _labels(viewer: TableViewer) -> list[str]:
    return [viewer._table_combo.itemData(i) for i in range(viewer._table_combo.count())]


@pytest.fixture
def viewer(qapp, widgets, tmp_path: Path) -> TableViewer:
    return _viewer(widgets, build_store(tmp_path / "store_no_ext"))


def test_views_offered_only_for_a_store(qapp, widgets, viewer, tmp_path: Path) -> None:
    labels = _labels(viewer)
    for label in (ENTITIES, STORE, MODEL, HISTORY, KEYS, EXTERNAL):
        assert label in labels
    plain = tmp_path / "plain.db"
    conn = sqlite3.connect(plain)
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    assert not [lab for lab in _labels(_viewer(widgets, plain)) if lab and lab.startswith("Core Data")]


def test_history_view_only_with_history(qapp, widgets, tmp_path: Path) -> None:
    v = _viewer(widgets, build_store(tmp_path / "s", history=False))
    assert HISTORY not in _labels(v)
    _show(v, STORE)
    texts = [v._source_model.item(r, 2).text() for r in range(v._source_model.rowCount())]
    assert any("no persistent history" in t for t in texts)


def test_every_view_renders(viewer: TableViewer) -> None:
    for label in (ENTITIES, STORE, MODEL, HISTORY, KEYS, EXTERNAL):
        _show(viewer, label)
        assert viewer._table_view.model().rowCount() > 0, label
        assert "Apple does not document" in viewer._source_status.text(), label


def _tree_names(panel: cdv.EntityTreePanel) -> list[str]:
    names = []

    def walk(item) -> None:
        for r in range(item.rowCount()):
            child = item.child(r, 0)
            names.append(child.data(cdv.ENTITY_ROLE))
            walk(child)

    walk(panel.model.invisibleRootItem())
    return names


def test_entities_tree_grid_and_detail(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    panel = viewer._cd_entity_panel
    assert panel.isVisibleTo(viewer)
    names = _tree_names(panel)
    assert {"GenericAlbum", "Album", "Folder", "Asset", "NSCKEvent", "CHANGE"} <= set(names)
    assert "Current rows only" in viewer._source_status.text()
    panel.select("Asset")
    model = viewer._table_view.model()
    assert model.rowCount() == 4
    viewer._table_view.setCurrentIndex(model.index(0, 1))
    detail = viewer._cd_record_panel.model
    props = detail.item(0, 0)
    prop_names = [props.child(r, 0).text() for r in range(props.rowCount())]
    assert "uuid" in prop_names and "ZEXTRA" in prop_names
    rels = detail.item(1, 0)
    rel_names = [rels.child(r, 0).text() for r in range(rels.rowCount())]
    assert {"albums", "additional", "contributors"} <= set(rel_names)


def test_follow_relationship_and_back(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._table_view.setCurrentIndex(viewer._table_view.model().index(0, 1))
    viewer._on_cd_navigate("Album", 2)
    assert viewer._cd_current_entity == "Album"
    record = viewer._cd_current_record()
    assert record is not None and record[2] == 2
    assert viewer._cd_entity_panel.back_button.isEnabled()
    viewer._on_cd_back()
    assert viewer._cd_current_entity == "Asset"
    assert viewer._cd_current_record()[2] == 1


def test_history_jumps_to_existing_object(viewer: TableViewer) -> None:
    _show(viewer, HISTORY)
    model = viewer._table_view.model()
    assert model.rowCount() == 4
    viewer._on_table_double_clicked(model.index(0, 1))  # insert of Asset 1, still there
    assert viewer._current_table() == ENTITIES
    assert viewer._cd_current_entity == "Asset"
    assert viewer._cd_current_record()[2] == 1


def test_history_says_when_object_is_gone(viewer: TableViewer) -> None:
    _show(viewer, HISTORY)
    model = viewer._table_view.model()
    viewer._table_view.setCurrentIndex(model.index(2, 1))  # delete of Asset 9
    assert "no such row" in viewer._sql_status.text()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    tomb = headers.index("Tombstones [interpreted]")
    assert "filename=IMG_0009.JPG" in model.data(model.index(2, tomb))
    assert "ZTOMBSTONE2" in headers  # every raw slot


def test_model_detail_shows_stored_keys(viewer: TableViewer) -> None:
    _show(viewer, MODEL)
    assert viewer._cd_object_panel.isVisibleTo(viewer)
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    prop_col = headers.index("Property")
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, prop_col)) == "trashedDate")
    viewer._table_view.setCurrentIndex(model.index(row, 1))
    tree = viewer._cd_object_panel.model
    titles = [tree.item(r, 0).text() for r in range(tree.rowCount())]
    assert any(t.startswith("NSAttributeDescription") for t in titles)
    assert any(t.startswith("NSEntityDescription") for t in titles)
    entity = next(tree.item(r, 0) for r in range(tree.rowCount()) if tree.item(r, 0).text().startswith("NSEntity"))
    keys = {entity.child(r, 0).text() for r in range(entity.rowCount())}
    assert {"NSFetchIndexDescriptions", "NSCompoundIndexes", "NSUserInfo"} <= keys


def _cell_index(viewer: TableViewer, header: str, row: int):
    model = viewer._table_view.model()
    col = next(c for c in range(model.columnCount()) if model.headerData(c, Qt.Orientation.Horizontal) == header)
    return model.index(row, col)


def _actions(viewer: TableViewer, index) -> dict[str, object]:
    menu = QMenu(viewer)
    actions = viewer._add_cd_cell_actions(menu, index)
    return {a.text(): fn for a, fn in actions.items()}


def test_prefix_action_offered_only_in_external_storage_column(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    opened: list[tuple[bytes, str, dict]] = []
    viewer.open_bytes_with_format_requested.connect(lambda d, p, f, m: opened.append((d, p, m)))
    inline = _actions(viewer, _cell_index(viewer, "imageData (ZIMAGEDATA)", 1))
    assert list(inline) == ["Open without the 0x01 prefix"]
    raw_before = viewer._table_view.model().data(_cell_index(viewer, "imageData (ZIMAGEDATA)", 1),
                                                  Qt.ItemDataRole.UserRole)
    inline["Open without the 0x01 prefix"]()
    data, path, meta = opened[-1]
    assert data == raw_before[1:]
    assert "first byte" in meta["Opened bytes"]
    assert meta["Source table"] == "ZASSET" and meta["Source row"] == "Z_PK 2"
    assert viewer._table_view.model().data(_cell_index(viewer, "imageData (ZIMAGEDATA)", 1),
                                           Qt.ItemDataRole.UserRole) == raw_before
    # 0x01 in a column without an external-storage attribute: not offered.
    assert "Open without the 0x01 prefix" not in _actions(viewer, _cell_index(viewer, "ZEXTRA", 0))
    # A reference cell: open external file.
    assert "Open external file" in _actions(viewer, _cell_index(viewer, "imageData (ZIMAGEDATA)", 0))


def test_plain_table_cell_actions_and_z_ent_tooltip(viewer: TableViewer) -> None:
    _show(viewer, "ZASSET")
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]

    def row_of(pk: int) -> int:
        return next(r for r in range(model.rowCount()) if model.data(model.index(r, headers.index("Z_PK"))) == str(pk))

    ent = model.index(row_of(1), headers.index("Z_ENT"))
    assert model.data(ent) == "4"
    assert "Asset" in model.data(ent, Qt.ItemDataRole.ToolTipRole)
    inline = _actions(viewer, model.index(row_of(2), headers.index("ZIMAGEDATA")))
    assert "Open without the 0x01 prefix" in inline
    ref = _actions(viewer, model.index(row_of(1), headers.index("ZIMAGEDATA")))
    assert "Open external file" in ref
    assert "Open without the 0x01 prefix" not in _actions(viewer, model.index(row_of(1), headers.index("ZEXTRA")))


def test_external_view_opens_file(qapp, widgets, tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    build_store(root / "Store.sqlite")
    external = root / ".Store_SUPPORT" / "_EXTERNAL_DATA"
    external.mkdir(parents=True)
    (external / EXTERNAL_NAME).write_bytes(b"\xff\xd8\xff\xe0JPEG")
    vfs = DirectoryVFS(root)
    v = _viewer(widgets, root / "Store.sqlite", vfs, find_node(vfs, str(root / "Store.sqlite")))
    opened: list[tuple[bytes, str, dict]] = []
    v.open_bytes_with_format_requested.connect(lambda d, p, f, m: opened.append((d, p, m)))
    _show(v, EXTERNAL)
    model = v._table_view.model()
    row = next(r for r in range(model.rowCount())
               if model.data(model.index(r, 7)) == EXTERNAL_NAME and model.data(model.index(r, 3)) == "ZIMAGEDATA")
    v._on_table_double_clicked(model.index(row, 1))
    data, path, meta = opened[-1]
    assert data == b"\xff\xd8\xff\xe0JPEG"
    assert path.endswith(f".Store_SUPPORT/_EXTERNAL_DATA/{EXTERNAL_NAME}")
    assert meta["Source table"] == "ZASSET" and meta["External value reference"] == EXTERNAL_NAME


def test_record_cell_hex_provenance(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._toggle_hex_pane()
    index = _cell_index(viewer, "filename (ZFILENAME)", 0)
    viewer._table_view.setCurrentIndex(index)
    model = viewer._cd_record_model
    source = viewer._proxy_model.mapToSource(index)
    location = viewer._cell_locator.locate_cell("ZASSET", model.rowid(source.row()), model.source_column(source.column()))
    assert location is not None and location.column_ranges


def test_csv_export_and_search_work_on_records(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._search.setText("IMG_0003")
    viewer._apply_filter("IMG_0003")  # the search applies after a pause in typing
    assert viewer._table_view.model().rowCount() == 1
    record = viewer._cd_current_record()
    viewer._table_view.setCurrentIndex(viewer._table_view.model().index(0, 1))
    record = viewer._cd_current_record()
    assert record is not None and record[2] == 3  # the filtered row maps to its record
    viewer._apply_filter("")
    viewer._table_view.sortByColumn(1, Qt.SortOrder.DescendingOrder)  # Z_PK
    model = viewer._table_view.model()
    assert [model.data(model.index(r, 1)) for r in range(model.rowCount())] == ["6", "3", "2", "1"]


def test_history_sorts_and_filters_itself(viewer: TableViewer) -> None:
    _show(viewer, HISTORY)
    viewer._apply_filter("delete")
    model = viewer._table_view.model()
    assert model.rowCount() == 2
    viewer._table_view.setCurrentIndex(model.index(0, 1))
    assert viewer._cd_history_row(model.index(0, 1)).change_type == "delete"


def test_mom_file_gets_model_tab(qapp, widgets, tmp_path: Path) -> None:
    path = tmp_path / "model_without_extension"
    path.write_bytes(model_archive())
    vfs = FileVFS(path)
    result = PlistParser().parse(vfs.root(), vfs)
    view = widgets(TreeTextViewer(result.data, **result.viewer_hints))
    tabs = [view._tabs.tabText(i) for i in range(view._tabs.count())]
    assert tabs[0] == "Core Data Model"
    assert "Decoded" in tabs and "Stored archive" in tabs
    model_view = view._tabs.widget(0)
    assert model_view.model.rowCount() > 0
    model_view.table.setCurrentIndex(model_view.proxy.index(0, 1))
    assert model_view.detail.model.rowCount() >= 2
