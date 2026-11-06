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
        assert "Apple does not document" not in viewer._source_status.text(), label


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
    tomb = headers.index("Tombstones [derived]")
    assert "filename = IMG_0009.JPG (heuristic)" in model.data(model.index(2, tomb))
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
    inline = _actions(viewer, _cell_index(viewer, "imageData (ZIMAGEDATA) [heuristic]", 1))
    assert list(inline) == ["Open without the 0x01 prefix (heuristic: byte pattern)"]
    raw_before = viewer._table_view.model().data(_cell_index(viewer, "imageData (ZIMAGEDATA) [heuristic]", 1),
                                                  Qt.ItemDataRole.UserRole)
    inline["Open without the 0x01 prefix (heuristic: byte pattern)"]()
    data, path, meta = opened[-1]
    assert data == raw_before[1:]
    assert "first byte" in meta["Opened bytes"]
    assert meta["Source table"] == "ZASSET" and meta["Source row"] == "Z_PK 2"
    assert viewer._table_view.model().data(_cell_index(viewer, "imageData (ZIMAGEDATA) [heuristic]", 1),
                                           Qt.ItemDataRole.UserRole) == raw_before
    # 0x01 in a column without an external-storage attribute: not offered.
    assert "Open without the 0x01 prefix (heuristic: byte pattern)" not in _actions(viewer, _cell_index(viewer, "ZEXTRA", 0))
    # A reference cell: open external file.
    assert "Open external file (heuristic: byte pattern)" in _actions(viewer, _cell_index(viewer, "imageData (ZIMAGEDATA) [heuristic]", 0))


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
    assert "Open without the 0x01 prefix (heuristic: byte pattern)" in inline
    ref = _actions(viewer, model.index(row_of(1), headers.index("ZIMAGEDATA")))
    assert "Open external file (heuristic: byte pattern)" in ref
    assert "Open without the 0x01 prefix (heuristic: byte pattern)" not in _actions(viewer, model.index(row_of(1), headers.index("ZEXTRA")))


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
    index = _cell_index(viewer, "filename (ZFILENAME) [heuristic]", 0)
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


# -- review fixes ------------------------------------------------------------------

STORE_NOTE = (
    'Some links in these views are heuristic, not stored in the file. Rows marked "heuristic" '
    "show where; check the raw values for important findings."
)


def _status_lines(viewer: TableViewer) -> list[str]:
    text = viewer._source_status.text()
    return text.split("\n") if viewer._source_status.isVisibleTo(viewer) and text else []


def test_each_view_shows_only_its_sentence_and_conditional_statuses(viewer: TableViewer) -> None:
    store = viewer._coredata
    _show(viewer, STORE)
    assert _status_lines(viewer) == [STORE_NOTE]
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    assert _status_lines(viewer) == ["Current rows only. Deleted data may be in other views."]
    viewer._cd_entity_panel.select("NSCKEvent")  # a conditional status of this entity
    assert _status_lines(viewer) == [
        "Current rows only. Deleted data may be in other views.", "not in the model: column names only",
    ]
    _show(viewer, MODEL)
    assert _status_lines(viewer) == [str(i) for i in store.model_issues]  # only this model's states
    _show(viewer, HISTORY)
    assert _status_lines(viewer) == ["What the ZCOLUMNS bits stand for is unknown."]
    _show(viewer, KEYS)
    assert _status_lines(viewer) == ["These numbers don't show why keys are missing."]
    _show(viewer, EXTERNAL)
    # A store file opened on its own: the folder state is a state of this source.
    assert _status_lines(viewer) == [str(store.support.status())]
    assert viewer._sql_status.text() == ""


def test_filtered_out_record_is_shown_not_reported_missing(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._search.setText("IMG_0003")
    viewer._apply_filter("IMG_0003")
    assert viewer._table_view.model().rowCount() == 1
    assert viewer._cd_select_pk(1)
    assert "no such row" not in viewer._sql_status.text()
    assert viewer._cd_current_record()[2] == 1
    assert not viewer._cd_select_pk(999)
    assert "no such row" in viewer._sql_status.text()


def _detail_row(viewer: TableViewer, name: str):
    props = viewer._cd_record_panel.model.item(0, 0)
    row = next(r for r in range(props.rowCount()) if props.child(r, 0).text() == name)
    return [props.child(row, c) for c in range(7)]


def test_ambiguous_candidates_each_open_their_complete_bytes(qapp, widgets, tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    blob = bytes(range(40))
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ZGENERICALBUM SET ZMAXIMUMVALUE1 = ? WHERE Z_PK = 2", (blob,))
    conn.commit()
    conn.close()
    v = _viewer(widgets, path)
    _show(v, ENTITIES)
    v._cd_entity_panel.select("Album")
    v._table_view.setCurrentIndex(v._table_view.model().index(0, 1))
    row = _detail_row(v, "maximumValue")
    assert row[6].text().startswith("ambiguous")
    # The candidates are what the analyst compares: shown without a click.
    assert v._cd_record_panel.tree.isExpanded(row[0].index())
    children = {row[0].child(r, 0).text(): row[0].child(r, 0) for r in range(row[0].rowCount())}
    assert set(children) == {"ZMAXIMUMVALUE", "ZMAXIMUMVALUE1"}
    assert children["ZMAXIMUMVALUE1"].data(cdv.BYTES_ROLE) == blob
    raw_text = row[0].child(list(children).index("ZMAXIMUMVALUE1"), 4).text()
    assert "preview" in raw_text  # longer than shown: labelled, the row opens all of it
    opened: list[tuple[bytes, str]] = []
    v._cd_record_panel.openBytesRequested.connect(lambda d, c: opened.append((d, c)))
    v._cd_record_panel._on_double_clicked(children["ZMAXIMUMVALUE1"].index())
    assert opened == [(blob, "ZMAXIMUMVALUE1")]


def test_inspected_value_provenance_names_the_sql_column(viewer: TableViewer, monkeypatch) -> None:
    import crush.viewers.table_viewer as tv

    seen: list[dict] = []

    class _Inspector:
        def __init__(self, data, parent, artifact_path="", provenance=None, **_kw) -> None:
            seen.append({"path": artifact_path, **(provenance or {})})

        def show(self) -> None:
            pass

    monkeypatch.setattr(tv, "BlobInspector", _Inspector)
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._table_view.setCurrentIndex(viewer._table_view.model().index(0, 1))
    viewer._on_cd_open_value(b"\x00", "ZUUID")
    assert seen[-1]["Source column"] == "ZUUID"
    assert "/ZUUID/" in seen[-1]["path"]


def test_every_heuristic_is_marked_in_its_row_with_its_raw_value(viewer: TableViewer) -> None:
    # Entities: linked and decoded columns say so in their header, the stored column is next to it.
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    assert "uuid [derived, heuristic]" in headers and "uuid (ZUUID) [heuristic]" in headers
    assert headers.index("uuid (ZUUID) [heuristic]") == headers.index("uuid [derived, heuristic]") + 1
    assert "ZEXTRA" in headers  # no link, no marker
    # Entities detail: the value's row, its Raw column, the relationship's link.
    viewer._table_view.setCurrentIndex(model.index(0, 1))
    uuid_row = _detail_row(viewer, "uuid")
    assert uuid_row[6].text() == "heuristic: name match"
    assert uuid_row[4].text().startswith("<BLOB 16 B> 7b 08")
    rels = viewer._cd_record_panel.model.item(1, 0)
    albums = next(rels.child(r, 6).text() for r in range(rels.rowCount()) if rels.child(r, 0).text() == "albums")
    assert albums == "heuristic: Z_2ASSETS"
    additional = next(rels.child(r, c).text() for r in range(rels.rowCount()) for c in (6,)
                      if rels.child(r, 0).text() == "additional")
    assert additional == "heuristic: ZADDITIONAL"
    # Model: the mapping status and the table, on the property's row.
    _show(viewer, MODEL)
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    row = next(r for r in range(model.rowCount())
               if model.data(model.index(r, headers.index("Property"))) == "uuid"
               and model.data(model.index(r, headers.index("Entity"))) == "Asset")
    assert model.data(model.index(row, headers.index("Mapping status"))) == "heuristic: name match"
    assert model.data(model.index(row, headers.index("Column candidates"))) == "ZUUID"
    assert model.data(model.index(row, headers.index("Root table"))) == "ZASSET (heuristic)"
    # History: the tombstone cell, with every raw slot next to it.
    _show(viewer, HISTORY)
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    tomb = model.data(model.index(2, headers.index("Tombstones [derived]")))
    assert "uuid = 1FF60740-AAAA-4BBB-8CCC-DDDDEEEEFFFF (heuristic)" in tomb
    assert model.data(model.index(2, headers.index("ZTOMBSTONE1")), Qt.ItemDataRole.UserRole) is not None
    assert "Time (UTC) [derived, heuristic]" in headers
    # External Data: the byte pattern, with the complete stored cell.
    _show(viewer, EXTERNAL)
    model = viewer._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, 1)) == "reference")
    assert model.data(model.index(row, headers.index("Recognised by"))) == "heuristic: byte pattern"
    raw = model.data(model.index(row, headers.index("Raw")), Qt.ItemDataRole.UserRole)
    assert isinstance(raw, bytes) and len(raw) == 38
    # Store: the folder rule.
    _show(viewer, STORE)
    notes = [viewer._source_model.item(r, 3).text() for r in range(viewer._source_model.rowCount())]
    assert "heuristic: folder name" in notes


def _enriched(widgets, parser, node, vfs, result) -> dict:
    from crush.ui.main_window import MainWindow

    win = widgets(MainWindow())
    return dict(win._enrich_with_format_info(parser, node, vfs, result).metadata)


def test_properties_show_core_data_knowledge_whatever_the_name(qapp, widgets, tmp_path: Path) -> None:
    store_path = build_store(tmp_path / "no_name")
    vfs = FileVFS(store_path)
    result = SQLiteParser().parse(vfs.root(), vfs)
    meta = _enriched(widgets, SQLiteParser(), vfs.root(), vfs, result)
    result.data["__coredata"].close()
    assert meta["Format"] == "Core Data Store"
    assert "persistent history" in str(meta["Forensic relevance"])
    assert meta["Base format"] == "SQLite Database"  # SQLite knowledge stays reachable
    assert "WAL" in str(meta["Base format relevance"])
    assert meta["Core Data"].code == "coredata.detected"
    assert "Format (identified)" not in meta
    mom = tmp_path / "blob_without_extension"
    mom.write_bytes(model_archive())
    vfs = FileVFS(mom)
    meta = _enriched(widgets, PlistParser(), vfs.root(), vfs, PlistParser().parse(vfs.root(), vfs))
    # Format row and format knowledge name the same format; how the plist
    # is stored keeps its own row.
    assert meta["Format"] == "Core Data Model"
    assert "NSManagedObjectModel" in str(meta["Forensic relevance"])
    assert meta["Plist format"]  # binary, resolved or not
    assert meta["Core Data model"].code == "coredata.mom_model"
    assert meta["Base format"] == "Binary Property List"


def test_ordinary_sqlite_and_plist_unchanged(qapp, widgets, tmp_path: Path) -> None:
    import plistlib

    from crush.core.format_db import FormatDatabase

    plain = tmp_path / "plain.db"
    conn = sqlite3.connect(plain)
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    vfs = FileVFS(plain)
    meta = _enriched(widgets, SQLiteParser(), vfs.root(), vfs, SQLiteParser().parse(vfs.root(), vfs))
    assert meta["Format"] == "SQLite Database"
    assert "Base format" not in meta and "Format (identified)" not in meta and "Format (specific)" not in meta
    plist = tmp_path / "plain.plist"
    plist.write_bytes(plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY))
    vfs = FileVFS(plist)
    peek = plist.read_bytes()[:512]
    expected = FormatDatabase.get().for_parser("PlistParser", peek)
    meta = _enriched(widgets, PlistParser(), vfs.root(), vfs, PlistParser().parse(vfs.root(), vfs))
    assert len(expected) == 1
    assert str(meta["Forensic relevance"]) == expected[0].forensic_relevance
    assert "Base format" not in meta and "Format (identified)" not in meta


def test_unknown_specific_format_falls_back_with_status(qapp, widgets, tmp_path: Path) -> None:
    from crush.parsers.base import ParseResult

    path = build_store(tmp_path / "s")
    vfs = FileVFS(path)
    result = ParseResult("table", {}, format_short_name="No Such Format")
    meta = _enriched(widgets, SQLiteParser(), vfs.root(), vfs, result)
    assert meta["Format (specific)"].code == "entry.format_entry_missing"
    assert meta["Format"] == "SQLite Database"


def test_format_info_uses_the_open_parse_else_the_bytes(qapp, widgets, tmp_path: Path, monkeypatch) -> None:
    import crush.ui.format_info_dialog as fid
    from crush.ui.main_window import MainWindow
    from PySide6.QtWidgets import QWidget

    shown: list[str | None] = []

    class _Dialog:
        def __init__(self, node, fmt, parent, candidates) -> None:
            shown.append(fmt.name if fmt is not None else None)

        def exec(self) -> int:
            return 0

    monkeypatch.setattr(fid, "FormatInfoDialog", _Dialog)

    def no_open(*_a, **_kw):
        raise AssertionError("Format Info must not open the database")

    monkeypatch.setattr(SQLiteParser, "parse", no_open)
    path = build_store(tmp_path / "s")
    vfs = FileVFS(path)
    node = vfs.root()
    win = widgets(MainWindow())
    win._show_format_info(node, vfs)
    assert shown[-1] == "SQLite Database"  # not open: the bytes alone
    tab = QWidget()
    tab.setProperty("crush_path", node.path)
    tab.setProperty("crush_vfs", vfs)
    tab.setProperty("crush_format_short_name", "Core Data Store")
    win._viewer_tabs.addTab(tab, "s")
    win._show_format_info(node, vfs)
    assert shown[-1] == "Core Data Store"  # open: the format its parse found


def test_relationship_shows_a_stored_null_and_its_bytes(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    model = viewer._table_view.model()
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, 1)) == "3")
    viewer._table_view.setCurrentIndex(model.index(row, 1))
    rels = viewer._cd_record_panel.model.item(1, 0)
    additional = next(r for r in range(rels.rowCount()) if rels.child(r, 0).text() == "additional")
    assert rels.child(additional, 4).text() == "NULL"  # stored NULL, not an empty cell
    albums = next(r for r in range(rels.rowCount()) if rels.child(r, 0).text() == "albums")
    assert rels.child(albums, 4).text() == ""  # to-many: no key stored in this row


# -- full branch review ------------------------------------------------------------

FREEBLOCKS = "Freeblocks (generated)"


def _headers(viewer: TableViewer) -> list[str]:
    model = viewer._table_view.model()
    return [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]


def _select_record(viewer: TableViewer, entity: str, pk: int) -> None:
    viewer._cd_entity_panel.select(entity)
    model = viewer._table_view.model()
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, 1)) == str(pk))
    viewer._table_view.setCurrentIndex(model.index(row, 1))


def test_detail_column_is_named_stored(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    _select_record(viewer, "Asset", 1)
    detail = viewer._cd_record_panel.model
    headers = [detail.horizontalHeaderItem(c).text() for c in range(detail.columnCount())]
    assert headers[4] == "Stored" and "Raw" not in headers


def test_failed_record_read_clears_the_grid(viewer: TableViewer, monkeypatch) -> None:
    _show(viewer, ENTITIES)
    _select_record(viewer, "Asset", 1)
    assert viewer._table_view.model().rowCount() == 4
    store = viewer._coredata
    real = store.load_records

    def failing(name, conn=None):
        if name == "Album":
            raise RuntimeError("disk I/O error")
        return real(name, conn)

    monkeypatch.setattr(store, "load_records", failing)
    viewer._cd_entity_panel.select("Album")
    assert viewer._table_view.model().rowCount() == 0  # never Asset's rows under Album
    assert viewer._cd_record_model is None
    assert viewer._cd_current_entity == "Album"
    assert "Reading the records of Album failed" in viewer._sql_status.text()
    assert "disk I/O error" in viewer._sql_status.text()
    assert "Asset" not in viewer._row_count_label.text()
    assert viewer._cd_detail_record is None


def test_failed_history_read_clears_the_grid(viewer: TableViewer, monkeypatch) -> None:
    _show(viewer, KEYS)
    assert viewer._table_view.model().rowCount() > 0

    def failing(conn=None):
        raise RuntimeError("database disk image is malformed")

    monkeypatch.setattr(viewer._coredata, "load_history", failing)
    _show(viewer, HISTORY)
    assert viewer._table_view.model().rowCount() == 0
    assert "Reading the Core Data history failed" in viewer._sql_status.text()
    assert viewer._cd_history_cache is None  # read again next time


def test_history_with_hex_after_freeblocks_highlights_nothing(viewer: TableViewer, monkeypatch) -> None:
    from PySide6.QtGui import QStandardItem

    import crush.viewers.table_viewer as tv

    _show(viewer, FREEBLOCKS)
    # A Freeblocks row with its own byte range, whatever the store holds.
    item = QStandardItem("1")
    item.setData("db", tv._STRUCTURE_FILE_KIND_ROLE)
    item.setData((0, 16), tv._STRUCTURE_BYTE_RANGE_ROLE)
    viewer._source_model.appendRow([item])
    highlighted: list[object] = []
    monkeypatch.setattr(viewer, "_highlight_stashed_byte_ranges", lambda *a: highlighted.append(a))
    monkeypatch.setattr(viewer, "_highlight_located_cell", lambda *a: highlighted.append(a))
    viewer._toggle_hex_pane()
    _show(viewer, HISTORY)
    assert viewer._source_model.rowCount() == 0  # the previous view's rows are gone
    model = viewer._table_view.model()
    for row in range(model.rowCount()):
        viewer._table_view.setCurrentIndex(model.index(row, 1))
    assert highlighted == []
    for label in (STORE, MODEL, KEYS, EXTERNAL):
        _show(viewer, label)
        viewer._table_view.setCurrentIndex(viewer._table_view.model().index(0, 1))
    assert highlighted == []


def test_query_then_entity_leaves_query_mode(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._sql_input.setPlainText("SELECT 1 AS a")
    viewer._run_sql()
    assert viewer._query_results_active
    _select_record(viewer, "Album", 2)
    assert not viewer._query_results_active
    index = _cell_index(viewer, "name (ZNAME) [heuristic]", 0)
    assert viewer._cd_cell_context(index) is not None  # the Core Data actions stay
    _path, meta = viewer._virtual_cell_path_and_metadata(index, "name (ZNAME) [heuristic]")
    assert "Source query" not in meta
    assert meta["Source table"] == "ZGENERICALBUM" and meta["Source row"] == "Z_PK 2"


def test_provenance_names_the_rows_own_entity(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    _select_record(viewer, "GenericAlbum", 2)  # an Album row under its parent
    index = _cell_index(viewer, "title (ZTITLE) [heuristic]", viewer._table_view.currentIndex().row())
    _path, meta = viewer._virtual_cell_path_and_metadata(index, "title")
    assert meta["Core Data entity"] == "Album"
    # A plain table's cell: the entity of that row's Z_ENT, not the tree's.
    _show(viewer, "ZGENERICALBUM")
    model = viewer._table_view.model()
    headers = _headers(viewer)
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, headers.index("Z_PK"))) == "3")
    cell = viewer._cd_cell_context(model.index(row, headers.index("ZTITLE")))
    assert cell.entity == "Folder"
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, headers.index("Z_PK"))) == "1")
    assert viewer._cd_cell_context(model.index(row, headers.index("ZTITLE"))).entity == "GenericAlbum"


def test_row_without_z_pk_is_named_by_rowid(viewer: TableViewer, monkeypatch) -> None:
    _show(viewer, "plain_notes")
    seen: list[dict] = []
    monkeypatch.setattr(viewer, "_open_cd_file", lambda file, meta, status: seen.append(meta))
    model = viewer._table_view.model()
    headers = _headers(viewer)
    actions = _actions(viewer, model.index(0, headers.index("ref")))
    actions["Open external file (heuristic: byte pattern)"]()
    assert seen[-1]["Source row"] == "rowid 1"
    assert "None" not in seen[-1]["Source row"]
    path, meta = viewer._cd_provenance("plain_notes", "ref", None, 1)
    assert path.endswith("/rowid 1") and meta["Source row"] == "rowid 1"


def test_derived_and_stored_cells_have_their_own_paths(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    _select_record(viewer, "Asset", 1)
    row = viewer._table_view.currentIndex().row()
    paths = {}
    for header in ("hidden [derived, heuristic]", "hidden (ZHIDDEN) [heuristic]",
                   "dateCreated [derived, heuristic]", "dateCreated (ZDATECREATED) [heuristic]",
                   "entity [derived]", "Z_ENT"):
        paths[header] = viewer._virtual_cell_path_and_metadata(_cell_index(viewer, header, row), header)[0]
    assert len(set(paths.values())) == len(paths)
    assert paths["hidden [derived, heuristic]"].startswith(paths["hidden (ZHIDDEN) [heuristic]"] + "/derived-")
    # The entity name of two different records: two paths.
    _select_record(viewer, "Album", 2)
    album_entity = viewer._virtual_cell_path_and_metadata(
        _cell_index(viewer, "entity [derived]", viewer._table_view.currentIndex().row()), "entity [derived]",
    )[0]
    assert album_entity != paths["entity [derived]"]


def test_panel_keeps_its_record_after_a_filter_reset(viewer: TableViewer, monkeypatch) -> None:
    from PySide6.QtCore import QModelIndex

    import crush.viewers.table_viewer as tv

    seen: list[dict] = []

    class _Inspector:
        def __init__(self, data, parent, artifact_path="", provenance=None, **_kw) -> None:
            seen.append(provenance or {})

        def show(self) -> None:
            pass

    monkeypatch.setattr(tv, "BlobInspector", _Inspector)
    _show(viewer, ENTITIES)
    _select_record(viewer, "Asset", 1)
    viewer._search.setText("IMG_0003")
    viewer._apply_filter("IMG_0003")
    viewer._table_view.setCurrentIndex(QModelIndex())  # the reset cleared the selection
    assert viewer._cd_current_record() is None
    viewer._on_cd_open_value(b"\x00", "ZUUID")
    assert seen[-1]["Source row"] == "Z_PK 1"
    viewer._on_cd_navigate("Album", 2)
    assert viewer._cd_back_stack[-1] == ("Asset", 1)
    viewer._on_cd_back()
    assert viewer._cd_current_entity == "Asset"
    assert "no such row" not in viewer._sql_status.text()
    assert "Album" not in viewer._sql_status.text()  # no status left from the previous step
    assert viewer._cd_current_record()[2] == 1


def test_row_count_follows_the_filter(viewer: TableViewer) -> None:
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    viewer._search.setText("IMG_0003")
    viewer._apply_filter("IMG_0003")
    label = viewer._row_count_label.text()
    assert "(1 of 4 rows)" in label and label.startswith("Asset · table ZASSET")
    viewer._cd_entity_panel.select("Album")  # entering with the filter active
    assert "of 1 row" in viewer._row_count_label.text()
    viewer._search.setText("delete")
    _show(viewer, HISTORY)
    assert viewer._row_count_label.text() == "(2 of 4 rows)"


def test_exports_are_english_whatever_the_ui_language(viewer: TableViewer, monkeypatch) -> None:
    import crush.viewers.generated_text as gt

    from crush.viewers.generated_text import EXPORT_TEXT_ROLE

    monkeypatch.setattr(gt, "gen_text", lambda english: f"[{english}]")
    _show(viewer, HISTORY)
    model = viewer._table_view.model()
    tomb = next(c for c in range(model.columnCount())
                if model.headerData(c, Qt.Orientation.Horizontal, EXPORT_TEXT_ROLE) == "Tombstones [derived]")
    index = model.index(2, tomb)
    assert model.data(index).startswith("[")  # shown in the (pseudo) UI language
    exported = model.data(index, EXPORT_TEXT_ROLE)
    assert "filename = IMG_0009.JPG (heuristic)" in exported and "[" not in exported.split(";")[0]
    _show(viewer, EXTERNAL)
    model = viewer._table_view.model()
    col = next(c for c in range(model.columnCount())
               if model.headerData(c, Qt.Orientation.Horizontal, EXPORT_TEXT_ROLE) == "Recognised by")
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, col)))
    assert model.data(model.index(row, col), EXPORT_TEXT_ROLE).startswith("heuristic: byte pattern")


def test_history_status_counted_only_without_rows(viewer: TableViewer, monkeypatch) -> None:
    calls: list[int] = []
    real = viewer._coredata.history_status
    monkeypatch.setattr(viewer._coredata, "history_status", lambda conn=None: calls.append(1) or real(conn))
    _show(viewer, HISTORY)
    assert viewer._table_view.model().rowCount() == 4
    assert calls == []


def test_history_gap_cells_say_why(qapp, widgets, tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO ACHANGE (Z_PK, Z_ENT, Z_OPT, ZCHANGETYPE, ZENTITY, ZENTITYPK, ZTRANSACTIONID) "
                 "VALUES (5, 16001, 1, 7, 4, 1, 99)")
    conn.commit()
    conn.close()
    v = _viewer(widgets, path)
    _show(v, HISTORY)
    model = v._table_view.model()
    headers = _headers(v)
    row = next(r for r in range(model.rowCount()) if model.data(model.index(r, headers.index("Z_PK"))) == "5")
    time = model.data(model.index(row, headers.index("Time (UTC) [derived, heuristic]")))
    assert "no row Z_PK 99 in ATRANSACTION" in time
    assert "no row Z_PK 99" in model.data(model.index(row, headers.index("Author")))
    assert "ZCHANGETYPE 7" in model.data(model.index(row, headers.index("Change type [derived]")))


def test_failed_count_shows_its_reason_and_is_retried(viewer: TableViewer, monkeypatch) -> None:
    def failing(conn=None):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(viewer._coredata, "row_counts", failing)
    _show(viewer, ENTITIES)
    panel = viewer._cd_entity_panel
    asset = panel._items["Asset"]
    rows_cell = asset.parent().child(asset.row(), 1) if asset.parent() else panel.model.item(asset.row(), 1)
    assert "rows not counted" in rows_cell.text() and "database is locked" in rows_cell.text()
    assert viewer._cd_counts is None
    monkeypatch.undo()
    _show(viewer, STORE)
    _show(viewer, ENTITIES)
    asset = panel._items["Asset"]
    assert panel.model.item(asset.row(), 1).text() == "4"


def test_unresolved_relationship_summary_and_candidates(qapp, widgets, tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    blob = bytes(range(40))
    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE ZGENERICALBUM ADD COLUMN ZPARENTFOLDER1 BLOB")
    conn.execute("UPDATE ZGENERICALBUM SET ZPARENTFOLDER1 = ? WHERE Z_PK = 2", (blob,))
    conn.commit()
    conn.close()
    v = _viewer(widgets, path)
    _show(v, ENTITIES)
    _select_record(v, "Album", 2)
    rels = v._cd_record_panel.model.item(1, 0)
    row = next(r for r in range(rels.rowCount()) if rels.child(r, 0).text() == "parentFolder")
    summary = rels.child(row, 3).text()
    assert "(preview)" in summary and "double-click" not in summary  # this row has no bytes
    candidate = rels.child(row, 0)
    texts = [candidate.child(r, 4).text() for r in range(candidate.rowCount())]
    assert any("double-click for all" in t for t in texts)  # the candidate rows open them
    # Candidates in another table: named with their table, no value from this row.
    folder_rels = None
    _select_record(v, "Folder", 3)
    folder_rels = v._cd_record_panel.model.item(1, 0)
    child_albums = next(r for r in range(folder_rels.rowCount()) if folder_rels.child(r, 0).text() == "childAlbums")
    assert folder_rels.child(child_albums, 5).text() == "ZGENERICALBUM: ZPARENTFOLDER, ZPARENTFOLDER1"
    assert folder_rels.child(child_albums, 3).text() == "—"
    assert folder_rels.child(child_albums, 0).rowCount() == 0


def test_formats_db_names_the_real_parsers(qapp, widgets, tmp_path: Path) -> None:
    from crush.core.format_db import FormatDatabase

    db = FormatDatabase.get()
    assert db.by_short_name("Core Data Store").parser_class == "SQLiteParser"
    assert db.by_short_name("Core Data Model").parser_class == "PlistParser"
    path = build_store(tmp_path / "s")
    peek = path.read_bytes()[:4096]
    assert [f.short_name for f in db.for_parser("SQLiteParser", peek)] == ["SQLite"]


def _run_query(viewer: TableViewer) -> None:
    viewer._sql_input.setPlainText("SELECT 1 AS a UNION ALL SELECT 2")
    viewer._run_sql()
    assert viewer._query_results_active


def test_query_results_never_drive_core_data_row_actions(viewer: TableViewer, monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(viewer, "_open_cd_external_row", lambda *a: calls.append("external"))
    monkeypatch.setattr(viewer, "_update_cd_object_detail", lambda *a: calls.append("model"))
    monkeypatch.setattr(viewer, "_on_cd_history_activated", lambda *a, **k: calls.append("history"))
    monkeypatch.setattr(viewer, "_update_cd_record_detail", lambda *a: calls.append("record"))
    for label in (EXTERNAL, MODEL, HISTORY, ENTITIES):
        _show(viewer, label)
        calls.clear()
        _run_query(viewer)
        for row in range(2):
            index = viewer._table_view.model().index(row, 1)
            viewer._table_view.setCurrentIndex(index)
            viewer._on_table_double_clicked(index)
        assert calls == [], label
        assert not viewer._cd_rows_shown(label)
        assert viewer._cd_record_cell(viewer._table_view.model().index(0, 1)) is None


def test_rows_shown_only_for_the_views_own_rows(viewer: TableViewer, monkeypatch) -> None:
    _show(viewer, EXTERNAL)
    assert viewer._cd_rows_shown(EXTERNAL) and not viewer._cd_rows_shown(MODEL)
    _show(viewer, HISTORY)
    assert viewer._cd_rows_shown(HISTORY)
    _show(viewer, ENTITIES)
    viewer._cd_entity_panel.select("Asset")
    assert viewer._cd_rows_shown(ENTITIES)
    monkeypatch.setattr(viewer._coredata, "load_records", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    viewer._cd_entity_panel.select("Album")  # a failed read: an empty grid, no rows of the view
    assert not viewer._cd_rows_shown(ENTITIES)


def test_status_reset_after_a_successful_read(viewer: TableViewer, monkeypatch) -> None:
    _show(viewer, ENTITIES)
    store = viewer._coredata
    real = store.load_records
    monkeypatch.setattr(store, "load_records", lambda name, conn=None: (
        (_ for _ in ()).throw(RuntimeError("disk I/O error")) if name == "Album" else real(name, conn)
    ))
    viewer._cd_entity_panel.select("Album")
    assert "failed" in viewer._sql_status.text() and "red" in viewer._sql_status.styleSheet()
    viewer._cd_entity_panel.select("Asset")
    assert viewer._sql_status.text() == "" and viewer._sql_status.styleSheet() == ""
    # A later message is never red because of an earlier one.
    viewer._sql_status.setStyleSheet("color: red;")
    viewer._cd_select_pk(999)
    assert "no such row" in viewer._sql_status.text() and viewer._sql_status.styleSheet() == ""


def test_failed_read_on_opening_entities_reads_once(viewer: TableViewer, monkeypatch) -> None:
    calls: list[str] = []

    def failing(name, conn=None):
        calls.append(name)
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(viewer._coredata, "load_records", failing)
    _show(viewer, ENTITIES)
    assert len(calls) == 1
    assert "Reading the records of" in viewer._sql_status.text()


def test_unresolved_relationship_without_candidates_has_no_dangling_prefix(qapp, widgets, tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE ZCONTRIBUTOR DROP COLUMN Z4CONTRIBUTORS")
    conn.commit()
    conn.close()
    v = _viewer(widgets, path)
    _show(v, ENTITIES)
    _select_record(v, "Asset", 1)
    rels = v._cd_record_panel.model.item(1, 0)
    row = next(r for r in range(rels.rowCount()) if rels.child(r, 0).text() == "contributors")
    assert rels.child(row, 5).text() == ""  # no "ZCONTRIBUTOR: " with nothing after it
    assert "Z4CONTRIBUTORS" in rels.child(row, 6).text()  # the status says what is missing


def test_core_data_headers_are_in_the_catalog() -> None:
    """Every header is found by lupdate (no QT_TRANSLATE_NOOP alias)."""
    import crush.viewers.coredata_views as views
    import crush.viewers.table_viewer as table

    root = Path(views.__file__).parents[1]
    catalog = (root / "i18n" / "crush_de.ts").read_text(encoding="utf-8")
    for header in ("Model flag", "File status", "Missing key values", "UUID / file", "Raw", "Recognised by"):
        assert f"<source>{header}</source>" in catalog, header
    for module in (views, table):
        assert "= QT_TRANSLATE_NOOP\n" not in Path(module.__file__).read_text(encoding="utf-8")


def test_omo_is_not_yet_supported_but_opens_and_is_named(qapp, widgets, tmp_path: Path) -> None:
    """Recognised, not decoded: the catalog says "Not yet supported", the
    file still opens with its status, Properties and Format Info name it."""
    from PySide6.QtWidgets import QLabel

    from crush.core.format_db import FormatDatabase
    from crush.parsers.coredata_omo_parser import CoreDataOmoParser
    from crush.ui.format_info_dialog import FormatInfoDialog

    fmt = FormatDatabase.get().by_short_name("Core Data OMO")
    assert fmt.parser_class is None
    omo = tmp_path / "omo_without_extension"
    omo.write_bytes(b"momv2$sr" + bytes(64))
    vfs = FileVFS(omo)
    result = CoreDataOmoParser().parse(vfs.root(), vfs)
    assert result.viewer_type == "hex"
    assert result.metadata["Status"].code == "coredata.omo_not_decoded"
    meta = _enriched(widgets, CoreDataOmoParser(), vfs.root(), vfs, result)
    # The parser's Format row (it wins over the catalog's) names the format
    # and that it isn't decoded; the catalog's knowledge is next to it.
    assert meta["Format"].code == "coredata.omo_not_decoded"
    assert "Optimized Core Data model" in str(meta["Format"])
    assert "momv2$sr" in str(meta["Forensic relevance"])
    assert FormatDatabase.get().identify(omo.read_bytes(), "") is fmt
    dialog = widgets(FormatInfoDialog(vfs.root(), fmt, None, []))
    texts = [label.text() for label in dialog.findChildren(QLabel)]
    assert "Not yet supported" in texts and "Supported" not in texts
