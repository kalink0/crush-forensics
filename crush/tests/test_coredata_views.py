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
    # The plist parser's own "Format" row (its encoding) keeps precedence,
    # as for every plist; the knowledge shown is the model's.
    assert "NSManagedObjectModel" in str(meta["Forensic relevance"])
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
