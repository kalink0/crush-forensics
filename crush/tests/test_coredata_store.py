# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Core Data stores on SQLite: detection, model, mapping, records,
relationships, history, keys and externally stored values
(crush/parsers/coredata_store.py through SQLiteParser)."""
from __future__ import annotations

import io
import plistlib
import sqlite3
import tarfile
import zipfile
from pathlib import Path

import pytest

from crush.core.vfs import DirectoryVFS, FileVFS, TarVFS, ZipVFS, find_node
from crush.parsers import coredata_store as cds
from crush.parsers.coredata_omo_parser import CoreDataOmoParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.sqlite_parser import SQLiteParser
from crush.tests.coredata_helpers import (
    ASSET_UUID,
    DELETED_UUID,
    EXTERNAL_NAME,
    MISSING_NAME,
    build_store,
    model_archive,
    reference,
)


def _parse(path: Path):
    vfs = FileVFS(path)
    return SQLiteParser().parse(vfs.root(), vfs)


def _store(path: Path) -> cds.CoreDataStore:
    result = _parse(path)
    store = result.data["__coredata"]
    return store


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    return build_store(tmp_path / "evidence_without_extension")


@pytest.fixture
def store(store_path: Path):
    s = _store(store_path)
    yield s
    s.close()


# -- detection ---------------------------------------------------------------


def test_detected_by_content_whatever_the_name(store_path: Path) -> None:
    result = _parse(store_path)
    assert isinstance(result.data["__coredata"], cds.CoreDataStore)
    assert result.metadata["Core Data"].code == "coredata.detected"
    result.data["__coredata"].close()


def test_partial_markers_give_status_and_no_store(tmp_path: Path) -> None:
    path = tmp_path / "partial.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER, Z_NAME VARCHAR, Z_SUPER INTEGER)")
    conn.execute("CREATE TABLE ZTHING (Z_PK INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    result = _parse(path)
    assert "__coredata" not in result.data
    status = result.metadata["Core Data"]
    assert status.code == "coredata.detection_incomplete"
    assert "Z_PRIMARYKEY.Z_MAX" in status.params["missing"]
    assert "Z_METADATA" in status.params["missing"]


def test_plain_sqlite_file_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "plain.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (a, b)")
    conn.execute("INSERT INTO t VALUES (1, 'x')")
    conn.commit()
    conn.close()
    result = _parse(path)
    assert "__coredata" not in result.data
    assert "Core Data" not in result.metadata
    assert result.data["t"]["rows"] == [[1, "x"]]


def test_plain_tables_of_a_store_stay_as_stored(store_path: Path) -> None:
    result = _parse(store_path)
    table = result.data["ZASSET"]
    assert table["columns"][:3] == ["Z_PK", "Z_ENT", "Z_OPT"]
    first = table["rows"][0]
    assert first[table["columns"].index("ZUUID")] == ASSET_UUID.bytes
    assert first[table["columns"].index("ZDATECREATED")] == 786092798.4
    result.data["__coredata"].close()


# -- model ---------------------------------------------------------------------


def test_model_read_with_unknown_class_and_type(store) -> None:
    assert store.model is not None
    assert store.model_status.code == "coredata.model_read"
    codes = {i.code for i in store.model_issues}
    assert {"coredata.unknown_attribute_type", "coredata.model_unknown_class"} <= codes
    contributor = store.model.entities["Contributor"]
    future = next(p for p in contributor.properties if p.name == "futureThing")
    assert future.kind == "NSSomeFutureDescription" and not future.known_class
    rows = store.model_rows()
    assert any(r.prop is future for r in rows)
    weird = next(r for r in rows if r.prop.name == "weird")
    assert weird.prop.attribute_type == 4242 and weird.prop.type_name() is None


@pytest.mark.parametrize("model, code", [
    ("drop", "coredata.model_cache_missing"),
    (None, "coredata.model_cache_empty"),
    (b"\x00\x01garbage-not-deflate", "coredata.model_not_decompressible"),
])
def test_model_cache_problems_give_status_and_tables_open(tmp_path: Path, model, code) -> None:
    path = build_store(tmp_path / "s", model=model)
    result = _parse(path)
    store = result.data["__coredata"]
    assert store.model is None
    assert store.model_status.code == code
    assert result.data["ZASSET"]["rows"]
    # Without a model: column names and declared types, still every entity.
    records = store.load_records("Asset")
    assert len(records.rows) == 4
    headers = [g.header for g in records.grid]
    assert "ZDATECREATED [date]" in headers
    store.close()


def test_model_not_a_keyed_archive(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s", model=cds_deflate(plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)))
    store = _store(path)
    assert store.model is None
    assert store.model_status.code == "coredata.model_not_keyed_archive"
    store.close()


def cds_deflate(data: bytes) -> bytes:
    from crush.tests.coredata_helpers import deflate

    return deflate(data)


def test_proxies_for_inherited_properties(tmp_path: Path) -> None:
    store = _store(build_store(tmp_path / "s", proxy_inherited=True))
    album = store.model.entities["Album"]
    inherited = next(p for p in album.properties if p.name == "uuid")
    assert inherited.via_class == "_NSPropertyDescriptionProxy"
    assert inherited.class_name == "NSAttributeDescription" and inherited.attribute_type == 1100
    assert not [i for i in store.model_issues if i.code == "coredata.model_unknown_class"
                and i.params["property"] == "uuid"]
    names = [p.name for p in store.model.all_properties("Album")]
    assert names.count("uuid") == 1
    store.close()


def test_detail_shows_every_stored_key(store) -> None:
    asset = store.model.entities["Asset"]
    nodes = store.describe(asset.index)
    keys = {n.key for n in nodes}
    assert {"NSProperties", "NSFetchIndexDescriptions", "NSCompoundIndexes", "NSUserInfo",
            "NSVersionHashModifier", "NSRenamingIdentifier", "NSSubentities", "NSSuperentity"} <= keys
    # A reference back into the cyclic graph is shown, not expanded forever.
    props = next(n for n in nodes if n.key == "NSProperties")
    assert props.children and all(c.ref is not None for c in props.children)


# -- tables and mapping ---------------------------------------------------------


def test_subentity_shares_root_table_and_a_prefix_for_internal(store) -> None:
    assert store.entity("Album").table == "ZGENERICALBUM"
    assert store.entity("Folder").table == "ZGENERICALBUM"
    assert store.entity("CHANGE").table == "ACHANGE"
    assert store.entity("NSCKEvent").table == "ANSCKEVENT"


def test_mapping_statuses(store) -> None:
    album = store.model.entity("Album")
    max_value = next(p for p in album.properties if p.name == "maximumValue")
    link = store.column_link("Album", max_value)
    assert link.status == cds.MAP_AMBIGUOUS
    assert link.candidates == ("ZMAXIMUMVALUE", "ZMAXIMUMVALUE1")
    title = next(p for p in store.model.entity("Asset").properties if p.name == "title")
    assert store.column_link("Asset", title).status == cds.MAP_NO_COLUMN
    uuid_prop = next(p for p in store.model.entity("Asset").properties if p.name == "uuid")
    assert store.column_link("Asset", uuid_prop) == cds.ColumnLink(cds.MAP_NAME_MATCH, ("ZUUID",))


def test_numbered_column_of_another_property_is_not_a_candidate() -> None:
    link = cds.link_columns("value", ["ZVALUE", "ZVALUE1"], {"ZVALUE", "ZVALUE1"})
    assert link == cds.ColumnLink(cds.MAP_NAME_MATCH, ("ZVALUE",))


# -- entities and values ---------------------------------------------------------


def test_every_primarykey_entity_present_including_internal(store) -> None:
    names = {e.name for e in store.entities}
    assert {"GenericAlbum", "Album", "Folder", "Asset", "CHANGE", "TRANSACTION", "NSCKEvent"} <= names
    assert store.entity_status("NSCKEvent").code == "coredata.entity_not_in_model"
    records = store.load_records("NSCKEvent")
    assert len(records.rows) == 1
    # Declared TIMESTAMP decodes without a model.
    started = next(g for g in records.grid if g.decode == cds.DECODE_DATE)
    text, _ = store.cell_text(records, records.rows[0], started)
    assert text.endswith("UTC")


def test_parent_shows_subentity_rows_and_subentity_only_its_own(store) -> None:
    counts = store.row_counts()
    assert store.entity_row_count("GenericAlbum", counts) == 3
    assert store.entity_row_count("Album", counts) == 1
    parent = store.load_records("GenericAlbum")
    entity_col = next(g for g in parent.grid if g.is_entity_name)
    names = [store.cell_text(parent, r, entity_col)[0] for r in parent.rows]
    assert names == ["GenericAlbum", "Album", "Folder"]
    album = store.load_records("Album")
    assert [r[0] for r in album.rows] == [2]


def test_no_row_cap(tmp_path: Path) -> None:
    store = _store(build_store(tmp_path / "big", asset_rows=10_050))
    assert len(store.load_records("Asset").rows) == 10_050
    store.close()


def _cell(store, records, row_pk, header):
    row = next(r for r in records.rows if r[0] == row_pk)
    col = next(g for g in records.grid if g.header == header)
    return store.cell_text(records, row, col)


def test_value_decoding_by_type(store) -> None:
    assets = store.load_records("Asset")
    assert _cell(store, assets, 1, "uuid") == (str(ASSET_UUID).upper(), None)
    text, status = _cell(store, assets, 2, "uuid")
    assert text == "<BLOB 2 B>" and status.code == "coredata.value_not_uuid"
    assert _cell(store, assets, 1, "hidden") == ("true", None)
    assert _cell(store, assets, 2, "hidden") == ("false", None)
    text, status = _cell(store, assets, 3, "hidden")
    assert text == "5" and status.code == "coredata.value_not_boolean"
    # Raw value next to every decoded one.
    assert _cell(store, assets, 1, "hidden (ZHIDDEN)") == ("1", None)
    assert _cell(store, assets, 1, "dateCreated")[0] == "2025-11-29 07:06:38.4 UTC"
    assert _cell(store, assets, 2, "dateCreated")[0] == "2025-11-29 07:06:38 UTC"  # integer
    albums = store.load_records("GenericAlbum")
    text, status = _cell(store, albums, 2, "trashedDate")
    assert text == "2001-01-01 00:00:00 UTC" and status.code == "coredata.date_zero"
    assert _cell(store, albums, 2, "trashedDate (ZTRASHEDDATE)")[0] == "0"
    # Ambiguous: candidates as stored, nothing decoded.
    headers = [g.header for g in albums.grid]
    assert any(h.startswith("ZMAXIMUMVALUE (candidate:") for h in headers)
    assert any(h.startswith("ZMAXIMUMVALUE1 (candidate:") for h in headers)


def test_date_not_a_number_keeps_raw() -> None:
    text, status = cds.decode_value(cds.DECODE_DATE, "not a date")
    assert text is None and status.code == "coredata.value_not_date"


def test_property_values_list_unassigned_and_missing(store) -> None:
    assets = store.load_records("Asset")
    values = {v.name: v for v in store.property_values(assets, assets.rows[0])}
    assert values["title"].status.code == "coredata.mapping_no_column"
    assert values["ZEXTRA"].kind == "column" and values["ZEXTRA"].status.code == "coredata.column_unassigned"
    assert values["imageData"].status.code == "coredata.external_reference"
    albums = store.load_records("Album")
    values = {v.name: v for v in store.property_values(albums, albums.rows[0])}
    assert values["maximumValue"].status.code == "coredata.mapping_ambiguous"
    assert values["maximumValue"].columns == ("ZMAXIMUMVALUE", "ZMAXIMUMVALUE1")


def test_timestamp_portable(store) -> None:
    # epoch + timedelta: a negative value before 1970 decodes on every platform.
    text, status = cds.decode_value(cds.DECODE_DATE, -1_000_000_000)
    assert status is None and text.startswith("1969-")


# -- relationships -------------------------------------------------------------------


def _rels(store, entity, pk):
    records = store.load_records(entity)
    row = next(r for r in records.rows if r[0] == pk)
    return {r.name: r for r in store.relationship_values(records, row)}


def test_relationship_kinds(store) -> None:
    rels = _rels(store, "Asset", 1)
    assert rels["additional"].rule.kind == "to-one column" and rels["additional"].rule.resolved
    assert [t.pk for t in rels["additional"].targets] == [1]
    assert rels["albums"].rule.kind == "join table"
    assert rels["albums"].rule.table == "Z_2ASSETS"
    assert [t.pk for t in rels["albums"].targets] == [2]
    assert rels["contributors"].rule.kind == "destination column"
    assert [t.pk for t in rels["contributors"].targets] == [1]
    album = _rels(store, "Album", 2)
    # Ordered many-to-many: by Z_FOK_4ASSETS.
    assert album["assets"].rule.order_column == "Z_FOK_4ASSETS"
    assert [t.pk for t in album["assets"].targets] == [3, 1]
    assert album["parentFolder"].targets[0].pk == 3 and album["parentFolder"].targets[0].entity == "Folder"
    folder = _rels(store, "Folder", 3)
    assert folder["childAlbums"].rule.kind == "inverse column"
    assert folder["childAlbums"].rule.order_column == "Z_FOK_PARENTFOLDER"
    assert [t.pk for t in folder["childAlbums"].targets] == [2]


def test_relationship_missing_target_and_unresolved(store) -> None:
    rels = _rels(store, "Asset", 2)
    assert rels["additional"].stored == 99
    assert not rels["additional"].targets[0].exists
    assert rels["additional"].status.code == "coredata.rel_target_missing"
    albums = _rels(store, "Album", 2)
    unresolved = albums["assetsKey"]  # to-one column ZASSETSKEY exists -> resolved, NULL
    assert unresolved.rule.resolved and unresolved.targets == []
    rule = store.relationship_rule("Asset", cds.ModelProperty(
        index=-1, class_name="NSRelationshipDescription", kind="relationship", known_class=True,
        name="nowhere", entity="Asset", destination="Album", max_count=1,
    ))
    assert not rule.resolved and rule.reason.code == "coredata.mapping_no_column"


def test_reflexive_join_table_unresolved(tmp_path: Path) -> None:
    store = _store(build_store(tmp_path / "s"))
    conn = sqlite3.connect(tmp_path / "s")
    conn.close()
    prop = cds.ModelProperty(index=-1, class_name="NSRelationshipDescription", kind="relationship",
                             known_class=True, name="peers", entity="Contributor", destination="Contributor",
                             inverse="peers", max_count=0)
    store.tables["Z_6PEERS"] = [("Z_6PEERS", "INTEGER"), ("REFLEXIVE", "INTEGER")]
    store._table_by_upper["Z_6PEERS"] = "Z_6PEERS"
    store.model.entities["Contributor"].properties.append(prop)
    rule = store.relationship_rule("Contributor", prop)
    assert rule.reason.code == "coredata.rel_reflexive"
    store.close()


# -- history ----------------------------------------------------------------------


def test_history_rows_resolved_and_tombstones(store) -> None:
    result = store.load_history()
    assert [r.change_type for r in result.rows] == ["insert", "update", "delete", "delete"]
    first = result.rows[0]
    assert first.strings["bundle"] == (1, "com.example.app", None)
    assert first.strings["process"][1] == "exampled"
    assert first.timestamp == "2025-11-29 07:06:38.4 UTC"
    assert first.target_exists is True
    update = result.rows[1]
    assert update.columns_bits == (0, 2, 8)
    delete = result.rows[2]
    assert delete.target_exists is False
    slots = {s.slot: s for s in delete.tombstones}
    assert slots[0].attribute == "filename" and slots[0].raw == "IMG_0009.JPG"
    assert slots[1].attribute == "uuid" and slots[1].raw == DELETED_UUID.bytes
    assert slots[2].attribute is None and slots[2].status.code == "coredata.tombstone_beyond"
    assert slots[2].candidates == ("filename", "uuid")
    album_delete = result.rows[3]
    a_slots = {s.slot: s for s in album_delete.tombstones}
    # Inherited attribute (uuid from GenericAlbum) in alphabetical order after name.
    assert a_slots[0].attribute is None and a_slots[0].status.code == "coredata.tombstone_type"
    assert a_slots[1].attribute == "uuid"
    assert album_delete.timestamp_status.code == "coredata.date_zero"


def test_history_no_row_cap(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.executemany(
        "INSERT INTO ACHANGE (Z_ENT, Z_OPT, ZCHANGETYPE, ZENTITY, ZENTITYPK, ZTRANSACTIONID) VALUES (16001,1,1,4,1,1)",
        [()] * 10_100,
    )
    conn.commit()
    conn.close()
    store = _store(path)
    assert len(store.load_history().rows) == 10_104
    store.close()


def test_history_missing_and_empty(tmp_path: Path) -> None:
    store = _store(build_store(tmp_path / "a", history=False))
    assert store.history_status().code == "coredata.history_missing"
    store.close()
    path = build_store(tmp_path / "b")
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM ACHANGE")
    conn.commit()
    conn.close()
    store = _store(path)
    assert store.history_status().code == "coredata.history_empty"
    store.close()


# -- keys -----------------------------------------------------------------------------


def test_key_facts(store) -> None:
    facts = {f.entity: f for f in store.load_keys()}
    album = facts["GenericAlbum"]
    assert (album.z_max, album.rows, album.max_pk, album.max_gap, album.missing_count) == (3, 3, 3, 0, 0)
    asset = facts["Asset"]
    assert asset.z_max == 11 and asset.max_pk == 6 and asset.max_gap == 5
    assert asset.missing_count == 2 and asset.missing_ranges == "4–5"
    assert "Album" not in facts  # subentities share their root's key space


# -- WAL ----------------------------------------------------------------------------


def test_views_read_the_wal_state_the_grid_shows(tmp_path: Path) -> None:
    path = build_store(tmp_path / "walstore", journal_mode="wal")
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO ZASSET (Z_PK, Z_ENT, Z_OPT, ZFILENAME) VALUES (50, 4, 1, 'IN_WAL.JPG')")
    writer.execute("INSERT INTO plain_notes VALUES (2, 'wal', ?)", (reference(MISSING_NAME),))
    writer.commit()
    # Copy the store and its -wal while the writer still holds them open.
    copy = tmp_path / "copy"
    copy.mkdir()
    for suffix in ("", "-wal"):
        (copy / f"walstore{suffix}").write_bytes(Path(f"{path}{suffix}").read_bytes())
    writer.close()
    result = _parse(copy / "walstore")
    store = result.data["__coredata"]
    grid_pks = [r[0] for r in result.data["ZASSET"]["rows"]]
    records = store.load_records("Asset")
    assert [r[0] for r in records.rows] == grid_pks
    assert 50 in grid_pks
    refs = [r for r in store.scan_external().rows if r.kind == "reference" and r.table == "plain_notes"]
    assert {r.name for r in refs} == {EXTERNAL_NAME, MISSING_NAME}
    store.close()


# -- external data ----------------------------------------------------------------------


def test_reference_shape() -> None:
    assert cds.external_reference(reference(EXTERNAL_NAME)) == EXTERNAL_NAME
    assert cds.external_reference(b"\x02" + b"x" * 36 + b"\x00") is None
    assert cds.external_reference(reference(EXTERNAL_NAME) + b"\x00") is None
    assert cds.external_reference("text") is None


def _with_support(root: Path) -> Path:
    path = build_store(root / "Store.sqlite")
    external = root / ".Store_SUPPORT" / "_EXTERNAL_DATA"
    external.mkdir(parents=True)
    (external / EXTERNAL_NAME).write_bytes(b"\xff\xd8\xff\xe0JPEG")
    (external / "UNREFERENCED-FILE").write_bytes(b"\x89PNG\r\n\x1a\n")
    (root / ".Store_SUPPORT" / "_FBF").mkdir()
    (root / ".Store_SUPPORT" / "_FBF" / "blob").write_bytes(b"fbf")
    return path


def _scan_rows(store):
    scan = store.scan_external()
    return scan, {(r.kind, r.table, r.column, r.name): r for r in scan.rows}


def test_external_found_not_found_unreferenced_and_fbf(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    _with_support(root)
    vfs = DirectoryVFS(root)
    node = find_node(vfs, str(root / "Store.sqlite"))
    store = SQLiteParser().parse(node, vfs).data["__coredata"]
    scan, rows = _scan_rows(store)
    assert scan.folder_status.code == "coredata.support_found"
    found = rows[("reference", "ZASSET", "ZIMAGEDATA", EXTERNAL_NAME)]
    assert found.file is not None and found.status.code == "coredata.external_file_found"
    missing = rows[("reference", "ZASSET", "ZIMAGEDATA", MISSING_NAME)]
    assert missing.file is None and missing.status.code == "coredata.external_file_missing"
    # 38-byte shape outside an external-storage column: still a reference.
    outside = rows[("reference", "ZASSET", "ZEXTRA", EXTERNAL_NAME)]
    assert outside.model_flag == "no property"
    # 0x02 of another shape in a flagged column: unrecognised, not a reference.
    assert any(r.kind == "unrecognised" and r.column == "ZIMAGEDATA" for r in scan.rows)
    unreferenced = rows[("file", None, None, "_EXTERNAL_DATA/UNREFERENCED-FILE")]
    assert unreferenced.status.code == "coredata.external_unreferenced"
    fbf = rows[("file", None, None, "_FBF/blob")]
    assert fbf.status.code == "coredata.support_other_file"
    assert store.support.read(f"_EXTERNAL_DATA/{EXTERNAL_NAME}") == b"\xff\xd8\xff\xe0JPEG"
    store.close()


def test_folder_not_available_for_a_single_file(tmp_path: Path) -> None:
    store = _store(build_store(tmp_path / "alone.sqlite"))
    scan = store.scan_external()
    assert scan.folder_status.code == "coredata.support_unavailable"
    ref = next(r for r in scan.rows if r.kind == "reference")
    assert ref.status.code == "coredata.support_unavailable"
    store.close()


def test_single_file_with_folder_on_disk_uses_filesystem(tmp_path: Path) -> None:
    path = _with_support(tmp_path)
    store = _store(path)  # FileVFS: found through the filesystem fallback
    assert store.support.state == "found"
    store.close()


def test_folder_absent_in_a_source_that_has_the_parent(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    build_store(root / "Store.sqlite")
    vfs = DirectoryVFS(root)
    store = SQLiteParser().parse(find_node(vfs, str(root / "Store.sqlite")), vfs).data["__coredata"]
    assert store.support.status().code == "coredata.support_not_found"
    store.close()


def _archive_members(root: Path) -> list[tuple[str, bytes]]:
    members = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            members.append((str(path.relative_to(root)).replace("\\", "/"), path.read_bytes()))
    return members


def test_same_lookup_from_zip_and_tar_sources(tmp_path: Path) -> None:
    root = tmp_path / "src" / "private" / "var"
    root.mkdir(parents=True)
    _with_support(root)
    members = _archive_members(tmp_path / "src")
    zpath = tmp_path / "e.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    tpath = tmp_path / "e.tar"
    with tarfile.open(tpath, "w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    for vfs in (ZipVFS(zpath), TarVFS(tpath)):
        node = _find_by_name(vfs.root(), "Store.sqlite")
        store = SQLiteParser().parse(node, vfs).data["__coredata"]
        _scan, rows = _scan_rows(store)
        assert rows[("reference", "ZASSET", "ZIMAGEDATA", EXTERNAL_NAME)].file is not None, type(vfs)
        assert ("file", None, None, "_FBF/blob") in rows
        store.close()


def _find_by_name(node, name):
    if node.name == name:
        return node
    for child in node.children:
        found = _find_by_name(child, name)
        if found is not None:
            return found
    return None


def test_inline_action_only_for_external_storage_columns(store) -> None:
    assert store.inline_action("ZASSET", "ZIMAGEDATA") == (True, None)
    assert store.inline_action("ZASSET", "ZEXTRA") == (False, None)
    assert store.inline_action("plain_notes", "ref") == (False, None)
    assert store.is_inline_value(b"\x01\xff\xd8")
    assert not store.is_inline_value(b"\x02")


# -- .mom / .omo -----------------------------------------------------------------------------


def test_mom_recognised_without_extension(tmp_path: Path) -> None:
    path = tmp_path / "model_blob"
    path.write_bytes(model_archive())
    vfs = FileVFS(path)
    result = PlistParser().parse(vfs.root(), vfs)
    assert result.metadata["Core Data model"].code == "coredata.mom_model"
    source = result.viewer_hints["coredata_model"]
    rows = source.model_rows()
    assert rows and all(r.candidates == () and r.mapping is None for r in rows)
    # The plist views stay.
    assert "archive" in result.viewer_hints


def test_plain_keyed_archive_gets_no_model(tmp_path: Path) -> None:
    from crush.tests.coredata_helpers import ArchiveBuilder

    ab = ArchiveBuilder()
    root = ab.obj("NSSomethingElse", value=1)
    path = tmp_path / "other.plist"
    path.write_bytes(ab.build(root))
    vfs = FileVFS(path)
    result = PlistParser().parse(vfs.root(), vfs)
    assert "coredata_model" not in result.viewer_hints
    assert "Core Data model" not in result.metadata


def _tree_state(root: Path) -> dict[str, tuple[bytes, int]]:
    import hashlib

    return {
        str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).digest(), p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def _read_everything(store) -> None:
    for info in store.entities:
        store.load_records(info.name)
    store.load_history()
    store.load_keys()
    store.row_counts()
    scan = store.scan_external()
    for row in scan.rows:
        if row.file is not None:
            store.support.read(row.file.rel_path)
            store.support.head(row.file.rel_path)
    store.close()


@pytest.mark.forensic(
    category="Source Immutability",
    subject="SQLite database",
    desc="Reading a Core Data store and its _SUPPORT folder (every view's data, external files) "
         "leaves every file byte-identical with unchanged mtimes",
)
def test_coredata_reads_leave_evidence_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    _with_support(root)
    before = _tree_state(root)
    vfs = DirectoryVFS(root)
    store = SQLiteParser().parse(find_node(vfs, str(root / "Store.sqlite")), vfs).data["__coredata"]
    _read_everything(store)
    assert _tree_state(root) == before


@pytest.mark.forensic(
    category="No Side Effects",
    subject="SQLite database",
    desc="Core Data views create no file next to the store or in its _SUPPORT folder "
         "(no -wal, -shm or -journal)",
)
def test_coredata_reads_create_no_files(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    path = _with_support(root)
    names_before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    store = _store(path)  # single file: the filesystem fallback for _SUPPORT
    _read_everything(store)
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == names_before


@pytest.mark.forensic(
    category="Reproducibility",
    subject="SQLite database",
    desc="Reading the same Core Data store twice gives the same records, history, keys and "
         "external-data rows",
)
def test_coredata_reads_reproducible(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")

    def snapshot():
        store = _store(path)
        data = (
            [store.load_records(e.name).rows for e in store.entities],
            [(r.change_pk, r.change_type, [(s.slot, s.attribute, s.raw) for s in r.tombstones])
             for r in store.load_history().rows],
            store.load_keys(),
            [(r.kind, r.table, r.column, r.pk, r.name) for r in store.scan_external().rows],
            [(r.entity, r.prop.name, r.mapping, r.candidates) for r in store.model_rows()],
        )
        store.close()
        return data

    assert snapshot() == snapshot()


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Core Data optimized model (.omo)",
    desc="Parsing an .omo file leaves it byte-identical with an unchanged mtime",
)
def test_omo_parse_leaves_file_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "Model.omo"
    path.write_bytes(b"momv2$sr" + bytes(range(256)))
    before = _tree_state(tmp_path)
    vfs = DirectoryVFS(tmp_path)
    CoreDataOmoParser().parse(find_node(vfs, str(path)), vfs)
    assert _tree_state(tmp_path) == before


@pytest.mark.forensic(
    category="No Side Effects",
    subject="Core Data optimized model (.omo)",
    desc="Parsing an .omo file creates no file next to it",
)
def test_omo_parse_creates_no_files(tmp_path: Path) -> None:
    path = tmp_path / "Model.omo"
    path.write_bytes(b"momv2$sr" + b"\x00" * 64)
    vfs = FileVFS(path)
    CoreDataOmoParser().parse(vfs.root(), vfs)
    assert [p.name for p in tmp_path.iterdir()] == ["Model.omo"]


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Core Data optimized model (.omo)",
    desc="An .omo file is shown as its exact bytes in the hex view with a 'not decoded' status",
)
def test_omo_known_output(tmp_path: Path) -> None:
    data = b"momv2$sr" + bytes(range(64))
    path = tmp_path / "x.omo"
    path.write_bytes(data)
    vfs = FileVFS(path)
    result = CoreDataOmoParser().parse(vfs.root(), vfs)
    assert result.data == data
    assert result.metadata["Format"].code == "coredata.omo_not_decoded"


@pytest.mark.forensic(
    category="Reproducibility",
    subject="Core Data optimized model (.omo)",
    desc="Parsing the same .omo file twice gives identical results",
)
def test_omo_reproducible(tmp_path: Path) -> None:
    path = tmp_path / "x.omo"
    path.write_bytes(b"momv2$sr" + bytes(range(64)))
    vfs = FileVFS(path)
    first = CoreDataOmoParser().parse(vfs.root(), vfs)
    second = CoreDataOmoParser().parse(vfs.root(), vfs)
    assert (first.data, first.metadata) == (second.data, second.metadata)


@pytest.mark.forensic(
    category="Read-only Media",
    subject="Core Data optimized model (.omo)",
    desc="An .omo file on read-only media (0o444, folder 0o555) is read and shown",
)
def test_omo_read_only(tmp_path: Path) -> None:
    import os
    import stat

    folder = tmp_path / "ro"
    folder.mkdir()
    path = folder / "x.omo"
    path.write_bytes(b"momv2$sr" + b"\x01" * 16)
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chmod(folder, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    try:
        vfs = FileVFS(path)
        result = CoreDataOmoParser().parse(vfs.root(), vfs)
        assert result.data.startswith(b"momv2$sr")
    finally:
        os.chmod(folder, stat.S_IRWXU)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def test_omo_status(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_bytes(b"momv2$sr" + b"\x00" * 32)
    vfs = FileVFS(path)
    parser = CoreDataOmoParser()
    assert parser.can_parse(str(path), vfs.peek(vfs.root(), 64))
    result = parser.parse(vfs.root(), vfs)
    assert result.viewer_type == "hex"
    assert result.metadata["Status"].code == "coredata.omo_not_decoded"


# -- review fixes ------------------------------------------------------------------


def _zip_at_host_path(tmp_path: Path, host_store: Path) -> ZipVFS:
    """A ZIP whose store sits at the same path inside it as *host_store* on
    this machine (an image of a macOS or Linux disk can look like that)."""
    zpath = tmp_path / "evidence.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(str(host_store).lstrip("/"), host_store.read_bytes())
    return ZipVFS(zpath)


@pytest.mark.skipif(not str(Path("/x").resolve()).startswith("/"), reason="POSIX paths only")
def test_host_files_never_read_for_an_archive_source(tmp_path: Path) -> None:
    host = tmp_path / "host"
    host.mkdir()
    host_store = build_store(host / "Store.sqlite")
    (host / "Store.sqlite-wal").write_bytes(b"host wal, not evidence")
    (host / "Store.sqlite-journal").write_bytes(b"host journal, not evidence")
    (host / ".Store_SUPPORT" / "_EXTERNAL_DATA").mkdir(parents=True)
    (host / ".Store_SUPPORT" / "_EXTERNAL_DATA" / EXTERNAL_NAME).write_bytes(b"host file")
    vfs = _zip_at_host_path(tmp_path, host_store)
    node = find_node(vfs, str(host_store))
    assert node is not None and node.path == str(host_store)
    result = SQLiteParser().parse(node, vfs)
    assert "Companion files" not in result.metadata
    assert "__journal_path" not in result.data
    store = result.data["__coredata"]
    assert store.support.state != "found"
    ref = next(r for r in store.scan_external().rows if r.kind == "reference")
    assert ref.file is None
    store.close()
    # The same store opened as a single file still finds them next to it.
    single = _store(host_store)
    assert single.support.state == "found"
    single.close()
    assert "Store.sqlite-wal" in str(_parse(host_store).metadata.get("Companion files", ""))


def test_app_entity_named_change_and_history_both_work(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO Z_PRIMARYKEY VALUES (7, 'Change', 0, 1)")
    conn.execute("CREATE TABLE ZCHANGE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZNOTE VARCHAR)")
    conn.execute("INSERT INTO ZCHANGE VALUES (1, 7, 1, 'app row')")
    conn.commit()
    conn.close()
    store = _store(path)
    assert store.entity("Change").table == "ZCHANGE"
    assert store.entity("CHANGE").table == "ACHANGE"
    assert store.history_status().code == "coredata.history_present"
    assert len(store.load_history().rows) == 4
    assert [r[0] for r in store.load_records("Change").rows] == [1]
    store.close()


def test_store_at_the_source_root_has_its_folder_checked(tmp_path: Path) -> None:
    store_path = build_store(tmp_path / "s.sqlite")
    zpath = tmp_path / "root.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("s.sqlite", store_path.read_bytes())
    vfs = ZipVFS(zpath)
    store = SQLiteParser().parse(find_node(vfs, "/s.sqlite"), vfs).data["__coredata"]
    assert store.support.state == "not_found"
    assert store.support.status().code == "coredata.support_not_found"
    store.close()


def test_huge_key_returns_promptly_with_exact_gaps(tmp_path: Path) -> None:
    import time

    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO ZASSET (Z_PK, Z_ENT, Z_OPT) VALUES (?, 4, 1)", (2**40,))
    conn.commit()
    conn.close()
    store = _store(path)
    started = time.perf_counter()
    asset = next(f for f in store.load_keys() if f.entity == "Asset")
    assert time.perf_counter() - started < 5
    # keys 1, 2, 3, 6, 2**40: missing 4-5 and 7 .. 2**40 - 1
    assert asset.missing_ranges == f"4–5, 7–{2**40 - 1}"
    assert asset.missing_count == 2 + (2**40 - 1 - 7 + 1)
    assert asset.rows == 5 and asset.max_pk == 2**40
    store.close()


def test_missing_key_ranges_walk_the_gaps() -> None:
    assert cds.missing_key_ranges([1, 2, 5, 9]) == [(3, 4), (6, 8)]
    assert cds.missing_key_ranges([3]) == [(1, 2)]
    assert cds.missing_key_ranges([]) == []
    assert cds.missing_key_ranges([0, 1, 1, 2]) == []


class _FailingConn:
    """A connection whose read of one table's keys fails."""

    def __init__(self, conn, table: str) -> None:
        self._conn = conn
        self._fail = f'SELECT Z_PK FROM "{table}"'

    def execute(self, sql, *args):
        if sql == self._fail:
            raise sqlite3.DatabaseError("simulated read failure")
        return self._conn.execute(sql, *args)

    def close(self) -> None:
        self._conn.close()


def test_unreadable_table_makes_existence_unknown_not_gone(store) -> None:
    conn = _FailingConn(store.open(), "ZASSET")
    result = store.load_history(conn)
    asset_rows = [r for r in result.rows if r.entity_name == "Asset"]
    assert asset_rows
    assert all(r.target_exists is None for r in asset_rows)
    assert all(r.target_status.code == "coredata.table_unreadable" for r in asset_rows)
    assert any(i.code == "coredata.table_unreadable" for i in result.issues)
    conn.close()


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() == 0,
                    reason="needs a non-root POSIX user to make a folder unlistable")
def test_unlistable_folder_makes_reference_unknown(tmp_path: Path) -> None:
    import os

    root = tmp_path / "src"
    root.mkdir()
    _with_support(root)
    external = root / ".Store_SUPPORT" / "_EXTERNAL_DATA"
    os.chmod(external, 0)
    try:
        vfs = DirectoryVFS(root)
        store = SQLiteParser().parse(find_node(vfs, str(root / "Store.sqlite")), vfs).data["__coredata"]
        scan = store.scan_external()
        ref = next(r for r in scan.rows if r.kind == "reference" and r.name == EXTERNAL_NAME
                   and r.column == "ZIMAGEDATA")
        assert ref.status.code == "coredata.external_file_unknown"
        assert any(r.kind == "folder" and r.status.code == "coredata.support_folder_unlisted" for r in scan.rows)
        store.close()
    finally:
        os.chmod(external, 0o700)


def test_heuristics_are_named_on_the_values(store) -> None:
    assets = store.load_records("Asset")
    values = {v.name: v for v in store.property_values(assets, assets.rows[0])}
    assert values["uuid"].heuristic == cds.HEURISTIC_NAME_MATCH
    assert values["uuid"].raw == ASSET_UUID.bytes
    assert values["ZEXTRA"].heuristic is None  # stored as is, no link
    grid = {g.header: g for g in assets.grid}
    assert grid["uuid"].heuristic and grid["uuid (ZUUID)"].heuristic
    assert not grid["ZEXTRA"].heuristic
    rows = [r for r in store.scan_external().rows if r.kind == "reference"]
    assert all(cds.HEURISTIC_BYTE_PATTERN in r.heuristics and r.raw for r in rows)
    history = store.load_history()
    assert history.timestamp_heuristic  # ATRANSACTION.ZTIMESTAMP is declared FLOAT
    slot = next(s for r in history.rows for s in r.tombstones if s.attribute == "uuid")
    assert slot.raw == DELETED_UUID.bytes


def test_parsers_report_the_specific_format(tmp_path: Path) -> None:
    assert _parse(build_store(tmp_path / "odd.name")).format_short_name == cds.CORE_DATA_STORE_FORMAT
    plain = tmp_path / "plain.db"
    conn = sqlite3.connect(plain)
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    assert _parse(plain).format_short_name is None
    mom = tmp_path / "blob"
    mom.write_bytes(model_archive())
    vfs = FileVFS(mom)
    assert PlistParser().parse(vfs.root(), vfs).format_short_name == cds.CORE_DATA_MODEL_FORMAT
    other = tmp_path / "plain.plist"
    other.write_bytes(plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY))
    vfs = FileVFS(other)
    assert PlistParser().parse(vfs.root(), vfs).format_short_name is None


def test_sixteen_bytes_are_a_uuid_only_for_a_uuid_attribute(tmp_path: Path) -> None:
    digest = bytes.fromhex("9e107d9d372bb6826bd81d3542a419d6")  # an MD5, 16 bytes
    uuid_attr = cds.ModelProperty(index=-1, class_name="NSAttributeDescription", kind="attribute",
                                  known_class=True, name="uuid", entity="X", attribute_type=cds.TYPE_UUID)
    hash_attr = cds.ModelProperty(index=-1, class_name="NSAttributeDescription", kind="attribute",
                                  known_class=True, name="hash", entity="X", attribute_type=cds.TYPE_BINARY)
    assert cds.tombstone_text(digest, uuid_attr) == "9E107D9D-372B-B682-6BD8-1D3542A419D6"
    assert cds.tombstone_text(digest, hash_attr) == digest.hex(" ")
    assert cds.tombstone_text(digest, None) == digest.hex(" ")
    # An unassigned slot holding 16 bytes: hex, never a UUID.
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ACHANGE SET ZTOMBSTONE0 = ? WHERE Z_PK = 3", (digest,))  # filename slot: type conflict
    conn.commit()
    conn.close()
    store = _store(path)
    slot = next(s for r in store.load_history().rows if r.change_pk == 3 for s in r.tombstones if s.slot == 0)
    assert slot.attribute is None and slot.value_text == digest.hex(" ")
    store.close()


def test_history_names_an_entity_without_a_table_correctly(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO Z_PRIMARYKEY VALUES (8, 'Orphan', 0, 1)")
    conn.execute("INSERT INTO ACHANGE (Z_ENT, Z_OPT, ZCHANGETYPE, ZENTITY, ZENTITYPK, ZTRANSACTIONID) "
                 "VALUES (16001, 1, 0, 8, 1, 1)")
    conn.execute("INSERT INTO ACHANGE (Z_ENT, Z_OPT, ZCHANGETYPE, ZENTITY, ZENTITYPK, ZTRANSACTIONID) "
                 "VALUES (16001, 1, 0, 77, 1, 1)")
    conn.commit()
    conn.close()
    store = _store(path)
    rows = store.load_history().rows
    orphan = next(r for r in rows if r.entity_raw == 8)
    assert orphan.target_status.code == "coredata.no_table"  # it is in Z_PRIMARYKEY
    stray = next(r for r in rows if r.entity_raw == 77)
    assert stray.target_status.code == "coredata.ent_unknown"
    store.close()


def test_table_falls_back_to_the_other_prefix_only_when_unclaimed(tmp_path: Path) -> None:
    path = build_store(tmp_path / "s")
    conn = sqlite3.connect(path)
    # An app entity named like Core Data's own: only its Z table exists.
    conn.execute("INSERT INTO Z_PRIMARYKEY VALUES (9, 'NSCKMine', 0, 1)")
    conn.execute("CREATE TABLE ZNSCKMINE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER)")
    # An app entity "Change" without ZCHANGE: ACHANGE is the history's, not its.
    conn.execute("INSERT INTO Z_PRIMARYKEY VALUES (10, 'Change', 0, 1)")
    conn.commit()
    conn.close()
    store = _store(path)
    assert store.entity("NSCKMine").table == "ZNSCKMINE"
    assert store.entity("Change").table is None
    assert store.entity("Change").table_status.code == "coredata.no_table"
    assert store.entity("CHANGE").table == "ACHANGE"
    store.close()


def test_column_roles_not_cached_after_a_failure(store, monkeypatch) -> None:
    real = store.column_link
    calls = {"n": 0}

    def flaky(entity, prop):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated failure")
        return real(entity, prop)

    store._roles_cache.clear()
    monkeypatch.setattr(store, "column_link", flaky)
    with pytest.raises(RuntimeError):
        store.column_roles("ZASSET")
    assert "ZASSET" not in store._roles_cache
    roles = store.column_roles("ZASSET")
    assert "ZUUID" in roles and "ZFILENAME" in roles
