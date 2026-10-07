# SPDX-License-Identifier: Apache-2.0
"""Tests for UFDRVFS: Cellebrite UFDR (Physical Analyzer report/delivery
container) filesystem browsing.

A synthetic UFDR is built for each test with pgdumplib's write API (a
pg_dump custom-format archive containing a minimal `Nodes` table) zipped
together with a matching `files/<Tag>/<name>` layout -- no checked-in
binary fixture needed. See crush/core/ufdr.py for what every design choice
here was verified against on a real 23.7 GB UFDR 10.x sample.
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from crush.core.ufdr import UFDRContentNotLocatedError, UFDROpenError, is_ufdr_zip
from crush.core.vfs import UFDRVFS, VFSNode, open_vfs

_COLUMNS = [
    "Id",
    "ParentId",
    "Type",
    "Name",
    "AbsolutePath",
    "Size",
    "Md5",
    "Sha256",
    "Tag",
    "IsCarved",
    "CreationTime",
    "ModifyTime",
    "AccessTime",
    "ChangeTime",
    "ChildCount",
]

_COLUMN_TYPES = {
    "ChildCount": "integer",
    "Id": "uuid",
    "ParentId": "uuid",
    "Type": "integer",
    "Name": "text",
    "AbsolutePath": "text",
    "Size": "bigint",
    "Md5": "text",
    "Sha256": "text",
    "Tag": "text",
    "IsCarved": "boolean",
    "CreationTime": "timestamp without time zone",
    "ModifyTime": "timestamp without time zone",
    "AccessTime": "timestamp without time zone",
    "ChangeTime": "timestamp without time zone",
}


def _row(
    node_id: str,
    type_: int,
    name: str,
    abs_path: str | None,
    *,
    parent_id: str | None = None,
    size: int = 0,
    md5: str | None = None,
    sha256: str | None = None,
    tag: str = "",
    is_carved: str = "f",  # real pg_dump COPY text for boolean -- not Python True/False
    modify_time: str | None = None,
    child_count: int | None = None,
) -> dict[str, Any]:
    return {
        "Id": node_id,
        "ParentId": parent_id,
        "Type": type_,
        "Name": name,
        "AbsolutePath": abs_path,
        "Size": size,
        "Md5": md5,
        "Sha256": sha256,
        "Tag": tag,
        "IsCarved": is_carved,
        "CreationTime": None,
        "ModifyTime": modify_time,
        "AccessTime": None,
        "ChangeTime": None,
        "ChildCount": child_count,
    }


def _write_schema(
    dump: Any, schema: str, rows: list[dict[str, Any]],
    source_nodes: list[tuple[str, str, int]] | None = None,
) -> None:
    dump.add_entry(desc="SCHEMA", tag=schema, defn=f'CREATE SCHEMA "{schema}";')
    col_defs = ",\n    ".join(f'"{c}" {_COLUMN_TYPES[c]}' for c in _COLUMNS)
    entry = dump.add_entry(
        desc="TABLE",
        namespace=schema,
        tag="Nodes",
        defn=f'CREATE TABLE "{schema}"."Nodes" (\n    {col_defs}\n);',
    )
    with dump.table_data_writer(entry, _COLUMNS) as writer:
        for row in rows:
            writer.append(*(row.get(c) for c in _COLUMNS))
    if source_nodes is not None:
        # Real column order of a UFDR 10.x SourceInfoNodes table (subset).
        entry = dump.add_entry(
            desc="TABLE", namespace=schema, tag="SourceInfoNodes",
            defn=(
                f'CREATE TABLE "{schema}"."SourceInfoNodes" (\n    "Id" uuid NOT NULL,\n'
                '    "FileName" text,\n    "FilePath" text,\n    "FileSize" bigint NOT NULL,\n'
                '    "NodeId" uuid NOT NULL\n);'
            ),
        )
        with dump.table_data_writer(entry, ["Id", "FileName", "FilePath", "FileSize", "NodeId"]) as writer:
            for k, (node_id, path, size) in enumerate(source_nodes):
                writer.append(f"s{k}", path.rsplit("/", 1)[-1], f"EXTRACTION_FFS.zip{path}", size, node_id)


def _build_fake_ufdr(
    tmp_path: Path,
    *,
    devices: dict[str, list[dict[str, Any]]],
    files: dict[str, bytes],
    name: str = "sample.ufdr",
    source_nodes: list[tuple[str, str, int]] | None = None,
) -> Path:
    """A minimal, self-contained fake UFDR: *devices* maps a device UUID to
    its Nodes rows (one or more devices), *files* maps a zip-internal
    ``files/<Tag>/<name>`` path to its content, *source_nodes* are
    SourceInfoNodes rows (node id, device path, size) for the first device."""
    import pgdumplib

    dump = pgdumplib.new(dbname="ufdr")
    for k, (device_id, rows) in enumerate(devices.items()):
        _write_schema(dump, f"device_{device_id}", rows, source_nodes if k == 0 else None)
    db_path = tmp_path / f"{name}.database.db"
    dump.save(db_path)

    first_device = next(iter(devices))
    ufdr_path = tmp_path / name
    with zipfile.ZipFile(ufdr_path, "w") as zf:
        zf.writestr("report.xml", "<Report/>")
        zf.writestr("settings.json", "{}")
        zf.writestr(
            "DbData/database.json",
            json.dumps(
                {
                    "DeviceId": first_device,
                    "DatabaseVersion": "10.11.0.3022",
                    "CaseId": "case-1",
                    "SourceExtractionIds": ["ext-1"],
                }
            ),
        )
        zf.write(db_path, "DbData/database.db")
        for zip_rel, content in files.items():
            zf.writestr(zip_rel, content)
    return ufdr_path


def _find(node: VFSNode, path_parts: list[str]) -> VFSNode | None:
    cur = node
    for part in path_parts:
        match = next((c for c in cur.children if c.name == part), None)
        if match is None:
            return None
        cur = match
    return cur


def _all_paths(node: VFSNode) -> set[str]:
    paths = {node.path}
    for child in node.children:
        paths |= _all_paths(child)
    return paths


DEVICE = "11111111-1111-1111-1111-111111111111"


def test_tree_shape_builds_from_absolute_path(tmp_path: Path) -> None:
    apk_bytes = b"apk content"
    apk_md5 = hashlib.md5(apk_bytes).hexdigest()
    rows = [
        _row("n1", 1, "app", "/data/app", tag=""),
        _row(
            "n2", 2, "base.apk", "/data/app/base.apk",
            size=len(apk_bytes), md5=apk_md5, tag="Application",
        ),
    ]
    path = _build_fake_ufdr(
        tmp_path,
        devices={DEVICE: rows},
        files={"files/Application/base.apk": apk_bytes},
    )
    vfs = UFDRVFS(path)
    root = vfs.root()
    apk_node = _find(root, ["data", "app", "base.apk"])
    assert apk_node is not None
    assert apk_node.size == len(apk_bytes)
    assert not apk_node.is_dir
    assert _all_paths(root) == {"/", "/data", "/data/app", "/data/app/base.apk"}
    vfs.close()


# -- Type 10: items Cellebrite derived from a file -----------------------------
# Shapes as in a real UFDR 10.x: signal.db's decrypted copy is a Type 10 row
# whose AbsolutePath runs through signal.db and whose ParentId is signal.db's.

DB_DIR = "/data/data/org.thoughtcrime.securesms/databases"


def _file_row(node_id: str, abs_path: str, content: bytes, tag: str, **kw: Any) -> dict[str, Any]:
    return _row(
        node_id, kw.pop("type_", 2), abs_path.rsplit("/", 1)[-1], abs_path,
        size=len(content), md5=hashlib.md5(content).hexdigest(), tag=tag, **kw,
    )


def test_lone_derived_item_sits_beside_its_file(tmp_path: Path) -> None:
    enc, dec = b"encrypted bytes", b"SQLite format 3\x00decrypted"
    rows = [
        _file_row("p", f"{DB_DIR}/signal.db", enc, "Database"),
        _file_row(
            "c", f"{DB_DIR}/signal.db/signal.db.decrypted", dec, "Database",
            type_=10, parent_id="p",
        ),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Database/signal.db": enc,
        "files/Database/signal.db.decrypted": dec,
    })
    vfs = UFDRVFS(path)
    folder = _find(vfs.root(), DB_DIR.strip("/").split("/"))
    assert folder is not None
    assert [c.name for c in folder.children] == ["signal.db", "signal.db.decrypted"]
    derived = folder.children[1]
    assert vfs.read(derived) == dec
    info = vfs.node_info(derived)
    assert info is not None
    assert str(info["Derived from"]).startswith(f"{DB_DIR}/signal.db -- an item Cellebrite derived")
    assert "catalog" not in str(info["Derived from"])
    original = vfs.node_info(folder.children[0])
    assert original is not None and "Derived from" not in original
    vfs.close()


def test_several_derived_items_go_into_a_derived_folder(tmp_path: Path) -> None:
    pdf, img1, img2 = b"%PDF-1.7 ...", b"\xff\xd8\xff one", b"\xff\xd8\xff two!"
    rows = [
        _file_row("p", "/sdcard/Download/report.pdf", pdf, "Document"),
        _file_row("c1", "/sdcard/Download/report.pdf/report.pdf_embedded_1.jpg", img1, "Image",
                  type_=10, parent_id="p"),
        _file_row("c2", "/sdcard/Download/report.pdf/report.pdf_embedded_2.jpg", img2, "Image",
                  type_=10, parent_id="p"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Document/report.pdf": pdf,
        "files/Image/report.pdf_embedded_1.jpg": img1,
        "files/Image/report.pdf_embedded_2.jpg": img2,
    })
    vfs = UFDRVFS(path)
    download = _find(vfs.root(), ["sdcard", "Download"])
    assert download is not None
    assert [c.name for c in download.children] == ["report.pdf (derived)", "report.pdf"]
    holder = download.children[0]
    assert holder.is_dir
    assert str(holder.status).startswith("Holds the items Cellebrite derived from /sdcard/Download/report.pdf")
    assert [c.name for c in holder.children] == ["report.pdf_embedded_1.jpg", "report.pdf_embedded_2.jpg"]
    assert vfs.read(holder.children[1]) == img2
    vfs.close()


def test_lone_derived_item_whose_name_is_taken_goes_into_a_folder(tmp_path: Path) -> None:
    a, b, m1, m2 = b"apk one", b"apk two!", b"<manifest 1>", b"<manifest 22>"
    rows = [
        _file_row("p1", "/data/app/base.apk", a, "Application"),
        _file_row("p2", "/data/app/split.apk", b, "Application"),
        _file_row("c1", "/data/app/base.apk/AndroidManifest.xml", m1, "Text", type_=10, parent_id="p1"),
        _file_row("c2", "/data/app/split.apk/AndroidManifest.xml", m2, "Text", type_=10, parent_id="p2"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Application/base.apk": a,
        "files/Application/split.apk": b,
        "files/Text/AndroidManifest.xml": m1,
        "files/Text/AndroidManifest_7.xml": m2,
    })
    vfs = UFDRVFS(path)
    app = _find(vfs.root(), ["data", "app"])
    assert app is not None
    assert [c.name for c in app.children] == [
        "base.apk (derived)", "split.apk (derived)", "base.apk", "split.apk",
    ]
    for holder, content in zip(app.children[:2], (m1, m2)):
        assert [c.name for c in holder.children] == ["AndroidManifest.xml"]
        assert vfs.read(holder.children[0]) == content
    vfs.close()


def test_file_the_ufdr_lacks_gets_a_placeholder_beside_its_items(tmp_path: Path) -> None:
    # Real case: Physical Analyzer exported an image carved from
    # /vendor/bin/toybox_vendor, not toybox_vendor itself; SourceInfoNodes
    # records its path and size.
    img = b"\x89PNG embedded"
    rows = [
        _row("d", 1, "bin", "/vendor/bin"),
        _file_row("c", "/vendor/bin/toybox_vendor/toybox_vendor_embedded_1.png", img, "Image",
                  type_=10, parent_id="absent"),
    ]
    path = _build_fake_ufdr(
        tmp_path, devices={DEVICE: rows},
        files={"files/Image/toybox_vendor_embedded_1.png": img},
        source_nodes=[("absent", "/vendor/bin/toybox_vendor", 527952)],
    )
    vfs = UFDRVFS(path)
    folder = _find(vfs.root(), ["vendor", "bin"])
    assert folder is not None
    assert [c.name for c in folder.children] == ["toybox_vendor", "toybox_vendor_embedded_1.png"]
    placeholder, item = folder.children
    assert placeholder.size == 527952
    assert str(placeholder.status) == (
        "Not contained in this UFDR: Cellebrite exported items derived from this file, not "
        "the file. It records only its path and size (527,952 bytes); no content, hashes or times"
    )
    with pytest.raises(UFDRContentNotLocatedError, match="exported items derived from this file, not the file's content"):
        vfs.read(placeholder)
    with pytest.raises(UFDRContentNotLocatedError):
        vfs.peek(placeholder)
    info = vfs.node_info(placeholder)
    assert info is not None and "not the file's content" in str(info["Content status"])

    assert vfs.read(item) == img
    info = vfs.node_info(item)
    assert info is not None
    assert str(info["Derived from"]).endswith(
        "the UFDR doesn't contain /vendor/bin/toybox_vendor itself"
    )
    vfs.close()


def test_placeholder_without_a_recorded_size_says_so(tmp_path: Path) -> None:
    img = b"\x89PNG"
    rows = [_file_row("c", "/x/blob/blob_embedded_1.png", img, "Image", type_=10, parent_id="absent")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={"files/Image/blob_embedded_1.png": img})
    vfs = UFDRVFS(path)
    placeholder = _find(vfs.root(), ["x", "blob"])
    assert placeholder is not None and not placeholder.is_dir
    assert "records only its path; no size" in str(placeholder.status)
    vfs.close()


def test_missing_file_inside_another_file_goes_into_its_derived_folder(tmp_path: Path) -> None:
    # Real shape: an icon Cellebrite found in a browser cache entry, and an
    # image derived from that icon -- only the image is in the UFDR.
    entry, img = b"cache entry bytes", b"\x89PNG from icon"
    base = "/data/data/com.duckduckgo.mobile.android/cache/Cache_Data"
    rows = [
        _file_row("e", f"{base}/3de5_0", entry, "Uncategorized"),
        _file_row("c", f"{base}/3de5_0/apnews.com.ico/apnews.com.ico_1.png", img, "Image",
                  type_=10, parent_id="ico"),
    ]
    path = _build_fake_ufdr(
        tmp_path, devices={DEVICE: rows},
        files={"files/Uncategorized/3de5_0": entry, "files/Image/apnews.com.ico_1.png": img},
        source_nodes=[("ico", f"{base}/3de5_0/apnews.com.ico", 777)],
    )
    vfs = UFDRVFS(path)
    cache = _find(vfs.root(), base.strip("/").split("/"))
    assert cache is not None
    assert [c.name for c in cache.children] == ["3de5_0 (derived)", "3de5_0"]
    holder = cache.children[0]
    assert [c.name for c in holder.children] == ["apnews.com.ico", "apnews.com.ico_1.png"]
    assert holder.children[0].size == 777
    assert vfs.read(holder.children[1]) == img
    vfs.close()


def test_empty_file_reads_as_empty_not_as_missing(tmp_path: Path) -> None:
    # Real: every 0-byte file of a sample has no MD5 and no files/ member.
    rows = [_row("n", 2, "restore.log", "/data/cache/restore.log", size=0, tag="Text")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["data", "cache", "restore.log"])
    assert node is not None
    assert vfs.read(node) == b""
    assert vfs.peek(node) == b""
    with vfs.open(node) as f:
        assert f.read() == b""
    info = vfs.node_info(node)
    assert info is not None and "Content status" not in info
    vfs.close()


def test_content_stored_in_another_bucket_is_found_by_hash(tmp_path: Path) -> None:
    # Real: four `._*.png` rows tagged Image share their bytes with a file
    # stored as files/Configuration/._scene.config.
    content = b"\x00\x05\x16\x07 AppleDouble"
    rows = [
        _file_row("a", "/x/__MACOSX/._faceMask.png", content, "Image"),
        _file_row("b", "/x/__MACOSX/._scene.config", content, "Configuration"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Configuration/._scene.config": content,
    })
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["x", "__MACOSX", "._faceMask.png"])
    assert node is not None
    assert vfs.read(node) == content
    vfs.close()


def test_lone_candidate_with_other_bytes_falls_back_to_another_bucket(tmp_path: Path) -> None:
    right, wrong = b"the recorded bytes!", b"same size, wrong!!!"
    assert len(right) == len(wrong)
    rows = [
        _file_row("a", "/x/a.png", right, "Image"),
        _file_row("b", "/x/b.cfg", right, "Configuration"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Image/a.png": wrong,
        "files/Configuration/b.cfg": right,
    })
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["x", "a.png"])
    assert node is not None
    assert vfs.read(node) == right
    vfs.close()


def test_folder_holding_all_its_files_has_no_missing_note(tmp_path: Path) -> None:
    content = b"db"
    rows = [_row("d", 1, "data", "/data", child_count=1), _file_row("f", "/data/a.db", content, "Database")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={"files/Database/a.db": content})
    vfs = UFDRVFS(path)
    data = _find(vfs.root(), ["data"])
    assert data is not None
    assert vfs.node_info(data) == {
        "Extraction files (Cellebrite count)": "1",
        "Extraction files in this UFDR": "1",
    }
    assert not vfs.root().status
    vfs.close()


def test_without_a_root_row_the_root_says_the_ufdr_is_partial(tmp_path: Path) -> None:
    # Real: no Nodes row for "/" itself, so no total of Cellebrite's to quote.
    content = b"db"
    rows = [
        _row("d", 1, "data", "/data", child_count=7),
        _row("s", 1, "system", "/system", child_count=0),
        _file_row("f", "/data/a.db", content, "Database"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={"files/Database/a.db": content})
    vfs = UFDRVFS(path)
    assert str(vfs.root().status).startswith(
        "This UFDR holds only the files Physical Analyzer exported into it, not the whole extraction"
    )
    vfs.close()


def test_folders_show_the_extractions_file_count_and_this_ufdrs(tmp_path: Path) -> None:
    content = b"db"
    rows = [
        _row("r", 1, "", "/", child_count=10),
        _row("d", 1, "data", "/data", child_count=7),
        _file_row("f", "/data/a.db", content, "Database"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={"files/Database/a.db": content})
    vfs = UFDRVFS(path)
    data = _find(vfs.root(), ["data"])
    assert data is not None
    info = vfs.node_info(data)
    assert info is not None
    assert info["Extraction files (Cellebrite count)"] == "7"
    assert info["Extraction files in this UFDR"] == "1"
    assert str(info["Missing from this UFDR"]) == (
        "6 of the 7 files below this folder in the extraction aren't in this UFDR: Cellebrite "
        "didn't export them, and records nothing about them but this count. They aren't listed"
    )
    assert str(vfs.root().status) == (
        "This UFDR holds 1 of the 10 files Cellebrite counted in the extraction: only these "
        "were exported into it. Each folder's Properties show both counts"
    )
    vfs.close()


def test_item_derived_from_a_derived_item_follows_it(tmp_path: Path) -> None:
    cache, pdf, img1, img2 = b"cache entry", b"%PDF-1.4 cached", b"\xff\xd8 a", b"\xff\xd8 bb"
    base = "/data/data/com.browser/cache/f_0"
    rows = [
        _file_row("p", base, cache, "Uncategorized"),
        _file_row("pdf", f"{base}/doc.pdf", pdf, "Document", type_=10, parent_id="p"),
        # Listed before their parent's own row, as row order is not guaranteed.
        _file_row("i1", f"{base}/doc.pdf/doc.pdf_embedded_1.jpg", img1, "Image", type_=10, parent_id="pdf"),
        _file_row("i2", f"{base}/doc.pdf/doc.pdf_embedded_2.jpg", img2, "Image", type_=10, parent_id="pdf"),
    ]
    rows = [rows[0], rows[2], rows[3], rows[1]]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Uncategorized/f_0": cache,
        "files/Document/doc.pdf": pdf,
        "files/Image/doc.pdf_embedded_1.jpg": img1,
        "files/Image/doc.pdf_embedded_2.jpg": img2,
    })
    vfs = UFDRVFS(path)
    cache_dir = _find(vfs.root(), ["data", "data", "com.browser", "cache"])
    assert cache_dir is not None
    assert [c.name for c in cache_dir.children] == ["doc.pdf (derived)", "doc.pdf", "f_0"]
    assert [c.name for c in cache_dir.children[0].children] == [
        "doc.pdf_embedded_1.jpg", "doc.pdf_embedded_2.jpg",
    ]
    info = vfs.node_info(cache_dir.children[0].children[0])
    assert info is not None and str(info["Derived from"]).startswith(f"{base}/doc.pdf --")
    vfs.close()


def test_rows_with_the_same_path_are_each_kept_and_numbered(tmp_path: Path) -> None:
    # Real case: two different images Cellebrite derived from contacts2.db
    # under one and the same AbsolutePath.
    one, two = b"\xff\xd8 first image", b"\xff\xd8 second, other image"
    db = b"contacts db"
    p = "/data/data/com.android.providers.contacts/databases/contacts2.db"
    rows = [
        _file_row("p", p, db, "Database"),
        _file_row("c1", f"{p}/ThisIs DFIR.jpg", one, "Image", type_=10, parent_id="p"),
        _file_row("c2", f"{p}/ThisIs DFIR.jpg", two, "Image", type_=10, parent_id="p"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Database/contacts2.db": db,
        "files/Image/ThisIs DFIR.jpg": one,
        "files/Image/ThisIs DFIR_3.jpg": two,
    })
    vfs = UFDRVFS(path)
    holder = _find(vfs.root(), [*p.strip("/").split("/")[:-1], "contacts2.db (derived)"])
    assert holder is not None
    assert [c.name for c in holder.children] == ["ThisIs DFIR.jpg", "ThisIs DFIR.jpg (2)"]
    assert [vfs.read(c) for c in holder.children] == [one, two]
    assert [str(c.status) for c in holder.children] == [
        f"Listed 2 times under this path in the UFDR's file catalog; this is entry {k} of 2 "
        "(catalog order)"
        for k in (1, 2)
    ]
    vfs.close()


def test_rows_of_an_undecoded_type_are_counted_on_the_root(tmp_path: Path) -> None:
    rows = [_row("n1", 1, "system", "/system"), _row("x", 42, "odd", "/system/odd")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    vfs = UFDRVFS(path)
    assert "of Type 42" in str(vfs.root().status)
    assert _all_paths(vfs.root()) == {"/", "/system"}
    vfs.close()


# -- Content resolution cost ---------------------------------------------------


def _count_hashing(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from crush.core import ufdr

    hashed: list[str] = []
    real = ufdr.UFDRHandle._md5_of

    def counting(self: Any, info: zipfile.ZipInfo) -> str:
        if info.filename not in self._member_md5:
            hashed.append(info.filename)
        return real(self, info)

    monkeypatch.setattr(ufdr.UFDRHandle, "_md5_of", counting)
    return hashed


def test_peek_of_an_unambiguous_member_hashes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"SQLite format 3\x00" + b"x" * 100
    rows = [_file_row("n", "/sdcard/a.db", content, "Database")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={"files/Database/a.db": content})
    hashed = _count_hashing(monkeypatch)
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "a.db"])
    assert node is not None
    assert vfs.peek(node, 16) == content[:16]
    assert hashed == []
    assert vfs.read(node) == content
    vfs.close()


def test_peek_of_a_lone_suffixed_member_hashes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"PK\x03\x04 apk"
    rows = [_file_row("n", "/data/app/base.apk", content, "Application")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Application/base_912.apk": content,
    })
    hashed = _count_hashing(monkeypatch)
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["data", "app", "base.apk"])
    assert node is not None
    assert vfs.peek(node, 4) == b"PK\x03\x04"
    assert hashed == []
    assert vfs.read(node) == content
    vfs.close()


def test_unambiguous_member_with_other_bytes_is_not_located_on_read(tmp_path: Path) -> None:
    recorded, stored = b"what the device had", b"other bytes, same n"
    assert len(recorded) == len(stored)
    rows = [_file_row("n", "/sdcard/a.bin", recorded, "Uncategorized")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Uncategorized/a.bin": stored,
    })
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "a.bin"])
    assert node is not None
    with pytest.raises(UFDRContentNotLocatedError):
        vfs.read(node)
    with pytest.raises(UFDRContentNotLocatedError):
        vfs.peek(node)
    vfs.close()

    # Properties settle the check too, before any read.
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "a.bin"])
    assert node is not None
    info = vfs.node_info(node)
    assert info is not None and str(info["Content status"]) == "not located in container"
    vfs.close()


def test_each_member_is_hashed_once_however_many_rows_try_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cellebrite stores identical content once: several rows, one member,
    # and same-sized members in the same bucket to choose between.
    libc_a, libc_b = b"libc build A", b"libc build B"
    rows = [
        _file_row("1", "/system/lib/libc.so", libc_a, "Application"),
        _file_row("2", "/apex/lib/libc.so", libc_a, "Application"),
        _file_row("3", "/vendor/lib/libc.so", libc_b, "Application"),
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={
        "files/Application/libc.so": libc_a,
        "files/Application/libc_264.so": libc_b,
    })
    hashed = _count_hashing(monkeypatch)
    vfs = UFDRVFS(path)
    reads = {
        p: vfs.read(_find(vfs.root(), p.split("/")))  # type: ignore[arg-type]
        for p in ("system/lib/libc.so", "apex/lib/libc.so", "vendor/lib/libc.so")
    }
    assert reads == {
        "system/lib/libc.so": libc_a, "apex/lib/libc.so": libc_a, "vendor/lib/libc.so": libc_b,
    }
    assert sorted(hashed) == ["files/Application/libc.so", "files/Application/libc_264.so"]
    vfs.close()


def test_exact_match_resolution_read_and_open(tmp_path: Path) -> None:
    content = b"hello world" * 100
    digest = hashlib.md5(content).hexdigest()
    rows = [
        _row(
            "n1", 2, "note.txt", "/sdcard/note.txt",
            size=len(content), md5=digest, tag="Text",
            modify_time="2024-07-27 22:04:00",
        )
    ]
    path = _build_fake_ufdr(
        tmp_path, devices={DEVICE: rows}, files={"files/Text/note.txt": content}
    )
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "note.txt"])
    assert node is not None
    assert vfs.read(node) == content
    with vfs.open(node) as f:
        assert f.read() == content
    # 2024-07-27 22:04:00 UTC, verified against a real cross-checked sample.
    assert node.modified == 1722117840.0
    vfs.close()


def test_streaming_open_above_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("crush.core.vfs.STREAM_THRESHOLD", 64)
    monkeypatch.setattr("crush.core.ufdr.STREAM_THRESHOLD", 64)
    content = b"x" * 500
    rows = [
        _row("n1", 2, "big.bin", "/sdcard/big.bin", size=len(content), tag="Uncategorized")
    ]
    path = _build_fake_ufdr(
        tmp_path, devices={DEVICE: rows}, files={"files/Uncategorized/big.bin": content}
    )
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "big.bin"])
    assert node is not None
    with vfs.open(node) as f:
        assert f.read() == content
    assert vfs.read(node) == content
    vfs.close()


def test_fallback_by_size_when_exact_name_is_missing(tmp_path: Path) -> None:
    content = b"collided content"
    digest = hashlib.md5(content).hexdigest()
    rows = [
        _row(
            "n1", 2, "base.apk", "/data/app/base.apk",
            size=len(content), md5=digest, tag="Application",
        )
    ]
    # The zip entry does not match the recorded name (Cellebrite's own
    # collision-disambiguation suffixing) -- only same-bucket, same-size,
    # hash-verified.
    path = _build_fake_ufdr(
        tmp_path,
        devices={DEVICE: rows},
        files={"files/Application/base_912.apk": content},
    )
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["data", "app", "base.apk"])
    assert node is not None
    assert vfs.read(node) == content
    vfs.close()


def test_content_not_located_raises_and_is_reported(tmp_path: Path) -> None:
    rows = [
        _row(
            "n1", 2, "missing.bin", "/sdcard/missing.bin",
            size=123, md5="deadbeef" * 4, tag="Uncategorized",
        )
    ]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "missing.bin"])
    assert node is not None

    info = vfs.node_info(node)
    assert info is not None
    assert str(info["Content status"]) == "not located in container"

    with pytest.raises(UFDRContentNotLocatedError):
        vfs.read(node)
    with pytest.raises(UFDRContentNotLocatedError):
        vfs.open(node)
    vfs.close()


def test_multi_device_gets_one_folder_per_device(tmp_path: Path) -> None:
    device_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    device_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    rows_a = [_row("a1", 1, "system", "/system")]
    rows_b = [_row("b1", 1, "system", "/system")]
    path = _build_fake_ufdr(
        tmp_path, devices={device_a: rows_a, device_b: rows_b}, files={}
    )
    vfs = UFDRVFS(path)
    root = vfs.root()
    names = {c.name for c in root.children}
    assert names == {f"Device {device_a}", f"Device {device_b}"}
    for child in root.children:
        assert _find(child, ["system"]) is not None
    vfs.close()


def test_single_device_is_flattened_at_root(tmp_path: Path) -> None:
    rows = [_row("n1", 1, "system", "/system")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    vfs = UFDRVFS(path)
    root = vfs.root()
    assert {c.name for c in root.children} == {"system"}
    vfs.close()


def test_node_info_surfaces_cellebrite_hashes(tmp_path: Path) -> None:
    content = b"payload"
    digest_md5 = hashlib.md5(content).hexdigest()
    digest_sha256 = hashlib.sha256(content).hexdigest()
    rows = [
        _row(
            "n1", 2, "f.bin", "/sdcard/f.bin",
            size=len(content), md5=digest_md5, sha256=digest_sha256,
            tag="Uncategorized", is_carved="t",
        )
    ]
    path = _build_fake_ufdr(
        tmp_path, devices={DEVICE: rows}, files={"files/Uncategorized/f.bin": content}
    )
    vfs = UFDRVFS(path)
    node = _find(vfs.root(), ["sdcard", "f.bin"])
    assert node is not None
    info = vfs.node_info(node)
    assert info == {
        "Cellebrite MD5": digest_md5,
        "Cellebrite SHA-256": digest_sha256,
        "Category (Tag)": "Uncategorized",
        "Carved": "Yes",
    }
    vfs.close()


def test_open_vfs_dispatches_ufdr_extension(tmp_path: Path) -> None:
    rows = [_row("n1", 1, "system", "/system")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    vfs = open_vfs(path)
    assert isinstance(vfs, UFDRVFS)
    vfs.close()


@pytest.mark.parametrize("name", ["renamed.zip", "renamed.bin", "no_extension"])
def test_open_vfs_recognises_ufdr_by_content_whatever_its_name(tmp_path: Path, name: str) -> None:
    rows = [_row("n1", 1, "system", "/system")]
    path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={}, name=name)
    vfs = open_vfs(path)
    assert isinstance(vfs, UFDRVFS)
    vfs.close()


def test_is_ufdr_zip_sniff(tmp_path: Path) -> None:
    rows = [_row("n1", 1, "system", "/system")]
    ufdr_path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={}, name="renamed.zip")
    assert is_ufdr_zip(ufdr_path) is True

    unrelated = tmp_path / "plain.zip"
    with zipfile.ZipFile(unrelated, "w") as zf:
        zf.writestr("hello.txt", "hi")
    assert is_ufdr_zip(unrelated) is False


def test_parse_ts_is_independent_of_local_timezone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nodes timestamps are raw UTC (verified against a real sample -- see
    crush/core/ufdr.py's _parse_ts docstring). Parsing must not reinterpret
    them through the process's local timezone the way naive
    datetime.fromtimestamp()/.timestamp() would."""
    import time

    from crush.core.ufdr import _parse_ts

    tzset = getattr(time, "tzset", None)
    if tzset is None:
        pytest.skip("time.tzset() is POSIX-only")

    text = "2024-07-27 22:04:00"
    results = set()
    for tz in ("UTC", "America/New_York", "Asia/Tokyo"):
        monkeypatch.setenv("TZ", tz)
        tzset()
        results.add(_parse_ts(text))
    tzset()  # restore
    assert results == {1722117840.0}


def test_close_dump_releases_the_source_file_handle(tmp_path: Path) -> None:
    """pgdumplib.Dump.load() opens the temp database copy and keeps that
    handle open (no public close()) -- open_ufdr() must release it via
    _close_dump() before deleting the temp file, or the delete raises
    PermissionError on Windows (unlike POSIX, which allows unlinking an
    open file regardless of who still has it open). Regression test for
    a real Windows CI failure: open_ufdr() worked on Linux/macOS but
    crashed on every Windows run because that close was missing.

    This can't be reproduced on POSIX by asserting the temp file was
    deleted -- unlink() there succeeds whether or not the handle was
    closed first, so a POSIX-only run of that assertion would pass either
    way. Testing _close_dump()'s actual effect on the handle is portable.
    """
    import pgdumplib

    from crush.core.ufdr import _close_dump

    rows = [_row("n1", 1, "system", "/system")]
    ufdr_path = _build_fake_ufdr(tmp_path, devices={DEVICE: rows}, files={})
    with zipfile.ZipFile(ufdr_path) as zf:
        db_path = tmp_path / "extracted.db"
        db_path.write_bytes(zf.read("DbData/database.db"))

    dump = pgdumplib.load(db_path)
    assert not dump._handle.closed
    _close_dump(dump)
    assert dump._handle.closed
    # A closed handle must not block deleting the file it pointed at --
    # exactly what open_ufdr()'s own cleanup relies on.
    db_path.unlink()


def test_load_dump_keeps_only_the_nodes_tables_data(tmp_path: Path) -> None:
    """A real UFDR dump holds ~194 tables; pgdumplib.load() would cache all
    of them before returning. Only Nodes is read, so only Nodes is kept."""
    import pgdumplib

    from crush.core.ufdr import _close_dump, _load_dump

    schema = f"device_{DEVICE}"
    dump = pgdumplib.new(dbname="ufdr")
    _write_schema(dump, schema, [_row("n1", 1, "system", "/system")])
    other = dump.add_entry(
        desc="TABLE", namespace=schema, tag="Contacts",
        defn=f'CREATE TABLE "{schema}"."Contacts" (\n    "Name" text\n);',
    )
    with dump.table_data_writer(other, ["Name"]) as writer:
        writer.append("Alice")
    db_path = tmp_path / "database.db"
    dump.save(db_path)

    loaded = _load_dump(db_path)
    try:
        assert [r[3] for r in loaded.table_data(schema, "Nodes")] == ["system"]
        cached = {p.name for p in Path(loaded._temp_dir.name).iterdir()}
        nodes_id = loaded.lookup_entry("TABLE DATA", schema, "Nodes").dump_id
        assert cached == {f"{nodes_id}.gz"}
    finally:
        _close_dump(loaded)


def test_split_archive_raises_explicit_open_error(tmp_path: Path) -> None:
    # A single segment of a split/segmented export, or any other file that
    # isn't a valid standalone zip -- the natural failure mode when this
    # explicitly out-of-scope case is hit.
    truncated = tmp_path / "part1.ufdr"
    truncated.write_bytes(b"not actually a zip file")
    with pytest.raises(UFDROpenError, match="multiple parts"):
        UFDRVFS(truncated)


# ---------------------------------------------------------------------------
# The same guarantees as every other source (one test per subject and
# category: the coverage page reads literal markers)
# ---------------------------------------------------------------------------


def _evidence(tmp_path: Path) -> Path:
    """A UFDR alone in *tmp_path*/evidence: a file, an empty file, and an
    item derived from the file (its database dump is built elsewhere)."""
    enc, dec = b"encrypted bytes", b"SQLite format 3\x00decrypted"
    rows = [
        _file_row("p", f"{DB_DIR}/signal.db", enc, "Database"),
        _file_row("c", f"{DB_DIR}/signal.db/signal.db.decrypted", dec, "Database",
                  type_=10, parent_id="p"),
        _row("e", 2, "restore.log", "/data/cache/restore.log", size=0, tag="Text"),
    ]
    build = tmp_path / "build"
    build.mkdir()
    built = _build_fake_ufdr(build, devices={DEVICE: rows}, files={
        "files/Database/signal.db": enc,
        "files/Database/signal.db.decrypted": dec,
    })
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    return built.rename(evidence / built.name)


def _files_of(node: VFSNode) -> list[VFSNode]:
    if not node.is_dir:
        return [node]
    return [f for c in node.children for f in _files_of(c)]


def _read_all(path: Path) -> None:
    vfs = open_vfs(path)
    try:
        nodes = _files_of(vfs.root())
        assert len(nodes) == 3
        for node in nodes:
            vfs.read(node)
            vfs.peek(node)
            vfs.node_info(node)  # type: ignore[attr-defined]
    finally:
        vfs.close()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFDR",
    desc="Opening and reading a UFDR leaves its bytes unchanged",
)
def test_ufdr_does_not_modify_source(tmp_path: Path) -> None:
    path = _evidence(tmp_path)
    before = _sha(path)
    _read_all(path)
    assert _sha(path) == before


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFDR",
    desc="Opening and reading a UFDR leaves its mtime and ctime unchanged",
)
def test_ufdr_does_not_change_timestamps(tmp_path: Path) -> None:
    path = _evidence(tmp_path)
    before = (path.stat().st_mtime_ns, path.stat().st_ctime_ns)
    _read_all(path)
    assert (path.stat().st_mtime_ns, path.stat().st_ctime_ns) == before


@pytest.mark.forensic(
    category="No Side Effects",
    subject="Cellebrite UFDR",
    desc="Opening and reading a UFDR creates no files beside it (its database dump is "
         "extracted to the temp directory)",
)
def test_ufdr_creates_no_sibling_files(tmp_path: Path) -> None:
    path = _evidence(tmp_path)
    before = set(path.parent.iterdir())
    _read_all(path)
    assert set(path.parent.iterdir()) == before


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    subject="Cellebrite UFDR",
    desc="A UFDR opens and reads with its file 0o444 and its folder 0o555",
)
def test_ufdr_works_on_readonly_media(tmp_path: Path) -> None:
    path = _evidence(tmp_path)
    path.chmod(0o444)
    path.parent.chmod(0o555)
    try:
        _read_all(path)
    finally:
        path.parent.chmod(0o755)
        path.chmod(0o644)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="Cellebrite UFDR",
    desc="Opening a UFDR twice gives the same tree, statuses and bytes",
)
def test_ufdr_reproducible(tmp_path: Path) -> None:
    path = _evidence(tmp_path)

    def snapshot() -> list[tuple[str, int, str, str]]:
        vfs = open_vfs(path)
        try:
            return [(n.path, n.size, str(n.status), hashlib.sha256(vfs.read(n)).hexdigest())
                    for n in _files_of(vfs.root())]
        finally:
            vfs.close()

    assert snapshot() == snapshot()
