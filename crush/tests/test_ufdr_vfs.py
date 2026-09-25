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
]

_COLUMN_TYPES = {
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
    }


def _write_schema(dump: Any, schema: str, rows: list[dict[str, Any]]) -> None:
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


def _build_fake_ufdr(
    tmp_path: Path,
    *,
    devices: dict[str, list[dict[str, Any]]],
    files: dict[str, bytes],
    name: str = "sample.ufdr",
) -> Path:
    """A minimal, self-contained fake UFDR: *devices* maps a device UUID to
    its Nodes rows (one or more devices), *files* maps a zip-internal
    ``files/<Tag>/<name>`` path to its content."""
    import pgdumplib

    dump = pgdumplib.new(dbname="ufdr")
    for device_id, rows in devices.items():
        _write_schema(dump, f"device_{device_id}", rows)
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


def test_tree_shape_excludes_type_10_and_builds_from_absolute_path(tmp_path: Path) -> None:
    apk_bytes = b"apk content"
    apk_md5 = hashlib.md5(apk_bytes).hexdigest()
    rows = [
        _row("n1", 1, "app", "/data/app", tag=""),
        _row(
            "n2", 2, "base.apk", "/data/app/base.apk",
            size=len(apk_bytes), md5=apk_md5, tag="Application",
        ),
        # A Cellebrite-synthesised embedded sub-item -- must never appear.
        _row(
            "n3", 10, "AndroidManifest.xml", "/data/app/base.apk/AndroidManifest.xml",
            size=5, tag="Text",
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

    assert not any("AndroidManifest.xml" in p for p in _all_paths(root))
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
    assert info["Content status"] == "not located in container"

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


def test_split_archive_raises_explicit_open_error(tmp_path: Path) -> None:
    # A single segment of a split/segmented export, or any other file that
    # isn't a valid standalone zip -- the natural failure mode when this
    # explicitly out-of-scope case is hit.
    truncated = tmp_path / "part1.ufdr"
    truncated.write_bytes(b"not actually a zip file")
    with pytest.raises(UFDROpenError, match="multiple parts"):
        UFDRVFS(truncated)
