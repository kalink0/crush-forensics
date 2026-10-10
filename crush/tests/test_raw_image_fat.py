# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on FAT16 and FAT12 volumes, and on the layout of Windows CE's
transaction-safe FAT.

The images and their listings are abrignoni/qnxprobe's own MIT-licensed test
fixtures (tests/fixtures at the vendored commit), renamed with a `raw_`
prefix. macOS wrote all three volumes. `*.sha256` lists every file hashed
from the mounted volume, and `*.deleted.sha256` the files that were then
deleted, hashed before deletion. `raw_tfat16` has 2,048-byte sectors, the
`TFAT16` type string and its files under `__TFAT_HIDDEN_ROOT_DIR__`: it stands
in for the layout Windows CE writes, not for Windows CE's driver (qnxprobe's
tools/make_fat16_fixtures.sh says which boot sector bytes its builder set).
"""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from crush.core.vfs import RawImageVFS, VFSNode
from crush.tests.conftest import FIXTURES_DIR

_RECOVERED = "$Recovered"

# (fixture stem, the reader's name for the filesystem, its walker)
_VOLUMES = [
    ("raw_fat16", "fat16", "Fat16Walker"),
    ("raw_tfat16", "fat16", "Fat16Walker"),
    ("raw_fat12", "fat12", "Fat12Walker"),
]


def _open(tmp_path: Path, stem: str) -> RawImageVFS:
    img = tmp_path / f"{stem}.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / f"{stem}.img.gz").read_bytes()))
    return RawImageVFS(img)


def _listing(name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (FIXTURES_DIR / name).read_text(encoding="utf-8").splitlines():
        if line:
            digest, _, relpath = line.partition("  ")
            out[relpath] = digest
    return out


def _files(node: VFSNode) -> list[VFSNode]:
    out: list[VFSNode] = []
    for child in node.children:
        if child.is_dir:
            if child.name != _RECOVERED:
                out.extend(_files(child))
        else:
            out.append(child)
    return out


@pytest.mark.parametrize(("stem", "kind", "walker"), _VOLUMES)
def test_volume_is_read_as_what_its_cluster_count_makes_it(
    tmp_path: Path, stem: str, kind: str, walker: str
) -> None:
    vfs = _open(tmp_path, stem)
    try:
        assert [(v.get("kind"), type(v.get("walker")).__name__) for v in vfs._handle.volumes] == [
            (kind, walker)
        ]
    finally:
        vfs.close()


@pytest.mark.parametrize(("stem", "kind", "walker"), _VOLUMES)
def test_every_listed_file_reads_back_as_written(
    tmp_path: Path, stem: str, kind: str, walker: str
) -> None:
    """Every file the listing names is in the tree at that path with the bytes
    macOS wrote. The volume also holds macOS's own `._` companion files, which
    the listing leaves out, so the comparison runs from the listing."""
    vfs = _open(tmp_path, stem)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        prefix = volume.path.rstrip("/") + "/"
        got = {
            node.path.removeprefix(prefix): hashlib.sha256(vfs.read(node)).hexdigest()
            for node in _files(volume)
        }
        want = _listing(f"{stem}.sha256")
        assert want
        assert {path: got.get(path) for path in want} == want
    finally:
        vfs.close()


@pytest.mark.parametrize(("stem", "kind", "walker"), _VOLUMES)
def test_deleted_files_are_recovered(tmp_path: Path, stem: str, kind: str, walker: str) -> None:
    """The files deleted before the volume was unmounted come back under
    `$Recovered` with the bytes hashed before deletion. A short name loses its
    first character to the delete mark and is shown with `_` in its place."""
    vfs = _open(tmp_path, stem)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        recovered = next(c for c in _all_dirs(volume) if c.name == _RECOVERED)
        by_hash: dict[str, str] = {}
        for node in recovered.children:
            info = vfs.volume_info(node)
            if info and str(info["note"]).startswith("recovered"):
                by_hash[hashlib.sha256(vfs.read(node)).hexdigest()] = node.name
        want = _listing(f"{stem}.deleted.sha256")
        assert len(want) == 3
        for relpath, digest in want.items():
            name = relpath.rsplit("/", 1)[-1]
            assert by_hash.get(digest) in (name, "_" + name[1:]), relpath
    finally:
        vfs.close()


def _all_dirs(node: VFSNode) -> list[VFSNode]:
    out = [node]
    for child in node.children:
        if child.is_dir:
            out.extend(_all_dirs(child))
    return out


def test_transaction_safe_volume_keeps_its_files_under_one_root_folder(tmp_path: Path) -> None:
    """The folder a TFAT16 volume redirects its root to is shown as stored,
    and every listed file is under it."""
    vfs = _open(tmp_path, "raw_tfat16")
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        folders = [c.name for c in volume.children if c.is_dir and c.name != _RECOVERED]
        assert "__TFAT_HIDDEN_ROOT_DIR__" in folders
        assert all(p.startswith("__TFAT_HIDDEN_ROOT_DIR__/") for p in _listing("raw_tfat16.sha256"))
    finally:
        vfs.close()
