# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on XFS, Btrfs and ReFS volumes.

The images and their listings are abrignoni/qnxprobe's own MIT-licensed test
fixtures (tests/fixtures at the vendored commit), renamed with a `raw_`
prefix:

- `raw_xfs` is xfs-v5-4kn: mkfs.xfs wrote it from a source tree (4 KiB
  sectors, the metadata directory). `raw_xfs.known.json.gz` is its listing
  and the sha256 of every file, taken from the source tree.
- `raw_btrfs` is btrfs-zlib: mkfs.btrfs --rootdir wrote it, zlib-compressed,
  from a source tree. `raw_btrfs.sha256` is btrfs.src.sha256, the sha256 of
  every file in that tree.
- `raw_refs` is refs-fixture: a Windows 11 ReFS 3.14 volume of which only the
  bytes the reader reads are kept, each at its own offset (qnxprobe's
  tools/make_refs_fixture.py), so it is read through qnxprobe's own reader
  for that layout, not opened as an image file. `raw_refs.known.tsv.gz` is
  what Windows reported about each file and stream while the volume was
  mounted. The content of the files the fixture leaves out by name is not
  checked.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import render_value
from crush.core.raw_image import _Entry, build_volume_node, read_walker_file
from crush.core.vfs import RawImageVFS, VFSNode
from crush.tests.conftest import FIXTURES_DIR
from crush.third_party.qnxprobe import qnxprobe as qp


def _image(tmp_path: Path, stem: str, data: bytes | None = None) -> Path:
    img = tmp_path / f"{stem}.img"
    img.write_bytes(data if data is not None else gzip.decompress(
        (FIXTURES_DIR / f"{stem}.img.gz").read_bytes()))
    return img


def _files(node: VFSNode) -> list[VFSNode]:
    out: list[VFSNode] = []
    for child in node.children:
        if child.is_dir:
            out.extend(_files(child))
        else:
            out.append(child)
    return out


def _hashes(vfs: RawImageVFS, volume: VFSNode) -> dict[str, str]:
    prefix = volume.path.rstrip("/") + "/"
    return {
        f.path.removeprefix(prefix): hashlib.sha256(vfs.read(f)).hexdigest()
        for f in _files(volume)
    }


def _sha256_listing(name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (FIXTURES_DIR / name).read_text(encoding="utf-8").splitlines():
        if line:
            digest, _, relpath = line.partition("  ")
            out[relpath] = digest
    return out


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="XFS",
    desc="Every file on an XFS v5 volume with 4 KiB sectors reads back at its path with "
    "the bytes hashed from the source tree mkfs.xfs wrote it from",
)
def test_xfs_every_file_reads_back_as_written(tmp_path: Path) -> None:
    known = json.loads(gzip.decompress((FIXTURES_DIR / "raw_xfs.known.json.gz").read_bytes()))
    want = {e["path"]: e["sha256"] for e in known["entries"] if e["type"] == "file"}
    vfs = RawImageVFS(_image(tmp_path, "raw_xfs"))
    try:
        assert [(v.get("kind"), type(v.get("walker")).__name__) for v in vfs._handle.volumes
                if v.get("walker") is not None] == [("xfs", "XfsWalker")]
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        got = _hashes(vfs, volume)
        assert len(want) == 116
        assert {path: got.get(path) for path in want} == want
        assert not volume.status
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Btrfs",
    desc="Every file on a zlib-compressed Btrfs volume reads back at its path with the "
    "bytes hashed from the source tree mkfs.btrfs wrote it from",
)
def test_btrfs_every_file_reads_back_as_written(tmp_path: Path) -> None:
    want = _sha256_listing("raw_btrfs.sha256")
    vfs = RawImageVFS(_image(tmp_path, "raw_btrfs"))
    try:
        assert [(v.get("kind"), type(v.get("walker")).__name__) for v in vfs._handle.volumes
                if v.get("walker") is not None] == [("btrfs", "BtrfsWalker")]
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        got = _hashes(vfs, volume)
        assert len(want) == 572
        assert {path: got.get(path) for path in want} == want
    finally:
        vfs.close()


def test_xfs_damage_found_while_listing_is_on_the_volume(tmp_path: Path) -> None:
    """An inode that fails its CRC is recorded by the reader as damage while
    the volume is listed, after volumes() wrote its note. The name its
    directory gives is listed with no metadata, and the volume's status says
    what was damaged, so the listing does not look complete."""
    data = bytearray(gzip.decompress((FIXTURES_DIR / "raw_xfs.img.gz").read_bytes()))
    walker = qp.XfsWalker(qp._XfsPatchedImage(bytes(data)), 0)
    hello = next(node for path, node, *_rest in qp.walk_all(walker) if path == "hello.txt")
    at = walker.inode_offset(hello) + 60
    data[at] ^= 0x01
    vfs = RawImageVFS(_image(tmp_path, "raw_xfs_damaged", bytes(data)))
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        hello_node = next(c for c in volume.children if c.name == "hello.txt")
        assert "could not be read" in render_value(hello_node.status)
        status = render_value(volume.status)
        assert "failed a check while it was listed" in status and "fails its CRC" in status
    finally:
        vfs.close()


def _refs_known() -> list[dict[str, str]]:
    lines = gzip.decompress(
        (FIXTURES_DIR / "raw_refs.known.tsv.gz").read_bytes()
    ).decode("utf-8").splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, line.split("\t"), strict=True)) for line in lines[1:]]


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="ReFS",
    desc="Every file and alternate data stream on a Windows 11 ReFS 3.14 volume reads "
    "back with the SHA-256 Windows recorded, streams beside their file as file:stream",
)
def test_refs_every_file_and_stream_reads_back_as_windows_recorded() -> None:
    img = qp._RefsSparseImage(gzip.decompress((FIXTURES_DIR / "raw_refs.bin.gz").read_bytes()))
    unshipped = set(img.head.get("not_shipped", []))
    walker = qp.RefsWalker(img, 0)
    read_map: dict[str, _Entry] = {}
    vol: dict[str, Any] = {"name": "refs", "base": 0, "size": img.size, "kind": "refs",
                           "walker": walker}
    build_volume_node(vol, read_map)
    known = _refs_known()
    files = {k["path"]: k for k in known if k["kind"] == "file" and k["path"] not in unshipped}
    streams = {k["path"]: k for k in known if k["kind"] == "stream"}
    got: dict[str, str] = {}
    for path, entry in read_map.items():
        rel = path.removeprefix("/refs/")
        if rel in files or rel in streams:
            assert entry.walker is walker, rel
            got[rel] = hashlib.sha256(read_walker_file(walker, entry.node, entry.size)).hexdigest()
    assert len(files) == 2544 - len(unshipped) and len(streams) == 3
    assert {p: got.get(p) for p in files} == {p: k["sha256"] for p, k in files.items()}
    assert {p: got.get(p) for p in streams} == {p: k["sha256"] for p, k in streams.items()}
    assert not walker.damage
    # The paths Windows created and then deleted are not in the tree.
    deleted = [k["path"] for k in known if k["kind"] == "deleted"]
    assert len(deleted) == 17 and not [p for p in deleted if f"/refs/{p}" in read_map]
