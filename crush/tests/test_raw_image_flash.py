# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on flash filesystems: SquashFS, JFFS2, UBI/UBIFS, YAFFS1/2.

The images and their `.sha256` oracles are abrignoni/qnxprobe's own
MIT-licensed test fixtures (tests/fixtures at the vendored commit), renamed
with a `raw_flash_` prefix. Each oracle lists every regular file of the tree
the image was built from (`*.src.sha256`) or of the tree as the filesystem's
own writer left it after a history of renames and deletions
(`*.history.sha256`, written by the Linux kernel's JFFS2/UBIFS drivers and
by YAFFS's own core).
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
from pathlib import Path

import pytest

from crush.core.raw_image import RawImageFileUnreadableError
from crush.core.vfs import RawImageVFS, VFSNode
from crush.tests.conftest import FIXTURES_DIR

_RECOVERED = "$Recovered"


def _open(tmp_path: Path, name: str) -> RawImageVFS:
    img = tmp_path / name.removesuffix(".gz")
    img.write_bytes(gzip.decompress((FIXTURES_DIR / f"raw_flash_{name}").read_bytes()))
    return RawImageVFS(img)


def _oracle(name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (FIXTURES_DIR / f"raw_flash_{name}").read_text(encoding="utf-8").splitlines():
        if line:
            digest, _, relpath = line.partition("  ")
            out[relpath] = digest
    return out


def _regular_files(node: VFSNode) -> list[VFSNode]:
    """Every walked file below *node* that isn't a symlink/special entry
    (those carry a status and no content) and isn't a recovered entry."""
    out: list[VFSNode] = []
    for child in node.children:
        if child.is_dir:
            if child.name != _RECOVERED:
                out.extend(_regular_files(child))
        elif not child.status:
            out.append(child)
    return out


def _child(node: VFSNode, name: str) -> VFSNode:
    return next(c for c in node.children if c.name == name)


# (image, oracle, path of the filesystem root below the volume node)
_LIVE_TREES = [
    ("squashfs-gzip.img.gz", "squashfs.src.sha256", ""),
    ("yaffs1.img.gz", "yaffs.src.sha256", ""),
    ("yaffs2-history.img.gz", "yaffs2.history.sha256", ""),
    ("jffs2-nor-history.img.gz", "jffs2-nor.history.sha256", ""),
    ("ubi-nand-history.img.gz", "ubi-nand.history.sha256", "rootfs_data"),
]


@pytest.mark.parametrize(("image", "oracle", "fs_root"), _LIVE_TREES)
def test_live_tree_matches_the_writer(tmp_path: Path, image: str, oracle: str, fs_root: str) -> None:
    """Every live file the filesystem's writer left is listed with the same
    content, and nothing is listed that the writer didn't leave."""
    vfs = _open(tmp_path, image)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        root = _child(volume, fs_root) if fs_root else volume
        prefix = root.path.rstrip("/") + "/"
        got = {
            node.path.removeprefix(prefix): hashlib.sha256(vfs.read(node)).hexdigest()
            for node in _regular_files(root)
        }
        assert got == _oracle(oracle)
    finally:
        vfs.close()


def test_image_without_partition_table_is_one_volume(tmp_path: Path) -> None:
    """A bare flash dump is found by its filesystem's own header at offset 0
    and becomes one volume -- no partition table required."""
    vfs = _open(tmp_path, "squashfs-gzip.img.gz")
    try:
        assert [(v.get("kind"), v.get("walker") is not None) for v in vfs._handle.volumes] == [
            ("squashfs", True)
        ]
    finally:
        vfs.close()


@pytest.mark.skipif(
    importlib.util.find_spec("compression") is not None,
    reason="this Python reads zstd (compression.zstd); the reader has nothing to explain",
)
def test_zstd_squashfs_without_zstd_says_why_it_is_empty(tmp_path: Path) -> None:
    """On a Python without zstd the walker exists but lists nothing; the
    volume must carry the reader's reason, not look like an empty filesystem."""
    vfs = _open(tmp_path, "squashfs-zstd.img.gz")
    try:
        (volume,) = vfs.root().children
        assert volume.is_dir
        assert volume.status
        assert volume.status.code == "entry.raw_volume_note"  # type: ignore[union-attr]
        assert "zstd" in str(volume.status)
    finally:
        vfs.close()


# (image, deleted file that must be recovered whole, its original folder)
_RECOVERED_CASES = [
    ("yaffs2-history.img.gz", "deleted.txt", "/gone"),
    ("jffs2-nor-history.img.gz", "gone.txt", "/"),
    ("jffs2-nor-history.img.gz", "target.txt", "/dir"),
    ("ubi-nand-history.img.gz", "gone.txt", "/rootfs_data"),
    ("ubi-nand-history.img.gz", "target.txt", "/rootfs_data/dir"),
]


@pytest.mark.parametrize(("image", "name", "folder"), _RECOVERED_CASES)
def test_flash_deleted_file_is_recovered(tmp_path: Path, image: str, name: str, folder: str) -> None:
    vfs = _open(tmp_path, image)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        node = _child(_child(volume, _RECOVERED), name)
        info = vfs.volume_info(node)
        assert info is not None
        assert info["kind"] == "deleted file"
        assert info["original_folder"] == folder
        assert node.modified > 0  # the flash records keep the file's mtime
        data = vfs.read(node)
        assert len(data) == node.size > 0
        assert vfs.peek(node, 16) == data[:16]
        with vfs.open(node) as fh:
            assert fh.read() == data
    finally:
        vfs.close()


def test_unrecoverable_flash_deleted_file_is_listed_with_its_reason(tmp_path: Path) -> None:
    """A deleted file whose pages were erased stays visible, says why it
    can't be read, and refuses the read instead of returning a partial copy."""
    vfs = _open(tmp_path, "yaffs2-history.img.gz")
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        recovered = _child(volume, _RECOVERED)
        refused = [
            n for n in recovered.children
            if vfs.volume_info(n)["note"].code == "common.notes"  # type: ignore[index, union-attr]
            and "not recoverable" in str(vfs.volume_info(n)["note"])  # type: ignore[index]
        ]
        assert refused
        with pytest.raises(RawImageFileUnreadableError, match="not recoverable"):
            vfs.read(refused[0])
    finally:
        vfs.close()


def test_yaffs2_recovery_decision_is_shown(tmp_path: Path) -> None:
    """YAFFS2's recovery takes the header before a size-0 header as the
    file's -- a decision the flash doesn't record, so it must be visible."""
    vfs = _open(tmp_path, "yaffs2-history.img.gz")
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        info = vfs.volume_info(_child(_child(volume, _RECOVERED), "deleted.txt"))
        assert info is not None
        codes = [n.code for n in info["note"].params["notes"]]
        assert codes == ["entry.recovered_intact", "entry.recovery_note"]
        assert "size 0" in str(info["note"])
    finally:
        vfs.close()


def _gpt_4kn_image(payload: bytes, first_lba: int) -> bytes:
    """A disk with 4096-byte logical sectors: protective MBR, GPT header at
    LBA 1 (byte 4096) with valid CRCs (UEFI 2.10 5.3.2), one Linux-data
    partition holding *payload* from *first_lba*."""
    import struct
    import uuid
    import zlib

    ss = 4096
    part_sectors = -(-len(payload) // ss)
    last_lba = first_lba + part_sectors - 1
    disk_sectors = last_lba + 1 + 8
    img = bytearray(disk_sectors * ss)
    # protective MBR
    img[446 + 4] = 0xEE
    img[446 + 8:446 + 12] = (1).to_bytes(4, "little")
    img[446 + 12:446 + 16] = min(disk_sectors - 1, 0xFFFFFFFF).to_bytes(4, "little")
    img[510:512] = b"\x55\xaa"
    # partition entry array at LBA 2: 128 entries of 128 bytes
    entries = bytearray(128 * 128)
    entries[0:16] = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
    entries[16:32] = uuid.UUID(int=1).bytes_le
    struct.pack_into("<QQQ", entries, 32, first_lba, last_lba, 0)
    entries[56:56 + 8] = "data".encode("utf-16-le")
    img[2 * ss:2 * ss + len(entries)] = entries
    hdr = bytearray(92)
    struct.pack_into(
        "<8sIIIIQQQQ16sQIII", hdr, 0, b"EFI PART", 0x00010000, 92, 0, 0,
        1, disk_sectors - 1, 6, disk_sectors - 2, uuid.UUID(int=2).bytes_le,
        2, 128, 128, zlib.crc32(entries),
    )
    struct.pack_into("<I", hdr, 16, zlib.crc32(hdr))
    img[ss:ss + 92] = hdr
    img[first_lba * ss:first_lba * ss + len(payload)] = payload
    return bytes(img)


def test_gpt_on_4096_byte_sectors(tmp_path: Path) -> None:
    """A GPT whose header sits at byte 4096 counts its LBAs in 4096-byte
    sectors: the partition is found at the right byte offset and walked,
    and the space around it is still listed as unallocated."""
    payload = gzip.decompress((FIXTURES_DIR / "raw_flash_squashfs-gzip.img.gz").read_bytes())
    img = tmp_path / "disk4kn.img"
    img.write_bytes(_gpt_4kn_image(payload, first_lba=16))
    vfs = RawImageVFS(img)
    try:
        vols = vfs._handle.volumes
        (part,) = [v for v in vols if v.get("walker") is not None]
        assert (part["kind"], part["base"], part["lba"]) == ("squashfs", 16 * 4096, 16)
        # regions tile the whole disk: nothing is left out of the tree
        spans = sorted((v["base"], v["size"]) for v in vols if v.get("size"))
        assert spans[0][0] == 0
        assert sum(size for _, size in spans) >= img.stat().st_size
        volume = next(c for c in vfs.root().children if c.name == part["name"])
        prefix = volume.path + "/"
        got = {n.path.removeprefix(prefix): hashlib.sha256(vfs.read(n)).hexdigest()
               for n in _regular_files(volume)}
        assert got == _oracle("squashfs.src.sha256")
    finally:
        vfs.close()


def test_deleted_file_in_a_folder_that_is_gone(tmp_path: Path) -> None:
    """None as the parent path means the folder no longer exists; that is
    said explicitly rather than shown as the volume root."""
    vfs = _open(tmp_path, "jffs2-nor-history.img.gz")
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        folders = [vfs.volume_info(n)["original_folder"] for n in _child(volume, _RECOVERED).children]  # type: ignore[index]
        gone = [f for f in folders if not isinstance(f, str)]
        assert gone and all(f.code == "entry.original_folder_gone" for f in gone)
    finally:
        vfs.close()
