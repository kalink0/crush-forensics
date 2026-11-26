# SPDX-License-Identifier: Apache-2.0
"""What the qnxprobe readers say about a volume and its files beyond the
listing (qnxprobe 1.88), and where Crush shows it.

The exFAT and ext cases change one field in a copy of an existing fixture
(raw_exfat_deleted, raw_ext4_encrypt_flag) and check the result against the
image's own bytes, not against what qnxprobe returns. The cases no fixture
holds (a YAFFS object no listing reaches, QNX6 blocks without a pointer, a
volume note that grows while the volume is listed, a reader check that
raises) use stand-in walkers.
"""
from __future__ import annotations

import gzip
import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue, render_value
from crush.core.raw_image import _Entry, after_read_notes, build_volume_node
from crush.core.vfs import RawImageVFS, VFSNode
from crush.tests.conftest import FIXTURES_DIR
from crush.third_party.qnxprobe import qnxprobe as qp


def _codes(status: Any) -> list[str]:
    if not status:
        return []
    if status.code == "common.notes":
        return [n.code for n in status.params["notes"]]
    return [status.code]


def _notes(status: Any) -> list[ParseIssue]:
    if not status:
        return []
    return list(status.params["notes"]) if status.code == "common.notes" else [status]


# -- exFAT -------------------------------------------------------------------


class _Exfat:
    """Offsets in a copy of the raw_exfat_deleted fixture (exFAT, 4 KiB
    clusters). a.bin is 8,192 bytes in clusters 13 and 14, NoFatChain."""

    def __init__(self) -> None:
        self.data = bytearray(gzip.decompress((FIXTURES_DIR / "raw_exfat_deleted.img.gz").read_bytes()))
        self.heap, self.clusters, self.root = struct.unpack_from("<III", self.data, 88)
        self.sector = 1 << self.data[108]
        self.cluster = self.sector << self.data[109]
        root = self.at(self.root)
        self.entries = [root + i for i in range(0, self.cluster, 32)]
        bitmap = next(e for e in self.entries if self.data[e] == 0x81)
        self.bitmap = struct.unpack_from("<I", self.data, bitmap + 20)[0]

    def at(self, cluster: int) -> int:
        return self.heap * self.sector + (cluster - 2) * self.cluster

    def stream_of(self, first_cluster: int) -> int:
        (found,) = [e for e in self.entries if self.data[e] == 0xC0
                    and struct.unpack_from("<I", self.data, e + 20)[0] == first_cluster]
        return found

    def is_allocated(self, cluster: int) -> bool:
        byte = self.data[self.at(self.bitmap) + (cluster - 2) // 8]
        return bool(byte >> ((cluster - 2) % 8) & 1)

    def allocate(self, cluster: int) -> None:
        self.data[self.at(self.bitmap) + (cluster - 2) // 8] |= 1 << ((cluster - 2) % 8)

    @staticmethod
    def checksum(entry_set: bytearray) -> None:
        total = 0
        for index, byte in enumerate(entry_set):
            if index not in (2, 3):
                total = (((total << 15) | (total >> 1)) + byte) & 0xFFFF
        struct.pack_into("<H", entry_set, 2, total)

    def write(self, tmp_path: Path, name: str) -> Path:
        path = tmp_path / name
        path.write_bytes(bytes(self.data))
        return path


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="exFAT",
    desc="An exFAT entry set in an allocated cluster no live folder reaches is listed in "
    "$Orphaned, not as deleted, with the content its clusters hold and marked unverified",
)
def test_exfat_orphan_entry_is_listed_in_orphaned(tmp_path: Path) -> None:
    """a.bin's entry set is copied into a free cluster and pointed at two
    other free clusters that get a.bin's bytes; all three are then marked
    allocated. No live folder names that cluster, so the entry is an orphan."""
    fs = _Exfat()
    folder, first = fs.clusters - 10, fs.clusters - 8
    assert not any(fs.is_allocated(c) for c in (folder, first, first + 1))
    stream = fs.stream_of(13)
    entry_set = bytearray(fs.data[stream - 32:stream - 32 + 32 * (fs.data[stream - 31] + 1)])
    struct.pack_into("<I", entry_set, 32 + 20, first)
    fs.checksum(entry_set)
    fs.data[fs.at(folder):fs.at(folder) + len(entry_set)] = entry_set
    content = bytes(fs.data[fs.at(13):fs.at(13) + 8192])
    fs.data[fs.at(first):fs.at(first) + 8192] = content
    for cluster in (folder, first, first + 1):
        fs.allocate(cluster)

    vfs = RawImageVFS(fs.write(tmp_path, "orphan.img"))
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        orphaned = next(c for c in volume.children if c.name == "$Orphaned")
        (node,) = orphaned.children
        assert node.name == "a.bin" and node.size == 8192
        assert hashlib.sha256(vfs.read(node)).hexdigest() == hashlib.sha256(content).hexdigest()
        info = vfs.volume_info(node) or {}
        assert info["kind"] == "orphaned file"
        assert _codes(info["note"])[:1] == ["entry.recovered_unverified"]
        assert info["original_folder"].code == "entry.orphan_folder_unnamed"
        # The orphan is not a deleted file, and the live a.bin is untouched.
        recovered = next(c for c in volume.children if c.name == "$Recovered")
        assert "a.bin" not in {c.name for c in recovered.children}
        # exFAT's own count of clusters no live entry reaches is on the volume.
        assert "allocated clusters are reached by no live entry" in render_value(volume.status)
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="exFAT",
    desc="An exFAT file whose ValidDataLength is below its size reads its clusters up to "
    "ValidDataLength and zeros after, and says so on the file",
)
def test_exfat_past_valid_data_is_on_the_file(tmp_path: Path) -> None:
    fs = _Exfat()
    stream = fs.stream_of(13)
    struct.pack_into("<Q", fs.data, stream + 8, 4096)  # ValidDataLength
    entry_set = bytearray(fs.data[stream - 32:stream - 32 + 32 * (fs.data[stream - 31] + 1)])
    fs.checksum(entry_set)
    fs.data[stream - 32:stream - 32 + len(entry_set)] = entry_set
    expected = bytes(fs.data[fs.at(13):fs.at(13) + 4096]) + bytes(4096)

    vfs = RawImageVFS(fs.write(tmp_path, "vdl.img"))
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        a_bin = next(c for c in volume.children if c.name == "a.bin")
        c_bin = next(c for c in volume.children if c.name == "c.bin")
        assert vfs.read(a_bin) == expected
        (note,) = _notes(a_bin.status)
        assert note.code == "entry.raw_note_past_valid_data"
        assert "ValidDataLength 4,096 of DataLength 8,192" in render_value(note)
        assert not c_bin.status
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="FAT16",
    desc="A recoverable deleted FAT16 file says its content is a candidate and that its "
    "layout is assumed, not that its content is intact",
)
def test_fat_recovery_is_marked_unverified(tmp_path: Path) -> None:
    img = tmp_path / "fat16.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_fat16.img.gz").read_bytes()))
    vfs = RawImageVFS(img)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        recovered = next(c for c in volume.children if c.name == "$Recovered")
        node = next(c for c in recovered.children if c.name == "deleted-alone.bin")
        assert hashlib.sha256(vfs.read(node)).hexdigest() == (
            "3daa7b76caba0ea3f7313f4596fa251e1bb9c128e34e6a2da6d152fe865cef0f")
        assert _codes((vfs.volume_info(node) or {})["note"]) == [
            "entry.recovered_unverified", "entry.recovered_assumed_contiguous"]
        not_recoverable = next(c for c in recovered.children if c.name == "_one")
        assert _codes((vfs.volume_info(not_recoverable) or {})["note"]) == [
            "entry.not_recoverable"]
    finally:
        vfs.close()


# -- ext ---------------------------------------------------------------------


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="ext2/3/4",
    desc="A name whose ext inode is blank stays listed, without content, with the reason",
)
def test_ext_unread_inode_names_its_reason(tmp_path: Path) -> None:
    """plain.bin is inode 13, at block 34 offset 0xC00 of the fixture
    (debugfs imap); its 256 bytes are zeroed, as debugfs clri does."""
    data = bytearray(gzip.decompress((FIXTURES_DIR / "raw_ext4_encrypt_flag.img.gz").read_bytes()))
    at = 34 * 4096 + 0xC00
    assert struct.unpack_from("<HxxI", data, at) == (0o100644, 3000)
    data[at:at + 256] = bytes(256)
    img = tmp_path / "clri.img"
    img.write_bytes(bytes(data))
    vfs = RawImageVFS(img)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        node = next(c for c in volume.children if c.name == "plain.bin")
        assert node.status.code == "entry.raw_entry_unreadable"
        assert "its inode (13) is blank (mode 0)" in render_value(node.status)
        assert vfs.read(node) == b""
    finally:
        vfs.close()


# -- NTFS --------------------------------------------------------------------


def test_ntfs_named_stream_count_is_not_a_file_note(tmp_path: Path) -> None:
    """export_notes() counts a file's named streams for qnxprobe's zip export;
    Crush lists the streams as nodes beside the file, so the count is not
    repeated on the file."""
    img = tmp_path / "streams.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_ntfs_streams.img.gz").read_bytes()))
    vfs = RawImageVFS(img)
    try:
        (volume,) = [c for c in vfs.root().children if c.is_dir]
        comp = next(c for c in volume.children if c.name == "comp")
        names = {c.name for c in comp.children}
        assert {"packed.txt", "packed.txt:late", "packed.txt:packed"} <= names
        packed = next(c for c in comp.children if c.name == "packed.txt")
        assert not any(code.startswith("entry.raw_") and "note" in code
                       for code in _codes(packed.status))
    finally:
        vfs.close()


# -- stand-in walkers --------------------------------------------------------


class _Walker:
    """Just enough of a qnxprobe walker for build_volume_node(): a root
    holding one file."""

    root = 1
    damage: list[str] = []
    damage_count = 0

    def listdir(self, node: int) -> list[tuple[str, int]]:
        return [("kept.txt", 2)] if node == 1 else []

    def entry(self, node: int) -> tuple[int, int, int]:
        return (0o100644, 5, 0)

    def read_file(self, node: int, size: int) -> Any:
        yield b"kept."


def _build(walker: Any, note: str | None = None) -> tuple[VFSNode, dict[str, _Entry]]:
    read_map: dict[str, _Entry] = {}
    vol = {"name": "v", "base": 0, "size": 1 << 20, "kind": "test", "walker": walker,
           "note": note}
    return build_volume_node(vol, read_map), read_map


def test_volume_note_added_while_listing_is_shown_once() -> None:
    class Grows(_Walker):
        listed = False

        @property
        def volume_note(self) -> str:
            return ("the journal needs recovery; 2 folder(s) carry the encrypted flag"
                    if self.listed else "the journal needs recovery")

        def listdir(self, node: int) -> list[tuple[str, int]]:
            self.listed = True
            return super().listdir(node)

    node, _ = _build(Grows(), note="the journal needs recovery")
    notes = _notes(node.status)
    assert [n.code for n in notes] == ["entry.raw_volume_note", "entry.raw_volume_state"]
    assert notes[1].detail == "2 folder(s) carry the encrypted flag"

    class Same(_Walker):
        volume_note = "the journal needs recovery"

    node, _ = _build(Same(), note="the journal needs recovery")
    assert _codes(node.status) == ["entry.raw_volume_note"]


def test_after_walk_checks_run_and_a_failing_one_is_named() -> None:
    class Checks(_Walker):
        def __init__(self) -> None:
            self.damage = []
            self.damage_count = 0

        def check_reached(self) -> None:
            self.damage.append("the checkpoint counts 9 inodes and the folders account for 8")
            self.damage_count += 1

        def note_unreached_sets(self) -> None:
            raise OSError("read error at cluster 40")

        @property
        def not_read_note(self) -> str:
            return "1 B-tree node(s) or subtree(s) could not be read"

    node, _ = _build(Checks())
    notes = _notes(node.status)
    codes = [n.code for n in notes]
    assert codes == ["entry.raw_volume_check_failed", "entry.raw_volume_not_read",
                     "entry.raw_volume_damage"]
    assert notes[0].params["check"] == "note_unreached_sets"
    assert "read error at cluster 40" in render_value(notes[0])
    assert "account for 8" in render_value(notes[2])


def test_yaffs_objects_no_listing_reaches_are_in_unreached() -> None:
    class Yaffs(qp.YaffsWalker):
        root = 1
        damage: list[str] = []
        damage_count = 0

        def __init__(self) -> None:
            pass

        listdir = _Walker.listdir
        entry = _Walker.entry

        def unread_entries(self, files_only: bool = False) -> list[tuple[str, int, str]]:
            return [("photos/a.jpg", 7, "object 7 (file, 10 bytes) is not exported: folder "
                     "object 5, which it is under, has no header in this image"),
                    ("", 9, "object 9 is not exported: 1 data chunks holding 10 bytes carry "
                     "its id and no header for it is in this image")]

        def recover_deleted(self) -> list[Any]:
            return []

    node, read_map = _build(Yaffs())
    unreached = next(c for c in node.children if c.name == "$Unreached")
    assert [c.name for c in unreached.children] == ["object 7", "object 9"]
    for leaf in unreached.children:
        assert leaf.status.code == "entry.raw_unreached"
        assert read_map[leaf.path].stored == b""
    assert "folder object 5" in render_value(unreached.children[0].status)
    assert "entry.raw_unreached_count" in _codes(node.status)
    assert [c.name for c in node.children if not c.is_dir] == ["kept.txt"]


def test_qnx6_blocks_without_pointer_are_noted_after_the_read() -> None:
    """QNX6 records which blocks had no pointer while read_file() runs, so
    the note can only follow a read (valid_data_note answers for the last
    file read)."""
    class Qnx6(qp.Qnx6Walker):
        def __init__(self) -> None:
            self._last_holes = None

    walker = Qnx6()
    assert after_read_notes(walker, 5, 8192) == []
    walker._last_holes = (5, 1, 2)
    (note,) = after_read_notes(walker, 5, 8192)
    assert note.code == "entry.raw_note_no_pointer_zeros"
    assert "1 of its 2 blocks has no pointer" in render_value(note)
    assert after_read_notes(walker, 6, 8192) == []  # another file was read last

    node = VFSNode(name="f", path="/v/f", is_dir=False, size=8192)
    entry = _Entry(walker=walker, node=5, size=8192)
    RawImageVFS._note_after_read(None, node, entry)  # type: ignore[arg-type]
    RawImageVFS._note_after_read(None, node, entry)  # type: ignore[arg-type]
    assert _codes(node.status) == ["entry.raw_note_no_pointer_zeros"]
