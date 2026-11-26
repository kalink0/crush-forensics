# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on ext volumes, and what a short or long read is put down to.

The two ext images are synthetic (raw_ext_synthetic_README.md): each sets the
one on-disk field a reader decides on, an encrypt flag or a block-map pointer
past the end of the volume. Their known answers come from the raw image and
the source files, not from qnxprobe. The stub walkers below stand in for a
reader's own answer where no image with that case exists.
"""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import Any, Iterator

import pytest

from crush.core.raw_image import (
    RawImageFileUnreadableError,
    RawImageTruncatedReadError,
    read_walker_file,
    stream_walker_file,
)
from crush.core.vfs import RawImageVFS, VFSNode
from crush.tests.conftest import FIXTURES_DIR
from crush.third_party.qnxprobe import qnxprobe as qp

_ENC_BLOCKS_SHA256 = "c1e438609e5753955eff80081105e29c68351969de17cc94f575d06a8202f373"
_ENC_SOURCE_SHA256 = "6accb52144b47d1fbf464e13b7c12bfde77c6ad04a0037bcbb892bee8b086693"
_PLAIN_SHA256 = "6df4eaea8badf499539677363872162877a1ffe9ad46d60e5b0b917eac4c7b36"


def _open(tmp_path: Path, stem: str) -> tuple[RawImageVFS, Path]:
    img = tmp_path / f"{stem}.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / f"{stem}.img.gz").read_bytes()))
    return RawImageVFS(img), img


def _files(vfs: RawImageVFS) -> dict[str, VFSNode]:
    (volume,) = [c for c in vfs.root().children if c.is_dir]
    return {c.name: c for c in volume.children if not c.is_dir}


def _codes(status: Any) -> list[str]:
    if not status:
        return []
    if status.code == "common.notes":
        return [n.code for n in status.params["notes"]]
    return [status.code]


class TestEncryptedFile:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="ext2/3/4",
        desc="A file flagged encrypted (fscrypt) must read as the bytes stored through the end "
        "of its last block, matching the image's own blocks, and say on the file and the "
        "volume that it is ciphertext as stored",
    )
    def test_flagged_file_reads_as_stored_through_its_last_block(self, tmp_path: Path) -> None:
        vfs, img = _open(tmp_path, "raw_ext4_encrypt_flag")
        try:
            files = _files(vfs)
            enc = files["enc.bin"]
            assert enc.size == 5000  # the recorded size, as the inode holds it
            assert _codes(enc.status) == ["entry.raw_encrypted_as_stored"]
            data = vfs.read(enc)
            assert len(data) == 8192
            assert hashlib.sha256(data).hexdigest() == _ENC_BLOCKS_SHA256
            assert data == img.read_bytes()[8 * 4096:10 * 4096]
            assert hashlib.sha256(data[:5000]).hexdigest() == _ENC_SOURCE_SHA256

            entry = vfs._read_map[enc.path]
            streamed = b"".join(stream_walker_file(
                entry.walker, entry.node, entry.size, entry.stored_up_to,
            ))
            assert streamed == data

            (volume,) = [c for c in vfs.root().children if c.is_dir]
            assert "entry.raw_encrypted_files" in _codes(volume.status)
            assert "1 file(s)" in str(volume.status)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="ext2/3/4",
        desc="A file without the encrypt flag on the same volume must read at its recorded "
        "size, with no encryption status",
    )
    def test_unflagged_file_beside_it_reads_at_its_size(self, tmp_path: Path) -> None:
        vfs, _img = _open(tmp_path, "raw_ext4_encrypt_flag")
        try:
            plain = _files(vfs)["plain.bin"]
            assert not plain.status
            data = vfs.read(plain)
            assert len(data) == 3000
            assert hashlib.sha256(data).hexdigest() == _PLAIN_SHA256
        finally:
            vfs.close()

    def test_flagged_read_past_its_last_block_is_still_refused(self) -> None:
        """The allowance ends at the last block: a reader returning more than
        that is refused with its length, encrypted or not."""
        walker = _LengthWalker(9000)
        with pytest.raises(RawImageFileUnreadableError, match="more than the 5,000 bytes"):
            read_walker_file(walker, object(), 5000, stored_up_to=8192)


class TestShortReadReason:
    @pytest.mark.forensic(
        category="Completeness",
        subject="ext2/3/4",
        desc="A file whose block map points past the end of the volume, in an image that is "
        "whole, must be refused with the map's reason, never as an image that ends early",
    )
    def test_lost_block_map_is_named_not_put_down_to_the_image_end(self, tmp_path: Path) -> None:
        vfs, _img = _open(tmp_path, "raw_ext_indirect_lost")
        try:
            ind = _files(vfs)["ind.bin"]
            assert ind.size == 20480
            with pytest.raises(RawImageFileUnreadableError) as caught:
                vfs.read(ind)
            assert not isinstance(caught.value, RawImageTruncatedReadError)
            text = str(caught.value)
            assert text.startswith("only 12,288 of 20,480 bytes")
            assert "indirect block 999,999" in text
            assert "image ends" not in text
        finally:
            vfs.close()

    def test_reasons_are_asked_in_the_order_qnxprobe_uses(self) -> None:
        """map_shortfall() first, then short_reason(); only when neither names
        a cause is the read put down to the image ending early. Synthetic: a
        stub walker that counts its shortfall the way qnxprobe's do."""
        both = _ShortWalker(map_reason="its extent block failed its check",
                            outside="2 of its clusters lie outside this volume")
        with pytest.raises(RawImageFileUnreadableError, match="extent block failed"):
            read_walker_file(both, object(), 8)
        outside = _ShortWalker(outside="2 of its clusters lie outside this volume")
        with pytest.raises(RawImageFileUnreadableError, match="outside this volume"):
            b"".join(stream_walker_file(outside, object(), 8))
        neither = _ShortWalker()
        with pytest.raises(RawImageTruncatedReadError, match="image ends before the file does"):
            read_walker_file(neither, object(), 8)

    def test_run_list_shorter_than_the_size_is_named(self) -> None:
        """A short read with nothing past the image's end names the run list
        the walker reports (run_shortfall()) instead of "gave no reason"."""
        walker = _LengthWalker(3, run="its run list covers 3 of the 5 bytes it records")
        with pytest.raises(RawImageFileUnreadableError, match="run list covers 3 of the 5"):
            read_walker_file(walker, object(), 5)


class TestDeletedSizeUnknown:
    def test_ntfs_record_without_a_size_says_so(self, tmp_path: Path) -> None:
        """qnxprobe 1.88 gives a deleted NTFS record whose data attribute is in
        an unread extension record size None. Synthetic: one record of
        raw_ntfs.img.gz's $Recovered is replaced by such a record."""
        img = tmp_path / "ntfs.img"
        img.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes()))
        vfs = RawImageVFS(img)
        try:
            (volume,) = [c for c in vfs.root().children if c.is_dir]
            recovered = next(c for c in volume.children if c.name == "$Recovered")
            node = recovered.children[0]
            entry = vfs._read_map[node.path]
            entry.deleted = qp.NtfsDeletedFile(
                1, node.name, 5, False, None, None, False, "attributes overflowed the record",
                0, 0, 0, True, None,
            )
            note = vfs.volume_info(node)["note"]  # type: ignore[index]
            assert _codes(note) == ["entry.not_recoverable", "entry.recovered_size_unknown"]
        finally:
            vfs.close()


class _LengthWalker:
    """Returns `returned` bytes whatever the size; `run` is its run_shortfall()."""

    def __init__(self, returned: int, run: str | None = None) -> None:
        self.returned, self.run = returned, run

    def read_file(self, node: Any, size: int) -> Iterator[bytes]:
        yield b"A" * self.returned

    def run_shortfall(self, node: Any) -> str | None:
        return self.run


class _ShortWalker:
    """Returns 4 of 8 bytes and counts the other 4 in EOF_SHORTFALL, the way a
    qnxprobe walker does for bytes it could not read."""

    def __init__(self, map_reason: str | None = None, outside: str | None = None) -> None:
        self.map_reason, self.outside = map_reason, outside

    def read_file(self, node: Any, size: int) -> Iterator[bytes]:
        qp.EOF_SHORTFALL["bytes"] += 4
        yield b"B" * 8

    def map_shortfall(self, node: Any) -> str | None:
        return self.map_reason

    def short_reason(self, node: Any) -> str | None:
        return self.outside
