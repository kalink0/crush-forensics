# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on macOS compressed files (decmpfs), and on an acquisition chunk
whose stored data ran out.

`raw_decmpfs_apfs` and `raw_decmpfs_hfsplus` are abrignoni/qnxprobe's
decmpfs-apfs and decmpfs-hfsplus test fixtures (MIT, tests/fixtures at the
vendored commit), renamed with a `raw_` prefix. macOS wrote both volumes, and
their `.sha256` listings hold, per file, the decmpfs method the image holds and
the sha256 of what macOS itself read back through the mounted volume
(qnxprobe's tools/make_decmpfs_fixture.py).
"""
from __future__ import annotations

import gzip
import hashlib
import struct
import zlib
from pathlib import Path

import pytest

from crush.core.raw_image import RawImageFileUnreadableError
from crush.core.vfs import RawImageVFS, VFSNode, open_vfs
from crush.tests.conftest import FIXTURES_DIR
from crush.third_party.ewfprobe import ewfprobe


def _image(tmp_path: Path, stem: str) -> Path:
    img = tmp_path / f"{stem}.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / f"{stem}.img.gz").read_bytes()))
    return img


def _files(node: VFSNode) -> dict[str, VFSNode]:
    out: dict[str, VFSNode] = {}
    for child in node.children:
        if child.is_dir:
            out.update(_files(child))
        else:
            out[child.path] = child
    return out


def _macos_read(stem: str) -> dict[str, tuple[int, str]]:
    out: dict[str, tuple[int, str]] = {}
    for line in (FIXTURES_DIR / f"{stem}.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, method, relpath = line.split(None, 2)
            out[relpath.strip()] = (int(method), digest)
    return out


def _check(tmp_path: Path, stem: str) -> RawImageVFS:
    vfs = open_vfs(_image(tmp_path, stem), as_disk_image=True)
    assert isinstance(vfs, RawImageVFS)
    files = _files(vfs.root())
    for relpath, (method, digest) in _macos_read(stem).items():
        node = next(n for p, n in files.items() if p.endswith("/" + relpath))
        if method in (13, 14):
            with pytest.raises(RawImageFileUnreadableError, match="LZBITMAP"):
                vfs.read(node)
        else:
            assert hashlib.sha256(vfs.read(node)).hexdigest() == digest, relpath
    return vfs


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="APFS",
    desc="Every macOS compressed file on an APFS volume (zlib, LZVN, LZFSE, stored) reads "
    "back as macOS read it; an LZBITMAP file is refused with the reason",
)
def test_apfs_compressed_files_read_as_macos_read_them(tmp_path: Path) -> None:
    vfs = _check(tmp_path, "raw_decmpfs_apfs")
    try:
        volume = vfs.root().children[0]
        assert "2 file(s) recorded as damage while the volume was listed, and listed as stored" \
            in str(volume.status)
        assert "not flagged compressed" in str(volume.status)
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="HFS+",
    desc="Every macOS compressed file on an HFS+ volume reads back as macOS read it; an "
    "LZBITMAP file is refused with the reason",
)
def test_hfsplus_compressed_files_read_as_macos_read_them(tmp_path: Path) -> None:
    _check(tmp_path, "raw_decmpfs_hfsplus").close()


def _section(out: bytearray, name: str, payload: bytes, last: bool = False) -> None:
    start = len(out)
    size = ewfprobe.SECTION_SIZE + len(payload)
    head = struct.pack("<16sQQ40s", name.encode("ascii").ljust(16, b"\x00"),
                       start if last else start + size, size, b"\x00" * 40)
    out += head + struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF) + payload


def _e01(data: bytes, cut: int | None, chunk: int = 32768) -> bytes:
    """`data` as a one-segment E01 (the layout of ewfprobe's own test writer), chunk
    number `cut` keeping only the first half of its compressed stream."""
    chunks = [data[i:i + chunk] for i in range(0, len(data), chunk)]
    blob, entries = bytearray(), []
    for n, piece in enumerate(chunks):
        packed = zlib.compress(piece, 6)
        entries.append(len(blob) | 0x80000000)
        blob += packed[:len(packed) // 2] if n == cut else packed
    vol = bytearray(1052)
    vol[0] = 1
    struct.pack_into("<III", vol, 4, len(chunks), chunk // 512, 512)
    struct.pack_into("<Q", vol, 16, len(data) // 512)
    vol[52] = 1
    out = bytearray(struct.pack("<8sBHH", ewfprobe.SIGNATURE, 1, 1, 0))
    _section(out, "header", zlib.compress(b"1\nmain\nc\n\n"))
    _section(out, "volume", bytes(vol))
    base = len(out) + ewfprobe.SECTION_SIZE
    _section(out, "sectors", bytes(blob))
    head = struct.pack("<IIQI", len(entries), 0, base, 0)
    body = b"".join(struct.pack("<I", e) for e in entries)
    _section(out, "table", head + struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF) + body
             + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF))
    _section(out, "done", b"", last=True)
    return bytes(out)


def test_a_chunk_whose_data_ran_out_is_named_on_the_source(tmp_path: Path) -> None:
    """The listing reads the volume's directory structures, so a chunk holding them
    that is cut short is read with zeros, and the source says so."""
    data = gzip.decompress((FIXTURES_DIR / "raw_decmpfs_apfs.img.gz").read_bytes())
    whole = tmp_path / "whole.E01"
    whole.write_bytes(_e01(data, None))
    vfs = open_vfs(whole, as_disk_image=True)
    try:
        assert "hold less data than the bytes they cover" not in str(vfs.load_note)
    finally:
        vfs.close()
    cut = tmp_path / "cut.E01"
    cut.write_bytes(_e01(data, 0))
    vfs = open_vfs(cut, as_disk_image=True)
    try:
        assert "1 chunk(s) of this acquisition read so far hold less data than the bytes " \
            "they cover" in str(vfs.load_note)
        assert vfs.root().status == vfs.load_note
    finally:
        vfs.close()
