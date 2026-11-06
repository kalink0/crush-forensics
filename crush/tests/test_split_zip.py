# SPDX-License-Identifier: Apache-2.0
"""Tests for split (segmented) ZIP reading (crush/core/split_zip.py).

A real multi-disk set is built here by writing an ordinary ZIP and then
re-expressing its central directory as disk-relative offsets split across
segment files -- the inverse of the reader. This exercises the classic
(non-ZIP64) multi-disk layout; the ZIP64 multi-disk layout was verified
separately against a real 33-segment Cellebrite UFDR export.
"""
from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from crush.core.split_zip import (
    SplitZipError,
    find_split_set,
    open_split_zip_stream,
)
from crush.core.vfs import ZipVFS, is_browsable_source_file, open_vfs

_EOCD_SIG = b"PK\x05\x06"
_CD_SIG = b"PK\x01\x02"


def _make_split_zip(
    tmp_path: Path, members: dict[str, bytes], *, seg_size: int, stem: str = "set"
) -> Path:
    """Write *members* as a classic multi-disk split set under *stem*: data
    segments ``<stem>.z01..`` of *seg_size* bytes and a final ``<stem>.zip``
    carrying the central directory. Returns the final segment path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    raw = buf.getvalue()

    e = raw.rfind(_EOCD_SIG)
    cd_offset = struct.unpack_from("<I", raw, e + 16)[0]
    member_region = raw[:cd_offset]
    cd = bytearray(raw[cd_offset:e])

    disks = [member_region[i : i + seg_size] for i in range(0, len(member_region), seg_size)] or [b""]
    n_data = len(disks)

    # Re-express each entry's absolute local-header offset as (disk, offset).
    off = 0
    count = 0
    while off + 46 <= len(cd) and cd[off : off + 4] == _CD_SIG:
        nlen, elen, clen = struct.unpack_from("<HHH", cd, off + 28)
        loff = struct.unpack_from("<I", cd, off + 42)[0]
        struct.pack_into("<H", cd, off + 34, loff // seg_size)  # disk number start
        struct.pack_into("<I", cd, off + 42, loff % seg_size)  # offset within that disk
        off += 46 + nlen + elen + clen
        count += 1

    eocd = struct.pack(
        "<IHHHHIIH", int.from_bytes(_EOCD_SIG, "little"),
        n_data, n_data, count, count, len(cd), 0, 0,
    )
    final = bytes(cd) + eocd

    for k, disk in enumerate(disks, start=1):
        (tmp_path / f"{stem}.z{k:02d}").write_bytes(disk)
    final_path = tmp_path / f"{stem}.zip"
    final_path.write_bytes(final)
    return final_path


def _members() -> dict[str, bytes]:
    return {
        "a/first.bin": bytes((i * 3) % 256 for i in range(2000)),
        "a/second.txt": b"second member body\n" * 200,
        "third.dat": bytes((i * 7 + 1) % 256 for i in range(5000)),
    }


def test_find_split_set_orders_segments(tmp_path: Path) -> None:
    members = _members()
    final = _make_split_zip(tmp_path, members, seg_size=1500)
    segs = find_split_set(final)
    assert segs is not None
    assert [s.name for s in segs[:-1]] == sorted(s.name for s in segs[:-1])
    assert segs[-1] == final
    # Opening via the first data segment finds the same set.
    assert find_split_set(segs[0]) == segs


def test_split_members_read_with_correct_crc(tmp_path: Path) -> None:
    members = _members()
    # seg_size well below a member's size so local headers and data cross
    # segment boundaries.
    final = _make_split_zip(tmp_path, members, seg_size=1500)
    segs = find_split_set(final)
    with open_split_zip_stream(segs) as stream:
        with zipfile.ZipFile(stream) as zf:
            assert sorted(zf.namelist()) == sorted(members)
            for name, data in members.items():
                assert zf.read(name) == data  # zipfile verifies CRC on read


def test_open_vfs_reads_split_set_from_either_end(tmp_path: Path) -> None:
    members = _members()
    final = _make_split_zip(tmp_path, members, seg_size=1500)
    segs = find_split_set(final)
    for entry in (final, segs[0]):
        vfs = open_vfs(entry)
        assert isinstance(vfs, ZipVFS)
        node = next(n for n in _walk(vfs.root()) if n.name == "third.dat")
        assert vfs.read(node) == members["third.dat"]
        vfs.close()


def test_every_segment_counts_as_browsable_source(tmp_path: Path) -> None:
    # Drives the GUI's "Open in New Window" offer and large-file guard: each
    # part of a split set -- including the final segment, whose first bytes
    # are mid-member and don't sniff as an archive -- is browsable.
    members = _members()
    final = _make_split_zip(tmp_path, members, seg_size=1200)
    for seg in find_split_set(final):
        assert is_browsable_source_file(seg) is True


def test_incomplete_split_set_is_not_browsable(tmp_path: Path) -> None:
    final = _make_split_zip(tmp_path, _members(), seg_size=800)
    segs = find_split_set(final)
    segs[1].unlink()  # drop a middle part
    # The final segment on its own is not a browsable source once the set is
    # incomplete (open_vfs would not assemble it).
    assert is_browsable_source_file(final) is False


def test_missing_segment_is_explicit(tmp_path: Path) -> None:
    members = _members()
    final = _make_split_zip(tmp_path, members, seg_size=800)
    segs = find_split_set(final)
    assert len(segs) >= 4  # several data segments
    segs[1].unlink()  # drop .z02
    with pytest.raises(SplitZipError):
        find_split_set(final)


def test_lone_data_segment_without_final_is_explicit(tmp_path: Path) -> None:
    (tmp_path / "orphan.z01").write_bytes(b"PK\x07\x08" + b"\x00" * 100)
    with pytest.raises(SplitZipError):
        find_split_set(tmp_path / "orphan.z01")


def test_sibling_with_extra_dotted_name_is_not_a_segment(tmp_path: Path) -> None:
    members = _members()
    final = _make_split_zip(tmp_path, members, seg_size=1500, stem="set")
    segs_before = find_split_set(final)
    # A sibling whose name only starts with the stem must not be pulled in.
    (tmp_path / "set.extra.z01").write_bytes(b"not a segment")
    assert find_split_set(final) == segs_before


def test_plain_single_zip_is_not_a_split_set(tmp_path: Path) -> None:
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("x.txt", b"hello")
    assert find_split_set(p) is None


def _walk(node):  # type: ignore[no-untyped-def]
    yield node
    for c in node.children:
        yield from _walk(c)
