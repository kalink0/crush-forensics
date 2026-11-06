# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Reading PKWARE split (segmented / "spanned to files") ZIP sets.

A split ZIP is written across several files: the data segments ``<name>.z01``,
``<name>.z02`` ... and a final segment ``<name>.zip`` (or, for a Cellebrite
report, ``<name>.ufdr``) that ends with the central directory and the
end-of-central-directory (EOCD) record (PKWARE APPNOTE 8.5). Python's
``zipfile`` refuses such a set outright ("zipfiles that span multiple disks
are not supported"), because the central directory addresses each local
header by a (disk number, offset-within-that-disk) pair rather than by one
absolute offset.

This module presents the whole set to ``zipfile`` as a single seekable stream.
The data segments are concatenated in order (segment ``k`` is "disk" ``k``,
counting from 0) and the central directory is rewritten in place so every
entry carries the absolute offset of its local header in that concatenation
and a disk number of 0, and the EOCD/ZIP64-EOCD records are rewritten to a
single-disk archive. No segment's data bytes are copied or altered: the member
payloads and local headers are served from the segments unchanged, and only
the trailing central directory is replaced with an equivalent single-disk one.

Segments are discovered by name (no segment points at the others, exactly like
a ``.001``/``.002`` raw-image split set), then confirmed by content: the first
segment begins with the spanning marker or a local header, the final segment
carries the EOCD, the ``.zNN`` numbering has no gap, and the entry count the
EOCD declares matches the rewritten directory.
"""
from __future__ import annotations

import io
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from crush.core.issues import ParseIssue

# Signatures (APPNOTE 4.3.16, 4.3.9, 4.3.12, 4.3.14).
_EOCD_SIG = b"PK\x05\x06"
_EOCD64_SIG = b"PK\x06\x06"
_EOCD64_LOC_SIG = b"PK\x06\x07"
_CD_SIG = b"PK\x01\x02"
_SPANNING_SIG = b"PK\x07\x08"  # ahead of the first local header in a split set
_LOCAL_SIG = b"PK\x03\x04"

_U16 = 0xFFFF
_U32 = 0xFFFFFFFF
_ZIP64_EXTRA_TAG = 0x0001

# A trailing non-".zNN" segment with this extension is the final one. UFDR
# reports end in .ufdr; ordinary split sets end in .zip (.zipx for some tools).
_FINAL_SUFFIXES = (".zip", ".zipx", ".ufdr")
_SEGMENT_RE = re.compile(r"\.z(\d{2,})$", re.IGNORECASE)


class SplitZipError(ValueError):
    """A split ZIP set could not be assembled (missing/misordered segment,
    unreadable structure)."""


@dataclass(frozen=True)
class _Eocd:
    total_entries: int
    cd_size: int
    cd_disk: int
    cd_offset: int  # within cd_disk
    total_disks: int


def _read_tail(path: Path, n: int) -> tuple[bytes, int]:
    size = path.stat().st_size
    span = min(size, n)
    with path.open("rb") as fh:
        fh.seek(size - span)
        return fh.read(span), size


def _parse_eocd(final: Path) -> _Eocd | None:
    """Parse the EOCD (and ZIP64 EOCD when present) from the final segment,
    or None when it carries no EOCD (so it is not the final segment)."""
    tail, _ = _read_tail(final, 1 << 20)
    e = tail.rfind(_EOCD_SIG)
    if e < 0 or len(tail) < e + 22:
        return None
    (disk, cd_disk, ent_disk, total_entries, cd_size, cd_offset, clen) = struct.unpack_from(
        "<HHHHIIH", tail, e + 4
    )
    z = tail.rfind(_EOCD64_SIG)
    if z >= 0 and len(tail) >= z + 56:
        (_sz, _vm, _vn, disk64, cd_disk64, _ed, et, cds, cdo) = struct.unpack_from(
            "<QHHIIQQQQ", tail, z + 4
        )
        total_disks = disk64 + 1
        return _Eocd(et, cds, cd_disk64, cdo, max(total_disks, cd_disk64 + 1))
    return _Eocd(total_entries, cd_size, cd_disk, cd_offset, disk + 1)


def _segment_number(path: Path) -> int | None:
    m = _SEGMENT_RE.search(path.name)
    return int(m.group(1)) if m else None


def find_split_set(path: str | Path) -> list[Path] | None:
    """The ordered segments of the split ZIP set *path* belongs to -- data
    segments ``.z01..`` first, final segment last -- or None when *path* is
    not part of a split set. Raises SplitZipError when it clearly is one but a
    segment is missing or the numbering has a gap (never a silent partial)."""
    p = Path(path)
    seg_no = _segment_number(p)
    if seg_no is not None:
        stem = p.name[: p.name.rfind(".")]
        final = _find_final(p.parent, stem)
    elif p.suffix.lower() in _FINAL_SUFFIXES:
        eocd = _parse_eocd(p)
        if eocd is None:
            return None
        stem = p.name[: p.name.rfind(".")]
        final = p
        if eocd.total_disks <= 1 and not _data_segments(p.parent, stem):
            return None  # an ordinary single-file ZIP, not a split set
    else:
        return None

    if final is None:
        raise SplitZipError(ParseIssue("splitzip.no_final", {"stem": stem}))
    segments = _data_segments(p.parent, stem)
    if not segments:
        return None if seg_no is None else _single(p)
    _check_contiguous(segments, stem)
    return [s for _, s in segments] + [final]


def _single(p: Path) -> list[Path] | None:
    # A lone .zNN with no final sibling: not an assemblable set.
    raise SplitZipError(ParseIssue("splitzip.no_final", {"stem": p.name}))


def _find_final(parent: Path, stem: str) -> Path | None:
    for suffix in _FINAL_SUFFIXES:
        cand = parent / f"{stem}{suffix}"
        if cand.exists() and _parse_eocd(cand) is not None:
            return cand
    return None


def _data_segments(parent: Path, stem: str) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for cand in parent.iterdir():
        if not cand.is_file():
            continue
        # The name must be exactly "<stem>.zNN" -- not merely start with the
        # stem, so a sibling like "<stem>.extra.z01" is not mistaken for one.
        m = _SEGMENT_RE.fullmatch(cand.name[len(stem) :]) if cand.name.startswith(stem) else None
        if m:
            found.append((int(m.group(1)), cand))
    found.sort()
    return found


def _check_contiguous(segments: list[tuple[int, Path]], stem: str) -> None:
    numbers = [n for n, _ in segments]
    expected = list(range(1, len(numbers) + 1))
    if numbers != expected:
        missing = sorted(set(expected) - set(numbers))
        raise SplitZipError(ParseIssue("splitzip.missing_segment", {
            "stem": stem,
            "missing": ", ".join(f".z{m:02d}" for m in missing) or "(out of order)",
        }))


class _SegmentedReader:
    """A seekable, read-only view over ordered segment files concatenated."""

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths
        self._sizes = [p.stat().st_size for p in paths]
        self._starts: list[int] = []
        acc = 0
        for s in self._sizes:
            self._starts.append(acc)
            acc += s
        self.total = acc
        self._fh = [p.open("rb") for p in paths]

    def start_of(self, disk: int) -> int:
        return self._starts[disk]

    def read_at(self, pos: int, length: int) -> bytes:
        out = bytearray()
        while length > 0 and pos < self.total:
            i = max(j for j in range(len(self._starts)) if self._starts[j] <= pos)
            within = pos - self._starts[i]
            self._fh[i].seek(within)
            chunk = self._fh[i].read(min(length, self._sizes[i] - within))
            if not chunk:
                break
            out += chunk
            pos += len(chunk)
            length -= len(chunk)
        return bytes(out)

    def close(self) -> None:
        for fh in self._fh:
            fh.close()


def _zip64_fields(fixed: dict[str, int], extra: bytes) -> dict[str, int]:
    """Resolve uncompressed size, compressed size, local-header offset and
    disk-start, taking any that the fixed record marks with a sentinel from
    the ZIP64 extra block (APPNOTE 4.5.3: present only for sentinel fields,
    in this fixed order)."""
    out = dict(fixed)
    block = b""
    eo = 0
    while eo + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, eo)
        if tag == _ZIP64_EXTRA_TAG:
            block = extra[eo + 4 : eo + 4 + size]
            break
        eo += 4 + size
    pos = 0
    for name, sentinel, width in (
        ("usize", _U32, 8), ("csize", _U32, 8), ("offset", _U32, 8), ("disk", _U16, 4)
    ):
        if fixed[name] == sentinel and pos + width <= len(block):
            out[name] = int.from_bytes(block[pos : pos + width], "little")
            pos += width
    return out


def _nonzip64_extra(extra: bytes) -> bytes:
    """Every extra block except the ZIP64 one (rebuilt fresh on re-emit)."""
    out = bytearray()
    eo = 0
    while eo + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, eo)
        if tag != _ZIP64_EXTRA_TAG:
            out += extra[eo : eo + 4 + size]
        eo += 4 + size
    return bytes(out)


def _rewrite_cd(cd: bytes, reader: _SegmentedReader) -> tuple[bytes, int]:
    """Rewrite the central directory so every entry's local-header offset is
    absolute in the concatenation and its disk number is 0. Returns the new
    directory bytes and the entry count."""
    out = bytearray()
    off = 0
    count = 0
    while off + 46 <= len(cd) and cd[off : off + 4] == _CD_SIG:
        # From offset +20: compressed/uncompressed size, name/extra/comment
        # lengths, disk-start, then internal (2) + external (4) attrs skipped,
        # then the local-header offset at +42.
        (csize, usize, nlen, elen, clen, disk, loff) = struct.unpack_from(
            "<II HHH H 6x I", cd, off + 20
        )
        name = cd[off + 46 : off + 46 + nlen]
        extra = cd[off + 46 + nlen : off + 46 + nlen + elen]
        comment = cd[off + 46 + nlen + elen : off + 46 + nlen + elen + clen]
        resolved = _zip64_fields(
            {"usize": usize, "csize": csize, "offset": loff, "disk": disk}, extra
        )
        absolute = reader.start_of(resolved["disk"]) + resolved["offset"]

        need_u = resolved["usize"] >= _U32
        need_c = resolved["csize"] >= _U32
        need_o = absolute >= _U32
        z64 = bytearray()
        if need_u:
            z64 += resolved["usize"].to_bytes(8, "little")
        if need_c:
            z64 += resolved["csize"].to_bytes(8, "little")
        if need_o:
            z64 += absolute.to_bytes(8, "little")
        new_extra = bytearray(_nonzip64_extra(extra))
        if z64:
            new_extra = bytearray(struct.pack("<HH", _ZIP64_EXTRA_TAG, len(z64)) + z64) + new_extra

        header = bytearray(cd[off : off + 46])
        struct.pack_into("<II", header, 20, _U32 if need_c else resolved["csize"],
                         _U32 if need_u else resolved["usize"])
        struct.pack_into("<H", header, 30, len(new_extra))  # extra length
        struct.pack_into("<H", header, 34, 0)  # disk number start
        struct.pack_into("<I", header, 42, _U32 if need_o else absolute)
        out += header + name + bytes(new_extra) + comment
        off += 46 + nlen + elen + clen
        count += 1
    return bytes(out), count


class _ReassembledStream(io.RawIOBase):
    """A seekable stream presenting the split set as one single-disk ZIP: the
    segments' bytes up to the central directory, then the rewritten directory
    and EOCD records."""

    def __init__(self, segments: list[Path], eocd: _Eocd) -> None:
        super().__init__()
        self._reader = _SegmentedReader(segments)
        cd_abs = self._reader.start_of(eocd.cd_disk) + eocd.cd_offset
        raw_cd = self._reader.read_at(cd_abs, eocd.cd_size)
        new_cd, count = _rewrite_cd(raw_cd, self._reader)
        if count != eocd.total_entries:
            self._reader.close()
            raise SplitZipError(ParseIssue("splitzip.entry_count", {
                "declared": eocd.total_entries, "found": count,
            }))
        tail = bytearray(new_cd)
        cd64_pos = cd_abs + len(new_cd)
        tail += self._build_eocd64(count, len(new_cd), cd_abs)
        tail += self._build_locator(cd64_pos)
        tail += self._build_eocd(count, len(new_cd), cd_abs)
        self._cd_abs = cd_abs
        self._tail = bytes(tail)
        self._total = cd_abs + len(self._tail)
        self._pos = 0

    @staticmethod
    def _build_eocd64(count: int, cd_size: int, cd_off: int) -> bytes:
        rec = struct.pack("<IQHHIIQQQQ", int.from_bytes(_EOCD64_SIG, "little"),
                          44, 45, 45, 0, 0, count, count, cd_size, cd_off)
        return rec

    @staticmethod
    def _build_locator(eocd64_pos: int) -> bytes:
        return struct.pack("<IIQI", int.from_bytes(_EOCD64_LOC_SIG, "little"),
                           0, eocd64_pos, 1)

    @staticmethod
    def _build_eocd(count: int, cd_size: int, cd_off: int) -> bytes:
        ent = min(count, _U16)
        return struct.pack("<IHHHHIIH", int.from_bytes(_EOCD_SIG, "little"),
                           0, 0, ent, ent, cd_size, min(cd_off, _U32), 0)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._total + offset
        else:  # pragma: no cover
            raise ValueError(f"invalid whence: {whence}")
        self._pos = max(0, self._pos)
        return self._pos

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        want = len(b)
        if want == 0 or self._pos >= self._total:
            return 0
        end = min(self._pos + want, self._total)
        out = bytearray()
        if self._pos < self._cd_abs:
            n = min(end, self._cd_abs) - self._pos
            out += self._reader.read_at(self._pos, n)
        if end > self._cd_abs:
            lo = max(self._pos, self._cd_abs) - self._cd_abs
            out += self._tail[lo : end - self._cd_abs]
        b[: len(out)] = out
        self._pos += len(out)
        return len(out)

    def close(self) -> None:
        if not self.closed:
            try:
                self._reader.close()
            finally:
                super().close()


def open_split_zip_stream(segments: list[Path]) -> io.RawIOBase:
    """A seekable single-disk-ZIP stream over an ordered split set. The final
    segment must carry the EOCD."""
    eocd = _parse_eocd(segments[-1])
    if eocd is None:
        raise SplitZipError(ParseIssue("splitzip.no_final", {"stem": segments[-1].name}))
    return _ReassembledStream(segments, eocd)
