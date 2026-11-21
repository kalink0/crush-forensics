# SPDX-License-Identifier: Apache-2.0
"""Writing ZIP archives for exports: the compression method and level, AES-256
encryption, splitting into parts of a fixed size, and copying an archive's
entries over unchanged.

Built on pyzipper (WinZip AES, readable by 7-Zip, WinRAR, WinZip, unzip and
others). AES encrypts the entries' contents; their names, sizes and times stay
readable, as the ZIP format has no way to hide them.

Split archives are cut into plain parts -- `name.zip.001`, `name.zip.002` ... --
byte for byte: put together again (`copy /b`, `cat`) they are the archive;
7-Zip opens `.001` directly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Callable, Literal

import pyzipper
from pyzipper import zipfile as _pz_zipfile
from pyzipper.zipfile_aes import AESZipInfo

ZipMethod = Literal["stored", "deflate", "bzip2", "lzma"]

METHODS: dict[str, int] = {
    "stored": pyzipper.ZIP_STORED,
    "deflate": pyzipper.ZIP_DEFLATED,
    "bzip2": pyzipper.ZIP_BZIP2,
    "lzma": pyzipper.ZIP_LZMA,
}
# (lowest, highest, default) level for the methods that take one.
LEVELS: dict[str, tuple[int, int, int]] = {
    "deflate": (1, 9, 6),
    "bzip2": (1, 9, 9),
}
# Smallest part a split archive is cut into.
MIN_SPLIT_SIZE = 64 * 1024

_EXTRA_ZIP64 = 0x0001
_EXTRA_WZ_AES = 0x9901
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class ZipOptions:
    """How an archive is written. The password never shows in repr() or
    describe(), so it can't end up in a log."""

    method: ZipMethod = "deflate"
    level: int | None = None  # None: the method's default (LEVELS)
    password: str | None = field(default=None, repr=False)
    split_size: int | None = None  # bytes per part; None: one file

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise ValueError(f"unknown compression method: {self.method}")
        if self.level is not None:
            if self.method not in LEVELS:
                raise ValueError(f"{self.method} takes no compression level")
            low, high, _ = LEVELS[self.method]
            if not low <= self.level <= high:
                raise ValueError(f"{self.method} level must be {low}-{high}")
        if self.password == "":
            raise ValueError("empty password")
        if self.split_size is not None and self.split_size < MIN_SPLIT_SIZE:
            raise ValueError(f"parts must be at least {MIN_SPLIT_SIZE} bytes")

    @property
    def effective_level(self) -> int | None:
        if self.method not in LEVELS:
            return None
        return self.level if self.level is not None else LEVELS[self.method][2]

    def describe(self) -> str:
        """For the log: everything but the password itself."""
        level = self.effective_level
        parts = [self.method if level is None else f"{self.method} level {level}"]
        parts.append("AES-256 encrypted" if self.password else "not encrypted")
        if self.split_size:
            parts.append(f"split into parts of {self.split_size} B")
        return ", ".join(parts)


class _ZipInfo(AESZipInfo):  # type: ignore[misc]
    """pyzipper's entry, keeping an entry's own extra fields (its times, for
    one) in the central directory as zipfile does -- pyzipper writes only
    ZIP64 and AES there, which would drop them from entries it rewrites."""

    __slots__ = ()

    def encode_central_directory(self, *, extra_data: bytes, **kwargs: Any) -> Any:
        own = _pz_zipfile._strip_extra(self.extra, (_EXTRA_ZIP64, _EXTRA_WZ_AES))
        return super().encode_central_directory(extra_data=extra_data + own, **kwargs)


class CrushZipFile(pyzipper.AESZipFile):  # type: ignore[misc]
    zipinfo_cls = _ZipInfo


def new_info(name: str, date_time: tuple[int, int, int, int, int, int]) -> _ZipInfo:
    return _ZipInfo(name, date_time=date_time)


def open_archive(
    target: str | os.PathLike[str] | IO[bytes],
    mode: Literal["r", "w", "a"],
    options: ZipOptions | None = None,
) -> CrushZipFile:
    """An archive to read, or to write with *options* (new entries are
    compressed and, with a password, encrypted as they say)."""
    options = options or ZipOptions()
    zf = CrushZipFile(
        target,
        mode,
        compression=METHODS[options.method],
        compresslevel=options.effective_level,
        allowZip64=True,
        encryption=pyzipper.WZ_AES if options.password and mode != "r" else None,
        encryption_kwargs={"nbits": 256} if options.password else None,
    )
    if options.password and mode != "r":
        zf.setpassword(options.password.encode("utf-8"))
    return zf


def copy_entries_raw(
    source: Path,
    zf: CrushZipFile,
    skip: Callable[[str], bool],
    check_cancel: Callable[[], None],
) -> list[str]:
    """Copy every entry of the archive *source* into *zf* (opened to write)
    as it is stored -- still compressed, still encrypted, with its local
    header -- except those *skip* says. Nothing is unpacked, so this needs
    no password and changes no entry's bytes. Returns the names skipped."""
    skipped: list[str] = []
    with open_archive(source, "r") as src, open(source, "rb") as raw:
        infos = sorted(src.infolist(), key=lambda i: i.header_offset)
        ends = [i.header_offset for i in infos[1:]] + [src.start_dir]
        for info, end in zip(infos, ends):
            check_cancel()
            if skip(info.filename):
                skipped.append(info.filename)
                continue
            zf.fp.seek(zf.start_dir)
            new_offset = zf.fp.tell()
            raw.seek(info.header_offset)
            left = end - info.header_offset
            while left > 0:
                check_cancel()
                chunk = raw.read(min(_CHUNK, left))
                if not chunk:
                    raise OSError(f"{source}: archive ends inside entry {info.filename}")
                zf.fp.write(chunk)
                left -= len(chunk)
            info.header_offset = new_offset
            zf.filelist.append(info)
            zf.NameToInfo[info.filename] = info
            zf.start_dir = zf.fp.tell()
            zf._didModify = True
        zf.comment = src.comment
    return skipped


def part_path(archive: Path, number: int) -> Path:
    """Part *number* (from 1) of a split archive: `name.zip.001`, ..."""
    return archive.with_name(f"{archive.name}.{number:03d}")


def existing_parts(archive: Path) -> list[Path]:
    """Parts of a split archive of that name already in its folder."""
    prefix = f"{archive.name}."
    found = []
    try:
        entries = list(archive.parent.iterdir())
    except OSError:
        return []
    for entry in entries:
        suffix = entry.name[len(prefix):] if entry.name.startswith(prefix) else ""
        if len(suffix) >= 3 and suffix.isdigit() and int(suffix) >= 1:
            found.append(entry)
    return sorted(found, key=lambda p: int(p.name[len(prefix):]))


class SplitWriter:
    """A seekable file that is stored as consecutive parts of *part_size*
    bytes each (the last may be shorter), named by *part_name*(1, 2, ...).
    zipfile writes to it as to one file, seeking back to complete each
    entry's header. Only a few parts are kept open at a time."""

    _OPEN_PARTS = 8

    def __init__(self, part_name: Callable[[int], Path], part_size: int) -> None:
        if part_size < 1:
            raise ValueError("part size must be positive")
        self._part_name = part_name
        self._size = part_size
        self._pos = 0
        self._end = 0
        self._open: dict[int, IO[bytes]] = {}
        self._created: set[int] = set()
        self.closed = False

    # -- the file interface zipfile uses --

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = self._pos + offset
        elif whence == os.SEEK_END:
            pos = self._end + offset
        else:
            raise ValueError(f"bad whence: {whence}")
        if pos < 0:
            raise ValueError("negative seek position")
        self._pos = pos
        return pos

    def write(self, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data).cast("B")
        written = 0
        while written < len(view):
            index, offset = divmod(self._pos, self._size)
            n = min(len(view) - written, self._size - offset)
            f = self._part(index + 1)
            f.seek(offset)
            f.write(view[written:written + n])
            written += n
            self._pos += n
        self._end = max(self._end, self._pos)
        return written

    def flush(self) -> None:
        for f in self._open.values():
            f.flush()

    def close(self) -> None:
        for f in self._open.values():
            f.close()
        self._open.clear()
        self.closed = True

    # -- parts --

    @property
    def size(self) -> int:
        return self._end

    def parts(self) -> list[Path]:
        """The parts written, in order (at least one, even if empty)."""
        count = max(1, -(-self._end // self._size))
        for number in range(1, count + 1):
            if number not in self._created:  # an empty archive's single part
                self._part(number)
        return [self._part_name(n) for n in range(1, count + 1)]

    def _part(self, number: int) -> IO[bytes]:
        f = self._open.pop(number, None)
        if f is not None:
            self._open[number] = f  # now the most recently used
            return f
        if len(self._open) >= self._OPEN_PARTS:
            oldest = next(iter(self._open))
            self._open.pop(oldest).close()
        path = self._part_name(number)
        f = open(path, "r+b" if number in self._created else "w+b")
        self._created.add(number)
        self._open[number] = f
        return f
