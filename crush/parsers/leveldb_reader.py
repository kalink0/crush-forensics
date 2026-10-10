# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Crush's readers for LevelDB's files, on top of the vendored ccl_leveldb.

The vendored module is left exactly as published. Where its reading differs
from LevelDB's own, a subclass here overrides the one method concerned:

- log and MANIFEST records (_read_batches): a zero header is padding, as
  LevelDB's log_reader.cc treats it, and an unknown record type is named
  instead of raising an empty ValueError;
- table blocks (_LdbFile._read_block): only compression types 0 (none) and
  1 (Snappy) are decoded, any other is named instead of being fed to the
  Snappy decoder;
- MANIFEST edits (_decode_version_edit): a tag LevelDB doesn't define stops
  the edit with its offset, as VersionEdit::DecodeFrom does, instead of
  being read past; and the MANIFEST isn't read in full on opening, so such
  an edit doesn't make the whole file unopenable.

These are copies of the vendored methods with those changes. When
ccl_leveldb is updated, compare them with the new version.
"""
from __future__ import annotations

import io
import re
import struct
from collections import namedtuple
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, cast

from crush.third_party.ccl_leveldb import ccl_simplesnappy
from crush.third_party.ccl_leveldb.ccl_leveldb import (
    Block,
    BlockHandle,
    LdbFile,
    LogEntryType,
    LogFile,
    ManifestFile,
    VersionEdit,
    VersionEditTag,
    read_le_varint,
    read_length_prefixed_blob,
)

_BLOCK_SIZE = 32768  # log_format.h kBlockSize
_HEADER_SIZE = 7  # crc (4), length (2), type (1)

_CompactionPointer = namedtuple("_CompactionPointer", ["level", "pointer"])
_DeletedFile = namedtuple("_DeletedFile", ["level", "file_no"])
_NewFile = namedtuple("_NewFile", ["level", "file_no", "file_size", "smallest_key", "largest_key"])


class UnknownVersionEditTag(ValueError):
    """A VersionEdit tag LevelDB doesn't define. The fields after it can't be
    skipped (their length depends on the tag), so the edit stops here."""

    def __init__(self, tag: int, offset: int, path: Path | None = None) -> None:
        self.tag = tag
        self.offset = offset
        where = f" in {path}" if path is not None else ""
        super().__init__(f"Unknown VersionEdit tag {tag} at offset {offset}{where}")


def _read_batches(raw_blocks: Iterable[bytes], path: Path) -> Iterator[tuple[int, bytes]]:
    """(offset, record) for every record of a log-format file (a .log or a
    MANIFEST), joined from its fragments (db/log_format.h)."""
    in_record = False
    start_offset = 0
    record = b""
    for idx, chunk in enumerate(raw_blocks):
        with io.BytesIO(chunk) as buff:
            while buff.tell() < _BLOCK_SIZE - 6:
                header = buff.read(_HEADER_SIZE)
                if len(header) < _HEADER_SIZE:
                    break
                _crc, length, record_type = struct.unpack("<IHB", header)
                header_offset = idx * _BLOCK_SIZE + buff.tell() - _HEADER_SIZE
                here = idx * _BLOCK_SIZE + buff.tell()

                if record_type == LogEntryType.Zero and length == 0:
                    # Padding: log_reader.cc skips the rest of the block
                    # without reporting it. Inside a fragmented record it
                    # cuts that record off.
                    if in_record:
                        raise ValueError(
                            f"Record starting at offset {start_offset} is cut off by zero "
                            f"padding at offset {header_offset} in {path}"
                        )
                    break
                if record_type == LogEntryType.Full:
                    if in_record:
                        raise ValueError(f"Full block whilst still building a block at offset {here} in {path}")
                    yield here, buff.read(length)
                elif record_type == LogEntryType.First:
                    if in_record:
                        raise ValueError(f"First block whilst still building a block at offset {here} in {path}")
                    start_offset = here
                    record = buff.read(length)
                    in_record = True
                elif record_type == LogEntryType.Middle:
                    if not in_record:
                        raise ValueError(f"Middle block whilst not building a block at offset {here} in {path}")
                    record += buff.read(length)
                elif record_type == LogEntryType.Last:
                    if not in_record:
                        raise ValueError(f"Last block whilst not building a block at offset {here} in {path}")
                    record += buff.read(length)
                    in_record = False
                    yield start_offset, record
                else:
                    raise ValueError(
                        f"Unknown record type {record_type} (length {length}) at offset "
                        f"{header_offset} in {path}"
                    )


def _decode_version_edit(buffer: bytes) -> VersionEdit:
    """One MANIFEST edit (db/version_edit.cc), stopping at a tag LevelDB
    doesn't define; UnknownVersionEditTag carries its offset in *buffer*."""
    comparator = log_number = prev_log_number = last_sequence = next_file_number = None
    compaction_pointers: list[Any] = []
    deleted_files: list[Any] = []
    new_files: list[Any] = []

    with io.BytesIO(buffer) as b:
        while b.tell() < len(buffer) - 1:
            tag_offset = b.tell()
            tag = read_le_varint(b, is_google_32bit=True)
            if tag is None:  # the edit ends inside a varint, as in the vendored reader
                break
            if tag == VersionEditTag.Comparator:
                comparator = read_length_prefixed_blob(b).decode("utf-8")
            elif tag == VersionEditTag.LogNumber:
                log_number = read_le_varint(b)
            elif tag == VersionEditTag.PrevLogNumber:
                prev_log_number = read_le_varint(b)
            elif tag == VersionEditTag.NextFileNumber:
                next_file_number = read_le_varint(b)
            elif tag == VersionEditTag.LastSequence:
                last_sequence = read_le_varint(b)
            elif tag == VersionEditTag.CompactPointer:
                level = read_le_varint(b, is_google_32bit=True)
                compaction_pointers.append(_CompactionPointer(level, read_length_prefixed_blob(b)))
            elif tag == VersionEditTag.DeletedFile:
                level = read_le_varint(b, is_google_32bit=True)
                deleted_files.append(_DeletedFile(level, read_le_varint(b)))
            elif tag == VersionEditTag.NewFile:
                level = read_le_varint(b, is_google_32bit=True)
                file_no = read_le_varint(b)
                file_size = read_le_varint(b)
                smallest = read_length_prefixed_blob(b)
                largest = read_length_prefixed_blob(b)
                new_files.append(_NewFile(level, file_no, file_size, smallest, largest))
            else:
                raise UnknownVersionEditTag(tag, tag_offset)

    # cast: the vendored dataclass annotates its fields without None
    return cast(VersionEdit, cast(Any, VersionEdit)(
        comparator, log_number, prev_log_number, last_sequence, next_file_number,
        tuple(compaction_pointers), tuple(deleted_files), tuple(new_files),
    ))


class _LogFile(LogFile):
    """A .log file, its records read as LevelDB reads them."""

    def _get_batches(self) -> Iterator[tuple[int, bytes]]:
        return _read_batches(self._get_raw_blocks(), self.path)


class _LdbFile(LdbFile):
    """A .ldb/.sst table that names a compression type it can't decode."""

    def _read_block(self, handle: BlockHandle) -> Block:
        # block (handle.length bytes), then a 5-byte trailer: compression
        # type (1) and CRC (4)
        self._f.seek(handle.offset)
        raw_block = self._f.read(handle.length)
        trailer = self._f.read(LdbFile.BLOCK_TRAILER_SIZE)
        if len(raw_block) != handle.length or len(trailer) != LdbFile.BLOCK_TRAILER_SIZE:
            raise ValueError(f"Could not read all of the block at offset {handle.offset} in file {self.path}")
        if trailer[0] not in (0, 1):
            raise ValueError(
                f"Compression type {trailer[0]} of the block at offset {handle.offset} in {self.path} "
                f"is not supported (only none and Snappy are read)"
            )
        is_compressed = trailer[0] == 1
        if is_compressed:
            with io.BytesIO(raw_block) as buff:
                raw_block = ccl_simplesnappy.decompress(buff)
        return Block(raw_block, is_compressed, self, handle.offset)


class _ManifestFile(ManifestFile):
    """A MANIFEST, read edit by edit only when iterated."""

    def __init__(self, path: Path) -> None:  # no super(): it reads every edit
        if not re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, path.name):
            raise ValueError("Invalid name for Manifest")
        self.path = path
        self._f = path.open("rb")

    def _get_batches(self) -> Iterator[tuple[int, bytes]]:
        return _read_batches(self._get_raw_blocks(), self.path)

    def __iter__(self) -> Iterator[VersionEdit]:
        for batch_offset, batch in self._get_batches():
            try:
                yield _decode_version_edit(batch)
            except UnknownVersionEditTag as exc:
                # the offset in the file, not in the edit
                raise UnknownVersionEditTag(exc.tag, batch_offset + exc.offset, self.path) from None


def open_data_file(path: Path) -> Any:
    """A .log or table file, opened with the readers above."""
    return _LogFile(path) if path.suffix.lower() == ".log" else _LdbFile(path)


def open_manifest(path: Path) -> Any:
    """A MANIFEST, opened with the reader above."""
    return _ManifestFile(path)
