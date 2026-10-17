# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Crush's readers for LevelDB's files, on top of the vendored ccl_leveldb.

The vendored module is left exactly as published. Where its reading differs
from LevelDB's own, a subclass here overrides the one method concerned:

- log and MANIFEST records (_read_batches), following LevelDB's
  log_reader.cc: zero padding ends the block; in a .log, a damaged part
  (an unknown record type, a fragment without its start or end, a length
  past the block) is skipped and reading goes on -- where LevelDB skips
  silently (padding, the writer stopping at the end of the file), Crush
  still says so; each record's stored checksum is checked -- a .log
  record or MANIFEST edit whose checksum doesn't match is kept and marked
  (LevelDB doesn't apply it);
- table blocks (_LdbFile._read_block): only compression types 0 (none) and
  1 (Snappy) are decoded, any other is named instead of being fed to the
  Snappy decoder;
- MANIFEST edits (_decode_version_edit): a tag LevelDB doesn't define stops
  the edit with its offset, as VersionEdit::DecodeFrom does, instead of
  being read past, and says whether its record's checksum matches; and the
  MANIFEST isn't read in full on opening, so such an edit doesn't make the
  whole file unopenable;
- records (_LogFile.__iter__, _LdbFile.__iter__): each record also says
  where its parts are (record_location), and a .log record's offset is its
  position in the file -- the vendored reader adds its position in the
  joined batch to the start of the batch's first fragment, which is off
  once a batch spans fragments.

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
    KeyState,
    LdbFile,
    LogEntryType,
    LogFile,
    ManifestFile,
    Record,
    VersionEdit,
    VersionEditTag,
    read_le_varint,
    read_length_prefixed_blob,
)

_BLOCK_SIZE = 32768  # log_format.h kBlockSize
_HEADER_SIZE = 7  # crc (4), length (2), type (1)
_BATCH_HEADER_SIZE = 12  # write_batch.cc kHeader: sequence (8), count (4)
_TAG_SIZE = 8  # an internal key's sequence/type tag (dbformat.h)

Ranges = list[tuple[int, int]]

_CompactionPointer = namedtuple("_CompactionPointer", ["level", "pointer"])
_DeletedFile = namedtuple("_DeletedFile", ["level", "file_no"])
_NewFile = namedtuple("_NewFile", ["level", "file_no", "file_size", "smallest_key", "largest_key"])


class UnknownVersionEditTag(ValueError):
    """A VersionEdit tag LevelDB doesn't define. The fields after it can't be
    skipped (their length depends on the tag), so the edit stops here.
    *checksum_ok*: whether the record holding the edit has a matching stored
    checksum -- a damaged record yields arbitrary "tags"."""

    def __init__(
        self, tag: int, offset: int, path: Path | None = None, checksum_ok: bool | None = None
    ) -> None:
        self.tag = tag
        self.offset = offset
        self.checksum_ok = checksum_ok
        where = f" in {path}" if path is not None else ""
        crc = (
            "" if checksum_ok is None
            else " (the record's stored checksum matches)" if checksum_ok
            else " (the record's stored checksum doesn't match)"
        )
        super().__init__(f"Unknown VersionEdit tag {tag} at offset {offset}{where}{crc}")


def _checksum_ok(stored: int, record_type: int, data: bytes) -> bool:
    """Whether a physical record's stored, masked CRC32C matches its type
    byte and data (log_writer.cc EmitPhysicalRecord)."""
    return bool(
        ccl_simplesnappy.check_masked_crc(  # type: ignore[no-untyped-call]
            stored, bytes([record_type]) + data
        )
    )


def _with_last(blocks: Iterable[bytes]) -> Iterator[tuple[bytes, bool]]:
    """Each block with whether it is the file's last -- one block ahead, so a
    file of exactly whole blocks knows its last one too."""
    it = iter(blocks)
    current = next(it, None)
    while current is not None:
        following = next(it, None)
        yield current, following is None
        current = following


def _read_batches(
    raw_blocks: Iterable[bytes], path: Path, damaged: list[str] | None = None
) -> Iterator[tuple[int, bytes, bool, Ranges]]:
    """(offset, record, stored checksums match, fragments) for every record
    of a log-format file (a .log or a MANIFEST), joined from its fragments
    (db/log_format.h, db/log_reader.cc). *fragments* are the (start, end)
    file ranges of the record's data, in order; joined, they are the record.

    With *damaged* (a list), a damaged part is described there and skipped,
    and reading goes on, as LevelDB reads a .log. Without it, the first
    damaged part raises ValueError, as LevelDB fails on a damaged MANIFEST.
    Parts LevelDB drops without reporting (zero padding, a record the writer
    didn't finish before the file ends) are still described. A described
    record's offset is that of its (first) header; the yielded offset is that
    of its data, as the vendored reader gives it."""

    def problem(text: str) -> None:
        if damaged is None:
            raise ValueError(f"{text} in {path}")
        damaged.append(text)

    in_record = False
    start_offset = start_header = 0
    record = b""
    record_ok = True
    fragments: Ranges = []
    for idx, (chunk, last_block) in enumerate(_with_last(raw_blocks)):
        with io.BytesIO(chunk) as buff:
            while len(chunk) - buff.tell() >= _HEADER_SIZE:
                header_offset = idx * _BLOCK_SIZE + buff.tell()
                crc, length, record_type = struct.unpack("<IHB", buff.read(_HEADER_SIZE))
                here = header_offset + _HEADER_SIZE

                if record_type == LogEntryType.Zero and length == 0:
                    # Padding: the rest of the block holds no records.
                    if in_record:
                        problem(f"Record starting at offset {start_header} is cut off by "
                                f"zero padding at offset {header_offset}")
                        in_record = False
                    break
                if len(chunk) - buff.tell() < length:
                    end = "the end of the file" if last_block else "the end of its block"
                    problem(f"Record at offset {header_offset} gives a length of {length:,} "
                            f"bytes, past {end}; the rest of the block isn't read")
                    in_record = False
                    break
                data = buff.read(length)
                ok = _checksum_ok(crc, record_type, data)

                if record_type == LogEntryType.Full:
                    if in_record and record:
                        problem(f"Record starting at offset {start_header} has no end "
                                f"before the record at offset {header_offset}")
                    in_record = False
                    yield here, data, ok, [(here, here + length)]
                elif record_type == LogEntryType.First:
                    if in_record and record:
                        problem(f"Record starting at offset {start_header} has no end "
                                f"before the record at offset {header_offset}")
                    start_offset, start_header = here, header_offset
                    record, record_ok, in_record = data, ok, True
                    fragments = [(here, here + length)]
                elif record_type == LogEntryType.Middle:
                    if not in_record:
                        problem(f"Record part at offset {header_offset} has no start")
                    else:
                        record += data
                        record_ok = record_ok and ok
                        fragments.append((here, here + length))
                elif record_type == LogEntryType.Last:
                    if not in_record:
                        problem(f"Record part at offset {header_offset} has no start")
                    else:
                        in_record = False
                        fragments.append((here, here + length))
                        yield start_offset, record + data, record_ok and ok, fragments
                else:
                    problem(f"Unknown record type {record_type} (length {length}) at offset "
                            f"{header_offset}")
                    in_record = False
            rest = chunk[buff.tell():]
            if last_block and len(rest) < _HEADER_SIZE and any(rest):
                # Fewer bytes than a header, not zero: a header the writer
                # didn't finish before the file ends (log_reader.cc: EOF).
                problem(f"Record header at offset {idx * _BLOCK_SIZE + buff.tell()} is cut off "
                        f"by the end of the file")
    if in_record:
        problem(f"Record starting at offset {start_header} has no end before the end of the file")


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


def _in_fragments(fragments: Ranges, start: int, end: int) -> Ranges:
    """The file ranges holding bytes *start* to *end* of a record joined
    from *fragments* -- more than one where they cross a fragment."""
    found: Ranges = []
    pos = 0
    for frag_start, frag_end in fragments:
        length = frag_end - frag_start
        lo, hi = max(start, pos), min(end, pos + length)
        if lo < hi:
            found.append((frag_start + lo - pos, frag_start + hi - pos))
        pos += length
    return found


def _runs(positions: list[int], base: int = 0) -> Ranges:
    """Byte *positions* (in order) as (start, end) ranges of consecutive
    bytes, each shifted by *base*."""
    found: Ranges = []
    for pos in positions:
        if found and found[-1][1] == pos + base:
            found[-1] = (found[-1][0], pos + base + 1)
        else:
            found.append((pos + base, pos + base + 1))
    return found


class _LogFile(LogFile):
    """A .log file, its records read as LevelDB reads them: a damaged part
    is skipped and described in *damaged*, and reading goes on.

    After each record it yields, *checksum_ok* is whether the stored
    checksums of the record's batch match, and *location* is where the
    record's parts are in the file (see record_location)."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.damaged: list[str] = []
        self.checksum_ok = True
        self.location: dict[str, Any] | None = None

    def __iter__(self) -> Iterator[Record]:
        # The vendored __iter__ (write_batch.cc: a 12-byte header, then per
        # entry its type, key and -- unless a deletion -- value), keeping
        # the position of each part.
        self.damaged.clear()
        for _offset, batch, checksum_ok, fragments in _read_batches(
            self._get_raw_blocks(), self.path, self.damaged
        ):
            self.checksum_ok = checksum_ok
            with io.BytesIO(batch) as buff:
                seq, count = struct.unpack("<QI", buff.read(_BATCH_HEADER_SIZE))
                header = _in_fragments(fragments, 0, _BATCH_HEADER_SIZE)
                for i in range(count):
                    start = buff.tell()
                    state = KeyState(buff.read(1)[0])
                    key_length = read_le_varint(buff, is_google_32bit=True)
                    key_start = buff.tell()
                    key = buff.read(key_length)
                    key_end = buff.tell()
                    if state != KeyState.Deleted:
                        value_length = read_le_varint(buff, is_google_32bit=True)
                        value_start = buff.tell()
                        value = buff.read(value_length)
                    else:
                        value_start = buff.tell()
                        value = b""
                    end = buff.tell()
                    in_file = {
                        "entry": _in_fragments(fragments, start, end),
                        "batch_header": header,
                        "type": _in_fragments(fragments, start, start + 1),
                        "key": _in_fragments(fragments, key_start, key_end),
                        "value": _in_fragments(fragments, value_start, end),
                    }
                    self.location = record_location(in_file)
                    yield Record.log_record(
                        key, value, seq + i, state, self.path, in_file["type"][0][0]
                    )


def record_location(
    in_file: dict[str, Ranges] | None, block: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Where a record's parts are. *in_file*: (start, end) file ranges per
    part -- entry, the parts within it, and for a .log record its batch's
    header. *block*, for a record of a compressed table block, instead of
    *in_file*: the block's offset, length, compression and the number of
    records read from it, and the parts as ranges in the decompressed block
    -- the record's bytes exist only there."""
    return {"in_file": in_file, "compressed_block": block}


def _block_entries(
    block: Block,
) -> Iterator[tuple[bytes, bytes, dict[str, Ranges]]]:
    """(key, value, parts) for each entry of a table block, as the vendored
    Block.__iter__ reads them (doc/table_format.md, table/block_builder.cc),
    with the parts' ranges in the (decompressed) block: entry, user key,
    tag, value. A key's first *shared* bytes are stored in earlier entries
    (prefix compression back to the restart point); its user-key and tag
    ranges include those pieces."""
    raw = block._raw
    restarts = block._restart_array_offset
    with io.BytesIO(raw) as buff:
        buff.seek(block.get_first_entry_offset())
        key = b""
        key_positions: list[int] = []
        while buff.tell() < restarts:
            start = buff.tell()
            shared_length = read_le_varint(buff, is_google_32bit=True)
            non_shared_length = read_le_varint(buff, is_google_32bit=True)
            value_length = read_le_varint(buff, is_google_32bit=True)
            if shared_length is None or non_shared_length is None or value_length is None:
                raise ValueError(f"Entry at offset {start} of the block at offset {block.offset} "
                                 f"is cut off")
            if shared_length > len(key):
                raise ValueError("Shared key length is larger than the previous key")
            suffix_start = buff.tell()
            key = key[:shared_length] + buff.read(non_shared_length)
            key_positions = key_positions[:shared_length] + list(
                range(suffix_start, suffix_start + len(key) - shared_length)
            )
            value_start = buff.tell()
            value = buff.read(value_length)
            end = buff.tell()
            # Record.user_key: a key shorter than the tag is all user key
            has_tag = len(key) >= _TAG_SIZE
            user_positions = key_positions[:-_TAG_SIZE] if has_tag else key_positions
            yield key, value, {
                "entry": [(start, end)],
                "key": _runs(user_positions),
                "tag": _runs(key_positions[-_TAG_SIZE:]) if has_tag else [],
                "value": [(value_start, end)],
            }


def _shifted(parts: dict[str, Ranges], base: int) -> dict[str, Ranges]:
    return {name: [(s + base, e + base) for s, e in ranges] for name, ranges in parts.items()}


class _LdbFile(LdbFile):
    """A .ldb/.sst table that names a compression type it can't decode.

    After each record it yields, *location* is where the record's parts are
    (see record_location): in the file for an uncompressed block, in the
    decompressed block for a compressed one."""

    location: dict[str, Any] | None = None

    def __iter__(self) -> Iterator[Record]:
        # The vendored __iter__, keeping the position of each part.
        for _block_key, handle in self._index:
            block = self._read_block(handle)
            # Read the whole block first, for its record count; an entry
            # that can't be read still lets the ones before it through,
            # as the vendored reader does, then stops.
            entries: list[tuple[bytes, bytes, dict[str, Ranges]]] = []
            failure: Exception | None = None
            try:
                for entry in _block_entries(block):
                    entries.append(entry)
            except Exception as exc:  # noqa: BLE001 -- raised again below
                failure = exc
            for key, value, parts in entries:
                if block.was_compressed:
                    self.location = record_location(None, {
                        "offset": handle.offset,
                        "length": handle.length,
                        "trailer": LdbFile.BLOCK_TRAILER_SIZE,
                        "compression": "Snappy",
                        "records": len(entries),
                        **parts,
                    })
                    offset = block.offset
                else:
                    self.location = record_location(_shifted(parts, block.offset))
                    offset = block.offset + parts["entry"][0][0]
                yield Record.ldb_record(key, value, self.path, offset, block.was_compressed)
            if failure is not None:
                raise failure

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
    """A MANIFEST, read edit by edit only when iterated. *checksum_mismatches*
    lists the header offsets of edits whose record's stored checksum doesn't
    match (read and kept; LevelDB wouldn't apply them)."""

    def __init__(self, path: Path) -> None:  # no super(): it reads every edit
        if not re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, path.name):
            raise ValueError("Invalid name for Manifest")
        self.path = path
        self._f = path.open("rb")
        self.checksum_mismatches: list[int] = []

    def _get_batches(self) -> Iterator[tuple[int, bytes]]:
        # A damaged part stops the MANIFEST, as it makes LevelDB fail.
        for offset, record, _checksum_ok, _fragments in _read_batches(
            self._get_raw_blocks(), self.path
        ):
            yield offset, record

    def __iter__(self) -> Iterator[VersionEdit]:
        self.checksum_mismatches = []
        for batch_offset, batch, checksum_ok, _fragments in _read_batches(
            self._get_raw_blocks(), self.path
        ):
            if not checksum_ok:
                # the record's (first) header, where its checksum is stored
                self.checksum_mismatches.append(batch_offset - _HEADER_SIZE)
            try:
                yield _decode_version_edit(batch)
            except UnknownVersionEditTag as exc:
                # the offset in the file, not in the edit, and whether the
                # record holding it is the one that was written
                raise UnknownVersionEditTag(
                    exc.tag, batch_offset + exc.offset, self.path, checksum_ok
                ) from None


class DataFileBytes:
    """The bytes of a database's data files as read, by file name, for the
    viewer to show a record in its file; and a compressed table block's
    decompressed bytes, where such a record's ranges point."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files
        # the last block decompressed: the records of one block are
        # usually looked at one after another
        self._last: tuple[tuple[str, int], bytes] | None = None

    def file(self, name: str) -> bytes | None:
        return self._files.get(name)

    def decompressed_block(self, name: str, offset: int, length: int) -> bytes:
        """The block at *offset* (*length* bytes) of table file *name*,
        Snappy-decompressed as the reader decompressed it. Raises
        ValueError when it can't be."""
        if self._last is not None and self._last[0] == (name, offset):
            return self._last[1]
        raw = self._files.get(name)
        if raw is None:
            raise ValueError(f"The bytes of {name} weren't read")
        if offset < 0 or offset + length > len(raw):
            raise ValueError(f"The block at offset {offset} ({length} bytes) is past the end of {name}")
        with io.BytesIO(raw[offset:offset + length]) as buff:
            block = bytes(ccl_simplesnappy.decompress(buff))
        self._last = ((name, offset), block)
        return block


def open_data_file(path: Path) -> Any:
    """A .log or table file, opened with the readers above."""
    return _LogFile(path) if path.suffix.lower() == ".log" else _LdbFile(path)


def open_manifest(path: Path) -> Any:
    """A MANIFEST, opened with the reader above."""
    return _ManifestFile(path)
