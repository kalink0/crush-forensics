# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Chromium Simple cache backend: entry files, sparse files, the index
(index-dir/the-real-index) and the fake index (index).

Written from the Chromium source at revision 278016c7cf72 (2026-10-28):
net/disk_cache/simple/simple_entry_format.h, simple_backend_version.h,
simple_synchronous_entry.cc, simple_index_file.cc, simple_index.cc,
simple_util.cc, simple_version_upgrade.{h,cc}.

A file's role is read from its bytes, never from its name: the stream 0
EOF record alone carries FLAG_HAS_KEY_SHA256, a stream 0/1 file has two EOF
records, a sparse file has range headers after the key.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from typing import IO, Any

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue
from crush.parsers.chromium_pickle import PickleError, Tree, chrome_time

INITIAL_MAGIC = 0xFCFB6D1BA7725C30
FINAL_MAGIC = 0xF4FA6F45970D41D8
SPARSE_RANGE_MAGIC = 0xEB97BF016553676B
INDEX_MAGIC = 0x656E74657220796F

HEADER_SIZE = 24        # SimpleFileHeader, incl. unused_padding
EOF_SIZE = 24           # SimpleFileEOF, incl. unused_padding
RANGE_HEADER_SIZE = 32  # SimpleFileSparseRangeHeader, incl. unused_padding
FAKE_INDEX_SIZE = 24    # FakeIndexData
KEY_SHA256_SIZE = 32

ENTRY_VERSION = 5        # kSimpleEntryVersionOnDisk
SPARSE_VERSION = 9       # kSimpleSparseEntryVersion
INDEX_VERSION = 9        # kSimpleIndexFileVersion
MIN_INDEX_VERSION = 8    # kMinSimpleIndexFileVersionSupported

FLAG_HAS_CRC32 = 1
FLAG_HAS_KEY_SHA256 = 2

ROLE_STREAMS_0_1 = QT_TRANSLATE_NOOP("GeneratedView", "entry file, streams 0 and 1")
ROLE_STREAM_2 = QT_TRANSLATE_NOOP("GeneratedView", "entry file, stream 2")
ROLE_SPARSE = QT_TRANSLATE_NOOP("GeneratedView", "sparse data file")
ROLE_FAKE_INDEX = QT_TRANSLATE_NOOP("GeneratedView", "backend marker (fake index)")
ROLE_REAL_INDEX = QT_TRANSLATE_NOOP("GeneratedView", "index (the-real-index)")

# SimpleIndex::IndexWriteToDiskReason
_WRITE_REASONS = {0: "SHUTDOWN", 1: "STARTUP_MERGE", 2: "IDLE", 3: "ANDROID_STOPPED"}


class RandomAccess:
    """read_at() over a file object or bytes."""

    def __init__(self, source: IO[bytes] | bytes, size: int) -> None:
        self._source = source
        self.size = size

    def read_at(self, offset: int, n: int) -> bytes:
        if isinstance(self._source, (bytes, bytearray)):
            return bytes(self._source[offset:offset + n])
        self._source.seek(offset)
        return self._source.read(n)


def entry_hash(key: bytes) -> int:
    """simple_util::GetEntryHashKey: the first 8 bytes of the key's SHA-1,
    little-endian -- the hash in the index and in the file names."""
    return int.from_bytes(hashlib.sha1(key).digest()[:8], "little")


def has_initial_magic(head: bytes) -> bool:
    return len(head) >= 8 and struct.unpack_from("<Q", head)[0] == INITIAL_MAGIC


def has_index_magic(head: bytes) -> bool:
    """the-real-index: a pickle header (payload size, CRC), then the magic."""
    return len(head) >= 16 and struct.unpack_from("<Q", head, 8)[0] == INDEX_MAGIC


@dataclass
class Eof:
    offset: int
    magic_ok: bool
    flags: int
    crc32: int
    stream_size: int

    def tree(self) -> dict[str, Any]:
        flags = [n for bit, n in ((FLAG_HAS_CRC32, "HAS_CRC32"), (FLAG_HAS_KEY_SHA256, "HAS_KEY_SHA256"))
                 if self.flags & bit]
        return {
            "Final magic": "0xf4fa6f45970d41d8" if self.magic_ok else ParseIssue("chromium_cache.eof_magic_wrong"),
            "Flags": f"0x{self.flags:08x} ({', '.join(flags) or '-'})",
            "Data CRC32": f"0x{self.crc32:08x}" if self.flags & FLAG_HAS_CRC32 else "-",
            "Stream size": self.stream_size,
        }


def _read_eof(ra: RandomAccess, offset: int) -> Eof | None:
    if offset < 0 or offset + EOF_SIZE > ra.size:
        return None
    magic, flags, crc, size, _pad = struct.unpack("<QIIII", ra.read_at(offset, EOF_SIZE))
    return Eof(offset, magic == FINAL_MAGIC, flags, crc, size)


@dataclass
class SimpleFile:
    """One file of a Simple cache entry, its layout read from its bytes."""

    size: int
    role: str
    version: int = 0
    key: bytes = b""
    key_hash: int = 0
    # (start, end) in the file, end exclusive.
    streams: dict[int, tuple[int, int]] = field(default_factory=dict)
    eofs: dict[int, Eof] = field(default_factory=dict)
    key_sha256_range: tuple[int, int] | None = None
    sparse_ranges: list[dict[str, int]] = field(default_factory=list)
    notes: list[ParseIssue] = field(default_factory=list)
    # The layout couldn't be read (wrong magic, cut off ...): the streams
    # aren't known.
    unreadable: ParseIssue | None = None
    # FakeIndexData fields, for the fake index.
    fake: dict[str, int] = field(default_factory=dict)

    @property
    def key_range(self) -> tuple[int, int]:
        return HEADER_SIZE, HEADER_SIZE + len(self.key)


def read_simple_file(ra: RandomAccess) -> SimpleFile:
    """The layout of a file starting with the Simple initial magic."""
    head = ra.read_at(0, HEADER_SIZE)
    if ra.size == FAKE_INDEX_SIZE:
        magic, version, experiment, zero2, encrypted = struct.unpack("<QIIII", head)
        out = SimpleFile(ra.size, ROLE_FAKE_INDEX, version=version)
        out.fake = {
            "version": version, "experiment_type": experiment, "zero2": zero2,
            "encryption_status": encrypted,
        }
        if version > INDEX_VERSION or version < MIN_INDEX_VERSION:
            out.notes.append(ParseIssue("chromium_cache.fake_index_version", {"version": version}))
        return out
    if len(head) < HEADER_SIZE:
        out = SimpleFile(ra.size, ROLE_STREAMS_0_1)
        out.unreadable = ParseIssue("chromium_cache.file_too_short", {"size": ra.size})
        return out
    magic, version, key_length, key_hash, _pad = struct.unpack("<QIIII", head)
    key_end = HEADER_SIZE + key_length
    if key_end > ra.size:
        out = SimpleFile(ra.size, ROLE_STREAMS_0_1, version=version, key_hash=key_hash)
        out.unreadable = ParseIssue(
            "chromium_cache.key_past_end", {"length": key_length, "size": ra.size}
        )
        return out
    key = ra.read_at(HEADER_SIZE, key_length)

    if ra.size == key_end and version != SPARSE_VERSION:
        # Header and key only: no EOF record, so no streams. A sparse file
        # without ranges looks the same but carries the sparse version.
        out = SimpleFile(ra.size, ROLE_STREAMS_0_1, version, key, key_hash)
        out.unreadable = ParseIssue("chromium_cache.header_and_key_only", {"version": version})
        return out
    # Sparse file: range headers (or nothing) follow the key.
    after_key = ra.read_at(key_end, 8)
    if ra.size == key_end or (
        len(after_key) == 8 and struct.unpack("<Q", after_key)[0] == SPARSE_RANGE_MAGIC
    ):
        out = SimpleFile(ra.size, ROLE_SPARSE, version, key, key_hash)
        _read_sparse(ra, key_end, out)
        if version != SPARSE_VERSION:
            out.notes.append(ParseIssue(
                "chromium_cache.version_unexpected", {"version": version, "expected": SPARSE_VERSION}
            ))
        return out

    last = _read_eof(ra, ra.size - EOF_SIZE)
    if last is None or not last.magic_ok:
        out = SimpleFile(ra.size, ROLE_STREAMS_0_1, version, key, key_hash)
        out.unreadable = ParseIssue("chromium_cache.eof_missing")
        return out
    has_sha = bool(last.flags & FLAG_HAS_KEY_SHA256)
    s0_end = ra.size - EOF_SIZE - (KEY_SHA256_SIZE if has_sha else 0)
    s0_start = s0_end - last.stream_size
    inner = _read_eof(ra, s0_start - EOF_SIZE) if s0_start - EOF_SIZE >= key_end else None
    if has_sha or (inner is not None and inner.magic_ok):
        out = SimpleFile(ra.size, ROLE_STREAMS_0_1, version, key, key_hash)
        out.eofs[0] = last
        if inner is None or not inner.magic_ok or s0_start < key_end + EOF_SIZE:
            out.unreadable = ParseIssue(
                "chromium_cache.stream1_eof_missing", {"stream0": last.stream_size}
            )
            return out
        out.eofs[1] = inner
        out.streams[1] = (key_end, inner.offset)
        out.streams[0] = (s0_start, s0_end)
        if has_sha:
            out.key_sha256_range = (s0_end, s0_end + KEY_SHA256_SIZE)
            if ra.read_at(s0_end, KEY_SHA256_SIZE) != hashlib.sha256(key).digest():
                out.notes.append(ParseIssue("chromium_cache.key_sha256_mismatch"))
    else:
        out = SimpleFile(ra.size, ROLE_STREAM_2, version, key, key_hash)
        out.eofs[2] = last
        out.streams[2] = (key_end, last.offset)
    if version != ENTRY_VERSION:
        out.notes.append(ParseIssue(
            "chromium_cache.version_unexpected", {"version": version, "expected": ENTRY_VERSION}
        ))
    return out


def _read_sparse(ra: RandomAccess, offset: int, out: SimpleFile) -> None:
    """ScanSparseFile: range header + data, one after the other, to the end."""
    while offset < ra.size:
        raw = ra.read_at(offset, RANGE_HEADER_SIZE)
        if len(raw) < RANGE_HEADER_SIZE:
            out.notes.append(ParseIssue("chromium_cache.sparse_cut_off", {"offset": offset}))
            return
        magic, start, length, crc, _pad = struct.unpack("<QQQII", raw)
        if magic != SPARSE_RANGE_MAGIC:
            out.notes.append(ParseIssue("chromium_cache.sparse_magic_wrong", {"offset": offset}))
            return
        data_start = offset + RANGE_HEADER_SIZE
        data_end = data_start + length
        if data_end > ra.size:
            out.notes.append(ParseIssue("chromium_cache.sparse_cut_off", {"offset": offset}))
            data_end = ra.size
        out.sparse_ranges.append({
            "header": offset, "offset": start, "length": length, "crc32": crc,
            "data_start": data_start, "data_end": data_end,
        })
        offset = data_start + length


def crc_note(data: bytes, eof: Eof) -> str | ParseIssue:
    """Whether a stream's stored CRC32 matches its bytes."""
    if not eof.flags & FLAG_HAS_CRC32:
        return QT_TRANSLATE_NOOP("GeneratedView", "not stored")
    if zlib.crc32(data) & 0xFFFFFFFF == eof.crc32:
        return QT_TRANSLATE_NOOP("GeneratedView", "matches")
    return ParseIssue("chromium_cache.crc_mismatch", {"stored": f"0x{eof.crc32:08x}"})


def structure_tree(sf: SimpleFile, ra: RandomAccess) -> Tree:
    """The file's parts with their byte ranges, for the structure view."""
    t = Tree()
    t.put(("Role",), sf.role)
    if sf.role == ROLE_FAKE_INDEX:
        t.put(("Initial magic",), "0xfcfb6d1ba7725c30", 0, 8)
        t.put(("Version",), sf.fake["version"], 8, 12)
        t.put(("Experiment type",), sf.fake["experiment_type"], 12, 16)
        t.put(("Zero2",), sf.fake["zero2"], 16, 20)
        t.put(("Encryption status",), sf.fake["encryption_status"], 20, 24)
        for i, note in enumerate(sf.notes):
            t.put((f"Note {i + 1}",), note)
        return t
    t.put(("Header", "Initial magic"), "0xfcfb6d1ba7725c30", 0, 8)
    t.put(("Header", "Version"), sf.version, 8, 12)
    t.put(("Header", "Key length"), len(sf.key), 12, 16)
    t.put(("Header", "Key hash"), f"0x{sf.key_hash:08x}", 16, 20)
    t.put(("Header", "Padding"), "", 20, 24)
    t.mark(("Header",), 0, HEADER_SIZE)
    if sf.key:
        t.put(("Key",), sf.key.decode("utf-8", errors="backslashreplace"), *sf.key_range)
    names = {0: "Stream 0", 1: "Stream 1", 2: "Stream 2"}
    for index in (1, 0, 2):
        if index in sf.streams:
            start, end = sf.streams[index]
            t.put((names[index],), f"{end - start:,} B", start, end)
        if index in sf.eofs:
            eof = sf.eofs[index]
            t.put((f"EOF record, stream {index}",), eof.tree(), eof.offset, eof.offset + EOF_SIZE)
            t.mark((f"EOF record, stream {index}",), eof.offset, eof.offset + EOF_SIZE)
        if index == 0 and sf.key_sha256_range:
            t.put(("SHA-256 of the key",), ra.read_at(*_span(sf.key_sha256_range)).hex(), *sf.key_sha256_range)
    for i, rng in enumerate(sf.sparse_ranges):
        path = ("Sparse ranges", str(i))
        t.put(path + ("Offset in the entry",), rng["offset"], rng["header"] + 8, rng["header"] + 16)
        t.put(path + ("Length",), rng["length"], rng["header"] + 16, rng["header"] + 24)
        t.put(path + ("Data CRC32",), f"0x{rng['crc32']:08x}", rng["header"] + 24, rng["header"] + 28)
        t.put(path + ("Data",), f"{rng['data_end'] - rng['data_start']:,} B", rng["data_start"], rng["data_end"])
        t.mark(path, rng["header"], rng["data_end"])
    if sf.unreadable is not None:
        t.put(("Status",), sf.unreadable)
    for i, note in enumerate(sf.notes):
        t.put((f"Note {i + 1}",), note)
    return t


def _span(rng: tuple[int, int]) -> tuple[int, int]:
    return rng[0], rng[1] - rng[0]


# -- Index ------------------------------------------------------------------------


@dataclass
class IndexRecord:
    hash: int
    # The first field: last-used time (base::Time internal value) for most
    # cache types, the trailer prefetch size for net::APP_CACHE.
    first_field: int
    size: int          # entry size, 256-byte chunks rounded up
    in_memory_data: int
    offset: int        # of the record in the file


@dataclass
class RealIndex:
    version: int = 0
    entry_count: int = 0
    cache_size: int = 0
    reason: int | None = None
    crc_stored: int = 0
    crc_ok: bool = False
    cache_last_modified: int | None = None
    records: list[IndexRecord] = field(default_factory=list)
    tree: Tree = field(default_factory=Tree)
    stopped: ParseIssue | None = None


def read_real_index(data: bytes) -> RealIndex:
    """SimpleIndexFile::Deserialize: a pickle with a CRC in its header,
    the IndexMetadata, entry_count records, then the cache's last-modified
    time. Records are read whatever the CRC says (Chromium discards such an
    index; its records are still the file's content) -- the CRC result is
    shown."""
    from crush.parsers.chromium_pickle import Pickle

    out = RealIndex()
    t = out.tree
    try:
        p = Pickle(data, 0, header_size=8)
        out.crc_stored = struct.unpack_from("<I", data, 4)[0]
        out.crc_ok = zlib.crc32(data[8:p.end]) & 0xFFFFFFFF == out.crc_stored
        t.put(("Pickle payload size",), p.payload_size, 0, 4)
        t.put(("Pickle CRC32",), f"0x{out.crc_stored:08x}", 4, 8)
        t.put(("CRC32 check",), QT_TRANSLATE_NOOP("GeneratedView", "matches") if out.crc_ok
              else ParseIssue("chromium_cache.index_crc_mismatch"))
        magic, s, e = p.uint64("index magic")
        t.put(("Magic",), f"0x{magic:016x}", s, e)
        out.version, s, e = p.uint32("index version")
        t.put(("Version",), out.version, s, e)
        out.entry_count, s, e = p.uint64("entry count")
        t.put(("Entry count",), out.entry_count, s, e)
        out.cache_size, s, e = p.uint64("cache size")
        t.put(("Cache size",), out.cache_size, s, e)
        # IndexMetadata::Deserialize reads the write reason in every version
        # it supports (8 and 9).
        out.reason, s, e = p.uint32("write reason")
        t.put(("Write reason",), f"{_WRITE_REASONS.get(out.reason, 'unknown')} ({out.reason})", s, e)
        if out.version < MIN_INDEX_VERSION or out.version > INDEX_VERSION:
            t.put(("Version note",), ParseIssue("chromium_cache.index_version", {"version": out.version}))
        start = p.base + p.pos
        for i in range(out.entry_count):
            hash_value, rs, _ = p.uint64(f"record {i} hash")
            first, _, _ = p.int64(f"record {i} time or prefetch size")
            packed, _, re_ = p.uint64(f"record {i} size")
            out.records.append(IndexRecord(
                hash_value, first, (packed >> 8) << 8, packed & 0x03, rs,
            ))
        t.put(("Records",), f"{len(out.records):,}", start, p.base + p.pos)
        modified, s, e = p.int64("cache last modified")
        out.cache_last_modified = modified
        t.put(("Cache directory last modified",), chrome_time(modified), s, e)
        if p.remaining:
            t.put(("Unread bytes after the last field",), p.remaining, p.pos, p.end)
    except PickleError as exc:
        out.stopped = exc.issue
        t.put(("Stopped",), exc.issue)
    return out
