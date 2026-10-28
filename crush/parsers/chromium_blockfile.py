# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Chromium Blockfile cache backend: the index, block files (data_N),
external files (f_XXXXXX), entries, rankings nodes and sparse children.

Written from the Chromium source at revision 278016c7cf72 (2026-10-28):
net/disk_cache/blockfile/disk_format.h, disk_format_base.h, addr.{h,cc},
entry_impl.cc, sparse_control.cc, backend_impl.cc, block_files.cc,
base/hash/hash.cc and base/third_party/superfasthash/superfasthash.c.

The backend addresses its files by name (data_<n>, f_<6 hex digits>); the
format itself is recognised by the index and block file magics.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue
from crush.core.vfs import join_notes
from crush.parsers.chromium_pickle import Tree, chrome_time

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
VERSIONS = {0x20000: "2.0", 0x20001: "2.1", 0x30000: "3.0"}
INDEX_HEADER_SIZE = 368
INDEX_TABLE_SIZE = 0x10000
BLOCK_HEADER_SIZE = 8192
ENTRY_SIZE = 256
RANKINGS_SIZE = 36
KEY_OFFSET = 96
MAX_INTERNAL_KEY = 4 * ENTRY_SIZE - KEY_OFFSET - 1  # kMaxInternalKeyLength
NUM_STREAMS = 3

# FileType (addr.h)
EXTERNAL, RANKINGS, BLOCK_256, BLOCK_1K, BLOCK_4K, BLOCK_FILES, BLOCK_ENTRIES, BLOCK_EVICTED = range(8)
_BLOCK_SIZES = {RANKINGS: 36, BLOCK_256: 256, BLOCK_1K: 1024, BLOCK_4K: 4096,
                BLOCK_FILES: 8, BLOCK_ENTRIES: 104, BLOCK_EVICTED: 48}

# EntryState / EntryFlags (disk_format.h)
STATE_NORMAL, STATE_EVICTED, STATE_DOOMED = 0, 1, 2
STATE_NAMES = {
    STATE_NORMAL: QT_TRANSLATE_NOOP("GeneratedView", "normal"),
    STATE_EVICTED: QT_TRANSLATE_NOOP("GeneratedView", "evicted"),
    STATE_DOOMED: QT_TRANSLATE_NOOP("GeneratedView", "doomed"),
}
PARENT_ENTRY = 1
CHILD_ENTRY = 2

# LRU lists (rankings.h)
LIST_NAMES = ("NO_USE", "LOW_USE", "HIGH_USE", "RESERVED", "DELETED")

# sparse_control.cc
SPARSE_INDEX_STREAM = 2
SPARSE_DATA_STREAM = 1
SPARSE_HEADER_SIZE = 64
SPARSE_CHILD_SIZE = 1 << 20
SPARSE_BLOCK = 1024


def super_fast_hash(data: bytes) -> int:
    """base::PersistentHash = Paul Hsieh's SuperFastHash (superfasthash.c),
    the hash Blockfile stores for a key and for its records."""
    length = len(data)
    if length <= 0:
        return 0
    h = length & 0xFFFFFFFF
    rem = length & 3
    i = 0
    for _ in range(length >> 2):
        h = (h + (data[i] | (data[i + 1] << 8))) & 0xFFFFFFFF
        tmp = (((data[i + 2] | (data[i + 3] << 8)) << 11) ^ h) & 0xFFFFFFFF
        h = ((h << 16) ^ tmp) & 0xFFFFFFFF
        i += 4
        h = (h + (h >> 11)) & 0xFFFFFFFF

    def signed(b: int) -> int:  # (signed char)
        return b - 256 if b > 127 else b

    if rem == 3:
        h = (h + (data[i] | (data[i + 1] << 8))) & 0xFFFFFFFF
        h ^= (h << 16) & 0xFFFFFFFF
        h ^= (signed(data[i + 2]) << 18) & 0xFFFFFFFF
        h = (h + (h >> 11)) & 0xFFFFFFFF
    elif rem == 2:
        h = (h + (data[i] | (data[i + 1] << 8))) & 0xFFFFFFFF
        h ^= (h << 11) & 0xFFFFFFFF
        h = (h + (h >> 17)) & 0xFFFFFFFF
    elif rem == 1:
        h = (h + signed(data[i])) & 0xFFFFFFFF
        h ^= (h << 10) & 0xFFFFFFFF
        h = (h + (h >> 1)) & 0xFFFFFFFF
    h ^= (h << 3) & 0xFFFFFFFF
    h = (h + (h >> 5)) & 0xFFFFFFFF
    h ^= (h << 4) & 0xFFFFFFFF
    h = (h + (h >> 17)) & 0xFFFFFFFF
    h ^= (h << 25) & 0xFFFFFFFF
    h = (h + (h >> 6)) & 0xFFFFFFFF
    return h


@dataclass(frozen=True)
class Addr:
    """CacheAddr (addr.h)."""

    value: int

    @property
    def initialized(self) -> bool:
        return bool(self.value & 0x80000000)

    @property
    def file_type(self) -> int:
        return (self.value & 0x70000000) >> 28

    @property
    def separate_file(self) -> bool:
        return self.file_type == EXTERNAL

    @property
    def file_number(self) -> int:
        if self.separate_file:
            return self.value & 0x0FFFFFFF
        return (self.value & 0x00FF0000) >> 16

    @property
    def start_block(self) -> int:
        return self.value & 0xFFFF

    @property
    def num_blocks(self) -> int:
        return ((self.value & 0x03000000) >> 24) + 1

    @property
    def reserved_bits(self) -> int:
        return self.value & 0x0C000000

    @property
    def block_size(self) -> int:
        return _BLOCK_SIZES.get(self.file_type, 0)

    def sane(self) -> bool:
        """Addr::SanityCheck."""
        if not self.initialized:
            return self.value == 0
        if self.file_type > BLOCK_4K:
            return False
        return self.separate_file or not self.reserved_bits

    def file_name(self) -> str:
        """The file the address points into (BackendImpl::GetFileName /
        BlockFiles: data_<n>, f_<6 hex digits>)."""
        if self.separate_file:
            return f"f_{self.file_number:06x}"
        return f"data_{self.file_number}"

    def offset(self) -> int:
        """Where the record starts in its block file."""
        return BLOCK_HEADER_SIZE + self.start_block * self.block_size

    def text(self) -> str:
        if not self.value:
            return "0"
        if not self.initialized:
            return f"0x{self.value:08x} (not initialized)"
        if self.separate_file:
            return f"0x{self.value:08x} ({self.file_name()})"
        return (
            f"0x{self.value:08x} ({self.file_name()}, block {self.start_block}, "
            f"{self.num_blocks} × {self.block_size} B)"
        )


@dataclass
class IndexFile:
    magic: int = 0
    version: int = 0
    num_entries: int = 0
    last_file: int = 0
    this_id: int = 0
    stats: int = 0
    table_len: int = 0
    crash: int = 0
    experiment: int = 0
    create_time: int = 0
    num_bytes: int = 0
    corruption_detected: int = 0
    lru_filled: int = 0
    lru_sizes: list[int] = field(default_factory=list)
    lru_heads: list[int] = field(default_factory=list)
    lru_tails: list[int] = field(default_factory=list)
    table: list[int] = field(default_factory=list)
    notes: list[ParseIssue] = field(default_factory=list)
    tree: Tree = field(default_factory=Tree)


def read_index(data: bytes) -> IndexFile:
    out = IndexFile()
    t = out.tree
    if len(data) < INDEX_HEADER_SIZE:
        out.notes.append(ParseIssue("chromium_cache.file_too_short", {"size": len(data)}))
        return out
    (out.magic, out.version, out.num_entries, _old, out.last_file, out.this_id, out.stats,
     out.table_len, out.crash, out.experiment, out.create_time, out.num_bytes,
     out.corruption_detected) = struct.unpack_from("<IIiiiiIiiiQqi", data)
    lru = struct.unpack_from("<2ii5i5I5IIii7i", data, 256)
    out.lru_filled = lru[2]
    out.lru_sizes = list(lru[3:8])
    out.lru_heads = list(lru[8:13])
    out.lru_tails = list(lru[13:18])
    fields = (
        ("Magic", f"0x{out.magic:08x}", 0, 4),
        ("Version", f"{VERSIONS.get(out.version, '?')} (0x{out.version:x})", 4, 8),
        ("Entries", out.num_entries, 8, 12),
        ("Last external file", out.last_file, 16, 20),
        ("Current id (dirty marker)", out.this_id, 20, 24),
        ("Stats address", Addr(out.stats).text(), 24, 28),
        ("Table length", out.table_len, 28, 32),
        ("Crash flag", out.crash, 32, 36),
        ("Experiment", out.experiment, 36, 40),
        ("Created", chrome_time(out.create_time), 40, 48),
        ("Stored data size", out.num_bytes, 48, 56),
        ("Corruption detected", out.corruption_detected, 56, 60),
    )
    for label, value, s, e in fields:
        t.put((label,), value, s, e)
    t.put(("LRU", "Filled"), out.lru_filled, 264, 268)
    for i, name in enumerate(LIST_NAMES):
        t.put(("LRU", name, "Size"), out.lru_sizes[i], 268 + 4 * i, 272 + 4 * i)
        t.put(("LRU", name, "Head"), Addr(out.lru_heads[i]).text(), 288 + 4 * i, 292 + 4 * i)
        t.put(("LRU", name, "Tail"), Addr(out.lru_tails[i]).text(), 308 + 4 * i, 312 + 4 * i)
    t.mark(("LRU",), 256, INDEX_HEADER_SIZE)
    if out.version not in VERSIONS:
        out.notes.append(ParseIssue("chromium_cache.blockfile_version", {"version": f"0x{out.version:x}"}))
    length = out.table_len or INDEX_TABLE_SIZE
    available = (len(data) - INDEX_HEADER_SIZE) // 4
    if available < length:
        out.notes.append(ParseIssue(
            "chromium_cache.index_table_short", {"length": length, "available": available}
        ))
        length = available
    out.table = list(struct.unpack_from(f"<{length}I", data, INDEX_HEADER_SIZE))
    t.put(("Hash table",), f"{sum(1 for a in out.table if a):,} of {length:,} buckets used",
          INDEX_HEADER_SIZE, INDEX_HEADER_SIZE + 4 * length)
    for i, note in enumerate(out.notes):
        t.put((f"Note {i + 1}",), note)
    return out


@dataclass
class BlockFile:
    name: str
    data: bytes
    magic: int = 0
    version: int = 0
    this_file: int = 0
    next_file: int = 0
    entry_size: int = 0
    num_entries: int = 0
    max_entries: int = 0
    bitmap: bytes = b""
    notes: list[ParseIssue] = field(default_factory=list)

    def allocated(self, block: int) -> bool:
        word = block // 32
        if word * 4 + 4 > len(self.bitmap):
            return False
        value = struct.unpack_from("<I", self.bitmap, word * 4)[0]
        return bool(value & (1 << (block % 32)))

    def tree(self) -> Tree:
        t = Tree()
        for label, value, s, e in (
            ("Magic", f"0x{self.magic:08x}", 0, 4),
            ("Version", f"0x{self.version:x}", 4, 8),
            ("This file", self.this_file, 8, 10),
            ("Next file", self.next_file, 10, 12),
            ("Block size", self.entry_size, 12, 16),
            ("Blocks in use", self.num_entries, 16, 20),
            ("Blocks available", self.max_entries, 20, 24),
        ):
            t.put((label,), value, s, e)
        t.put(("Allocation bitmap",), f"{len(self.bitmap):,} B", 80, BLOCK_HEADER_SIZE)
        t.put(("Blocks",), f"{max(0, (len(self.data) - BLOCK_HEADER_SIZE) // max(self.entry_size, 1)):,}",
              BLOCK_HEADER_SIZE, len(self.data))
        for i, note in enumerate(self.notes):
            t.put((f"Note {i + 1}",), note)
        return t


def read_block_file(name: str, data: bytes) -> BlockFile:
    out = BlockFile(name, data)
    if len(data) < BLOCK_HEADER_SIZE:
        out.notes.append(ParseIssue("chromium_cache.file_too_short", {"size": len(data)}))
        return out
    (out.magic, out.version, out.this_file, out.next_file, out.entry_size,
     out.num_entries, out.max_entries) = struct.unpack_from("<IIhhiii", data)
    out.bitmap = data[80:BLOCK_HEADER_SIZE]
    expected = name.removeprefix("data_")
    if expected.isdigit() and int(expected) != out.this_file:
        out.notes.append(ParseIssue(
            "chromium_cache.block_file_number", {"stored": out.this_file, "name": name}
        ))
    return out


@dataclass
class Rankings:
    addr: Addr
    last_used: int
    last_modified: int
    next: int
    prev: int
    contents: int
    dirty: int
    self_hash: int
    self_hash_ok: bool


@dataclass
class EntryStore:
    addr: Addr
    raw: bytes
    hash: int
    next: int
    rankings_node: int
    reuse_count: int
    refetch_count: int
    state: int
    creation_time: int
    key_len: int
    long_key: int
    data_size: list[int]
    data_addr: list[int]
    flags: int
    self_hash: int
    self_hash_ok: bool
    key: bytes = b""
    key_location: tuple[str, int, int] | None = None
    key_hash_ok: bool | None = None
    notes: list[ParseIssue] = field(default_factory=list)


class Cache:
    """A Blockfile cache: the index and its files by name, read through
    *read_file* (name -> bytes, or None when the file isn't there)."""

    def __init__(self, index_data: bytes, read_file: Callable[[str], bytes | None]) -> None:
        self.index = read_index(index_data)
        self._read_file = read_file
        self._block_files: dict[str, BlockFile | None] = {}
        self.missing: set[str] = set()

    def block_file(self, number: int) -> BlockFile | None:
        name = f"data_{number}"
        if name not in self._block_files:
            raw = self._read_file(name)
            if raw is None:
                self.missing.add(name)
                self._block_files[name] = None
            else:
                self._block_files[name] = read_block_file(name, raw)
        return self._block_files[name]

    def block_files(self) -> list[BlockFile]:
        return [bf for bf in self._block_files.values() if bf is not None]

    def file_bytes(self, name: str) -> bytes | None:
        """A file of the cache by name: a block file's kept bytes, else read."""
        if name.startswith("data_") and name[5:].isdigit():
            bf = self.block_file(int(name[5:]))
            return bf.data if bf is not None else None
        return self._read_file(name)

    def read(self, addr: Addr, length: int) -> tuple[bytes | None, tuple[str, int, int] | None, ParseIssue | None]:
        """*length* bytes at *addr*: (data, (file, start, end), why not)."""
        if not addr.initialized:
            return None, None, ParseIssue("chromium_cache.addr_not_initialized")
        if not addr.sane():
            return None, None, ParseIssue("chromium_cache.addr_invalid", {"addr": f"0x{addr.value:08x}"})
        if addr.separate_file:
            name = addr.file_name()
            raw = self._read_file(name)
            if raw is None:
                self.missing.add(name)
                return None, None, ParseIssue("chromium_cache.file_missing", {"name": name})
            return raw[:length], (name, 0, min(length, len(raw))), (
                None if len(raw) >= length else
                ParseIssue("chromium_cache.data_short", {"size": len(raw), "expected": length})
            )
        bf = self.block_file(addr.file_number)
        if bf is None:
            return None, None, ParseIssue("chromium_cache.file_missing", {"name": addr.file_name()})
        start = addr.offset()
        capacity = addr.num_blocks * addr.block_size
        end = start + min(length, capacity)
        raw = bf.data[start:end]
        note = None
        if length > capacity:
            note = ParseIssue("chromium_cache.data_exceeds_blocks", {"size": length, "capacity": capacity})
        elif len(raw) < end - start:
            note = ParseIssue("chromium_cache.data_short", {"size": len(raw), "expected": end - start})
        return raw, (bf.name, start, start + len(raw)), note

    def rankings(self, value: int) -> Rankings | None:
        addr = Addr(value)
        if not addr.initialized or addr.file_type != RANKINGS:
            return None
        raw, _loc, _note = self.read(addr, RANKINGS_SIZE)
        if raw is None or len(raw) < RANKINGS_SIZE:
            return None
        last_used, modified, nxt, prev, contents, dirty, self_hash = struct.unpack("<QQIIIiI", raw)
        return Rankings(
            addr, last_used, modified, nxt, prev, contents, dirty, self_hash,
            self_hash == 0 or self_hash == super_fast_hash(raw[:32]),
        )

    def entry_at(self, value: int) -> EntryStore | None:
        addr = Addr(value)
        if not addr.initialized or addr.separate_file or addr.file_type != BLOCK_256:
            return None
        raw, _loc, _note = self.read(addr, addr.num_blocks * ENTRY_SIZE)
        if raw is None or len(raw) < ENTRY_SIZE:
            return None
        return self._entry(addr, raw)

    def _entry(self, addr: Addr, raw: bytes) -> EntryStore:
        (h, nxt, rank, reuse, refetch, state, created, key_len, long_key) = struct.unpack_from(
            "<IIIiiiQiI", raw
        )
        sizes = list(struct.unpack_from("<4i", raw, 40))
        addrs = list(struct.unpack_from("<4I", raw, 56))
        flags, = struct.unpack_from("<I", raw, 72)
        self_hash, = struct.unpack_from("<I", raw, 92)
        e = EntryStore(
            addr, raw, h, nxt, rank, reuse, refetch, state, created, key_len, long_key,
            sizes, addrs, flags, self_hash,
            # EntryImpl::SanityCheck skips the check when no hash was stored.
            self_hash == 0 or self_hash == super_fast_hash(raw[:92]),
        )
        if not e.self_hash_ok:
            e.notes.append(ParseIssue("chromium_cache.entry_self_hash"))
        if key_len <= 0:
            e.notes.append(ParseIssue("chromium_cache.key_length_invalid", {"length": key_len}))
            return e
        key_addr = Addr(long_key)
        if key_len <= MAX_INTERNAL_KEY and not key_addr.initialized:
            span = len(raw) - KEY_OFFSET
            key = raw[KEY_OFFSET:KEY_OFFSET + min(key_len, span)]
            e.key = key
            loc = self._location(addr)
            if loc is not None:
                e.key_location = (loc[0], loc[1] + KEY_OFFSET, loc[1] + KEY_OFFSET + len(key))
            if key_len > span:
                e.notes.append(ParseIssue("chromium_cache.key_past_blocks", {"length": key_len, "span": span}))
        else:
            data, loc, note = self.read(key_addr, key_len)
            if data is None:
                e.notes.append(note or ParseIssue("chromium_cache.key_unreadable"))
            else:
                e.key = data
                e.key_location = loc
                if note is not None:
                    e.notes.append(note)
        if e.key:
            e.key_hash_ok = super_fast_hash(e.key) == h
            if not e.key_hash_ok:
                e.notes.append(ParseIssue("chromium_cache.key_hash_mismatch"))
        if state not in STATE_NAMES:
            e.notes.append(ParseIssue("chromium_cache.state_invalid", {"state": state}))
        return e

    def _location(self, addr: Addr) -> tuple[str, int, int] | None:
        if addr.separate_file:
            return None
        start = addr.offset()
        return addr.file_name(), start, start + addr.num_blocks * addr.block_size

    def walk(self) -> tuple[list[tuple[EntryStore, str]], list[ParseIssue]]:
        """Every entry the index reaches: through the hash table and the
        `next` chains, then through the five LRU lists (an entry only on a
        list, e.g. doomed, isn't in the table). Each entry once, with how it
        was reached; a loop or a bad address ends that chain, said so."""
        found: dict[int, tuple[EntryStore, str]] = {}
        notes: list[ParseIssue] = []
        for bucket, value in enumerate(self.index.table):
            seen: set[int] = set()
            while value:
                if value in seen:
                    notes.append(ParseIssue("chromium_cache.chain_loop", {"bucket": bucket}))
                    break
                seen.add(value)
                if value in found:
                    break
                entry = self.entry_at(value)
                if entry is None:
                    notes.append(ParseIssue(
                        "chromium_cache.chain_bad_addr", {"bucket": bucket, "addr": f"0x{value:08x}"}
                    ))
                    break
                found[value] = (entry, QT_TRANSLATE_NOOP("GeneratedView", "hash table"))
                value = entry.next
        for i, head in enumerate(self.index.lru_heads):
            value = head
            seen = set()
            while value:
                if value in seen:
                    notes.append(ParseIssue("chromium_cache.list_loop", {"list": LIST_NAMES[i]}))
                    break
                seen.add(value)
                node = self.rankings(value)
                if node is None:
                    notes.append(ParseIssue(
                        "chromium_cache.list_bad_addr", {"list": LIST_NAMES[i], "addr": f"0x{value:08x}"}
                    ))
                    break
                if node.contents and node.contents not in found:
                    entry = self.entry_at(node.contents)
                    if entry is not None:
                        found[node.contents] = (entry, f"LRU list {LIST_NAMES[i]}")
                # A list's tail points to itself (Rankings::Insert).
                value = 0 if node.next == value else node.next
        return list(found.values()), notes

    def entry_tree(self, e: EntryStore) -> Tree:
        """The EntryStore's fields with their ranges in its block file."""
        t = Tree()
        loc = self._location(e.addr)
        base = loc[1] if loc else 0
        fields = (
            ("Key hash", f"0x{e.hash:08x}", 0, 4),
            ("Next entry", Addr(e.next).text(), 4, 8),
            ("Rankings node", Addr(e.rankings_node).text(), 8, 12),
            ("Reuse count", e.reuse_count, 12, 16),
            ("Refetch count", e.refetch_count, 16, 20),
            ("State", f"{STATE_NAMES.get(e.state, '?')} ({e.state})", 20, 24),
            ("Created", chrome_time(e.creation_time), 24, 32),
            ("Key length", e.key_len, 32, 36),
            ("Long key address", Addr(e.long_key).text(), 36, 40),
        )
        for label, value, s, en in fields:
            t.put((label,), value, base + s, base + en)
        for i in range(4):
            t.put(("Streams", str(i), "Size"), e.data_size[i], base + 40 + 4 * i, base + 44 + 4 * i)
            t.put(("Streams", str(i), "Address"), Addr(e.data_addr[i]).text(), base + 56 + 4 * i, base + 60 + 4 * i)
        flag_names = [n for bit, n in ((PARENT_ENTRY, "PARENT_ENTRY"), (CHILD_ENTRY, "CHILD_ENTRY")) if e.flags & bit]
        t.put(("Flags",), f"0x{e.flags:x} ({', '.join(flag_names) or '-'})", base + 72, base + 76)
        t.put(("Self hash",), f"0x{e.self_hash:08x}", base + 92, base + 96)
        t.put(("Self hash check",), (
            QT_TRANSLATE_NOOP("GeneratedView", "not stored") if not e.self_hash else
            QT_TRANSLATE_NOOP("GeneratedView", "matches") if e.self_hash_ok else
            ParseIssue("chromium_cache.entry_self_hash")
        ))
        if e.key_location and e.key_location[0] == (loc[0] if loc else ""):
            t.put(("Key",), e.key.decode("utf-8", errors="backslashreplace"), e.key_location[1], e.key_location[2])
        elif e.key:
            t.put(("Key",), e.key.decode("utf-8", errors="backslashreplace"))
        for i, note in enumerate(e.notes):
            t.put((f"Note {i + 1}",), note)
        return t

    def carve(self, known: set[int]) -> list[dict[str, Any]]:
        """Heuristic: EntryStore records in blocks the allocation bitmap of a
        256-byte block file marks free. A candidate is a block whose key
        length is positive and whose stored key hash is the SuperFastHash of
        the key -- read in the record, or for a key stored outside it, at
        the record's long key address. A record whose long key address is
        valid but can't be read is listed too, marked weak (its hash isn't
        checked). Every candidate is listed, with what else holds (self
        hash, rankings node pointing back)."""
        out: list[dict[str, Any]] = []
        for bf in self.block_files():
            if bf.entry_size != ENTRY_SIZE:
                continue
            blocks = (len(bf.data) - BLOCK_HEADER_SIZE) // ENTRY_SIZE
            for block in range(blocks):
                if bf.allocated(block):
                    continue
                start = BLOCK_HEADER_SIZE + block * ENTRY_SIZE
                key_len = struct.unpack_from("<i", bf.data, start + 32)[0]
                long_key = struct.unpack_from("<I", bf.data, start + 36)[0]
                if key_len <= 0:
                    continue
                stored_hash = struct.unpack_from("<I", bf.data, start)[0]
                if long_key:
                    # Key outside the record (EntryImpl::CreateEntry: a key
                    # longer than the record holds): the record is one block.
                    key_addr = Addr(long_key)
                    if not key_addr.initialized or not key_addr.sane():
                        continue
                    n_blocks = 1
                    raw = bf.data[start:start + ENTRY_SIZE]
                    key, _loc, why = self.read(key_addr, key_len)
                    if key is not None and len(key) == key_len:
                        if super_fast_hash(key) != stored_hash:
                            continue
                        first = ParseIssue("chromium_cache.carved_long_key", {
                            "file": bf.name, "block": block, "addr": key_addr.text(),
                        })
                    else:
                        first = ParseIssue("chromium_cache.carved_long_key_unread", {
                            "file": bf.name, "block": block, "addr": key_addr.text(),
                            "reason": why or ParseIssue("chromium_cache.key_unreadable"),
                        })
                else:
                    if key_len > MAX_INTERNAL_KEY:
                        continue
                    # The record and up to three following blocks (a long
                    # inline key), as far as the file goes.
                    n_blocks = min(4, (KEY_OFFSET + key_len + 1 + ENTRY_SIZE - 1) // ENTRY_SIZE)
                    raw = bf.data[start:start + n_blocks * ENTRY_SIZE]
                    if len(raw) < KEY_OFFSET + key_len:
                        continue
                    if super_fast_hash(raw[KEY_OFFSET:KEY_OFFSET + key_len]) != stored_hash:
                        continue
                    first = ParseIssue("chromium_cache.carved_key_hash", {"file": bf.name, "block": block})
                addr_value = 0x80000000 | (BLOCK_256 << 28) | ((n_blocks - 1) << 24) | (bf.this_file << 16) | block
                entry = self._entry(Addr(addr_value), raw)
                node = self.rankings(entry.rankings_node)
                back = Addr(node.contents) if node is not None else None
                points_back = back is not None and back.initialized and back.file_type == BLOCK_256 and (
                    back.file_number == bf.this_file and back.start_block == block
                )
                reasons = [
                    first,
                    ParseIssue("chromium_cache.carved_self_hash_ok" if entry.self_hash_ok
                               else "chromium_cache.carved_self_hash_bad"),
                    ParseIssue("chromium_cache.carved_rankings_back" if points_back
                               else "chromium_cache.carved_rankings_not_back"),
                ]
                if addr_value in known:
                    reasons.append(ParseIssue("chromium_cache.carved_also_listed"))
                out.append({
                    "entry": entry,
                    "file": bf.name,
                    "block": block,
                    "offset": start,
                    "rankings": node if points_back else None,
                    "reason": join_notes(reasons),
                })
        return out
