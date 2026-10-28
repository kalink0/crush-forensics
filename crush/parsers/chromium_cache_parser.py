# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Chromium Disk Cache parser: Simple and Blockfile caches -- browser HTTP
caches, app WebView caches, Cronet, Service Worker CacheStorage and script
caches, Code Cache, GPU/shader caches.

A cache is recognised by its files' bytes: a directory holding a file with
the Simple initial magic, the Simple index magic or the Blockfile index
magic opens as a cache; a Simple entry or index file opened on its own is
read on its own. File names are never used to tell formats apart.

How stream 0 is read follows from what the entry shows: the key's grammar
(HTTP cache, Code Cache) or the CacheStorage index (index.txt) naming the
cache's directory. Where neither does, the readings that are valid are shown
as heuristic readings, each marked.

Bodies and entry details are read when an entry is selected
(ChromiumCacheStore), not while parsing.
"""
from __future__ import annotations

import hashlib
import logging
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue
from crush.core.vfs import VFS, VFSNode, find_node, join_notes
from crush.parsers import chromium_blockfile as bfmt
from crush.parsers import chromium_simple as sfmt
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.chromium_cache_content import (
    KIND_CACHE_STORAGE,
    KIND_CODE,
    KIND_CODE_DATA,
    KIND_HTTP,
    KIND_UNDETERMINED,
    KIND_URL_KEY,
    KeyParts,
    cache_metadata_view,
    content_codings,
    decode_body,
    decode_code_header,
    decode_proto,
    is_sha_key,
    sha_key_matches,
    split_key,
    with_times,
)
from crush.parsers.chromium_pickle import (
    ResponseInfo,
    Tree,
    chrome_time,
    chrome_time_utc,
    decode_response_info,
    strictly_valid,
)

_logger = logging.getLogger(__name__)

FORMAT_SIMPLE = "Simple"
FORMAT_BLOCKFILE = "Blockfile"

STATE_NORMAL = bfmt.STATE_NAMES[bfmt.STATE_NORMAL]
STATE_EVICTED = bfmt.STATE_NAMES[bfmt.STATE_EVICTED]
STATE_DOOMED = bfmt.STATE_NAMES[bfmt.STATE_DOOMED]

# How the index's first record field is read (see _index_reading).
READ_TIME = "time"
READ_PREFETCH = "prefetch"
READ_BOTH = "both"

# simple_util.cc: a doomed entry's files are renamed todelete_<hash>_<n>_<gen>.
_TODELETE_RE = re.compile(r"^todelete_([0-9a-f]{16})_([01s])_(\d+)$")
# CacheStorage's index of a storage key's caches (cache_storage.cc kIndexFileName).
_CACHE_STORAGE_INDEX = "index.txt"

_BODY_NOTE_CODE = ParseIssue("chromium_cache.body_v8_not_decoded")
_BODY_NOTE_UNDETERMINED = ParseIssue("chromium_cache.content_kind_undetermined")
_NOTE_URL_KEY_NO_READING = ParseIssue("chromium_cache.url_key_no_reading")


def _key_basis(key: KeyParts) -> str:
    """Why an entry has the kind its key gives ("" for none)."""
    if key.kind == KIND_UNDETERMINED:
        return ""
    if key.kind == KIND_URL_KEY:
        return QT_TRANSLATE_NOOP("GeneratedView", "the key is a URL alone (heuristic)")
    return key.basis or QT_TRANSLATE_NOOP("GeneratedView", "key grammar")


def _peek(vfs: VFS, node: VFSNode, n: int = 16) -> bytes:
    """The file's first bytes: those the source already holds (e.g. read
    by the background type scan), else read now."""
    try:
        cached = vfs.peek_if_cached(node, n)
        return cached if cached is not None else vfs.peek(node, n)
    except Exception:  # noqa: BLE001 -- unreadable: not counted as a cache file
        return b""


def _is_blockfile_index(head: bytes) -> bool:
    return len(head) >= 4 and int.from_bytes(head[:4], "little") == bfmt.INDEX_MAGIC


def _is_block_file(head: bytes) -> bool:
    return len(head) >= 4 and int.from_bytes(head[:4], "little") == bfmt.BLOCK_MAGIC


def _hint_order(node: VFSNode) -> int:
    """Files likely to carry a magic first -- an order only; every file
    is still looked at by its bytes."""
    name = node.name
    if name in ("index", "the-real-index"):
        return 0
    if name.endswith(("_0", "_1", "_s")):
        return 1
    return 2


class ChromiumCacheParser(AbstractParser):
    SUPPORTED_EXTENSIONS: list[str] = []
    DISPLAY_NAME = "Chromium Disk Cache"
    PARSE_OFF_UI_THREAD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return sfmt.has_initial_magic(peek_bytes) or sfmt.has_index_magic(peek_bytes)

    def can_parse_dir(self, node: VFSNode, vfs: VFS | None = None) -> bool:
        if vfs is None:
            return False
        files = sorted((c for c in node.children if not c.is_dir), key=_hint_order)
        for child in files:
            if child.size < 8:
                continue
            head = _peek(vfs, child)
            if sfmt.has_initial_magic(head) or sfmt.has_index_magic(head) or _is_blockfile_index(head):
                return True
        # A Simple cache whose entries are all gone keeps its index in index-dir.
        for sub in (c for c in node.children if c.is_dir):
            for child in sub.children:
                if not child.is_dir and child.size >= 16 and sfmt.has_index_magic(_peek(vfs, child)):
                    return True
        return False

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        if node.is_dir:
            return _DirectoryParse(node, vfs).run()
        return _parse_single_file(node, vfs)


# -- Entries ------------------------------------------------------------------------


@dataclass
class _Entry:
    """An entry as parsed: what the table shows and where its parts are."""

    id: int
    backend: str
    key: KeyParts
    state: str = STATE_NORMAL
    kind: str = KIND_UNDETERMINED
    kind_basis: str = ""
    # Simple: role -> (node, layout)
    simple_files: dict[str, tuple[VFSNode, sfmt.SimpleFile]] = field(default_factory=dict)
    simple_hash: int | None = None
    index_record: sfmt.IndexRecord | None = None
    # Blockfile
    store: bfmt.EntryStore | None = None
    rankings: bfmt.Rankings | None = None
    reached_via: str = ""
    # Stream 0, as read when parsing
    response: ResponseInfo | None = None
    readings: list[str] = field(default_factory=list)
    metadata_view: Any = None
    code_header: Any = None
    notes: list[ParseIssue] = field(default_factory=list)
    row: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Stream:
    """A stream's bytes and where they are: *file* from offset *start*."""

    data: bytes
    file: str
    start: int

    @property
    def where(self) -> str:
        return f"{self.file} 0x{self.start:x}–0x{self.start + len(self.data):x}"


def _headers_value(headers: list[tuple[str, str]], name: str) -> str:
    lower = name.lower()
    return next((v for k, v in headers if k.lower() == lower), "")


def _server(response: ResponseInfo | None) -> str:
    if response is None or not response.socket_host:
        return ""
    host = response.socket_host
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{response.socket_port}" if response.socket_port is not None else host


# -- Directory --------------------------------------------------------------------


class _DirectoryParse:
    def __init__(self, node: VFSNode, vfs: VFS) -> None:
        self.node = node
        self.vfs = vfs
        self.entries: list[_Entry] = []
        self.orphans: list[dict[str, Any]] = []
        self.read_problems: dict[str, ParseIssue] = {}
        self.file_roles: dict[str, Any] = {}
        self.status: list[ParseIssue] = []
        self.overview: dict[str, Any] = {}
        self.formats: list[str] = []
        self.cs_context: dict[str, Any] | None = None
        self.cs_note: ParseIssue | None = None
        self.index_reading = READ_BOTH
        self.real_index: sfmt.RealIndex | None = None
        self.real_index_node: VFSNode | None = None
        self.index_unchecked = False
        self.blockfile: bfmt.Cache | None = None
        self.carved: list[dict[str, Any]] = []
        self.versions: set[str] = set()
        # Read once by _scan: each Simple file's layout and stream 0.
        self._layouts: dict[str, sfmt.SimpleFile] = {}
        self._stream0: dict[str, bytes] = {}

    # -- reading files ----------------------------------------------------------

    def _read(self, node: VFSNode) -> bytes | None:
        try:
            return self.vfs.read(node)
        except Exception as exc:  # noqa: BLE001 -- listed with the reason
            _logger.debug("Could not read %s: %s", node.path, exc)
            self.read_problems[node.name] = ParseIssue("chromium_cache.file_unreadable", detail=str(exc))
            return None

    def _scan(self, node: VFSNode) -> bytes:
        """The file's first bytes; for a Simple file also its layout and
        stream 0, read through the same open (a file in an archive is
        decompressed once, not once per part)."""
        try:
            with self.vfs.open(node) as fh:
                head = fh.read(16)
                if not sfmt.has_initial_magic(head):
                    return head
                ra = sfmt.RandomAccess(fh, node.size)
                layout = sfmt.read_simple_file(ra)
                self._layouts[node.name] = layout
                rng = layout.streams.get(0)
                if rng is not None:
                    self._stream0[node.name] = ra.read_at(rng[0], rng[1] - rng[0])
                return head
        except Exception as exc:  # noqa: BLE001 -- listed with the reason
            _logger.debug("Could not read %s: %s", node.path, exc)
            self.read_problems[node.name] = ParseIssue("chromium_cache.file_unreadable", detail=str(exc))
            return b""

    def run(self) -> ParseResult:
        files = [c for c in self.node.children if not c.is_dir]
        heads = {c.name: self._scan(c) for c in files}
        simple_nodes = [c for c in files if sfmt.has_initial_magic(heads[c.name])]
        index_nodes = [c for c in files if sfmt.has_index_magic(heads[c.name])]
        for sub in (c for c in self.node.children if c.is_dir):
            for child in sub.children:
                if not child.is_dir and sfmt.has_index_magic(_peek(self.vfs, child)):
                    index_nodes.append(child)
        blockfile_indexes = [c for c in files if _is_blockfile_index(heads[c.name])]

        if simple_nodes or index_nodes:
            self.formats.append(FORMAT_SIMPLE)
            self._simple(simple_nodes, index_nodes)
        if blockfile_indexes:
            self.formats.append(FORMAT_BLOCKFILE)
            self._blockfile(blockfile_indexes, files, heads)
        if len(self.formats) > 1:
            self.status.append(ParseIssue("chromium_cache.both_formats"))
        for c in files:
            self.file_roles.setdefault(c.name, {
                "Role": ParseIssue("chromium_cache.file_not_recognised"), "Size": f"{c.size:,} B",
            })
        for sub in (c for c in self.node.children if c.is_dir):
            for child in sub.children:
                self.file_roles.setdefault(f"{sub.name}/{child.name}", {
                    "Role": ParseIssue("chromium_cache.file_not_recognised"),
                    "Size": f"{child.size:,} B" if not child.is_dir else "",
                })
        return self._result()

    # -- Simple -------------------------------------------------------------------

    def _simple(self, simple_nodes: list[VFSNode], index_nodes: list[VFSNode]) -> None:
        layouts: list[tuple[VFSNode, sfmt.SimpleFile]] = []
        for n in simple_nodes:
            layout = self._layouts.get(n.name)
            if layout is None:
                continue
            layouts.append((n, layout))
            self.file_roles[n.name] = {"Role": layout.role, "Size": f"{n.size:,} B"}
            if layout.role == sfmt.ROLE_FAKE_INDEX:
                self.versions.add(f"backend marker version {layout.version}")
                self.overview.setdefault("Backend marker (fake index)", {}).update({n.name: layout.fake})
        for n in index_nodes:
            data = self._read(n)
            if data is None:
                continue
            path = n.path.replace("\\", "/")
            rel = path[len(self.node.path.replace("\\", "/").rstrip("/")) + 1:]
            self.file_roles[rel] = {"Role": sfmt.ROLE_REAL_INDEX, "Size": f"{n.size:,} B"}
            if self.real_index is None:
                self.real_index = sfmt.read_real_index(data)
                self.real_index_node = n
                self.versions.add(f"index version {self.real_index.version}")
                # Chromium keeps the index in index-dir below the entry
                # files; one in the opened folder itself (index-dir opened
                # on its own) has no entry files beside it to check.
                self.index_unchecked = "/" not in rel
                rejected = [str(i) for i, r in enumerate(self.real_index.records) if r.size_rejected]
                if rejected:
                    self.status.append(ParseIssue(
                        "chromium_cache.index_entry_size_rejected", {"records": ", ".join(rejected)}
                    ))
            else:
                self.status.append(ParseIssue("chromium_cache.second_index", {"name": rel}))
        if self.index_unchecked:
            self.status.append(ParseIssue("chromium_cache.index_in_opened_folder"))

        self.cs_context, self.cs_note = _cache_storage_context(self.node, self.vfs)

        # Entries by the hash of their key (the content), doomed copies apart.
        groups: dict[tuple[int, str], _Entry] = {}
        for n, layout in layouts:
            if layout.role == sfmt.ROLE_FAKE_INDEX:
                continue
            if layout.unreadable is not None and not layout.key:
                self.read_problems[n.name] = layout.unreadable
                continue
            h = sfmt.entry_hash(layout.key)
            doomed = _TODELETE_RE.match(n.name)
            generation = doomed.group(3) if doomed else ""
            entry = groups.get((h, generation))
            if entry is None:
                entry = groups[(h, generation)] = _Entry(
                    id=len(self.entries), backend=FORMAT_SIMPLE, key=split_key(layout.key), simple_hash=h,
                )
                self.entries.append(entry)
                if doomed:
                    entry.state = STATE_DOOMED
                    entry.notes.append(ParseIssue("chromium_cache.doomed_simple_file"))
            if layout.role in entry.simple_files:
                entry.notes.append(ParseIssue("chromium_cache.duplicate_role", {"name": n.name}))
                continue
            entry.simple_files[layout.role] = (n, layout)
            if layout.version:
                self.versions.add(
                    f"sparse file version {layout.version}" if layout.role == sfmt.ROLE_SPARSE
                    else f"entry version {layout.version}"
                )
            if layout.unreadable is not None:
                entry.notes.append(layout.unreadable)
            entry.notes.extend(layout.notes)
            name_hash = n.name[:16]
            if not doomed and re.fullmatch(r"[0-9a-f]{16}_[01s]", n.name) and int(name_hash, 16) != h:
                entry.notes.append(ParseIssue("chromium_cache.name_hash_mismatch", {"name": n.name}))

        # Records and entries meet by the key hash wherever the index lies;
        # only what a record without an entry means depends on it.
        records = {r.hash: r for r in self.real_index.records} if self.real_index else {}
        for entry in self.entries:
            if entry.backend != FORMAT_SIMPLE or entry.simple_hash is None:
                continue
            rec = records.get(entry.simple_hash)
            if rec is not None:
                entry.index_record = rec
                if rec.size_rejected:
                    entry.notes.append(ParseIssue("chromium_cache.index_record_size_rejected"))
            elif self.real_index is not None and entry.state != STATE_DOOMED:
                entry.notes.append(ParseIssue("chromium_cache.not_in_index"))
        self._classify_simple()
        on_disk = {e.simple_hash for e in self.entries if e.simple_hash is not None}
        for rec in self.real_index.records if self.real_index else []:
            if rec.hash not in on_disk:
                self.orphans.append(self._orphan_record(rec))

    def _classify_simple(self) -> None:
        if self.cs_context is not None:
            for e in self.entries:
                e.kind = KIND_CACHE_STORAGE
                e.kind_basis = QT_TRANSLATE_NOOP("GeneratedView", "index.txt names this directory")
        else:
            for e in self.entries:
                e.kind = e.key.kind
                e.kind_basis = _key_basis(e.key)
            if any(e.kind == KIND_CODE for e in self.entries):
                for e in self.entries:
                    if e.kind == KIND_UNDETERMINED and is_sha_key(e.key.text):
                        e.kind = KIND_CODE_DATA
                        e.kind_basis = QT_TRANSLATE_NOOP(
                            "GeneratedView", "SHA-256 key in a Code Cache directory"
                        )
        self.index_reading = _index_reading(self.cs_context is not None, [e.kind for e in self.entries])
        for e in self.entries:
            self._read_stream0(e)
            self._fill_row(e)

    def _stream_bytes(self, e: _Entry, stream: int) -> tuple[bytes | None, int]:
        """A stream of a Simple entry, read now, and where it starts in its file."""
        role = sfmt.ROLE_STREAM_2 if stream == 2 else sfmt.ROLE_STREAMS_0_1
        found = e.simple_files.get(role)
        if found is None:
            return None, 0
        node, layout = found
        rng = layout.streams.get(stream)
        if rng is None:
            return None, 0
        if stream == 0 and node.name in self._stream0:
            return self._stream0.pop(node.name), rng[0]
        try:
            with self.vfs.open(node) as fh:
                return sfmt.RandomAccess(fh, node.size).read_at(rng[0], rng[1] - rng[0]), rng[0]
        except Exception as exc:  # noqa: BLE001
            self.read_problems[node.name] = ParseIssue("chromium_cache.file_unreadable", detail=str(exc))
            return None, 0

    def _read_stream0(self, e: _Entry) -> None:
        if e.backend == FORMAT_SIMPLE:
            data, base = self._stream_bytes(e, 0)
        else:
            data, base = _blockfile_stream(self.blockfile, e.store, 0) if e.store else (None, 0)
        if e.kind == KIND_CODE_DATA and e.backend == FORMAT_SIMPLE:
            body, _ = self._stream_bytes(e, 1)
            if body is not None and not sha_key_matches(e.key.text, body):
                e.notes.append(ParseIssue("chromium_cache.sha_key_mismatch"))
        _decode_stream0(e, data, base)


    def _fill_row(self, e: _Entry) -> None:
        last_used: int | None = None
        prefetch: int | None = None
        if e.index_record is not None:
            # Both readings when the cache type isn't known; the row's note
            # says so (as for index records in Orphans).
            if self.index_reading in (READ_TIME, READ_BOTH):
                last_used = e.index_record.first_field
            if self.index_reading in (READ_PREFETCH, READ_BOTH):
                prefetch = e.index_record.first_field
        elif e.rankings is not None:
            last_used = e.rankings.last_used
        e.row = _row(e, last_used, prefetch, self.index_reading if e.index_record else None)

    def _orphan_record(self, rec: sfmt.IndexRecord) -> dict[str, Any]:
        reading = self.index_reading
        row: dict[str, Any] = {
            "id": len(self.orphans),
            "source": _SOURCE_UNCHECKED if self.index_unchecked else QT_TRANSLATE_NOOP(
                "GeneratedView", "index record without entry file"
            ),
            "hash": f"0x{rec.hash:016x}",
            "size": rec.size,
            "offset": rec.offset,
            "key": "", "url": "", "state": "",
            "last_used": None, "last_used_text": "",
            "prefetch": None,
            "note": "",
        }
        if reading == READ_TIME:
            row["last_used"] = rec.first_field
            row["last_used_text"] = chrome_time_utc(rec.first_field)
        elif reading == READ_PREFETCH:
            row["prefetch"] = rec.first_field
        else:
            row["last_used_text"] = chrome_time_utc(rec.first_field)
            row["last_used"] = rec.first_field
            row["prefetch"] = rec.first_field
        row["note"] = _record_note(rec, reading)
        row["kind"] = "simple_index"
        return row

    # -- Blockfile ----------------------------------------------------------------

    def _blockfile(self, indexes: list[VFSNode], files: list[VFSNode], heads: dict[str, bytes]) -> None:
        by_name = {c.name: c for c in files}
        index_node = next((c for c in indexes if c.name == "index"), indexes[0])
        for other in indexes:
            if other is not index_node:
                self.status.append(ParseIssue("chromium_cache.second_index", {"name": other.name}))
        data = self._read(index_node)
        if data is None:
            return
        self.file_roles[index_node.name] = {
            "Role": QT_TRANSLATE_NOOP("GeneratedView", "Blockfile index"), "Size": f"{index_node.size:,} B",
        }

        def read_file(name: str) -> bytes | None:
            n = by_name.get(name)
            return self._read(n) if n is not None else None

        cache = bfmt.Cache(data, read_file)
        self.blockfile = cache
        self.versions.add(f"Blockfile {bfmt.VERSIONS.get(cache.index.version, hex(cache.index.version))}")
        found, notes = cache.walk()
        self.status.extend(notes)
        known = {e.addr.value for e, _ in found}
        children: list[_Entry] = []
        for store, how in found:
            entry = _Entry(id=len(self.entries), backend=FORMAT_BLOCKFILE, key=split_key(store.key, blockfile=True))
            entry.store = store
            entry.reached_via = how
            entry.state = bfmt.STATE_NAMES.get(store.state, str(store.state))
            entry.rankings = cache.rankings(store.rankings_node)
            entry.notes.extend(store.notes)
            if entry.rankings is not None and entry.rankings.dirty and entry.rankings.dirty != cache.index.this_id:
                entry.notes.append(ParseIssue(
                    "chromium_cache.entry_dirty",
                    {"dirty": entry.rankings.dirty, "current": cache.index.this_id},
                ))
            if store.flags & bfmt.CHILD_ENTRY:
                children.append(entry)
            self.entries.append(entry)
        for e in self.entries:
            if e.backend != FORMAT_BLOCKFILE:
                continue
            e.kind = e.key.kind
            e.kind_basis = _key_basis(e.key)
            if e.store is not None and e.store.flags & bfmt.CHILD_ENTRY:
                e.kind_basis = QT_TRANSLATE_NOOP("GeneratedView", "sparse child entry (Range_ key)")
        kinds = [e.kind for e in self.entries if e.backend == FORMAT_BLOCKFILE and not (
            e.store and e.store.flags & bfmt.CHILD_ENTRY)]
        if FORMAT_SIMPLE not in self.formats:
            self.index_reading = _index_reading(False, kinds)
        for e in self.entries:
            if e.backend == FORMAT_BLOCKFILE:
                self._read_stream0(e)
                self._fill_row(e)
        for name, n in by_name.items():
            if _is_block_file(heads.get(name, b"")):
                bf = cache.block_file(int(name[5:])) if re.fullmatch(r"data_\d+", name) else None
                self.file_roles[name] = {
                    "Role": QT_TRANSLATE_NOOP("GeneratedView", "Blockfile block file"),
                    "Size": f"{n.size:,} B",
                    **({"Header": bf.tree().root} if bf is not None else {
                        "Note": ParseIssue("chromium_cache.block_file_not_addressed")}),
                }
        referenced = _external_files(self.entries)
        for name, users in referenced.items():
            if name in by_name:
                self.file_roles[name] = {
                    "Role": QT_TRANSLATE_NOOP("GeneratedView", "Blockfile external data file"),
                    "Size": f"{by_name[name].size:,} B",
                    "Used by": ", ".join(users),
                }
            else:
                cache.missing.add(name)
        for name in sorted(cache.missing):
            self.status.append(ParseIssue("chromium_cache.file_missing", {"name": name}))
        self.carved = cache.carve(known)
        for carved_index, c in enumerate(self.carved):
            entry = c["entry"]
            key = split_key(entry.key, blockfile=True)
            rankings = c["rankings"]
            self.orphans.append({
                "id": len(self.orphans),
                "kind": "carved",
                "source": QT_TRANSLATE_NOOP("GeneratedView", "free block (heuristic)"),
                "hash": f"0x{entry.hash:08x}",
                "size": sum(max(s, 0) for s in entry.data_size[:3]),
                "offset": c["offset"],
                "file": c["file"],
                "key": key.text,
                "url": key.url,
                "state": bfmt.STATE_NAMES.get(entry.state, str(entry.state)),
                "created": entry.creation_time,
                "created_text": chrome_time_utc(entry.creation_time),
                "last_used": rankings.last_used if rankings else None,
                "last_used_text": chrome_time_utc(rankings.last_used) if rankings else "",
                "prefetch": None,
                "note": c["reason"],
                "carved_index": carved_index,
            })

    # -- result -------------------------------------------------------------------

    def _result(self) -> ParseResult:
        kinds = Counter(e.kind for e in self.entries)
        states = Counter(e.state for e in self.entries)
        fmt = " + ".join(self.formats)
        overview: dict[str, Any] = {
            "Format": f"Chromium Disk Cache ({fmt})" if fmt else "Chromium Disk Cache",
            "Versions": ", ".join(sorted(self.versions)) or "-",
            "Cache kind": {k: f"{n:,} entries" for k, n in kinds.most_common()} or "-",
            "Entries": {"Total": f"{len(self.entries):,}", **{s: f"{n:,}" for s, n in states.most_common()}},
        }
        if self.cs_context is not None:
            overview["CacheStorage"] = self.cs_context
        elif self.cs_note is not None:
            overview["CacheStorage"] = self.cs_note
        overview["Index field read as"] = _reading_text(self.index_reading)
        if self.real_index is not None:
            overview["Index (the-real-index)"] = self.real_index.tree.root
            index_rows = sum(1 for o in self.orphans if o["kind"] == "simple_index")
            if self.index_unchecked:
                overview["Index records (entry files not checked)"] = f"{index_rows:,}"
            else:
                overview["Index records without an entry file"] = f"{index_rows:,}"
        if self.blockfile is not None:
            overview["Blockfile index"] = self.blockfile.index.tree.root
            overview["Recovered from free blocks (heuristic)"] = f"{len(self.carved):,}"
        overview.update({k: v for k, v in self.overview.items()})
        overview["Files"] = dict(sorted(self.file_roles.items()))
        if self.status:
            overview["Status"] = list(self.status)
        if self.read_problems:
            overview["Read problems"] = dict(self.read_problems)

        store = ChromiumCacheStore(self.vfs, self.entries, self.orphans, self.blockfile, self.carved,
                                   self.index_reading, self.cs_context is not None, self.real_index_node)
        meta: dict[str, Any] = {
            "Format": overview["Format"],
            "Version": overview["Versions"],
            "Cache kind": ", ".join(k for k, _ in kinds.most_common()) or "-",
            "Entries": f"{len(self.entries):,}",
            "Files": f"{self.vfs.file_count(self.node):,}",
            "Total size": f"{self.vfs.total_size(self.node):,} B",
        }
        warning = join_notes([*self.status, *(
            [ParseIssue("chromium_cache.files_unreadable", {"count": len(self.read_problems)})]
            if self.read_problems else [])])
        if warning:
            meta["Parse warning"] = warning
        return ParseResult(
            viewer_type="chromium_cache",
            data={
                "overview": overview,
                "entries": [e.row for e in self.entries],
                "orphans": self.orphans,
                "entries_note": ParseIssue(
                    "chromium_cache.index_in_opened_folder" if self.index_unchecked and not self.entries
                    else "chromium_cache.no_entries"
                ),
                "orphans_note": ParseIssue(
                    "chromium_cache.no_orphans_blockfile" if self.blockfile is not None
                    else "chromium_cache.no_orphans_simple"
                ),
                "__store": store,
            },
            metadata=meta,
        )


_SOURCE_UNCHECKED = QT_TRANSLATE_NOOP("GeneratedView", "index record (entry files not checked)")


def _record_note(rec: sfmt.IndexRecord, reading: str) -> str | ParseIssue:
    return join_notes([
        ParseIssue("chromium_cache.index_field_both") if reading == READ_BOTH else None,
        ParseIssue("chromium_cache.index_record_size_rejected") if rec.size_rejected else None,
    ])


def _index_reading(cache_storage: bool, kinds: list[str]) -> str:
    """How the index's first record field is read. net::APP_CACHE caches
    (CacheStorage, Service Worker script caches) store the trailer prefetch
    size there, every other cache type the last-used time
    (EntryMetadata::Serialize). The type is known from CacheStorage's
    index.txt, or from an entry whose key grammar shows an HTTP or Code
    Cache; otherwise both readings are shown."""
    if cache_storage:
        return READ_PREFETCH
    if any(k in (KIND_HTTP, KIND_CODE, KIND_CODE_DATA) for k in kinds):
        return READ_TIME
    return READ_BOTH


def _reading_text(reading: str) -> str | ParseIssue:
    if reading == READ_TIME:
        return QT_TRANSLATE_NOOP("GeneratedView", "last-used time (cache type known from the keys)")
    if reading == READ_PREFETCH:
        return QT_TRANSLATE_NOOP("GeneratedView", "trailer prefetch size (CacheStorage, net::APP_CACHE)")
    return ParseIssue("chromium_cache.index_field_both")


def _cache_storage_context(node: VFSNode, vfs: VFS) -> tuple[dict[str, Any] | None, ParseIssue | None]:
    """CacheStorage: the parent directory's index.txt (a CacheStorageIndex)
    names this directory as one of its caches. (None, why) otherwise --
    no index.txt is no note."""
    path = node.path.replace("\\", "/").rstrip("/")
    parent_path = path.rsplit("/", 1)[0] or "/"
    parent = find_node(vfs, parent_path)
    if parent is None:
        return None, None
    index = next((c for c in parent.children if c.name == _CACHE_STORAGE_INDEX and not c.is_dir), None)
    if index is None:
        return None, None
    try:
        data = vfs.read(index)
    except Exception as exc:  # noqa: BLE001
        return None, ParseIssue("chromium_cache.cs_index_unreadable", detail=str(exc))
    decoded = decode_proto("CacheStorageIndex", data)
    if decoded.error is not None:
        return None, ParseIssue("chromium_cache.cs_index_not_decoded", detail=decoded.error.detail)
    for cache in decoded.decoded.get("cache", []):
        if cache.get("cache_dir") == node.name:
            name = cache.get("name", "")
            u16 = cache.get("u16string_name")
            if u16:
                import base64
                try:
                    name = base64.b64decode(u16).decode("utf-16-le")
                except (ValueError, UnicodeDecodeError):
                    pass
            context: dict[str, Any] = {
                "Index": f"{parent.name}/{_CACHE_STORAGE_INDEX}",
                "Cache name": name,
                "Cache directory": node.name,
            }
            for label, key in (("Storage key", "storage_key"), ("Origin", "origin"),
                               ("Bucket id", "bucket_id"), ("Size", "size"), ("Padding", "padding")):
                if key in decoded.decoded or key in cache:
                    context[label] = cache.get(key, decoded.decoded.get(key))
            others = [c.get("name", "") for c in decoded.decoded.get("cache", []) if c is not cache]
            if others:
                context["Other caches in this index"] = ", ".join(others)
            return context, None
    return None, ParseIssue("chromium_cache.cs_index_other_dir", {"name": node.name})


def _decode_stream0(e: _Entry, data: bytes | None, base: int) -> None:
    """Read stream 0 as the entry's kind says -- or, where it doesn't,
    every reading that is strictly valid, as a heuristic."""
    if data is None:
        if e.kind == KIND_URL_KEY:
            e.notes.append(_NOTE_URL_KEY_NO_READING)
        return
    if e.kind == KIND_CACHE_STORAGE:
        decoded = decode_proto("CacheMetadata", data, base, with_ranges=False)
        e.metadata_view = cache_metadata_view(decoded.decoded)
        e.notes.extend(decoded.notes())
        return
    if e.kind == KIND_HTTP:
        e.response = decode_response_info(data, base, with_tree=False)
        if e.response.stopped is not None:
            e.notes.append(e.response.stopped)
        return
    if e.kind == KIND_CODE:
        e.code_header = decode_code_header(data, base)
        if e.code_header.status is not None:
            e.notes.append(e.code_header.status)
        return
    if e.kind == KIND_CODE_DATA:
        return
    if not data:
        if e.kind == KIND_UNDETERMINED:
            e.notes.append(_BODY_NOTE_UNDETERMINED)
        elif e.kind == KIND_URL_KEY:
            e.notes.append(_NOTE_URL_KEY_NO_READING)
        return
    info = decode_response_info(data, base, with_tree=False)
    proto = decode_proto("CacheMetadata", data, base, with_ranges=False)
    if strictly_valid(info):
        e.readings.append("HttpResponseInfo")
    if proto.strictly_valid:
        e.readings.append("CacheMetadata")
    if e.readings == ["HttpResponseInfo"]:
        e.response = info
    elif e.readings == ["CacheMetadata"]:
        e.metadata_view = cache_metadata_view(proto.decoded)
    if e.readings:
        e.notes.append(_reading_note(e, ", ".join(e.readings)))
    else:
        e.notes.append(_NOTE_URL_KEY_NO_READING if e.kind == KIND_URL_KEY else _BODY_NOTE_UNDETERMINED)


def _reading_note(e: _Entry, readings: str) -> ParseIssue:
    """Why stream 0 is read as *readings* where the key doesn't settle it."""
    if e.kind == KIND_URL_KEY:
        return ParseIssue("chromium_cache.url_key_reading", {"readings": readings})
    return ParseIssue("chromium_cache.heuristic_reading", {"readings": readings})


def _row(e: _Entry, last_used: int | None, prefetch: int | None, reading: str | None) -> dict[str, Any]:
    r = e.response
    mv = e.metadata_view
    headers = r.headers if r is not None else (mv.headers if mv is not None else [])
    status = ""
    if r is not None and r.status_line.startswith("HTTP/"):
        parts = r.status_line.split(" ", 2)
        status = parts[1] if len(parts) > 1 else ""
    elif mv is not None and mv.status_code is not None:
        status = str(mv.status_code)
    url = e.key.url or (mv.url_list[-1] if mv is not None and mv.url_list else "")
    if e.kind == KIND_CACHE_STORAGE or (e.kind == KIND_UNDETERMINED and mv is not None):
        url = e.key.text
    request_time = r.request_time if r is not None else None
    response_time = (
        r.response_time if r is not None else
        mv.response_time if mv is not None else
        e.code_header.response_time if e.code_header is not None else None
    )
    created = (
        e.store.creation_time if e.store is not None else
        mv.entry_time if mv is not None else None
    )
    body_size = _body_size(e)
    files = (
        ", ".join(node.name for node, _ in e.simple_files.values()) if e.simple_files else
        e.store.addr.text() if e.store is not None else ""
    )
    reading_note = (
        ParseIssue("chromium_cache.index_field_both") if reading == READ_BOTH else None
    )
    return {
        "id": e.id,
        "backend": e.backend,
        "state": e.state,
        "kind": e.kind,
        "kind_basis": e.kind_basis,
        "url": url,
        "top_frame_site": e.key.top_frame_site,
        "frame_site": e.key.frame_site,
        "http_status": status,
        "content_type": _headers_value(headers, "content-type") or (mv.mime_type if mv is not None else ""),
        "content_encoding": _headers_value(headers, "content-encoding"),
        "body_size": body_size,
        "request_time": request_time,
        "request_time_text": chrome_time_utc(request_time),
        "response_time": response_time,
        "response_time_text": chrome_time_utc(response_time),
        "last_used": last_used,
        "last_used_text": chrome_time_utc(last_used),
        "prefetch": prefetch,
        "created": created,
        "created_text": chrome_time_utc(created),
        "server": _server(r),
        "protocol": r.protocol if r is not None else (mv.alpn if mv is not None else ""),
        "key": e.key.text,
        "hash": (
            f"0x{e.simple_hash:016x}" if e.simple_hash is not None else
            f"0x{e.store.hash:08x}" if e.store is not None else ""
        ),
        "files": files,
        "reached_via": e.reached_via,
        "note": join_notes([*e.notes, reading_note]),
    }


def _body_size(e: _Entry) -> int | None:
    if e.backend == FORMAT_SIMPLE:
        found = e.simple_files.get(sfmt.ROLE_STREAMS_0_1)
        if found is not None and 1 in found[1].streams:
            s, en = found[1].streams[1]
            return en - s
        sparse = e.simple_files.get(sfmt.ROLE_SPARSE)
        if sparse is not None:
            return sum(r["length"] for r in sparse[1].sparse_ranges)
        return None
    if e.store is not None:
        return max(e.store.data_size[1], 0)
    return None


def _blockfile_stream(cache: bfmt.Cache | None, store: bfmt.EntryStore | None, stream: int) -> tuple[bytes | None, int]:
    if cache is None or store is None:
        return None, 0
    size = store.data_size[stream]
    if size <= 0 or not store.data_addr[stream]:
        return (b"" if size == 0 else None), 0
    data, loc, _note = cache.read(bfmt.Addr(store.data_addr[stream]), size)
    return data, (loc[1] if loc else 0)


def _external_files(entries: list[_Entry]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in entries:
        if e.store is None:
            continue
        for i in range(bfmt.NUM_STREAMS):
            addr = bfmt.Addr(e.store.data_addr[i])
            if addr.initialized and addr.separate_file:
                out.setdefault(addr.file_name(), []).append(f"#{e.id} stream {i}")
        key_addr = bfmt.Addr(e.store.long_key)
        if key_addr.initialized and key_addr.separate_file:
            out.setdefault(key_addr.file_name(), []).append(f"#{e.id} key")
    return out


# -- Single file ------------------------------------------------------------------


def _parse_single_file(node: VFSNode, vfs: VFS) -> ParseResult:
    head = vfs.peek(node, 16)
    if sfmt.has_index_magic(head):
        data = vfs.read(node)
        index = sfmt.read_real_index(data)
        orphans: list[dict[str, Any]] = []
        for rec in index.records:
            orphans.append({
                "id": len(orphans), "kind": "simple_index",
                "source": _SOURCE_UNCHECKED,
                "hash": f"0x{rec.hash:016x}", "size": rec.size, "offset": rec.offset,
                "key": "", "url": "", "state": "",
                "last_used": rec.first_field, "last_used_text": chrome_time_utc(rec.first_field),
                "prefetch": rec.first_field, "note": _record_note(rec, READ_BOTH),
            })
        rejected = [str(i) for i, r in enumerate(index.records) if r.size_rejected]
        overview: dict[str, Any] = {
            "Format": "Chromium Disk Cache (Simple)",
            "File": sfmt.ROLE_REAL_INDEX,
            "Status": [ParseIssue("chromium_cache.index_alone"), *([ParseIssue(
                "chromium_cache.index_entry_size_rejected", {"records": ", ".join(rejected)}
            )] if rejected else [])],
            "Index field read as": ParseIssue("chromium_cache.index_field_both"),
            "Index (the-real-index)": index.tree.root,
        }
        store = ChromiumCacheStore(vfs, [], orphans, None, [], READ_BOTH, False, node)
        return ParseResult(
            viewer_type="chromium_cache",
            data={
                "overview": overview, "entries": [], "orphans": orphans, "__store": store,
                "entries_note": ParseIssue("chromium_cache.index_alone"),
                "orphans_note": ParseIssue("chromium_cache.no_orphans_simple"),
            },
            metadata={
                "Format": "Chromium Disk Cache (Simple)",
                "Version": f"index version {index.version}",
                "Entries": f"{len(index.records):,}",
                "Status": ParseIssue("chromium_cache.index_alone"),
            },
        )
    with vfs.open(node) as fh:
        layout = sfmt.read_simple_file(sfmt.RandomAccess(fh, node.size))
    overview = {"Format": "Chromium Disk Cache (Simple)", "File": layout.role}
    if layout.role == sfmt.ROLE_FAKE_INDEX:
        overview["Backend marker (fake index)"] = layout.fake
        overview["Status"] = [ParseIssue("chromium_cache.marker_alone"), *layout.notes]
        store = ChromiumCacheStore(vfs, [], [], None, [], READ_BOTH, False, None)
        return ParseResult(
            viewer_type="chromium_cache",
            data={
                "overview": overview, "entries": [], "orphans": [], "__store": store,
                "entries_note": ParseIssue("chromium_cache.marker_alone"),
                "orphans_note": ParseIssue("chromium_cache.marker_alone"),
            },
            metadata={
                "Format": "Chromium Disk Cache (Simple)",
                "Version": f"backend marker version {layout.version}",
                "Status": ParseIssue("chromium_cache.marker_alone"),
            },
        )
    entry = _Entry(id=0, backend=FORMAT_SIMPLE, key=split_key(layout.key))
    entry.simple_hash = sfmt.entry_hash(layout.key) if layout.key else None
    entry.simple_files[layout.role] = (node, layout)
    entry.kind = entry.key.kind
    entry.kind_basis = _key_basis(entry.key)
    if layout.unreadable is not None:
        entry.notes.append(layout.unreadable)
    entry.notes.extend(layout.notes)
    stream0: bytes | None = None
    base = 0
    rng = layout.streams.get(0)
    if rng is not None:
        with vfs.open(node) as fh:
            stream0 = sfmt.RandomAccess(fh, node.size).read_at(rng[0], rng[1] - rng[0])
        base = rng[0]
    _decode_stream0(entry, stream0, base)
    entry.notes.append(ParseIssue("chromium_cache.entry_alone"))
    entry.row = _row(entry, None, None, None)
    overview["Status"] = [ParseIssue("chromium_cache.entry_alone")]
    overview["Cache kind"] = entry.kind
    store = ChromiumCacheStore(vfs, [entry], [], None, [], READ_BOTH, False, None)
    return ParseResult(
        viewer_type="chromium_cache",
        data={
            "overview": overview, "entries": [entry.row], "orphans": [], "__store": store,
            "orphans_note": ParseIssue("chromium_cache.entry_alone"),
        },
        metadata={
            "Format": "Chromium Disk Cache (Simple)",
            "Version": f"entry version {layout.version}",
            "Cache kind": entry.kind,
            "Entries": "1",
            "Status": ParseIssue("chromium_cache.entry_alone"),
        },
    )


# -- Details, read when an entry is selected ---------------------------------------


def _certificate_fields(der: bytes) -> dict[str, Any]:
    """A certificate's identifying fields; what the library warns about while
    reading it (e.g. a serial number RFC 5280 disallows) is a fact of the
    certificate and shown with it."""
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _certificate_fields_inner(der)
    texts = sorted({str(w.message) for w in caught})
    if texts:
        out["Library warnings"] = texts
    return out


def _certificate_fields_inner(der: bytes) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001 -- the library's own diagnosis is kept
        return {"Status": ParseIssue("chromium_cache.certificate_not_decoded", detail=str(exc))}
    out: dict[str, Any] = {
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "Serial number": f"{cert.serial_number:x}",
        "Not valid before (UTC)": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "Not valid after (UTC)": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "SHA-256 fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "SHA-1 fingerprint": hashlib.sha1(der).hexdigest(),
    }
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out["Subject alternative names"] = ", ".join(str(n.value) for n in san.value)
    except x509.ExtensionNotFound:
        pass
    except Exception as exc:  # noqa: BLE001
        out["Subject alternative names"] = ParseIssue("chromium_cache.certificate_not_decoded", detail=str(exc))
    return out


class ChromiumCacheStore:
    """Reads an entry's files when it is selected: its structure with byte
    ranges, headers, certificates and body. Holds the source (VFS) the
    cache was parsed from."""

    def __init__(
        self, vfs: VFS, entries: list[_Entry], orphans: list[dict[str, Any]],
        blockfile: bfmt.Cache | None, carved: list[dict[str, Any]], index_reading: str,
        cache_storage: bool, real_index_node: VFSNode | None,
    ) -> None:
        self._vfs = vfs
        self._entries = entries
        self._orphans = orphans
        self._blockfile = blockfile
        self._carved = carved
        self._index_reading = index_reading
        self._cache_storage = cache_storage
        self._real_index_node = real_index_node

    def detail(self, entry_id: int) -> dict[str, Any]:
        e = self._entries[entry_id]
        if e.backend == FORMAT_SIMPLE:
            return self._simple_detail(e)
        return self._blockfile_detail(e)

    def read_size(self, entry_id: int) -> int:
        """About how many bytes detail() reads: the entry's files (Simple),
        its streams (Blockfile) -- for the viewer to decide whether to read
        them behind a wait dialog."""
        e = self._entries[entry_id]
        if e.simple_files:
            return sum(node.size for node, _layout in e.simple_files.values())
        if e.store is not None:
            return sum(max(s, 0) for s in e.store.data_size[:bfmt.NUM_STREAMS])
        return 0

    def orphan_detail(self, orphan_id: int) -> dict[str, Any]:
        row = self._orphans[orphan_id]
        if row.get("kind") == "carved" and self._blockfile is not None:
            c = self._carved[row["carved_index"]]
            e = _Entry(id=-1, backend=FORMAT_BLOCKFILE, key=split_key(c["entry"].key, blockfile=True))
            e.store = c["entry"]
            e.kind = e.key.kind
            e.kind_basis = _key_basis(e.key)
            e.rankings = c["rankings"]
            detail = self._blockfile_detail(e)
            detail["notes"] = [c["reason"], ParseIssue("chromium_cache.carved_blocks_reused"), *e.store.notes]
            return detail
        out = self._new_detail(_Entry(id=-1, backend=FORMAT_SIMPLE, key=split_key(b"")))
        out["key"] = {}
        out["notes"] = [row["note"]] if row.get("note") else []
        if self._real_index_node is not None:
            try:
                raw = self._vfs.read(self._real_index_node)
            except Exception as exc:  # noqa: BLE001
                out["notes"].append(ParseIssue("chromium_cache.file_unreadable", detail=str(exc)))
                return out
            off = row["offset"]
            t = Tree()
            t.put(("Hash",), row["hash"], off, off + 8)
            first = int.from_bytes(raw[off + 8:off + 16], "little", signed=True)
            if self._index_reading in (READ_TIME, READ_BOTH):
                t.put(("Last used",), chrome_time(first), off + 8, off + 16)
            if self._index_reading in (READ_PREFETCH, READ_BOTH):
                t.put(("Trailer prefetch size",), first, off + 8, off + 16)
            if self._index_reading == READ_BOTH:
                t.put(("Reading",), ParseIssue("chromium_cache.index_field_both"))
            packed = int.from_bytes(raw[off + 16:off + 24], "little")
            t.put(("Entry size (256-byte chunks)",), f"{(packed >> 8) << 8:,} B", off + 16, off + 24)
            t.put(("In-memory data",), packed & 3)
            out["structure"].append({
                "title": self._real_index_node.name, "raw": raw, "tree": t.root, "ranges": t.ranges,
            })
        return out

    # -- Simple ---------------------------------------------------------------

    def _simple_detail(self, e: _Entry) -> dict[str, Any]:
        out = self._new_detail(e)
        streams: dict[int, _Stream] = {}
        sparse: list[dict[str, Any]] = []
        for role, (node, layout) in e.simple_files.items():
            try:
                raw = self._vfs.read(node)
            except Exception as exc:  # noqa: BLE001
                out["notes"].append(ParseIssue("chromium_cache.file_unreadable", detail=str(exc)))
                continue
            tree = sfmt.structure_tree(layout, sfmt.RandomAccess(raw, len(raw)))
            for index, (s, en) in layout.streams.items():
                streams[index] = _Stream(raw[s:en], node.name, s)
                eof = layout.eofs.get(index)
                if eof is not None:
                    tree.put((f"EOF record, stream {index}", "CRC32 check"), sfmt.crc_note(raw[s:en], eof))
            for rng in layout.sparse_ranges:
                sparse.append({
                    "offset": rng["offset"], "length": rng["length"],
                    "data": raw[rng["data_start"]:rng["data_end"]],
                    "where": f"{node.name} 0x{rng['data_start']:x}",
                })
            if role == sfmt.ROLE_STREAMS_0_1:
                self._index_record_tree(e, tree)
                if 0 in layout.streams:
                    s0 = streams[0]
                    self._stream0_tree(e, tree, s0.data, s0.start, out)
            out["structure"].append({"title": node.name, "raw": raw, "tree": tree.root, "ranges": tree.ranges})
        self._finish(e, out, streams, sparse)
        return out

    @staticmethod
    def _new_detail(e: _Entry) -> dict[str, Any]:
        return {
            "structure": [], "headers": [], "request_headers": [], "status_line": "",
            "certificates": [], "streams": [], "body": None, "notes": list(e.notes),
            "key": e.key.tree(), "kind": e.kind, "kind_basis": e.kind_basis,
            # Why a stream that has a size couldn't be read (stream -> issue).
            "stream_notes": {},
        }

    def _index_record_tree(self, e: _Entry, tree: Tree) -> None:
        rec = e.index_record
        if rec is None:
            return
        if self._index_reading in (READ_TIME, READ_BOTH):
            tree.put(("Index record", "Last used"), chrome_time(rec.first_field))
        if self._index_reading in (READ_PREFETCH, READ_BOTH):
            tree.put(("Index record", "Trailer prefetch size"), rec.first_field)
        if self._index_reading == READ_BOTH:
            tree.put(("Index record", "Reading"), ParseIssue("chromium_cache.index_field_both"))
        tree.put(("Index record", "Entry size"), f"{rec.size:,} B")

    def _stream0_tree(self, e: _Entry, tree: Tree, data: bytes, base: int, out: dict[str, Any]) -> None:
        """Stream 0 decoded under its own node in the structure tree, and
        the headers/certificates it gives."""
        if e.kind == KIND_CACHE_STORAGE:
            decoded = decode_proto("CacheMetadata", data, base)
            self._graft_proto(tree, ("Stream 0 (CacheMetadata)",), decoded)
            self._from_metadata(cache_metadata_view(decoded.decoded), out)
            return
        if e.kind == KIND_HTTP:
            info = decode_response_info(data, base)
            tree.graft(("Stream 0 (HttpResponseInfo)",), info.tree)
            self._from_response(info, out)
            return
        if e.kind == KIND_CODE:
            tree.graft(("Stream 0 (Code Cache header)",), decode_code_header(data, base).tree)
            return
        if e.kind == KIND_CODE_DATA or not data:
            return
        info = decode_response_info(data, base)
        if strictly_valid(info):
            info.tree.put(("Reading",), _reading_note(e, "HttpResponseInfo"))
            tree.graft(("Stream 0 reading: HttpResponseInfo (heuristic)",), info.tree)
            if e.readings == ["HttpResponseInfo"]:
                self._from_response(info, out)
        proto = decode_proto("CacheMetadata", data, base)
        if proto.strictly_valid:
            self._graft_proto(tree, ("Stream 0 reading: CacheMetadata (heuristic)",), proto)
            if e.readings == ["CacheMetadata"]:
                self._from_metadata(cache_metadata_view(proto.decoded), out)

    @staticmethod
    def _graft_proto(tree: Tree, path: tuple[str, ...], decoded: Any) -> None:
        tree.put(path, with_times(decoded.decoded))
        for sub, rng in decoded.ranges.items():
            tree.ranges[path + sub] = rng
        for i, note in enumerate(decoded.notes()):
            tree.put(path + (f"Note {i + 1}",), note)

    @staticmethod
    def _from_response(info: ResponseInfo, out: dict[str, Any]) -> None:
        out["headers"] = info.headers
        out["status_line"] = info.status_line
        out["certificates"] = [
            {"der": der, "fields": _certificate_fields(der), "range": rng}
            for der, rng in zip(info.certificates, info.certificate_ranges)
        ]
        out["cache_zstd"] = info.zstd_uncompressed_size is not None
        out["truncated"] = info.truncated

    @staticmethod
    def _from_metadata(view: Any, out: dict[str, Any]) -> None:
        out["headers"] = view.headers
        out["request_headers"] = view.request_headers
        out["status_line"] = f"{view.status_code if view.status_code is not None else ''} {view.status_text}".strip()

    # -- Blockfile ------------------------------------------------------------

    def _blockfile_detail(self, e: _Entry) -> dict[str, Any]:
        out = self._new_detail(e)
        cache = self._blockfile
        if cache is None or e.store is None:
            return out
        store = e.store
        entry_tree = cache.entry_tree(store)
        if e.rankings is not None:
            r = e.rankings
            entry_tree.put(("Rankings node", "Address"), r.addr.text())
            entry_tree.put(("Rankings node", "Last used"), chrome_time(r.last_used))
            entry_tree.put(("Rankings node", "Last modified"), chrome_time(r.last_modified))
            entry_tree.put(("Rankings node", "Dirty"), r.dirty)
            if not r.self_hash_ok:
                entry_tree.put(("Rankings node", "Note"), ParseIssue("chromium_cache.rankings_self_hash"))
        trees: dict[str, Tree] = {store.addr.file_name(): entry_tree}
        streams: dict[int, _Stream] = {}
        for i in range(bfmt.NUM_STREAMS):
            size = store.data_size[i]
            if size <= 0 or not store.data_addr[i]:
                continue
            data, loc, note = cache.read(bfmt.Addr(store.data_addr[i]), size)
            if note is not None:
                entry_tree.put(("Streams", str(i), "Note"), note)
                out["stream_notes"][i] = note
            if data is None or loc is None:
                continue
            streams[i] = _Stream(data, loc[0], loc[1])
            trees.setdefault(loc[0], Tree()).put((f"Stream {i}",), f"{loc[2] - loc[1]:,} B", loc[1], loc[2])
        if 0 in streams:
            s0 = streams[0]
            self._stream0_tree(e, trees[s0.file], s0.data, s0.start, out)
        for name, t in trees.items():
            raw = cache.file_bytes(name)
            if raw is None:
                out["notes"].append(ParseIssue("chromium_cache.file_missing", {"name": name}))
                continue
            out["structure"].append({"title": name, "raw": raw, "tree": t.root, "ranges": t.ranges})
        sparse: list[dict[str, Any]] = []
        if store.flags & bfmt.PARENT_ENTRY:
            sparse, out["sparse_rejected"], child_notes = self._blockfile_children(e)
            out["notes"].extend(child_notes)
        self._finish(e, out, streams, sparse)
        return out

    def _blockfile_children(
        self, parent: _Entry,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[ParseIssue]]:
        """The sparse data of a parent entry: its children (keys
        Range_<key>:<signature>:<child id>), each child's 1 KB blocks that
        its bitmap marks written -- and apart from them, the children
        Chromium wouldn't read for the parent (SparseControl::OpenSparseEntry
        and OpenChild: parent header, child flag, header size, signature,
        magic, the parent's child bitmap), each with why and its blocks."""
        used: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        notes_out: list[ParseIssue] = []
        cache = self._blockfile
        if cache is None or parent.store is None:
            return used, rejected, notes_out
        data_size = bfmt.SPARSE_HEADER_SIZE + 128  # sizeof(SparseData)
        header, _ = _blockfile_stream(cache, parent.store, bfmt.SPARSE_INDEX_STREAM)
        header = header or b""
        parent_reasons: list[ParseIssue] = []
        if len(header) < data_size:
            parent_reasons.append(ParseIssue(
                "chromium_cache.sparse_parent_short", {"size": len(header), "expected": data_size}
            ))
        if parent.store.data_size[bfmt.SPARSE_DATA_STREAM]:
            parent_reasons.append(ParseIssue("chromium_cache.sparse_parent_has_data"))
        map_len = len(header) - bfmt.SPARSE_HEADER_SIZE
        if map_len > 8 * 1024 or map_len % 4:
            parent_reasons.append(ParseIssue("chromium_cache.sparse_parent_map_size", {"size": map_len}))
        signature = magic = key_len = None
        if len(header) >= 16:
            signature, magic, key_len = struct.unpack_from("<qIi", header)
            if magic != bfmt.INDEX_MAGIC:
                parent_reasons.append(ParseIssue(
                    "chromium_cache.sparse_magic",
                    {"magic": f"0x{magic:08x}", "expected": f"0x{bfmt.INDEX_MAGIC:08x}"},
                ))
            if key_len != len(parent.store.key):
                parent_reasons.append(ParseIssue(
                    "chromium_cache.sparse_parent_key_len", {"stored": key_len, "actual": len(parent.store.key)}
                ))
        children_map = int.from_bytes(header[bfmt.SPARSE_HEADER_SIZE:], "little") if map_len > 0 else 0
        map_bits = max(map_len, 0) * 8
        parent_sig = f"{signature & 0xFFFFFFFFFFFFFFFF:x}" if signature is not None else "-"

        prefix = b"Range_" + parent.store.key + b":"
        for child in self._entries:
            if child.store is None or not child.store.key.startswith(prefix):
                continue
            reasons: list[ParseIssue] = []
            other: list[ParseIssue] = []
            key_sig, _, id_text = child.store.key[len(prefix):].decode("ascii", "replace").partition(":")
            try:
                child_id: int | None = int(id_text, 16)
                int(key_sig, 16)
            except ValueError:
                child_id = None
                reasons.append(ParseIssue("chromium_cache.sparse_key_id"))
            if child_id is not None:
                if key_sig != parent_sig:
                    reasons.append(ParseIssue(
                        "chromium_cache.sparse_key_signature", {"key": key_sig, "parent": parent_sig}
                    ))
                if child_id >= map_bits or not children_map >> child_id & 1:
                    reasons.append(ParseIssue("chromium_cache.sparse_not_in_map", {"child": child_id}))
            if not child.store.flags & bfmt.CHILD_ENTRY:
                reasons.append(ParseIssue("chromium_cache.sparse_no_child_flag"))
            child_header, _ = _blockfile_stream(cache, child.store, bfmt.SPARSE_INDEX_STREAM)
            child_header = child_header or b""
            if len(child_header) < data_size:
                reasons.append(ParseIssue(
                    "chromium_cache.sparse_child_short", {"size": len(child_header), "expected": data_size}
                ))
            if len(child_header) >= 12:
                child_sig, child_magic = struct.unpack_from("<qI", child_header)
                if signature is None or child_sig != signature:
                    reasons.append(ParseIssue("chromium_cache.sparse_signature", {
                        "child": f"{child_sig & 0xFFFFFFFFFFFFFFFF:x}", "parent": parent_sig,
                    }))
                if child_magic != bfmt.INDEX_MAGIC:
                    reasons.append(ParseIssue(
                        "chromium_cache.sparse_magic",
                        {"magic": f"0x{child_magic:08x}", "expected": f"0x{bfmt.INDEX_MAGIC:08x}"},
                    ))
            data, _ = _blockfile_stream(cache, child.store, bfmt.SPARSE_DATA_STREAM)
            if data is None:
                other.append(ParseIssue("chromium_cache.sparse_no_data"))
            ranges, range_notes = _child_ranges(child, child_id, child_header, data)
            notes_out.extend(range_notes)
            if not reasons and not other and not parent_reasons:
                used.extend(ranges)
                continue
            notes: list[ParseIssue] = []
            if parent_reasons:
                notes.append(ParseIssue("chromium_cache.sparse_parent_invalid", {"reasons": parent_reasons}))
            if reasons:
                notes.append(ParseIssue("chromium_cache.sparse_child_rejected", {"reasons": reasons}))
            notes.extend(other)
            rejected.append({
                "child": child.id, "key": child.key.text, "reason": join_notes(list(notes)), "ranges": ranges,
            })
        return sorted(used, key=lambda r: r["offset"]), rejected, notes_out

    # -- common -----------------------------------------------------------------

    def _finish(
        self, e: _Entry, out: dict[str, Any], streams: dict[int, _Stream], sparse: list[dict[str, Any]],
    ) -> None:
        for index in sorted(streams):
            s = streams[index]
            out["streams"].append({"index": index, "size": len(s.data), "data": s.data, "where": s.where})
        out["body"] = self._body(e, out, streams, sparse)

    def _body(
        self, e: _Entry, out: dict[str, Any], streams: dict[int, _Stream], sparse: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # derived_candidate: the derived body holds only under one candidate
        # reading of a heuristic kind (the note says which).
        body: dict[str, Any] = {"raw": None, "where": "", "derived": None, "derived_label": "",
                                "derived_partial": False, "derived_candidate": False,
                                "note": None, "sparse": sparse,
                                "gaps": _gaps(sparse) if sparse else [],
                                "sparse_rejected": out.get("sparse_rejected") or []}
        header = e.code_header
        if e.kind == KIND_CODE and header is not None and header.inline_data is not None and 0 in streams:
            s0 = streams[0]
            body["raw"] = s0.data[12:]
            body["where"] = f"{s0.file} 0x{s0.start + 12:x}"
        elif 1 in streams:
            body["raw"], body["where"] = streams[1].data, streams[1].where
        body["note"] = self._body_note(e, out, body)
        if out.get("truncated"):
            body["note"] = join_notes([ParseIssue("chromium_cache.body_truncated_flag"), body["note"]])
        if body["raw"] is None and not sparse:
            unread = out["stream_notes"].get(1)
            if unread is not None:
                body["note"] = ParseIssue("chromium_cache.body_unreadable", {"reason": unread})
            elif body["note"] is None:
                body["note"] = ParseIssue("chromium_cache.no_body")
        if body["sparse_rejected"]:
            body["note"] = join_notes([body["note"], ParseIssue(
                "chromium_cache.sparse_children_apart", {"count": len(body["sparse_rejected"])}
            )])
        return body

    @staticmethod
    def _body_note(e: _Entry, out: dict[str, Any], body: dict[str, Any]) -> str | ParseIssue | None:
        """What the analyst must know about the body; fills the derived body
        where the declared Content-Encoding applies (HTTP cache only -- as a
        candidate where the HTTP cache is one of the kinds a URL key allows)."""
        if e.kind in (KIND_CODE, KIND_CODE_DATA):
            return _BODY_NOTE_CODE
        encoding = _headers_value(out["headers"], "content-encoding")
        if e.kind == KIND_URL_KEY and e.readings == ["HttpResponseInfo"]:
            if body["raw"] is None:
                return None
            note = ChromiumCacheStore._derive(out, body, encoding)
            if not encoding and body["derived"] is None:
                return note
            body["derived_candidate"] = body["derived"] is not None
            candidate = ParseIssue(
                "chromium_cache.url_key_body_candidate" if body["derived_candidate"]
                else "chromium_cache.url_key_body_no_candidate",
                {"coding": body["derived_label"] or encoding},
            )
            return join_notes([candidate, note])
        if e.kind == KIND_URL_KEY and e.readings != ["CacheMetadata"]:
            return _NOTE_URL_KEY_NO_READING
        if e.readings == ["HttpResponseInfo"]:
            # Only the HTTP cache stores bodies as transferred; other caches
            # that keep an HttpResponseInfo (Service Worker scripts) store
            # them decoded. Which one this is isn't known.
            if encoding:
                return ParseIssue("chromium_cache.heuristic_body_not_decoded", {"coding": encoding})
            return None
        if e.kind == KIND_HTTP:
            if body["raw"] is None:
                return None
            return ChromiumCacheStore._derive(out, body, encoding)
        if e.kind == KIND_CACHE_STORAGE or e.readings == ["CacheMetadata"]:
            if encoding:
                # The network stack decodes before the page's fetch() gets
                # the body; CacheStorage stores what the page put, with the
                # response's headers.
                return ParseIssue("chromium_cache.cs_body_stored_decoded", {"coding": encoding})
            return None
        return _BODY_NOTE_UNDETERMINED

    @staticmethod
    def _derive(out: dict[str, Any], body: dict[str, Any], encoding: str) -> ParseIssue | None:
        """The RAW body with the declared codings undone, into the body's
        derived fields; the decoder's note."""
        codings = content_codings(encoding)
        derived, note, partial = decode_body(body["raw"], codings, bool(out.get("cache_zstd")))
        if derived is not None:
            body["derived"] = derived
            body["derived_partial"] = partial
            body["derived_label"] = ", ".join(
                (["zstd (stored by the cache)"] if out.get("cache_zstd") else [])
                + [c for c in codings if c != "identity"]
            )
        return note


def _child_ranges(
    child: _Entry, child_id: int | None, header: bytes, data: bytes | None,
) -> tuple[list[dict[str, Any]], list[ParseIssue]]:
    """A sparse child's stored data, placed at child id × 1 MB in the
    parent's data (sparse_control.cc): the 1 KB blocks its block bitmap
    marks written, and the partly written block its header keeps apart
    (last_block, last_block_len: PartialBlockLength, DoGetAvailableRange),
    joined to the run before it where they meet. None without a child id:
    they have no place in the parent's data (the child's streams are in
    its own row in Entries). With notes on the header's partial block."""
    if child_id is None or data is None or len(header) < bfmt.SPARSE_HEADER_SIZE + 128:
        return [], []
    bitmap = int.from_bytes(header[bfmt.SPARSE_HEADER_SIZE:bfmt.SPARSE_HEADER_SIZE + 128], "little")
    last_block, last_len = struct.unpack_from("<ii", header, 16)
    notes: list[ParseIssue] = []
    if last_block >= 0 and not 0 <= last_len < bfmt.SPARSE_BLOCK:
        # OpenChild: such a value is reset to "no partial block".
        notes.append(ParseIssue("chromium_cache.sparse_last_block_reset", {
            "child": child.id, "block": last_block, "length": last_len,
        }))
        last_block = -1
    runs: list[tuple[int, int]] = []  # byte ranges in the child, end exclusive
    block = 0
    while block < 1024:
        if not bitmap >> block & 1:
            block += 1
            continue
        start = block
        while block < 1024 and bitmap >> block & 1:
            block += 1
        runs.append((start * bfmt.SPARSE_BLOCK, block * bfmt.SPARSE_BLOCK))
    if 0 <= last_block < 1024 and last_len > 0 and not bitmap >> last_block & 1:
        lo = last_block * bfmt.SPARSE_BLOCK
        before = next((i for i, (_s, e) in enumerate(runs) if e == lo), None)
        if before is not None:
            runs[before] = (runs[before][0], lo + last_len)
        else:
            runs.append((lo, lo + last_len))
            runs.sort()
    base = child_id * bfmt.SPARSE_CHILD_SIZE
    out = [{
        "offset": base + lo,
        "length": max(0, min(hi, len(data)) - lo),
        "data": data[lo:hi],
        "where": f"#{child.id} stream 1 0x{lo:x}",
    } for lo, hi in runs]
    return out, notes


def _gaps(ranges: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """The byte ranges between the stored ranges, from 0 to the last end."""
    gaps: list[tuple[int, int]] = []
    pos = 0
    for r in sorted(ranges, key=lambda x: x["offset"]):
        if r["offset"] > pos:
            gaps.append((pos, r["offset"]))
        pos = max(pos, r["offset"] + r["length"])
    return gaps
