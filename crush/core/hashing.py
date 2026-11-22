# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Hashes of VFS entries computed on the analyst's request, and where they are kept.

A hash is computed over the bytes ``vfs.open(node)`` returns -- the same
bytes the integrity hashes (on open, on export) cover, so the values can be
compared with those in the log and in crush-export-hashes.txt. For an
archive member that is its unpacked content.

An entry whose status says its content is not read or not stored (a
special file, a link whose target isn't decoded ...; see
crush.core.vfs.NO_CONTENT_STATUSES) is not hashed: it has no content to
hash, and the digest of no bytes would pass for one.

The store keeps every value computed in a window for as long as the source
it belongs to is open (:class:`crush.core.session.Session` forgets a
source's values when it is closed or read again). It holds nothing on disk.
Entries are told apart by the tree node itself, not by path: some sources
hold several entries under one path.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crush.core.vfs import VFS, VFSNode

# Order is display order. Digest lengths are fixed by the algorithms.
ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256")
DISPLAY_NAMES: dict[str, str] = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
_DIGEST_SIZES: dict[str, int] = {"md5": 16, "sha1": 20, "sha256": 32}
_OFFSETS: dict[str, int] = {}
_pos = 1  # byte 0: which algorithms are set
for _alg in ALGORITHMS:
    _OFFSETS[_alg] = _pos
    _pos += _DIGEST_SIZES[_alg]
_RECORD_SIZE = _pos
_CHUNK = 1024 * 1024


_HEX = frozenset("0123456789abcdef")
# Full digest length in hex digits -> the one algorithm it can be.
_FULL_LENGTHS = {2 * size: alg for alg, size in _DIGEST_SIZES.items()}
_MAX_HEX = max(_FULL_LENGTHS)

# HashQuery.problem values (plain facts; the UI words them).
QUERY_NOT_HEX = "not_hex"
QUERY_TOO_LONG = "too_long"


@dataclass(frozen=True)
class HashQuery:
    """A hash the analyst searches for (the filter's hash: token).

    *algorithm* is set when the length is a full digest (32 MD5, 40 SHA-1,
    64 SHA-256): the value must equal a computed one of that algorithm.
    Otherwise (shorter) it is a prefix matched against every computed
    value, any algorithm. *problem* says why nothing can match."""

    hex: str
    algorithm: str | None
    problem: str = ""


def parse_hash_query(value: str) -> HashQuery:
    text = value.strip().lower()
    if not text or any(c not in _HEX for c in text):
        return HashQuery(text, None, QUERY_NOT_HEX)
    if len(text) > _MAX_HEX:
        return HashQuery(text, None, QUERY_TOO_LONG)
    return HashQuery(text, _FULL_LENGTHS.get(len(text)))


def query_can_match(query: HashQuery, computed: dict[str, list[bytes]]) -> bool:
    """Whether *computed* holds a value *query* is matched against: one of
    its algorithm for a full digest, any for a prefix. An entry for which
    this is False is not a non-match -- it has nothing to compare."""
    if query.problem:
        return False
    if query.algorithm is not None:
        return bool(computed.get(query.algorithm))
    return any(computed.values())


def query_matches(query: HashQuery, computed: dict[str, list[bytes]]) -> bool:
    """Whether any computed value (every value per algorithm, also a
    differing later one) equals *query*, or starts with it for a prefix."""
    if query.problem:
        return False
    if query.algorithm is not None:
        return any(v.hex() == query.hex for v in computed.get(query.algorithm, []))
    return any(v.hex().startswith(query.hex) for values in computed.values() for v in values)


class HashCancelled(Exception):
    """The analyst stopped hashing."""


class HashReadError(Exception):
    """The entry's content could not be read (the message says why)."""


def hash_node(
    vfs: VFS,
    node: VFSNode,
    algorithms: Iterable[str],
    *,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[int], None] | None = None,
) -> tuple[dict[str, bytes], int]:
    """Digests of *node*'s content for *algorithms*, in one read pass, and
    the number of bytes read. Raises HashReadError when the content can't be
    read to its end (no digest of a partial read is returned), HashCancelled
    when *cancelled()* turns true. *progress* gets the bytes read so far."""
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    total = 0
    try:
        src = vfs.open(node)
    except Exception as exc:  # noqa: BLE001 -- any reader's failure is a read error here
        raise HashReadError(str(exc)) from exc
    with src:
        while True:
            if cancelled is not None and cancelled():
                raise HashCancelled()
            try:
                chunk = src.read(_CHUNK)
            except Exception as exc:  # noqa: BLE001
                raise HashReadError(str(exc)) from exc
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
            total += len(chunk)
            if progress is not None:
                progress(total)
    return {alg: h.digest() for alg, h in hashers.items()}, total


def iter_files(node: VFSNode) -> Iterator[VFSNode]:
    """*node* itself when it is a file, else every entry below it in tree
    order: files, and folders that carry a status (e.g. one that couldn't be
    listed -- its content is missing, which the caller must show)."""
    stack = [node]
    while stack:
        current = stack.pop()
        if not current.is_dir:
            yield current
            continue
        if current.status:
            yield current
        stack.extend(reversed(current.children))


class HashStore:
    """Computed digests per (source, entry); thread-safe (export workers
    record from their own threads).

    Per entry one packed record holds the first value per algorithm; a
    different value computed later for the same entry and algorithm is kept
    as well, never written over the first -- see :meth:`get`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # id(vfs) -> (vfs, {id(node): (node, record)}). The objects are held
        # so their ids can't be reused while the values are kept.
        self._sources: dict[int, tuple[VFS, dict[int, tuple[VFSNode, bytes]]]] = {}
        # (id(vfs), id(node)) -> further, different values per algorithm
        self._differing: dict[tuple[int, int], dict[str, list[bytes]]] = {}

    def record(self, vfs: VFS, node: VFSNode, digests: dict[str, bytes]) -> None:
        """Keep *digests* for *node*. Nothing is kept for an entry whose
        content is not read or not stored (vfs.has_no_content): the digest of
        no bytes would read like the hash of real content."""
        from crush.core.vfs import has_no_content

        if has_no_content(node):
            return
        with self._lock:
            entries = self._sources.setdefault(id(vfs), (vfs, {}))[1]
            held = entries.get(id(node))
            record = bytearray(held[1]) if held is not None else bytearray(_RECORD_SIZE)
            for alg, digest in digests.items():
                bit = 1 << ALGORITHMS.index(alg)
                start = _OFFSETS[alg]
                end = start + _DIGEST_SIZES[alg]
                if not record[0] & bit:
                    record[0] |= bit
                    record[start:end] = digest
                elif bytes(record[start:end]) != digest:
                    more = self._differing.setdefault((id(vfs), id(node)), {}).setdefault(alg, [])
                    if digest not in more:
                        more.append(digest)
            entries[id(node)] = (node, bytes(record))

    def get(self, vfs: VFS, node: VFSNode) -> dict[str, list[bytes]]:
        """algorithm -> every distinct value computed for *node*, first one
        first (in ALGORITHMS order); more than one value means the content
        read differed between computations."""
        with self._lock:
            source = self._sources.get(id(vfs))
            held = source[1].get(id(node)) if source is not None else None
            if held is None or held[0] is not node:
                return {}
            record = held[1]
            more = self._differing.get((id(vfs), id(node)), {})
            result: dict[str, list[bytes]] = {}
            for i, alg in enumerate(ALGORITHMS):
                if record[0] & (1 << i):
                    start = _OFFSETS[alg]
                    result[alg] = [record[start:start + _DIGEST_SIZES[alg]], *more.get(alg, [])]
            return result

    def forget(self, vfs: VFS) -> None:
        """Drop every value of *vfs* (closed, or read again)."""
        with self._lock:
            self._sources.pop(id(vfs), None)
            key = id(vfs)
            for pair in [p for p in self._differing if p[0] == key]:
                del self._differing[pair]

    def clear(self) -> None:
        with self._lock:
            self._sources.clear()
            self._differing.clear()
