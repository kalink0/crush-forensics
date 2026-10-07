# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Cellebrite UFDR (Physical Analyzer report/delivery container) reading.

A .ufdr file is itself a ZIP. Its `files/<Category>/<name>` entries are the
actual extracted bytes, but organised into Cellebrite's own type buckets
(Application, Image, Text, Database, ...) rather than the original device
path. The real device filesystem tree -- paths, sizes, hashes -- lives in
`DbData/database.db`, a PostgreSQL custom-format `pg_dump` archive (verified
against a real UFDR 10.x sample: `file(1)` reports "PostgreSQL custom
database dump"). It is read with `pgdumplib`, a pure-Python reader -- no
PostgreSQL server involved.

`report.xml`, also present at the UFDR root, duplicates the same data in a
legacy XML report format kept only for compatibility with older Cellebrite
Reader versions (confirmed with the examiner who supplied the sample); it is
never parsed here.

`UFDRVFS` (crush/core/vfs.py) is the thin VFS-facing wrapper; this module
holds everything specific to the container/dump format: extracting and
parsing the embedded Postgres dump, building the device filesystem tree, and
resolving a tree node back to its physical bytes in the outer ZIP.

Deliberately out of scope, both left for a future session with real samples
to verify against rather than guessed at here:
  - Split/segmented UFDR exports (multi-part cases). `open_ufdr()` doesn't
    attempt to detect or rejoin segments; opening one segment on its own
    fails with an explicit UFDROpenError rather than a bare zip exception.
  - Every Cellebrite table other than `Nodes` (Contacts, Calls, Chats, ...).
    This module only browses the device's file/folder tree.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crush.core import tempdir
from crush.core.issues import ParseIssue
from crush.core.vfs_stream import STREAM_THRESHOLD, copy_stream

if TYPE_CHECKING:
    from crush.core.vfs import VFSNode

_logger = logging.getLogger(__name__)

# The four members that identify a UFDR's top-level layout -- required for
# both the .ufdr-extension open path and the zip-content sniff.
_REQUIRED_MEMBERS = (
    "report.xml",
    "DbData/database.db",
    "DbData/database.json",
    "settings.json",
)

# The Nodes table has ~69 columns; these are the ones this module reads.
# pg_dump's COPY data has no column list of its own (copy_stmt is empty in
# a real dump) -- COPY-format rows follow the table's own declared column
# order, which _table_columns() reads from the dump's CREATE TABLE text.
# This set is only a completeness check: raise early, explicitly, if a
# future Cellebrite version drops or renames one of them, rather than
# silently building a tree from the wrong data.
_REQUIRED_NODE_COLUMNS = frozenset(
    {
        "Id",
        "ParentId",
        "Type",
        "Name",
        "AbsolutePath",
        "Size",
        "Md5",
        "Sha256",
        "Tag",
        "IsCarved",
        "CreationTime",
        "ModifyTime",
        "AccessTime",
        "ChangeTime",
    }
)
# Optional: a folder row's ChildCount -- the number of files below it in
# the whole extraction, not only in this UFDR (matched exactly against a
# real sample's original extraction, e.g. 93,173 below /data).
_CHILD_COUNT_COLUMN = "ChildCount"

_REQUIRED_SOURCE_COLUMNS = frozenset({"NodeId", "FileSize"})

# The only tables whose data is read (see _load_dump).
_READ_TABLES = frozenset({"Nodes", "SourceInfoNodes"})

_TYPE_DIR = 1
_TYPE_FILE = 2
# Type 10: an item Physical Analyzer derived from another node -- a
# decrypted copy of an app database (signal.db -> signal.db.decrypted, plus
# its -wal), an AndroidManifest.xml out of a base.apk, images embedded in a
# PDF or cached web page. Its bytes are stored in files/ like any file's.
# Not a file on the device: shown beside the file it came from, saying so
# (see _place_derived).
_TYPE_DERIVED = 10

_EMPTY_MD5 = hashlib.md5(b"").hexdigest()

_EPOCH = datetime(1970, 1, 1)


class UFDROpenError(ValueError):
    """*path* is not a readable UFDR container."""


class UFDRContentNotLocatedError(OSError):
    """A Nodes row's bytes could not be found anywhere in the outer ZIP."""


def is_ufdr_zip(path: str | Path) -> bool:
    """Sniff a zip's internal structure for the UFDR top-level layout, for
    a .ufdr renamed to .zip or opened with its extension stripped."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False
    return all(name in names for name in _REQUIRED_MEMBERS)


def _parse_ts(text: str | None) -> float:
    """Parse a Postgres "timestamp without time zone" COPY-text value
    (`YYYY-MM-DD HH:MM:SS[.ffffff]`) into Unix epoch seconds.

    Verified against a real UFDR sample and its creator's own documented,
    timezone-labelled action log (cross-checked one app's recorded update
    time against the corresponding Nodes.ModifyTime for its base.apk,
    exact to the minute once the documented Eastern-time offset was
    applied): these values are raw UTC, not the project's configured
    report display timezone (database.json's TimeZoneInfo, which only
    governs Cellebrite's own report/PDF generation) and not local device
    time -- so no offset is applied here.

    epoch + timedelta rather than datetime.fromtimestamp(), which would
    reinterpret a naive datetime as local time (same rationale as
    crush/core/ts_decode.py's decode_ts()).
    """
    if not text:
        return 0.0
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return (dt - _EPOCH).total_seconds()
    return 0.0


@dataclass
class _NodeMeta:
    tag: str
    bucket_name: str
    size: int
    md5: str | None
    sha256: str | None
    is_carved: bool
    # Set for a Type 10 item: Cellebrite's own path of the file it was
    # derived from, and whether the UFDR contains that file.
    derived_from: str | None = None
    parent_exported: bool = True


@dataclass
class _Catalog:
    """What building the tree learns about its nodes, for UFDRHandle."""

    # File node path -> its Nodes row's facts.
    node_meta: dict[str, _NodeMeta] = field(default_factory=dict)
    # Placeholder file node path -> Cellebrite's path of a file the UFDR
    # doesn't contain (known only as the source of derived items).
    absent: dict[str, str] = field(default_factory=dict)
    # Folder node path -> (files below it in the extraction per Cellebrite's
    # ChildCount, files below it in this UFDR).
    dir_counts: dict[str, tuple[int, int]] = field(default_factory=dict)


class UFDRHandle:
    """An opened UFDR: the outer ZIP, the built VFSNode tree, and the
    means to resolve a tree node back to its physical bytes."""

    def __init__(self, zf: zipfile.ZipFile, tree: "VFSNode", catalog: _Catalog) -> None:
        self.zf = zf
        self.tree = tree
        self._node_meta = catalog.node_meta
        self._absent = catalog.absent
        self._dir_counts = catalog.dir_counts
        self._by_exact: dict[tuple[str, str], zipfile.ZipInfo] = {}
        self._by_bucket_size: dict[tuple[str, int], list[zipfile.ZipInfo]] = defaultdict(list)
        self._by_size: dict[int, list[zipfile.ZipInfo]] = defaultdict(list)
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("files/"):
                continue
            tag, _, name = info.filename[len("files/") :].partition("/")
            if not name:
                continue
            self._by_exact[(tag, name)] = info
            self._by_bucket_size[(tag, info.file_size)].append(info)
            self._by_size[info.file_size].append(info)
        self._resolved: dict[str, zipfile.ZipInfo | None] = {}
        # Cellebrite stores identical content once and points several Nodes
        # rows at it, and a bucket holds many same-sized members -- each
        # member is hashed at most once, however many rows try it.
        self._member_md5: dict[str, str] = {}
        # Node paths resolved to their only same-bucket, same-size candidate,
        # whose MD5 is checked on first full read rather than on the type
        # pre-scan's peek (see _resolve_uncached).
        self._unconfirmed: set[str] = set()

    def close(self) -> None:
        self.zf.close()

    def _md5_of(self, info: zipfile.ZipInfo) -> str:
        md5 = self._member_md5.get(info.filename)
        if md5 is None:
            digest = hashlib.md5()
            with self.zf.open(info) as f:
                while chunk := f.read(1 << 20):
                    digest.update(chunk)
            md5 = self._member_md5[info.filename] = digest.hexdigest()
        return md5

    def _candidates(self, meta: _NodeMeta) -> list[zipfile.ZipInfo]:
        seen: list[zipfile.ZipInfo] = []
        exact = self._by_exact.get((meta.tag, meta.bucket_name))
        if exact is not None and exact.file_size == meta.size:
            seen.append(exact)
        for info in self._by_bucket_size.get((meta.tag, meta.size), []):
            if info not in seen:
                seen.append(info)
        return seen

    def _resolve_uncached(self, meta: _NodeMeta | None) -> tuple[zipfile.ZipInfo | None, bool]:
        """The member backing *meta*, and whether its MD5 is still to be
        confirmed on first full read."""
        if meta is None:
            return None, False
        candidates = self._candidates(meta)
        if not meta.md5:
            # Nothing recorded to check against -- accept the tag+name+size match.
            return (candidates[0] if candidates else None), False
        if len(candidates) == 1 and candidates[0].file_size <= STREAM_THRESHOLD:
            # The only member of this bucket and size (under the recorded
            # name or a collision-suffixed one): nothing to choose between.
            # Hashing it here would make the type pre-scan decompress every
            # file in full to read its first bytes; it is hashed on first
            # full read or Properties instead (confirm()).
            return candidates[0], True
        expected = meta.md5.lower()
        for info in candidates:
            if info.file_size <= STREAM_THRESHOLD:
                if self._md5_of(info) == expected:
                    return info, False
            else:
                # Verifying would mean streaming a huge member twice (once to
                # verify, once to actually serve it) -- trust the
                # Tag+Name+Size match instead of double-buffering it.
                return info, False
        return self._in_other_buckets(meta, candidates), False

    def _in_other_buckets(self, meta: _NodeMeta, tried: list[zipfile.ZipInfo]) -> zipfile.ZipInfo | None:
        """A same-sized member of another bucket holding *meta*'s recorded
        MD5. Cellebrite stores identical content once across buckets too:
        verified on a real sample, where four `._*.png` files tagged Image
        are stored as `files/Configuration/._scene.config`. Only a hash match
        counts here -- a bucket is no hint any more."""
        if not meta.md5 or meta.size > STREAM_THRESHOLD:
            return None
        expected = meta.md5.lower()
        for info in self._by_size.get(meta.size, []):
            if info not in tried and self._md5_of(info) == expected:
                return info
        return None

    def is_empty(self, node: "VFSNode") -> bool:
        """*node* is a file Cellebrite records as 0 bytes with no other
        hash than an empty one's. The UFDR stores no member for those (all
        268 such files of a real sample): its content is the empty string,
        not something missing."""
        meta = self._node_meta.get(node.path)
        return (
            meta is not None
            and meta.size == 0
            and (not meta.md5 or meta.md5.lower() == _EMPTY_MD5)
        )

    def resolve(self, node: "VFSNode", *, confirm: bool = True) -> zipfile.ZipInfo:
        """The physical ZipInfo backing *node*, or raise
        UFDRContentNotLocatedError -- never silently return nothing.

        confirm=False skips a pending MD5 check: only for reading a few
        leading bytes (peek), never for content handed out as the file's.
        """
        if node.path in self._absent:
            raise UFDRContentNotLocatedError(
                ParseIssue("ufdr.not_exported_content", {"path": self._absent[node.path]})
            )
        if node.path not in self._resolved:
            info, unconfirmed = self._resolve_uncached(self._node_meta.get(node.path))
            self._resolved[node.path] = info
            if unconfirmed:
                self._unconfirmed.add(node.path)
        pending = self._resolved[node.path]
        if confirm and pending is not None and node.path in self._unconfirmed:
            self.confirm(node, self._md5_of(pending))
        info = self._resolved[node.path]
        if info is None:
            raise UFDRContentNotLocatedError(ParseIssue("ufdr.content_not_located", {"path": node.path}))
        return info

    def confirm(self, node: "VFSNode", md5: str) -> None:
        """Settle *node*'s pending MD5 check with the hash of the bytes just
        read: on a mismatch the other buckets are searched, else the node is
        "not located"."""
        if node.path not in self._unconfirmed:
            return
        self._unconfirmed.discard(node.path)
        info = self._resolved[node.path]
        meta = self._node_meta[node.path]
        if info is not None:
            self._member_md5[info.filename] = md5
        if meta.md5 and md5 != meta.md5.lower():
            self._resolved[node.path] = self._in_other_buckets(meta, [info] if info else [])

    def is_unconfirmed(self, node: "VFSNode") -> bool:
        return node.path in self._unconfirmed

    def node_info(self, node: "VFSNode") -> dict[str, Any] | None:
        """Cellebrite's own recorded hashes/category for *node*, plus an
        explicit status if its bytes couldn't be located; for a folder, its
        file count in the extraction and in this UFDR -- None for nodes
        Cellebrite has no record of."""
        counts = self._dir_counts.get(node.path)
        if counts is not None:
            counted, held = counts
            folder: dict[str, Any] = {
                "Extraction files (Cellebrite count)": f"{counted:,}",
                "Extraction files in this UFDR": f"{held:,}",
            }
            if held < counted:
                folder["Missing from this UFDR"] = ParseIssue(
                    "ufdr.files_not_exported", {"missing": counted - held, "counted": counted}
                )
            return folder
        if node.path in self._absent:
            return {
                "Content status": ParseIssue(
                    "ufdr.not_exported_content", {"path": self._absent[node.path]}
                )
            }
        meta = self._node_meta.get(node.path)
        if meta is None:
            return None
        info: dict[str, Any] = {
            "Cellebrite MD5": meta.md5 or ParseIssue("ufdr.not_recorded"),
            "Cellebrite SHA-256": meta.sha256 or ParseIssue("ufdr.not_recorded"),
            "Category (Tag)": meta.tag,
            "Carved": "Yes" if meta.is_carved else "No",
        }
        if meta.derived_from is not None:
            info["Derived from"] = ParseIssue(
                "ufdr.derived_from" if meta.parent_exported else "ufdr.derived_from_not_exported",
                {"path": meta.derived_from},
            )
        if self.is_empty(node):
            return info
        try:
            self.resolve(node)
        except UFDRContentNotLocatedError:
            info["Content status"] = ParseIssue("ufdr.not_located")
        return info


def _close_dump(dump: Any) -> None:
    """Close a pgdumplib.Dump's source file handle.

    The public API (pgdumplib 4.0) has no close() -- Dump.load() opens
    `self._handle = open(path, 'rb')` and never closes it itself. Reaching
    into the private attribute is the only way to release it before the
    temp copy holding it is deleted.
    """
    handle = getattr(dump, "_handle", None)
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass


def _load_dump(path: Path) -> Any:
    """pgdumplib.load(), keeping only the data of the tables read here.

    Dump.load() copies every table's data into a temp cache of its own,
    gzip-recompressed, before returning -- on a real 421 MB UFDR dump that
    is 194 tables and ~12 s, for the two tables read here. The override
    skips the others (load() seeks to each table's offset itself, so nothing
    else is read). Should a future pgdumplib stop calling this hook, every
    table is cached again: slower, same result.
    """
    from pgdumplib import dump as pgdump

    class _ReadTablesOnlyDump(pgdump.Dump):
        def _cache_table_data(self, dump_id: int) -> None:
            entry = next((e for e in self.entries if e.dump_id == dump_id), None)
            if entry is None or entry.tag in _READ_TABLES:
                super()._cache_table_data(dump_id)

    return _ReadTablesOnlyDump().load(path)


def _device_schemas(dump: Any) -> list[str]:
    """Every `device_<uuid>` schema in the dump, discovered by scanning its
    entries rather than assumed to be exactly one -- a UFDR can bundle
    multiple extractions (settings.json's MergeSingleProject and
    database.json's SourceExtractionIds list both point at this being
    possible), even though the sample used to build this only has one."""
    return sorted(
        {e.tag for e in dump.entries if e.desc == "SCHEMA" and (e.tag or "").startswith("device_")}
    )


def _table_columns(dump: Any, schema: str, tag: str, required: frozenset[str]) -> list[str]:
    """The real, declared column order of *schema*.*tag*, parsed from the
    dump's own CREATE TABLE text.

    pg_dump's COPY data carries no column list of its own when the table
    hasn't been reordered by an ALTER TABLE (its `copy_stmt` is empty in
    a real dump, verified against the sample) -- rows follow the table's
    declared column order, which is exactly what a freshly emitted CREATE
    TABLE lists them in.
    """
    for e in dump.entries:
        if e.desc == "TABLE" and e.namespace == schema and e.tag == tag:
            columns = [
                line.strip().split('"')[1]
                for line in e.defn.splitlines()
                if line.strip().startswith('"')
            ]
            missing = required - set(columns)
            if missing:
                raise UFDROpenError(ParseIssue("ufdr.missing_columns", {
                    "tag": repr(tag), "columns": ", ".join(sorted(missing)),
                }))
            return columns
    raise UFDROpenError(ParseIssue("ufdr.no_table", {"tag": repr(tag), "schema": repr(schema)}))


def _source_sizes(dump: Any, schema: str) -> dict[str, int]:
    """Node id -> size, from SourceInfoNodes: Cellebrite's record of the
    file each item was found in (name, path, size, offset of the item in
    it). For a file the UFDR doesn't contain, this is all it records --
    verified on a real sample, where 3,120 of 3,136 such files exist in the
    original extraction with exactly this size. Empty if the table is
    missing or lacks those columns."""
    try:
        columns = _table_columns(dump, schema, "SourceInfoNodes", _REQUIRED_SOURCE_COLUMNS)
    except UFDROpenError:
        return {}
    sizes: dict[str, int] = {}
    for row in dump.table_data(schema, "SourceInfoNodes"):
        d = _row_dict(row, columns)
        try:
            sizes.setdefault(d["NodeId"], int(d["FileSize"]))
        except (TypeError, ValueError):
            continue
    return sizes


def _row_dict(row: tuple[Any, ...], columns: list[str]) -> dict[str, Any]:
    return dict(zip(columns, row))


def _device_label(schema: str) -> str:
    return f"Device {schema[len('device_') :]}" if schema.startswith("device_") else schema


def _child_path(parent_path: str, name: str) -> str:
    return f"/{name}" if parent_path == "/" else f"{parent_path}/{name}"


def _set_leaf_fields(node: "VFSNode", d: dict[str, Any], node_meta: dict[str, _NodeMeta]) -> None:
    node.size = int(d["Size"] or 0)
    node.modified = _parse_ts(d["ModifyTime"])
    node.accessed = _parse_ts(d["AccessTime"])
    node.changed = _parse_ts(d["ChangeTime"])
    node.birth = _parse_ts(d["CreationTime"])
    node_meta[node.path] = _NodeMeta(
        tag=d["Tag"] or "",
        bucket_name=d["Name"] or "",
        size=node.size,
        md5=d["Md5"],
        sha256=d["Sha256"],
        is_carved=d["IsCarved"] == "t",
    )


def _path_parts(abs_path: str) -> list[str]:
    return [p for p in abs_path.strip("/").split("/") if p]


class _TreeBuilder:
    """One device's tree under construction: every node by its tree path,
    and the files stored under each path, so that same-path rows are each
    kept and numbered (as ZipVFS numbers same-named members)."""

    def __init__(self, root: "VFSNode") -> None:
        self.root = root
        self.nodes: dict[str, VFSNode] = {root.path: root}
        self.occurrences: dict[str, list[VFSNode]] = {}
        self.derived_folders: set[str] = set()

    def ensure_dir(self, parts: list[str]) -> str:
        """Tree path of the folder at *parts* below the root, synthesising
        missing ones -- not every ancestor has a Nodes row of its own. A
        segment already taken by a file gets a folder beside it."""
        from crush.core.vfs import VFSNode

        parent_path = self.root.path
        for part in parts:
            path = _child_path(parent_path, part)
            node = self.nodes.get(path)
            status = None
            if node is not None and not node.is_dir:
                part = f"{part} (dir)"
                path = _child_path(parent_path, part)
                node = self.nodes.get(path)
                status = ParseIssue("ufdr.path_collision", {"other": ParseIssue("ufdr.other_file")})
            if node is None:
                node = VFSNode(name=part, path=path, is_dir=True)
                node.status = status or ""
                self.nodes[parent_path].children.append(node)
                self.nodes[path] = node
            parent_path = path
        return parent_path

    def add(self, parent_path: str, name: str, is_dir: bool) -> "VFSNode":
        """A node for one row named *name* in the folder at *parent_path*. A
        folder row reuses the folder already there; a file never shares a
        path: it is placed beside a same-named folder, or numbered after a
        same-named file."""
        from crush.core.vfs import VFSNode, _free_sibling

        stored_path = _child_path(parent_path, name)
        path = stored_path
        existing = self.nodes.get(path)
        status = None
        if existing is not None and existing.is_dir != is_dir:
            # A file's path collides with a directory synthesised from
            # another row's ancestry (or vice versa) -- keep both.
            name = f"{name} (file)" if not is_dir else f"{name} (dir)"
            path = _child_path(parent_path, name)
            _logger.warning("UFDR: path collision at %s, kept as %s", stored_path, path)
            status = ParseIssue("ufdr.path_collision", {
                "other": ParseIssue("ufdr.other_directory" if not is_dir else "ufdr.other_file"),
            })
            existing = self.nodes.get(path)
        if existing is not None and is_dir and existing.is_dir:
            return existing
        if existing is not None:
            name, path = _free_sibling(self.nodes, parent_path, name)
        node = VFSNode(name=name, path=path, is_dir=is_dir)
        node.status = status or ""
        self.nodes[parent_path].children.append(node)
        self.nodes[path] = node
        if not is_dir:
            self.occurrences.setdefault(stored_path, []).append(node)
        return node

    def derived_folder(self, folder: str, parent_name: str, parent_device: str, exported: bool) -> str:
        """Tree path of the "<file> (derived)" folder for the file
        *parent_name* in *folder* -- never a device folder of that name."""
        from crush.core.vfs import VFSNode, _free_sibling

        name = f"{parent_name} (derived)"
        path = _child_path(folder, name)
        if path in self.derived_folders:
            return path
        if path in self.nodes:
            name, path = _free_sibling(self.nodes, folder, name)
        node = VFSNode(name=name, path=path, is_dir=True)
        node.status = ParseIssue(
            "ufdr.derived_folder" if exported else "ufdr.derived_folder_not_exported",
            {"path": parent_device},
        )
        self.nodes[folder].children.append(node)
        self.nodes[path] = node
        self.derived_folders.add(path)
        return path


def _child_count(d: dict[str, Any]) -> int | None:
    try:
        return int(d.get(_CHILD_COUNT_COLUMN))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _build_device_tree(dump: Any, schema: str, catalog: _Catalog, root: "VFSNode") -> None:
    """Walk *schema*'s Nodes table and attach its filesystem tree under
    *root* -- directly if it's the only device, or (handled by the caller)
    under a per-device folder if there are several.

    Built from AbsolutePath, split into segments and synthesising any
    missing intermediate directories -- the same shape ZipVFS/
    ITunesBackupVFS already build their trees in, and it doesn't require
    every ancestor directory to have its own Nodes row. Items Cellebrite
    derived from a file (Type 10) are placed beside that file afterwards
    (_place_derived).

    A UFDR holds only the files Physical Analyzer exported into it, not the
    whole extraction (a real sample: 33,790 of the extraction's 102,897
    files). Each folder row's ChildCount still counts the whole
    extraction, so every folder says how many files it had there and how
    many of them this UFDR holds.
    """
    from crush.core.vfs import join_notes

    node_meta = catalog.node_meta
    tree = _TreeBuilder(root)
    id_to_path: dict[str, str] = {}
    pending: list[dict[str, Any]] = []
    derived: list[dict[str, Any]] = []
    columns = _table_columns(dump, schema, "Nodes", _REQUIRED_NODE_COLUMNS)
    unreadable_type = 0
    other_types: dict[int, int] = defaultdict(int)
    # Folder tree path -> (its device path, ChildCount); device path -> files below.
    folders: dict[str, tuple[str, int]] = {}
    files_below: dict[str, int] = defaultdict(int)

    for row in dump.table_data(schema, "Nodes"):
        d = _row_dict(row, columns)
        try:
            type_ = int(d["Type"])
        except (TypeError, ValueError):
            unreadable_type += 1
            continue
        if type_ == _TYPE_DERIVED:
            derived.append(d)
            continue
        if type_ not in (_TYPE_DIR, _TYPE_FILE):
            other_types[type_] += 1
            continue
        abs_path = d["AbsolutePath"]
        if not abs_path:
            pending.append(d)
            continue
        parts = _path_parts(abs_path)
        is_dir = type_ == _TYPE_DIR
        if not is_dir:
            for depth in range(len(parts)):
                files_below["/" + "/".join(parts[:depth])] += 1
        if not parts:
            # The device root itself -- already represented by `root`.
            count = _child_count(d)
            if is_dir and count is not None:
                folders[root.path] = ("/", count)
            continue

        leaf = tree.add(tree.ensure_dir(parts[:-1]), parts[-1], is_dir)
        id_to_path[d["Id"]] = leaf.path
        if not is_dir:
            _set_leaf_fields(leaf, d, node_meta)
        else:
            count = _child_count(d)
            if count is not None:
                folders[leaf.path] = ("/" + "/".join(parts), count)

    # Fallback for the unconfirmed case of a null/empty AbsolutePath: attach
    # under the parent's already-resolved path, or a synthetic bucket at the
    # schema root if that can't be resolved either -- never drop a row.
    for d in pending:
        is_dir = int(d["Type"]) == _TYPE_DIR
        parent_path = id_to_path.get(d["ParentId"]) or tree.ensure_dir(["(no path)"])
        leaf = tree.add(parent_path, d["Name"] or d["Id"], is_dir)
        id_to_path[d["Id"]] = leaf.path
        if not is_dir:
            _set_leaf_fields(leaf, d, node_meta)

    _place_derived(tree, derived, id_to_path, catalog, _source_sizes(dump, schema))
    for same_path in tree.occurrences.values():
        if len(same_path) > 1:
            for k, node in enumerate(same_path, 1):
                note = ParseIssue("ufdr.duplicate", {"count": len(same_path), "k": k})
                node.status = join_notes([node.status, note])

    for tree_path, (device_path, count) in folders.items():
        catalog.dir_counts[tree_path] = (count, files_below[device_path])

    notes = [root.status]
    root_counts = catalog.dir_counts.get(root.path)
    if root_counts is not None and root_counts[1] < root_counts[0]:
        notes.append(ParseIssue("ufdr.partial_export", {
            "in_ufdr": root_counts[1], "extraction": root_counts[0],
        }))
    elif root_counts is None and any(
        held < counted for tree_path, (counted, held) in catalog.dir_counts.items()
        if tree_path in tree.nodes
    ):
        # No row for the device root (as in a real sample): no total of
        # Cellebrite's to quote, and a sum of the top folders' counts would
        # be one of our own.
        notes.append(ParseIssue("ufdr.partial_export_folders"))
    if unreadable_type:
        notes.append(ParseIssue("ufdr.rows_skipped", {"count": unreadable_type}))
    for type_, count in sorted(other_types.items()):
        notes.append(ParseIssue("ufdr.rows_other_type", {"count": count, "type": type_}))
    root.status = join_notes(notes)

    for node in tree.nodes.values():
        node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))


def _place_derived(
    tree: _TreeBuilder,
    rows: list[dict[str, Any]],
    id_to_path: dict[str, str],
    catalog: _Catalog,
    source_sizes: dict[str, int],
) -> None:
    """Place the items Cellebrite derived from a file (Type 10 rows: a
    decrypted database, images embedded in a PDF, a manifest inside an
    APK) beside that file. Their AbsolutePath runs *through* the file
    (`.../signal.db/signal.db.decrypted`), and a file can't hold children
    in the tree:

    - a file's only derived item sits next to it in the same folder;
    - several derived items (or one whose name is taken there) go into a
      folder "<file> (derived)" next to it.

    The file is found by ParentId (its path is the item's dirname -- verified
    on every such row of a real sample). An item can itself be derived from
    another, e.g. images from a PDF found in a browser cache, so groups are
    placed once their parent is.

    Many items name a file the UFDR doesn't contain: Physical Analyzer
    exported the item, not the file it was found in (a font, a binary, a
    cache entry). That file gets a placeholder at its path, with the size
    Cellebrite recorded for it and no content, and its items are placed
    beside it like any other file's.
    """
    derived_ids = {d["Id"] for d in rows}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in rows:
        groups[d["ParentId"] or f"path:{posixpath.dirname(d['AbsolutePath'] or '')}"].append(d)

    not_exported = _add_placeholders(tree, groups, derived_ids, id_to_path, catalog, source_sizes)

    remaining = dict(groups)
    while remaining:
        ready = [k for k in remaining if k not in derived_ids or k in id_to_path]
        if not ready:
            ready = list(remaining)  # a cycle of derived items -- placed by path
        # (rows, folder, parent file's name or None for "inside folder", device path, exported)
        plans: list[tuple[list[dict[str, Any]], str, str | None, str, bool]] = []
        for key in ready:
            group = remaining.pop(key)
            parent_device = posixpath.dirname(group[0]["AbsolutePath"] or "")
            parent_tree = id_to_path.get(key)
            exported = key not in not_exported
            if parent_tree is None or tree.nodes[parent_tree].is_dir:
                # No path to place a file at, or a folder row: inside it.
                plans.append((group, parent_tree or tree.root.path, None, parent_device, exported))
                continue
            folder, _, parent_name = parent_tree.rpartition("/")
            plans.append((group, folder or "/", parent_name, parent_device, exported))

        # A lone item goes beside its file unless its name is taken there --
        # by a node or by another lone item placed in this round.
        targets: dict[str, int] = defaultdict(int)
        for group, folder, file_name, _, _ in plans:
            if file_name is not None and len(group) == 1:
                targets[_child_path(folder, group[0]["Name"] or group[0]["Id"])] += 1

        for group, folder, file_name, parent_device, exported in plans:
            if file_name is not None:
                name = group[0]["Name"] or group[0]["Id"]
                beside = _child_path(folder, name)
                if len(group) > 1 or beside in tree.nodes or targets[beside] > 1:
                    folder = tree.derived_folder(folder, file_name, parent_device, exported)
            for d in group:
                leaf = tree.add(folder, d["Name"] or d["Id"], False)
                id_to_path[d["Id"]] = leaf.path
                _set_leaf_fields(leaf, d, catalog.node_meta)
                meta = catalog.node_meta[leaf.path]
                meta.derived_from = parent_device
                meta.parent_exported = exported


def _add_placeholders(
    tree: _TreeBuilder,
    groups: dict[str, list[dict[str, Any]]],
    derived_ids: set[str],
    id_to_path: dict[str, str],
    catalog: _Catalog,
    source_sizes: dict[str, int],
) -> set[str]:
    """A placeholder file node for every file that items were derived from
    but that the UFDR doesn't contain; returns those files' ids.

    Shallow paths first: a missing file can lie inside another missing (or
    present) file -- an icon inside a cache entry -- and then goes into that
    file's "(derived)" folder, never under a folder named like a file.
    """
    from crush.core.vfs import join_notes

    missing: list[tuple[list[str], str]] = []
    for key, group in groups.items():
        if key in id_to_path or key in derived_ids:
            continue
        parts = _path_parts(posixpath.dirname(group[0]["AbsolutePath"] or ""))
        if parts:
            missing.append((parts, key))
    missing.sort(key=lambda m: (len(m[0]), m[0]))

    for parts, key in missing:
        outer_path = _child_path(tree.root.path, "/".join(parts[:-1])) if len(parts) > 1 else tree.root.path
        outer = tree.nodes.get(outer_path)
        if outer is not None and not outer.is_dir:
            folder_of_outer, _, outer_name = outer_path.rpartition("/")
            folder = tree.derived_folder(
                folder_of_outer or "/", outer_name, "/" + "/".join(parts[:-1]),
                outer_path not in catalog.absent,
            )
        else:
            folder = tree.ensure_dir(parts[:-1])
        placeholder: VFSNode = tree.add(folder, parts[-1], False)
        device_path = "/" + "/".join(parts)
        size = source_sizes.get(key)
        if size is not None:
            placeholder.size = size
            note = ParseIssue("ufdr.not_exported", {"size": size})
        else:
            note = ParseIssue("ufdr.not_exported_no_size")
        placeholder.status = join_notes([placeholder.status, note])
        catalog.absent[placeholder.path] = device_path
        id_to_path[key] = placeholder.path
    return {key for _, key in missing}


def open_ufdr(path: str | Path) -> UFDRHandle:
    """Open a UFDR container: validate its layout, extract and parse the
    embedded Postgres dump, and build the device filesystem tree(s)."""
    from crush.core.vfs import VFSNode

    p = Path(path)
    try:
        zf = zipfile.ZipFile(p, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise UFDROpenError(ParseIssue("ufdr.not_readable", detail=str(exc))) from exc

    try:
        names = set(zf.namelist())
        missing = [m for m in _REQUIRED_MEMBERS if m not in names]
        if missing:
            raise UFDROpenError(ParseIssue("ufdr.missing_members", {"members": ", ".join(missing)}))

        try:
            manifest = json.loads(zf.read("DbData/database.json"))
        except (json.JSONDecodeError, KeyError, zipfile.BadZipFile):
            manifest = {}
        manifest_device_id = manifest.get("DeviceId")

        db_info = zf.getinfo("DbData/database.db")
        space = tempdir.check_space(db_info.file_size)
        if not space.enough_space:
            raise UFDROpenError(ParseIssue("ufdr.no_space", {
                "needed": db_info.file_size, "free": space.free, "location": str(space.location),
            }))

        fd, tmp_path_str = tempdir.mkstemp(prefix="crush-ufdr-db-", suffix=".db")
        tmp_path = Path(tmp_path_str)
        try:
            with zf.open("DbData/database.db") as src, os.fdopen(fd, "wb") as dst:
                copy_stream(src, dst, total=db_info.file_size)

            dump = _load_dump(tmp_path)
            try:
                schemas = _device_schemas(dump)
                if not schemas:
                    raise UFDROpenError(ParseIssue("ufdr.no_device_schema"))
                if (
                    manifest_device_id
                    and f"device_{manifest_device_id}" not in schemas
                ):
                    _logger.warning(
                        "UFDR: database.json's DeviceId %s has no matching device_* schema "
                        "in the dump (found: %s) -- using the schemas found in the dump",
                        manifest_device_id,
                        schemas,
                    )
                    device_mismatch: ParseIssue | None = ParseIssue("ufdr.device_id_mismatch", {
                        "device": manifest_device_id, "found": ", ".join(schemas),
                    })
                else:
                    device_mismatch = None

                root = VFSNode(name=p.name, path="/", is_dir=True)
                if device_mismatch is not None:
                    root.status = device_mismatch
                catalog = _Catalog()
                if len(schemas) == 1:
                    _build_device_tree(dump, schemas[0], catalog, root)
                else:
                    for schema in schemas:
                        device_root = VFSNode(
                            name=_device_label(schema), path=f"/{_device_label(schema)}", is_dir=True
                        )
                        root.children.append(device_root)
                        _build_device_tree(dump, schema, catalog, device_root)
                    root.children.sort(key=lambda n: n.name.lower())
            finally:
                # pgdumplib.Dump.load() keeps its source file open (no public
                # close()) -- release it before the outer finally tries to
                # delete that same temp file. Windows refuses to unlink an
                # open file (unlike POSIX, where the delete just succeeds and
                # the handle keeps the bytes alive until closed) -- this was
                # missed on the first pass and only surfaced on Windows CI.
                _close_dump(dump)
        finally:
            tmp_path.unlink(missing_ok=True)
    except Exception:
        zf.close()
        raise

    return UFDRHandle(zf, root, catalog)
