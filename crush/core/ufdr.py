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
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crush.core import tempdir
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

_TYPE_DIR = 1
_TYPE_FILE = 2
# Type 10: Cellebrite's own embedded/carved sub-items synthesised inside
# another node (e.g. an AndroidManifest.xml pulled virtually out of a real
# base.apk node). Excluded by design -- redundant with crush's own
# recursive ZIP/7z drill-down once the real container file is opened
# directly, and including it would mean two different views of the same
# bytes under two different paths.
_INCLUDED_TYPES = frozenset({_TYPE_DIR, _TYPE_FILE})

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


class UFDRHandle:
    """An opened UFDR: the outer ZIP, the built VFSNode tree, and the
    means to resolve a tree node back to its physical bytes."""

    def __init__(
        self,
        zf: zipfile.ZipFile,
        tree: "VFSNode",
        node_meta: dict[str, _NodeMeta],
    ) -> None:
        self.zf = zf
        self.tree = tree
        self._node_meta = node_meta
        self._by_exact: dict[tuple[str, str], zipfile.ZipInfo] = {}
        self._by_bucket_size: dict[tuple[str, int], list[zipfile.ZipInfo]] = defaultdict(list)
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("files/"):
                continue
            tag, _, name = info.filename[len("files/") :].partition("/")
            if not name:
                continue
            self._by_exact[(tag, name)] = info
            self._by_bucket_size[(tag, info.file_size)].append(info)
        self._resolved: dict[str, zipfile.ZipInfo | None] = {}

    def close(self) -> None:
        self.zf.close()

    def _hash_matches(self, info: zipfile.ZipInfo, expected_md5: str | None) -> bool:
        if not expected_md5:
            return True  # nothing recorded to check against -- accept the tag+name+size match
        with self.zf.open(info) as f:
            data = f.read()
        return hashlib.md5(data).hexdigest().lower() == expected_md5.lower()

    def _candidates(self, meta: _NodeMeta) -> list[zipfile.ZipInfo]:
        seen: list[zipfile.ZipInfo] = []
        exact = self._by_exact.get((meta.tag, meta.bucket_name))
        if exact is not None and exact.file_size == meta.size:
            seen.append(exact)
        for info in self._by_bucket_size.get((meta.tag, meta.size), []):
            if info not in seen:
                seen.append(info)
        return seen

    def _resolve_uncached(self, meta: _NodeMeta | None) -> zipfile.ZipInfo | None:
        if meta is None:
            return None
        for info in self._candidates(meta):
            if info.file_size <= STREAM_THRESHOLD:
                # Cheap: we would buffer this whole member for read() anyway.
                if self._hash_matches(info, meta.md5):
                    return info
            else:
                # Verifying would mean streaming a huge member twice (once to
                # verify, once to actually serve it) -- trust the
                # Tag+Name+Size match instead of double-buffering it.
                return info
        return None

    def resolve(self, node: "VFSNode") -> zipfile.ZipInfo:
        """The physical ZipInfo backing *node*, or raise
        UFDRContentNotLocatedError -- never silently return nothing."""
        if node.path not in self._resolved:
            self._resolved[node.path] = self._resolve_uncached(self._node_meta.get(node.path))
        info = self._resolved[node.path]
        if info is None:
            raise UFDRContentNotLocatedError(f"Content not located in UFDR container: {node.path}")
        return info

    def node_info(self, node: "VFSNode") -> dict[str, str] | None:
        """Cellebrite's own recorded hashes/category for *node*, plus an
        explicit status if its bytes couldn't be located -- None for
        directories or nodes with no Nodes-table metadata."""
        meta = self._node_meta.get(node.path)
        if meta is None:
            return None
        info: dict[str, str] = {
            "Cellebrite MD5": meta.md5 or "(not recorded)",
            "Cellebrite SHA-256": meta.sha256 or "(not recorded)",
            "Category (Tag)": meta.tag,
            "Carved": "Yes" if meta.is_carved else "No",
        }
        try:
            self.resolve(node)
        except UFDRContentNotLocatedError:
            info["Content status"] = "not located in container"
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


def _device_schemas(dump: Any) -> list[str]:
    """Every `device_<uuid>` schema in the dump, discovered by scanning its
    entries rather than assumed to be exactly one -- a UFDR can bundle
    multiple extractions (settings.json's MergeSingleProject and
    database.json's SourceExtractionIds list both point at this being
    possible), even though the sample used to build this only has one."""
    return sorted(
        {e.tag for e in dump.entries if e.desc == "SCHEMA" and (e.tag or "").startswith("device_")}
    )


def _table_columns(dump: Any, schema: str, tag: str) -> list[str]:
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
            missing = _REQUIRED_NODE_COLUMNS - set(columns)
            if missing:
                raise UFDROpenError(
                    f"UFDR database's {tag!r} table is missing expected column(s): "
                    f"{', '.join(sorted(missing))}"
                )
            return columns
    raise UFDROpenError(f"UFDR database has no {tag!r} table in schema {schema!r}")


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


def _build_device_tree(dump: Any, schema: str, node_meta: dict[str, _NodeMeta], root: "VFSNode") -> None:
    """Walk *schema*'s Nodes table and attach its filesystem tree under
    *root* -- directly if it's the only device, or (handled by the caller)
    under a per-device folder if there are several.

    Built from AbsolutePath, split into segments and synthesising any
    missing intermediate directories -- the same shape ZipVFS/
    ITunesBackupVFS already build their trees in, and it doesn't require
    every ancestor directory to have its own Nodes row.
    """
    from crush.core.vfs import VFSNode

    nodes: dict[str, VFSNode] = {root.path: root}
    id_to_path: dict[str, str] = {}
    pending: list[dict[str, Any]] = []
    columns = _table_columns(dump, schema, "Nodes")

    for row in dump.table_data(schema, "Nodes"):
        d = _row_dict(row, columns)
        try:
            type_ = int(d["Type"])
        except (TypeError, ValueError):
            continue
        if type_ not in _INCLUDED_TYPES:
            continue
        abs_path = d["AbsolutePath"]
        if not abs_path:
            pending.append(d)
            continue
        parts = [p for p in abs_path.strip("/").split("/") if p]
        if not parts:
            continue  # the device root itself -- already represented by `root`

        # Ensure every intermediate directory exists.
        parent_path = root.path
        for depth in range(1, len(parts)):
            virtual_path = _child_path(root.path, "/".join(parts[:depth]))
            if virtual_path not in nodes:
                node = VFSNode(name=parts[depth - 1], path=virtual_path, is_dir=True)
                nodes[parent_path].children.append(node)
                nodes[virtual_path] = node
            parent_path = virtual_path

        is_dir = type_ == _TYPE_DIR
        leaf_path = _child_path(parent_path, parts[-1])
        if leaf_path in nodes and nodes[leaf_path].is_dir != is_dir:
            # A file's path collides with a directory synthesised from
            # another row's ancestry (or vice versa) -- keep both.
            leaf_path = f"{leaf_path} (file)" if not is_dir else f"{leaf_path} (dir)"
            _logger.warning("UFDR: path collision at %s, kept as %s", abs_path, leaf_path)
        leaf = nodes.get(leaf_path)
        if leaf is None:
            leaf = VFSNode(name=parts[-1], path=leaf_path, is_dir=is_dir)
            nodes[parent_path].children.append(leaf)
            nodes[leaf_path] = leaf

        id_to_path[d["Id"]] = leaf.path
        if not is_dir:
            _set_leaf_fields(leaf, d, node_meta)

    # Fallback for the unconfirmed case of a null/empty AbsolutePath: attach
    # under the parent's already-resolved path, or a synthetic bucket at the
    # schema root if that can't be resolved either -- never drop a row.
    if pending:
        no_path_root = _child_path(root.path, "(no path)")
        for d in pending:
            type_ = int(d["Type"])
            is_dir = type_ == _TYPE_DIR
            name = d["Name"] or d["Id"]
            parent_path = id_to_path.get(d["ParentId"], no_path_root)
            if parent_path == no_path_root and no_path_root not in nodes:
                dir_node = VFSNode(name="(no path)", path=no_path_root, is_dir=True)
                root.children.append(dir_node)
                nodes[no_path_root] = dir_node
            leaf_path = _child_path(parent_path, name)
            leaf = nodes.get(leaf_path)
            if leaf is None or leaf.is_dir != is_dir:
                leaf = VFSNode(name=name, path=leaf_path, is_dir=is_dir)
                nodes[parent_path].children.append(leaf)
                nodes[leaf_path] = leaf
            id_to_path[d["Id"]] = leaf.path
            if not is_dir:
                _set_leaf_fields(leaf, d, node_meta)

    for node in nodes.values():
        node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))


def open_ufdr(path: str | Path) -> UFDRHandle:
    """Open a UFDR container: validate its layout, extract and parse the
    embedded Postgres dump, and build the device filesystem tree(s)."""
    from crush.core.vfs import VFSNode

    p = Path(path)
    try:
        zf = zipfile.ZipFile(p, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise UFDROpenError(
            "Not a readable UFDR container -- if this was exported as multiple parts, "
            "rejoin them first; segmented UFDR exports aren't supported yet."
        ) from exc

    try:
        names = set(zf.namelist())
        missing = [m for m in _REQUIRED_MEMBERS if m not in names]
        if missing:
            raise UFDROpenError(f"Not a UFDR container -- missing {', '.join(missing)}")

        try:
            manifest = json.loads(zf.read("DbData/database.json"))
        except (json.JSONDecodeError, KeyError, zipfile.BadZipFile):
            manifest = {}
        manifest_device_id = manifest.get("DeviceId")

        db_info = zf.getinfo("DbData/database.db")
        space = tempdir.check_space(db_info.file_size)
        if not space.enough_space:
            raise UFDROpenError(
                f"Not enough space in the temp directory to extract the UFDR's database "
                f"({db_info.file_size:,} bytes needed, {space.free:,} available at {space.location})"
            )

        fd, tmp_path_str = tempdir.mkstemp(prefix="crush-ufdr-db-", suffix=".db")
        tmp_path = Path(tmp_path_str)
        try:
            with zf.open("DbData/database.db") as src, os.fdopen(fd, "wb") as dst:
                copy_stream(src, dst, total=db_info.file_size)

            import pgdumplib

            dump = pgdumplib.load(tmp_path)
            try:
                schemas = _device_schemas(dump)
                if not schemas:
                    raise UFDROpenError(
                        "UFDR database has no per-device schema -- unrecognised layout"
                    )
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

                root = VFSNode(name=p.name, path="/", is_dir=True)
                node_meta: dict[str, _NodeMeta] = {}
                if len(schemas) == 1:
                    _build_device_tree(dump, schemas[0], node_meta, root)
                else:
                    for schema in schemas:
                        device_root = VFSNode(
                            name=_device_label(schema), path=f"/{_device_label(schema)}", is_dir=True
                        )
                        root.children.append(device_root)
                        _build_device_tree(dump, schema, node_meta, device_root)
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

    return UFDRHandle(zf, root, node_meta)
