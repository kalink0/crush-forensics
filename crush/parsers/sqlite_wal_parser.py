# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SQLite Write-Ahead Log (`-wal`) parser -- structured view for a WAL file
opened on its own, without its companion .db.

Magic-detected (see crush.core.sqlite_wal.classify_wal_frames), same
detection this module's already-existing companion handling in
sqlite_parser.py uses. Unlike a rollback journal, every WAL frame is
legitimately part of some version of the database's real content (Active,
Superseded, or Uncommitted -- see classify_wal_frames' docstring), so there
is no "merge into a reconstructed current view" step here: this just lists
every frame's own decoded page content directly, the same inventory
table_viewer.py's "WAL Frames" tab builds for a -wal opened alongside its
.db. No schema is available without the companion database, so rows are
shown as raw decoded values, not resolved to real column names.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from crush.core.sqlite_wal import (
    PAGE_TYPE_TABLE_LEAF,
    classify_wal_frames,
    get_btree_page_type,
    parse_table_leaf_page,
)
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

_WAL_MAGIC_BYTES = (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")


class SQLiteWALParser(AbstractParser):
    SUPPORTED_EXTENSIONS = ["-wal"]
    DISPLAY_NAME = "SQLite WAL"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[:4] in _WAL_MAGIC_BYTES

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        classified = classify_wal_frames(raw)

        columns = ["Frame", "Page", "Transaction", "Status", "RowID", "Value", "Offset (B)"]
        rows: list[list[Any]] = []
        text_parts: list[str] = []

        if classified is not None:
            page_size, frames = classified
            for f in frames:
                page_start = f["offset"] + 24
                page_bytes = raw[page_start: page_start + page_size]
                btree_offset = 100 if f["page"] == 1 else 0
                is_leaf = (
                    f["salt_ok"]
                    and get_btree_page_type(page_bytes, f["page"]) == PAGE_TYPE_TABLE_LEAF
                )
                parsed = (
                    parse_table_leaf_page(
                        page_bytes, page_size=page_size, btree_offset=btree_offset,
                    )
                    if is_leaf else None
                )
                if not parsed:
                    rows.append([
                        f["frame"], f["page"], f["tx"] or "—", f["status"],
                        "—", "(not a decodable table-leaf page)" if f["salt_ok"] else "(WAL slack)",
                        f["offset"],
                    ])
                    continue
                for rowid, values in parsed:
                    value_text = str(values)
                    for v in values:
                        if isinstance(v, str) and v.strip():
                            text_parts.append(v)
                    rows.append([
                        f["frame"], f["page"], f["tx"] or "—", f["status"],
                        rowid, value_text, f["offset"],
                    ])

        meta: dict[str, Any] = {
            "Format": "SQLite Write-Ahead Log",
            "File size": f"{node.size:,} B",
        }
        if classified is None:
            meta["Status"] = "Not a valid WAL file (magic mismatch or file too short)"
        else:
            _page_size, frames = classified
            counts = Counter(f["status"] for f in frames)
            meta["Frames"] = str(len(frames))
            meta["Active"] = str(counts.get("Active", 0))
            meta["Superseded"] = str(counts.get("Superseded", 0))
            meta["Uncommitted"] = str(counts.get("Uncommitted", 0))
            meta["WAL slack"] = str(counts.get("WAL slack", 0))
        meta["Note"] = (
            "Shown standalone (no companion database opened alongside it), so rows are "
            "raw decoded values, not resolved to real column names. Open the companion "
            "database normally instead to see this content with column names, table "
            "attribution, and (for Active frames) merged transparently into the live "
            "table view, plus this same per-frame inventory in its own 'WAL Frames' tab."
        )

        data = {"WAL Frames": {"columns": columns, "rows": rows, "truncated": False}}
        return ParseResult(
            viewer_type="table",
            data=data,
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )
