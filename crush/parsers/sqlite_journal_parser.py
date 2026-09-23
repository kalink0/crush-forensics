# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SQLite legacy rollback-journal (`-journal`) parser -- structured view for
a journal file opened on its own, without its companion database.

Magic-detected (see crush.core.sqlite_journal.JOURNAL_MAGIC), unlike the
-wal/-shm companions SQLiteParser copies alongside a database. A standalone
journal is never merged into anything here either -- there's no companion
database to reconstruct a "current" view against in the first place, so this
just shows the full raw record inventory (live cells, deleted-but-
recoverable freeblocks, non-zero unallocated-space slack) that
table_viewer.py's "Rollback Journal" tab also builds for a companion
journal opened alongside its database -- reused here as the entire parse
result, since a standalone journal has no schema/tables of its own to
organize rows by.
"""
from __future__ import annotations

from typing import Any

from crush.core.sqlite_journal import (
    JOURNAL_MAGIC,
    extract_journal_rows,
    parse_rollback_journal,
)
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult


class SQLiteJournalParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".db-journal"]
    DISPLAY_NAME = "SQLite rollback journal"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[:8] == JOURNAL_MAGIC

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        result = parse_rollback_journal(raw)

        columns = [
            "Segment", "Record", "Page", "Kind", "RowID", "Value", "Checksum", "Offset (B)",
        ]
        rows: list[list[Any]] = []
        text_parts: list[str] = []
        for jr in extract_journal_rows(result):
            if jr.kind == "Live cell":
                value = str(jr.values)
                for v in jr.values or []:
                    if isinstance(v, str) and v.strip():
                        text_parts.append(v)
            elif jr.raw is not None and not any(jr.raw):
                value = f"(all zero — {len(jr.raw)} B)"
            elif jr.raw is not None:
                value = jr.raw.decode("utf-8", errors="replace")
                if value.strip():
                    text_parts.append(value)
            else:
                value = ""
            rows.append([
                jr.segment_index,
                jr.record_index,
                jr.page_num,
                jr.kind,
                jr.rowid if jr.rowid is not None else "—",
                value,
                "valid" if jr.checksum_valid else "MISMATCH",
                jr.file_offset,
            ])

        n_records = sum(len(s.records) for s in result.segments)
        meta: dict[str, Any] = {
            "Format": "SQLite rollback journal",
            "File size": f"{node.size:,} B",
            "Segments": str(len(result.segments)),
            "Page records": str(n_records),
            "Recovered entries": str(len(rows)),
        }
        if not result.segments:
            meta["Status"] = result.error or "Not a valid rollback journal"
        else:
            n_bad = sum(1 for s in result.segments for r in s.records if not r.checksum_valid)
            meta["Status"] = (
                "Valid / hot — every segment header and page checksum validated"
                if result.mergeable else
                f"NOT fully valid — {n_bad} checksum mismatch(es); shown raw, unmerged"
            )
        meta["Note"] = (
            "This is the journal's own pre-transaction page content, shown standalone "
            "(no companion database opened alongside it). Open the companion database "
            "normally instead to see this same inventory in its own 'Rollback Journal' "
            "tab, with a valid journal's content automatically merged into the "
            "database's default table view (never applied to any file on disk)."
        )

        data = {"Journal Records": {"columns": columns, "rows": rows, "truncated": False}}
        return ParseResult(
            viewer_type="table",
            data=data,
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )
