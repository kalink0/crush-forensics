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

from crush.core.cell_locator import RawBytesCellLocator
from crush.core.issues import ParseIssue
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
        # Byte provenance for the embedded Hex pane's "Show Hex" -- keyed by
        # row index (see RawBytesCellLocator/data["rowids"] below), same as
        # table_viewer.py's own companion-mode Rollback Journal tab.
        row_ranges: dict[int, tuple[int, int]] = {}
        decode_problems: list[ParseIssue] = []
        for jr in extract_journal_rows(result, decode_problems):
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
            row_ranges[len(rows)] = (jr.file_offset, jr.file_offset + jr.byte_length)
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
            meta["Status"] = result.error or ParseIssue("sqlite_journal.invalid")
        else:
            n_bad = sum(1 for s in result.segments for r in s.records if not r.checksum_valid)
            meta["Status"] = (
                ParseIssue("sqlite_journal.valid_hot")
                if result.mergeable else
                ParseIssue("sqlite_journal.not_fully_valid", {"mismatches": n_bad})
            )
        meta["Note"] = ParseIssue("sqlite_journal.standalone")
        if decode_problems:
            meta["Not decoded"] = decode_problems

        data: dict[str, Any] = {
            "Journal Records": {
                "columns": columns, "rows": rows, "truncated": False,
                "rowids": list(range(len(rows))),
            },
            "__cell_locator": RawBytesCellLocator(
                file_bytes=raw, label="-journal file", row_ranges=row_ranges,
            ),
        }
        return ParseResult(
            viewer_type="table",
            data=data,
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )
