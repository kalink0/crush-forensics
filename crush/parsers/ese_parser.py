# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ESE (Extensible Storage Engine, "JET Blue") database parser: SRUDB.dat,
Windows.edb, WebCacheV01.dat, ntds.dit, Exchange .edb and others.

The decoding itself is in crush/parsers/ese_reader.py. This module turns the
tables into the Table Viewer's shape:

- every table of the catalog (system tables included), with each record's
  state (Live, or Deleted for a node ESE flagged deleted but has not yet
  removed) and the page it is stored on in front of the table's columns;
- a "[Schema]" table listing every column with its ESE type, codepage and
  flags, so the declared type of a value is always visible;
- the first _ROW_LIMIT rows of each table in memory, and every row in a
  temporary SQLite file (``__db_path``) for SQL queries and paging, so a
  large database is never held in memory as a whole.

A value that could not be decoded is shown as its raw bytes, and why is
listed in the Properties panel ("Not decoded").
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
from collections import Counter
from typing import Any

from crush.core import tempdir
from crush.core.issues import ParseIssue
from crush.core.load_phase import check_cancelled
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.ese_reader import (
    ESE_SIGNATURE,
    Column,
    EseDatabase,
    EseError,
    is_undecoded,
    undecoded_parts,
)

_logger = logging.getLogger(__name__)

# Rows of each table shown without SQL (as for SQLite databases).
_ROW_LIMIT = 10_000
# Characters of text collected for the file filter's content search.
_TEXT_INDEX_LIMIT = 8_000
_INSERT_BATCH = 2_000

SCHEMA_TABLE = "[Schema]"
STATE_LIVE = "Live"
STATE_DELETED = "Deleted"


class EseParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".edb", ".dat", ".dit"]
    DISPLAY_NAME = "ESE database"
    # Reads from the VFS and writes a temp SQLite file; no Qt objects or
    # connections are kept in the result.
    PARSE_OFF_UI_THREAD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        # Signature at offset 4, file type 0 (database: transaction logs and
        # checkpoint files share the signature but not the layout) and a page
        # size ESE uses.
        if len(peek_bytes) < 240 or peek_bytes[4:8] != ESE_SIGNATURE:
            return False
        file_type, = struct.unpack_from("<I", peek_bytes, 12)
        page_size, = struct.unpack_from("<I", peek_bytes, 236)
        return file_type == 0 and page_size in (0, 2048, 4096, 8192, 16384, 32768)

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        try:
            with vfs.open(node) as stream:
                return _parse(node, stream)
        except EseError as exc:
            return _failed(node, vfs, exc.issue)
        except Exception as exc:  # noqa: BLE001 -- one bad file must not stop the app
            _logger.warning("ESE parse error for %s: %s", node.path, exc, exc_info=True)
            return _failed(node, vfs, ParseIssue("ese.parse_failed", detail=str(exc)))


def _failed(node: VFSNode, vfs: VFS, issue: ParseIssue) -> ParseResult:
    try:
        raw = vfs.read(node) if node.size <= 64 * 1024 * 1024 else vfs.peek(node, 1024 * 1024)
    except Exception:  # noqa: BLE001
        raw = b""
    return ParseResult(
        viewer_type="hex",
        data=raw,
        metadata={
            "Format": "ESE database",
            "File size": f"{node.size:,} B",
            "Parse error": issue,
        },
    )


def _parse(node: VFSNode, stream: Any) -> ParseResult:
    db = EseDatabase(stream, node.size)
    hdr = db.header
    meta: dict[str, Any] = {
        "Format": "ESE database",
        "File size": f"{node.size:,} B",
        "Version": hdr.format_text,
        "Page size": f"{hdr.page_size:,} B",
        "Database state": hdr.state_name,
    }
    if hdr.creation_time:
        meta["Created"] = hdr.creation_time
    if hdr.db_state == 2:
        meta["Status"] = ParseIssue("ese.dirty_shutdown")
    meta["Note"] = [ParseIssue("ese.times_local"), ParseIssue("ese.checksums_not_verified")]

    fd, sql_path = tempdir.mkstemp(suffix=".db", prefix="crush_ese_")
    os.close(fd)
    conn = sqlite3.connect(sql_path)
    data: dict[str, Any] = {}
    text_parts: list[str] = []
    text_len = 0
    not_decoded: Counter[tuple[str, str]] = Counter()
    first_issue: dict[tuple[str, str], ParseIssue] = {}
    table_problems: list[ParseIssue] = list(db.catalog_problems)
    total_records = 0
    total_deleted = 0
    sql_issue: ParseIssue | None = None

    schema_rows: list[list[Any]] = []
    for table in db.tables:
        for col in db.table_columns(table):
            schema_rows.append([
                table.name, col.name, col.id, col.type_name,
                col.codepage or None, f"0x{col.flags:x}",
                "template" if col.from_template else None,
            ])
    schema_cols = ["Table", "Column", "Column id", "Type", "Codepage", "Flags", "From template"]
    data[SCHEMA_TABLE] = {"columns": schema_cols, "rows": schema_rows, "truncated": False}
    sql_issue = sql_issue or _sql_write_table(conn, SCHEMA_TABLE, schema_cols, schema_rows)

    for table in db.tables:
        columns = db.table_columns(table)
        names = _column_names(columns)
        sql_cols = names
        rows: list[list[Any]] = []
        batch: list[list[Any]] = []
        problems: list[ParseIssue] = []
        sql_ok = sql_issue is None and _sql_create(conn, table.name, sql_cols)
        count = 0
        for record in db.iter_records(table, problems):
            count += 1
            if count % 1000 == 0:
                check_cancelled()
            if record.deleted:
                total_deleted += 1
            row: list[Any] = [STATE_DELETED if record.deleted else STATE_LIVE, record.page]
            for col in columns:
                key = -col.id if col.from_template and col.id >= 256 else col.id
                value = _display(record.values.get(key))
                for issue in _issues_in(record.values.get(key)):
                    k = (table.name, issue.code)
                    not_decoded[k] += 1
                    first_issue.setdefault(k, issue)
                row.append(value)
                if text_len < _TEXT_INDEX_LIMIT and isinstance(value, str) and value.strip():
                    text_parts.append(value)
                    text_len += len(value)
            if len(rows) <= _ROW_LIMIT:
                rows.append(row)
            if sql_ok:
                batch.append([_sql_value(v) for v in row])
                if len(batch) >= _INSERT_BATCH:
                    sql_issue = _sql_insert(conn, table.name, sql_cols, batch)
                    sql_ok = sql_issue is None
                    batch = []
        if sql_ok and batch:
            sql_issue = _sql_insert(conn, table.name, sql_cols, batch)
        total_records += count
        truncated = len(rows) > _ROW_LIMIT
        data[table.name] = {
            "columns": names,
            "rows": rows[:_ROW_LIMIT],
            "truncated": truncated,
        }
        for p in problems:
            table_problems.append(ParseIssue("ese.table_problem", {"table": table.name, "problem": p}))

    try:
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        sql_issue = sql_issue or ParseIssue("ese.sql_failed", detail=str(exc))
    if sql_issue is None:
        data["__db_path"] = sql_path
    else:
        meta["SQL"] = sql_issue

    meta["Tables"] = str(len(db.tables))
    meta["Records"] = f"{total_records:,}"
    if total_deleted:
        meta["Deleted"] = ParseIssue("ese.deleted_records", {"count": total_deleted})
    if not_decoded:
        meta["Not decoded"] = [
            ParseIssue("ese.not_decoded", {
                "table": tname, "count": n, "reason": first_issue[(tname, code)],
            })
            for (tname, code), n in sorted(not_decoded.items())
        ]
    if table_problems:
        meta["Parse warning"] = table_problems
    return ParseResult(
        viewer_type="table",
        data=data,
        metadata=meta,
        text_index=" ".join(text_parts),
        viewer_hints={"show_db_tabs": False},
        format_short_name="ESE",
    )


def _column_names(columns: list[Column]) -> list[str]:
    """Header names: record state and page first, then the table's columns.
    A table column of the same name as one of ours keeps its name; ours
    gets an "(ESE)" suffix. Duplicate column names (template + own) get
    their id appended."""
    taken = {c.name for c in columns}
    state = "Record state" if "Record state" not in taken else "Record state (ESE)"
    page = "Page" if "Page" not in taken else "Page (ESE)"
    names = [state, page]
    seen: set[str] = set(names)
    for col in columns:
        name = col.name if col.name not in seen else f"{col.name} (id {col.id})"
        seen.add(name)
        names.append(name)
    return names


def _display(value: Any) -> Any:
    """A decoded value as the Table Viewer shows it."""
    if is_undecoded(value):
        raw, _issue = undecoded_parts(value)
        return raw
    if isinstance(value, list):
        return [_display(v) for v in value]
    return value


def _issues_in(value: Any) -> list[ParseIssue]:
    if is_undecoded(value):
        return [undecoded_parts(value)[1]]
    if isinstance(value, list):
        return [i for v in value for i in _issues_in(v)]
    return []


def _sql_value(value: Any) -> Any:
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return value[0]
    if isinstance(value, list):
        return json.dumps([_json_value(v) for v in value], ensure_ascii=False)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and not -(2**63) <= value < 2**63:
        return str(value)
    return value


def _json_value(value: Any) -> Any:
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return value[0]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _sql_create(conn: sqlite3.Connection, table: str, columns: list[str]) -> bool:
    try:
        conn.execute(
            f"CREATE TABLE {_quote(table)} ({', '.join(_quote(c) for c in columns)})"  # noqa: S608
        )
        return True
    except sqlite3.Error as exc:
        _logger.warning("ESE: SQL table %r not created: %s", table, exc)
        return False


def _sql_insert(
    conn: sqlite3.Connection, table: str, columns: list[str], rows: list[list[Any]]
) -> ParseIssue | None:
    placeholders = ", ".join("?" * len(columns))
    try:
        conn.executemany(f"INSERT INTO {_quote(table)} VALUES ({placeholders})", rows)  # noqa: S608
        return None
    except sqlite3.Error as exc:
        return ParseIssue("ese.sql_failed", detail=str(exc))


def _sql_write_table(
    conn: sqlite3.Connection, table: str, columns: list[str], rows: list[list[Any]]
) -> ParseIssue | None:
    if not _sql_create(conn, table, columns):
        return ParseIssue("ese.sql_failed", detail=f"table {table!r} not created")
    return _sql_insert(conn, table, columns, rows)

