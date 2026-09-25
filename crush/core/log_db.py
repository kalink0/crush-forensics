# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SQLite-backed temporary database for Multi-Log Studio.

One LogDatabase instance is created per MultiLogViewer and lives for the
duration of that viewer.  All log entries from all sources are stored here;
the QAbstractTableModel queries this database instead of holding entries in
memory.

Schema
------
entries
    rowid       INTEGER PRIMARY KEY  — SQLite implicit rowid
    source_id   INTEGER NOT NULL     — maps to MultiLogViewer source registry
    ts_unix     REAL                 — UTC epoch (float), NULL when unknown
    level       TEXT NOT NULL        — ERROR/WARN/INFO/DEBUG/TRACE/UNKNOWN
    process     TEXT NOT NULL
    pid         TEXT NOT NULL
    message     TEXT NOT NULL
    raw         TEXT NOT NULL        — original line(s); fetched only on row select
    extra_json  TEXT NOT NULL        — JSON-encoded extra dict
    ts_flags    TEXT NOT NULL        — crush.core.log_ts TS_* tokens (what the log
                                       didn't record: zone, year) or ""
    level_note  TEXT NOT NULL        — keywords the level was guessed from (formats
                                       without a level field) or "" if recorded

Indexes: ts_unix, level, source_id  — cover all common filter/sort operations.
"""
from __future__ import annotations

import array
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from crush.core import tempdir

# ---------------------------------------------------------------------------
# FilterSpec — immutable snapshot of active filter state
# ---------------------------------------------------------------------------

class FilterSpec:
    """Translates UI filter state into a SQL WHERE clause + parameter list."""

    __slots__ = (
        "allowed_levels",
        "hidden_source_ids",
        "ts_from",
        "ts_to",
        "text",
        "column_filters",
        "column_text_filters",
    )

    def __init__(
        self,
        allowed_levels: frozenset[str],
        hidden_source_ids: frozenset[int],
        ts_from: datetime | None,
        ts_to:   datetime | None,
        text:    str,
        column_filters: dict[str, str] | None = None,
        column_text_filters: dict[str, str] | None = None,
    ) -> None:
        self.allowed_levels      = allowed_levels
        self.hidden_source_ids   = hidden_source_ids
        self.ts_from             = ts_from
        self.ts_to               = ts_to
        self.text                = text
        self.column_filters      = column_filters or {}
        self.column_text_filters = column_text_filters or {}

    # ------------------------------------------------------------------

    def where(self) -> tuple[str, list[Any]]:
        """Return (WHERE clause string, params list).

        The clause starts with ``WHERE`` when conditions exist, or is an
        empty string when there are no active filters.
        """
        parts: list[str] = []
        params: list[Any] = []

        # Level filter
        if self.allowed_levels:
            placeholders = ",".join("?" * len(self.allowed_levels))
            parts.append(f"level IN ({placeholders})")
            params.extend(sorted(self.allowed_levels))

        # Hidden sources
        if self.hidden_source_ids:
            placeholders = ",".join("?" * len(self.hidden_source_ids))
            parts.append(f"source_id NOT IN ({placeholders})")
            params.extend(sorted(self.hidden_source_ids))

        # Time range
        if self.ts_from is not None:
            parts.append("(ts_unix IS NOT NULL AND ts_unix >= ?)")
            params.append(self.ts_from.timestamp())
        if self.ts_to is not None:
            parts.append("(ts_unix IS NOT NULL AND ts_unix <= ?)")
            params.append(self.ts_to.timestamp())

        # Full-text search (message OR process OR pid OR subsystem OR category)
        if self.text:
            like = f"%{self.text}%"
            parts.append(
                "(message LIKE ? OR process LIKE ? OR pid LIKE ? OR subsystem LIKE ? OR category LIKE ?)"
            )
            params.extend([like, like, like, like, like])

        # Column-specific exact-match filters (from right-click "Filter by value")
        _SAFE_COLS = frozenset({"level", "process", "pid", "subsystem", "category", "message"})
        for col, val in self.column_filters.items():
            if col in _SAFE_COLS:
                parts.append(f"{col} = ?")
                params.append(val)

        # Column-specific contains filters (from text input row)
        for col, val in self.column_text_filters.items():
            if col in _SAFE_COLS and val.strip():
                parts.append(f"{col} LIKE ?")
                params.append(f"%{val}%")

        if not parts:
            return ("", [])
        return ("WHERE " + " AND ".join(parts), params)


# ---------------------------------------------------------------------------
# LogDatabase
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode     = WAL;
PRAGMA synchronous      = OFF;
PRAGMA temp_store       = MEMORY;
PRAGMA cache_size       = -65536;
PRAGMA wal_autocheckpoint = 400;

CREATE TABLE IF NOT EXISTS entries (
    rowid       INTEGER PRIMARY KEY,
    source_id   INTEGER NOT NULL,
    ts_unix     REAL,
    level       TEXT    NOT NULL DEFAULT 'UNKNOWN',
    process     TEXT    NOT NULL DEFAULT '',
    pid         TEXT    NOT NULL DEFAULT '',
    message     TEXT    NOT NULL DEFAULT '',
    raw         TEXT    NOT NULL DEFAULT '',
    extra_json  TEXT    NOT NULL DEFAULT '{}',
    subsystem   TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT '',
    ts_flags    TEXT    NOT NULL DEFAULT '',
    level_note  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ts       ON entries(ts_unix);
CREATE INDEX IF NOT EXISTS idx_level    ON entries(level);
CREATE INDEX IF NOT EXISTS idx_src      ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_process  ON entries(process);
CREATE INDEX IF NOT EXISTS idx_sub      ON entries(subsystem);
CREATE INDEX IF NOT EXISTS idx_cat      ON entries(category);
"""

_INSERT_SQL = """
INSERT INTO entries
    (source_id, ts_unix, level, process, pid, message, raw, extra_json, subsystem, category,
     ts_flags, level_note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _ts_to_unix(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _unix_to_ts(unix: float | None) -> datetime | None:
    if unix is None:
        return None
    return datetime.fromtimestamp(unix, tz=timezone.utc)


def entry_rows(source_id: int, entries: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """_INSERT_SQL parameter rows for standard entry dicts."""
    return [
        (
            source_id,
            _ts_to_unix(e.get("timestamp")),
            e.get("level", "UNKNOWN"),
            e.get("process", ""),
            e.get("pid", ""),
            e.get("message", ""),
            e.get("raw", ""),
            json.dumps(e.get("extra") or {}),
            (e.get("extra") or {}).get("subsystem", ""),
            (e.get("extra") or {}).get("category", ""),
            e.get("ts_flags", ""),
            e.get("level_note", ""),
        )
        for e in entries
    ]


class LogDatabase:
    """Temporary SQLite database that backs one MultiLogViewer session.

    The database lives in a temp file that is deleted when ``close()`` is
    called (or the object is garbage-collected).

    Worker threads open their own connection to ``self.path`` using
    ``open_worker_connection()`` — WAL mode allows one writer per time slot
    with concurrent readers.  The main-thread connection is read-only during
    loading.
    """

    def __init__(self) -> None:
        fd, self._path = tempdir.mkstemp(prefix="crush-log-", suffix=".db")
        os.close(fd)
        self._con = sqlite3.connect(self._path, check_same_thread=False)
        self._con.executescript(_SCHEMA)
        self._con.commit()

    @property
    def path(self) -> str:
        """Filesystem path of the temp DB file (for worker connections)."""
        return self._path

    @staticmethod
    def open_worker_connection(db_path: str) -> sqlite3.Connection:
        """Return a new SQLite connection for use inside a worker thread.

        Does NOT change journal_mode — the DB is already in WAL mode from
        the main connection, and re-issuing that PRAGMA from a second
        connection requires a brief exclusive lock that can cause SQLITE_FULL
        on constrained /tmp filesystems.
        """
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.execute("PRAGMA synchronous  = OFF")
        con.execute("PRAGMA temp_store   = MEMORY")
        con.execute("PRAGMA cache_size   = -65536")
        return con

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "LogDatabase":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_batch(self, source_id: int, entries: list[dict[str, Any]]) -> None:
        """Bulk-insert a list of standard entry dicts for *source_id*."""
        self._con.executemany(_INSERT_SQL, entry_rows(source_id, entries))
        self._con.commit()

    def delete_source(self, source_id: int) -> None:
        """Remove all entries belonging to *source_id*."""
        self._con.execute("DELETE FROM entries WHERE source_id = ?", (source_id,))
        self._con.commit()

    # ------------------------------------------------------------------
    # Read — counts
    # ------------------------------------------------------------------

    def count(self, filter_spec: FilterSpec) -> int:
        """Return the number of entries matching *filter_spec*."""
        where, params = filter_spec.where()
        sql = f"SELECT COUNT(*) FROM entries {where}"
        row = self._con.execute(sql, params).fetchone()
        return row[0] if row else 0

    def count_all(self) -> int:
        """Return total entry count regardless of any filter."""
        row = self._con.execute("SELECT COUNT(*) FROM entries").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Read — sorted rowid index
    # ------------------------------------------------------------------

    def fetch_sorted_rowids(
        self,
        filter_spec: FilterSpec,
        order_col:   str,
        order_asc:   bool,
    ) -> "array.array[int]":
        """Return all rowids matching *filter_spec* in sorted order.

        Uses a compact ``array.array('q')`` (8 bytes/entry) instead of a
        Python list so 1 M entries costs ~8 MB rather than ~28 MB.

        This is called once on filter/sort changes; subsequent page fetches
        use :meth:`fetch_by_rowids` with slices of this array, giving O(1)
        random access regardless of offset depth.
        """
        direction = "ASC" if order_asc else "DESC"
        where, params = filter_spec.where()
        sql = (
            f"SELECT rowid FROM entries {where} "
            f"ORDER BY {order_col} {direction} NULLS LAST"
        )
        cur = self._con.execute(sql, params)
        return array.array("q", (row[0] for row in cur))

    # ------------------------------------------------------------------
    # Read — pages by rowid (O(1) random access)
    # ------------------------------------------------------------------

    def fetch_by_rowids(
        self,
        rowids: "array.array[int] | list[int]",
    ) -> list[tuple[Any, ...]]:
        """Fetch entries for specific rowids, returned in *rowids* order.

        Returns a list of tuples:
            (rowid, source_id, ts_unix, level, process, pid, message,
             subsystem, category, ts_flags, level_note)
        """
        if not rowids:
            return []
        placeholders = ",".join("?" * len(rowids))
        sql = (
            f"SELECT rowid, source_id, ts_unix, level, process, pid, message, subsystem, category, "
            f"ts_flags, level_note "
            f"FROM entries WHERE rowid IN ({placeholders})"
        )
        rows_by_id = {
            row[0]: row
            for row in self._con.execute(sql, list(rowids)).fetchall()
        }
        return [rows_by_id[rid] for rid in rowids if rid in rows_by_id]

    def fetch_raw_lines_for_source(
        self,
        source_id: int,
        limit:     int,
    ) -> list[str]:
        """Return up to *limit* raw log lines for *source_id* (for format preview)."""
        rows = self._con.execute(
            "SELECT raw FROM entries WHERE source_id = ? LIMIT ?",
            (source_id, limit),
        ).fetchall()
        return [row[0] for row in rows]

    def fetch_row_detail(self, rowid: int) -> tuple[str, dict[str, str]] | None:
        """Return (raw, extra_dict) for one entry by its SQLite rowid."""
        row = self._con.execute(
            "SELECT raw, extra_json FROM entries WHERE rowid = ?", (rowid,)
        ).fetchone()
        if row is None:
            return None
        raw, extra_json = row
        try:
            extra = json.loads(extra_json) if extra_json else {}
        except (json.JSONDecodeError, ValueError):
            extra = {}
        return raw, extra

    # ------------------------------------------------------------------
    # Read — aggregates
    # ------------------------------------------------------------------

    def timestamp_range(
        self, filter_spec: FilterSpec
    ) -> tuple[datetime | None, datetime | None]:
        """Return (min_ts, max_ts) for entries matching *filter_spec*."""
        where, params = filter_spec.where()
        sql = (
            f"SELECT MIN(ts_unix), MAX(ts_unix) "
            f"FROM entries {where}"
        )
        row = self._con.execute(sql, params).fetchone()
        if not row:
            return None, None
        return _unix_to_ts(row[0]), _unix_to_ts(row[1])

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the connection and delete the temp file."""
        try:
            self._con.close()
        except Exception:
            pass
        try:
            if os.path.exists(self._path):
                os.unlink(self._path)
        except Exception:
            pass
