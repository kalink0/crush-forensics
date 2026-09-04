# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Multi-Log Studio viewer — SQLite-backed, scalable to millions of entries.

Architecture
------------
  LogLoaderWorker (QThread)  — reads + parses a VFS node off the main thread,
                               emits results in chunks of CHUNK_SIZE entries.
                               Carries source_id in every signal.
  LogDatabase                — temporary SQLite file (crush/core/log_db.py);
                               all entries from all sources are stored here.
                               Owned by MultiLogViewer, shared with the model.
  MultiLogModel              — QAbstractTableModel backed by LogDatabase;
                               keeps only a small LRU page cache in RAM.
                               Filters and sorts are translated to SQL.
  MultiLogViewer             — widget that owns N workers, one LogDatabase,
                               and one model.  Closes/deletes the DB on destroy.

Entry dict schema (standard fields — all parsers must map to these):
    timestamp  : datetime | None   — UTC-normalised
    level      : str               — ERROR / WARN / INFO / DEBUG / TRACE / UNKNOWN
    process    : str               — process name, logger name, tag, etc.
    pid        : str               — process ID (empty string if unavailable)
    message    : str               — primary message (may be multiline)
    raw        : str               — original line(s) for copy / export
    source     : str               — filename of the source (stamped by model)
    source_id  : int               — internal source index (stamped by model)
    extra      : dict[str, str]    — parser-specific fields not covered above
                                     (e.g. subsystem, category, thread_id,
                                      activity_id, facility, sender for Apple UL)
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
from collections import OrderedDict
from datetime import datetime, timezone, tzinfo
from typing import TYPE_CHECKING, Any, Generator

if TYPE_CHECKING:
    pass

from PySide6.QtCore import (
    QAbstractTableModel,
    QDateTime,
    QModelIndex,
    QSettings,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import array as _array
import logging
import time

from crush.core.log_db import FilterSpec, LogDatabase, _INSERT_SQL, _ts_to_unix, _unix_to_ts

from crush.core.vfs import VFS, VFSNode
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

_log = logging.getLogger("crush")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LEVELS = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE", "UNKNOWN"]

_LEVEL_COLORS: dict[str, QColor] = {
    "ERROR":   QColor("#c0392b"),
    "WARN":    QColor("#e67e22"),
    "INFO":    QColor("#2980b9"),
    "DEBUG":   QColor("#7f8c8d"),
    "TRACE":   QColor("#95a5a6"),
    "UNKNOWN": QColor("#bdc3c7"),
}

# Source accent colours — cycled as sources are added
_SOURCE_COLORS: list[QColor] = [
    QColor("#2980b9"),
    QColor("#27ae60"),
    QColor("#8e44ad"),
    QColor("#e67e22"),
    QColor("#16a085"),
    QColor("#c0392b"),
    QColor("#f39c12"),
    QColor("#2c3e50"),
]

# Column indices
_COL_SRC  = 0
_COL_TS   = 1
_COL_LVL  = 2
_COL_PROC = 3
_COL_PID  = 4
_COL_SUB  = 5
_COL_CAT  = 6
_COL_MSG  = 7

_HEADERS = ["Source", "Timestamp", "Level", "Process / Tag", "PID", "Subsystem", "Category", "Message"]

# Custom data roles
_ROLE_TS_DT    = Qt.ItemDataRole.UserRole + 1   # datetime | None
_ROLE_LEVEL    = Qt.ItemDataRole.UserRole + 2   # str
_ROLE_RAW      = Qt.ItemDataRole.UserRole + 3   # str (original lines)
_ROLE_MSG_FULL = Qt.ItemDataRole.UserRole + 4   # str (full message, may be multiline)


def _fmt_ts(dt: datetime | None, tz: tzinfo = timezone.utc) -> str:
    if dt is None:
        return "—"
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def _msg_display(msg: str) -> str:
    if "\n" in msg:
        lines = msg.split("\n")
        n = len(lines) - 1
        return f"{lines[0]}  [{n} more line{'s' if n > 1 else ''}]"
    return msg


# Colours used in the live-preview to highlight named regex groups
_PREVIEW_GROUP_COLORS: dict[str, str] = {
    "timestamp": "#3498db",
    "level":     "#e67e22",
    "process":   "#27ae60",
    "pid":       "#9b59b6",
    "message":   "#bdc3c7",
}
_PREVIEW_EXTRA_COLOR = "#1abc9c"


# ---------------------------------------------------------------------------
# Define Format dialog (Phase 4)
# ---------------------------------------------------------------------------

class DefineFormatDialog(QDialog):
    """Dialog for defining and managing custom log format profiles.

    Opened via the 'Format…' button in MultiLogViewer's toolbar.

    After the user clicks *Apply*:
      - ``result_profile()``    returns the active ``CustomFormatProfile``
      - ``result_source_id()``  returns the source_id to re-parse

    The dialog has a live preview that highlights named groups in the
    raw text as the user edits the pattern (debounced, 300 ms).
    """

    PREVIEW_LINES   = 20
    PREVIEW_DELAY   = 300   # ms

    def __init__(
        self,
        preview_lines: list[str],
        sources: list[tuple[int, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Define Log Format — Multi-Log Studio")
        self.setMinimumSize(840, 660)

        self._preview_lines = preview_lines[: self.PREVIEW_LINES]
        self._sources       = sources
        self._result_profile: Any = None
        self._result_source_id: int = sources[0][0] if sources else 0

        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.timeout.connect(self._refresh_preview)

        self._build_ui()
        self._reload_profiles_combo()
        self._schedule_preview()

    # ------------------------------------------------------------------
    # Results (read after exec() returns Accepted)
    # ------------------------------------------------------------------

    def result_profile(self) -> Any:
        return self._result_profile

    def result_source_id(self) -> int:
        return self._result_source_id

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        # ---- Saved-profiles bar ----
        saved_row = QHBoxLayout()
        saved_row.addWidget(QLabel("Saved profiles:"))
        self._profiles_combo = QComboBox()
        self._profiles_combo.setMinimumWidth(220)
        saved_row.addWidget(self._profiles_combo)
        load_btn = QPushButton("Load")
        load_btn.setFixedWidth(64)
        load_btn.clicked.connect(self._on_load_profile)
        saved_row.addWidget(load_btn)
        del_btn = QPushButton("Delete")
        del_btn.setFixedWidth(64)
        del_btn.clicked.connect(self._on_delete_profile)
        saved_row.addWidget(del_btn)
        saved_row.addStretch()
        root.addLayout(saved_row)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ---- Form ----
        form_outer = QWidget()
        form = QFormLayout(form_outer)
        form.setSpacing(6)
        form.setContentsMargins(0, 0, 0, 0)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g. Nginx Access Log")
        form.addRow("Profile Name:", self._name_edit)

        self._pattern_edit = QLineEdit()
        self._pattern_edit.setPlaceholderText(
            r"(?P<timestamp>\S+) (?P<level>\w+) (?P<process>[^:]+): (?P<message>.*)"
        )
        self._pattern_edit.textChanged.connect(self._schedule_preview)
        form.addRow("Parse Pattern:", self._pattern_edit)

        hint = QLabel(
            "Named groups → columns: "
            "<b>timestamp</b> · <b>level</b> · <b>process</b> · "
            "<b>pid</b> · <b>message</b> — any other group → <i>extra</i> field."
        )
        hint.setWordWrap(True)
        form.addRow("", hint)

        self._ts_fmt_edit = QLineEdit()
        self._ts_fmt_edit.setPlaceholderText(
            "%Y-%m-%d %H:%M:%S  (empty = auto-detect ISO / epoch)"
        )
        self._ts_fmt_edit.textChanged.connect(self._schedule_preview)
        form.addRow("Timestamp Format:", self._ts_fmt_edit)

        self._line_start_edit = QLineEdit()
        self._line_start_edit.setPlaceholderText(
            r"^\d{4}-\d{2}-\d{2}  (optional — marks start of multiline events)"
        )
        self._line_start_edit.textChanged.connect(self._schedule_preview)
        form.addRow("Line-Start Regex:", self._line_start_edit)

        self._level_map_edit = QLineEdit()
        self._level_map_edit.setPlaceholderText(
            '{"GET":"INFO","POST":"INFO","500":"ERROR"}  (optional JSON)'
        )
        self._level_map_edit.textChanged.connect(self._schedule_preview)
        form.addRow("Level Map:", self._level_map_edit)

        self._default_level_combo = QComboBox()
        for lvl in ["UNKNOWN", "INFO", "DEBUG", "WARN", "ERROR", "TRACE"]:
            self._default_level_combo.addItem(lvl)
        self._default_level_combo.currentTextChanged.connect(self._schedule_preview)
        form.addRow("Default Level:", self._default_level_combo)

        splitter.addWidget(form_outer)

        # ---- Preview ----
        prev_outer = QWidget()
        prev_layout = QVBoxLayout(prev_outer)
        prev_layout.setContentsMargins(0, 4, 0, 0)
        prev_layout.setSpacing(4)

        legend_row = QHBoxLayout()
        legend_row.addWidget(QLabel(f"Live preview (first {self.PREVIEW_LINES} lines):"))
        legend_parts = " · ".join(
            f"<span style='color:{c};'>{g}</span>"
            for g, c in _PREVIEW_GROUP_COLORS.items()
        ) + f" · <span style='color:{_PREVIEW_EXTRA_COLOR};'>extra</span>"
        legend_lbl = QLabel(legend_parts)
        legend_row.addStretch()
        legend_row.addWidget(legend_lbl)
        prev_layout.addLayout(legend_row)

        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._preview.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._preview, smooth_item_scroll=False)
        font = self._preview.font()
        font.setFamily("monospace")
        font.setPointSize(10)
        self._preview.setFont(font)
        self._preview.setStyleSheet("background-color:#1a1a2e; color:#e0e0e0;")
        prev_layout.addWidget(self._preview)

        splitter.addWidget(prev_outer)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter)

        # ---- Bottom buttons ----
        btn_row = QHBoxLayout()
        btn_row.addWidget(QLabel("Apply to source:"))
        self._source_combo = QComboBox()
        for sid, name in self._sources:
            self._source_combo.addItem(name, sid)
        btn_row.addWidget(self._source_combo)
        btn_row.addStretch()

        save_btn = QPushButton("Save Profile")
        save_btn.clicked.connect(self._on_save_profile)
        btn_row.addWidget(save_btn)

        apply_btn = QPushButton("Apply")
        apply_btn.setDefault(True)
        apply_btn.clicked.connect(self._on_apply)
        btn_row.addWidget(apply_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(close_btn)

        root.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def _reload_profiles_combo(self) -> None:
        from crush.parsers.multi_log_parser import ProfileManager
        self._profiles_combo.clear()
        self._profiles_combo.addItem("— select a saved profile —", None)
        for p in ProfileManager.all():
            self._profiles_combo.addItem(p.name, p)

    def _on_load_profile(self) -> None:
        profile = self._profiles_combo.currentData()
        if profile is not None:
            self._populate_fields(profile)

    def _on_delete_profile(self) -> None:
        profile = self._profiles_combo.currentData()
        if profile is None:
            return
        from crush.parsers.multi_log_parser import ProfileManager
        ProfileManager.delete(profile.name)
        self._reload_profiles_combo()

    def _on_save_profile(self) -> None:
        profile = self._build_profile()
        if profile is None:
            return
        from crush.parsers.multi_log_parser import ProfileManager
        ProfileManager.save(profile)
        self._reload_profiles_combo()

    def _on_apply(self) -> None:
        profile = self._build_profile()
        if profile is None:
            return
        self._result_profile = profile
        sid = self._source_combo.currentData()
        if sid is not None:
            self._result_source_id = sid
        self.accept()

    # ------------------------------------------------------------------
    # Field helpers
    # ------------------------------------------------------------------

    def _populate_fields(self, profile: Any) -> None:
        self._name_edit.setText(profile.name)
        self._pattern_edit.setText(profile.parse_pattern)
        self._ts_fmt_edit.setText(profile.timestamp_format)
        self._line_start_edit.setText(profile.line_start_pattern)
        lm_str = json.dumps(profile.level_map) if profile.level_map else ""
        self._level_map_edit.setText(lm_str)
        idx = self._default_level_combo.findText(profile.level_default)
        if idx >= 0:
            self._default_level_combo.setCurrentIndex(idx)

    def _build_profile(self) -> Any:
        from crush.parsers.multi_log_parser import CustomFormatProfile
        name    = self._name_edit.text().strip()
        pattern = self._pattern_edit.text().strip()
        if not name or not pattern:
            return None
        try:
            re.compile(pattern)
        except re.error:
            return None
        level_map: dict[str, str] = {}
        lm_text = self._level_map_edit.text().strip()
        if lm_text:
            try:
                level_map = json.loads(lm_text)
            except (json.JSONDecodeError, ValueError):
                pass
        line_start = self._line_start_edit.text().strip()
        if line_start:
            try:
                re.compile(line_start)
            except re.error:
                line_start = ""
        return CustomFormatProfile(
            name=               name,
            parse_pattern=      pattern,
            timestamp_format=   self._ts_fmt_edit.text().strip(),
            line_start_pattern= line_start,
            level_map=          level_map,
            level_default=      self._default_level_combo.currentText(),
        )

    # ------------------------------------------------------------------
    # Live preview
    # ------------------------------------------------------------------

    def _schedule_preview(self) -> None:
        self._preview_timer.start(self.PREVIEW_DELAY)

    def _refresh_preview(self) -> None:
        if not self._preview_lines:
            self._preview.setPlainText("(no preview content)")
            return

        pattern = self._pattern_edit.text().strip()
        if not pattern:
            raw_block = "<br>".join(html.escape(ln) for ln in self._preview_lines)
            self._preview.setHtml(
                f"<pre style='color:#888;'>"
                f"(enter a parse pattern to see matches)<br><br>"
                f"{raw_block}</pre>"
            )
            return

        try:
            rx = re.compile(pattern)
        except re.error as exc:
            self._preview.setHtml(
                f"<pre style='color:#e74c3c;'>"
                f"Invalid regex: {html.escape(str(exc))}</pre>"
            )
            return

        rows: list[str] = []
        for i, line in enumerate(self._preview_lines, 1):
            m = rx.search(line)
            if m:
                rows.append(self._colorize_line(i, line, m))
            else:
                rows.append(
                    f"<div style='padding:1px 4px;'>"
                    f"<span style='color:#7f8c8d;'>{i:3d}</span> "
                    f"<span style='color:#e74c3c;'>✗</span> "
                    f"<span style='color:#666;'>{html.escape(line)}</span>"
                    f"</div>"
                )

        self._preview.setHtml(
            "<div style='font-family:monospace;font-size:10pt;'>"
            + "".join(rows)
            + "</div>"
        )

    @staticmethod
    def _colorize_line(line_num: int, line: str, m: re.Match) -> str:  # type: ignore[type-arg]
        """Return an HTML row with each named group highlighted."""
        spans: list[tuple[int, int, str]] = []
        for name in m.groupdict():
            try:
                start, end = m.span(name)
            except IndexError:
                continue
            if start < 0:
                continue
            color = _PREVIEW_GROUP_COLORS.get(name, _PREVIEW_EXTRA_COLOR)
            spans.append((start, end, color))
        spans.sort(key=lambda x: x[0])

        # Drop overlapping spans (keep first)
        merged: list[tuple[int, int, str]] = []
        for span in spans:
            if merged and span[0] < merged[-1][1]:
                continue
            merged.append(span)

        parts: list[str] = []
        pos = 0
        for start, end, color in merged:
            if pos < start:
                parts.append(
                    f"<span style='color:#bdc3c7;'>{html.escape(line[pos:start])}</span>"
                )
            parts.append(
                f"<span style='color:{color};font-weight:bold;'>"
                f"{html.escape(line[start:end])}</span>"
            )
            pos = end
        if pos < len(line):
            parts.append(
                f"<span style='color:#bdc3c7;'>{html.escape(line[pos:])}</span>"
            )

        return (
            f"<div style='padding:1px 4px;'>"
            f"<span style='color:#7f8c8d;'>{line_num:3d}</span> "
            f"<span style='color:#27ae60;'>✓</span> "
            + "".join(parts)
            + "</div>"
        )


# ---------------------------------------------------------------------------
# Background loader
# ---------------------------------------------------------------------------

class LogLoaderWorker(QThread):
    """Parses a VFS node in a worker thread and writes entries directly to SQLite.

    The worker opens its own DB connection (WAL mode, synchronous=OFF) and
    inserts entries in batches without touching the main thread.  Only small
    progress/status signals cross the thread boundary — no entry data is
    passed via signals.

    Signals
    -------
    progress(int, int)           — (source_id, total_inserted) periodically during load.
    load_finished(int, str, dict)— (source_id, format_name, metadata) when done.
    error(int, str)              — (source_id, message) if parsing raises.
    status_update(int, str)      — (source_id, status_text) for long binary conversions.
    """

    progress:      Signal = Signal(int, int)
    load_finished: Signal = Signal(int, str, dict)
    error:         Signal = Signal(int, str)
    status_update: Signal = Signal(int, str)

    CHUNK_SIZE    = 5_000
    UL_CHUNK_SIZE = 50_000

    def __init__(
        self,
        node:      VFSNode,
        vfs:       VFS,
        source_id: int,
        db_path:   str,
        profile:   Any = None,
        parent:    QWidget | None = None,
        temp_dir:  str | None = None,
    ) -> None:
        super().__init__(parent)
        self._node        = node
        self._vfs         = vfs
        self._source_id   = source_id
        self._db_path     = db_path
        self._temp_dir    = temp_dir
        self._profile     = profile
        self._cancel_flag = False
        self._converter: Any = None

    def cancel(self) -> None:
        self._cancel_flag = True
        if self._converter is not None:
            self._converter.cancel()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _insert_entries(
        self,
        con: "sqlite3.Connection",
        entries: list[dict[str, Any]],
    ) -> None:
        """Bulk-insert *entries* into the worker's own DB connection."""
        rows = [
            (
                self._source_id,
                _ts_to_unix(e.get("timestamp")),
                e.get("level",   "UNKNOWN"),
                e.get("process", ""),
                e.get("pid",     ""),
                e.get("message", ""),
                e.get("raw",     ""),
                json.dumps(e.get("extra") or {}),
                (e.get("extra") or {}).get("subsystem", ""),
                (e.get("extra") or {}).get("category", ""),
            )
            for e in entries
        ]
        con.executemany(_INSERT_SQL, rows)

    def _stream_to_db(
        self,
        con: "sqlite3.Connection",
        generator: "Generator[dict[str, Any], None, None]",
        chunk_size: int,
    ) -> int:
        """Consume *generator*, insert in chunks, return total inserted."""
        chunk: list[dict[str, Any]] = []
        total = 0
        for entry in generator:
            if self._cancel_flag:
                con.commit()
                return total
            chunk.append(entry)
            total += 1
            if len(chunk) >= chunk_size:
                self._insert_entries(con, chunk)
                con.commit()
                chunk = []
                self.progress.emit(self._source_id, total)
        if chunk:
            self._insert_entries(con, chunk)
            con.commit()
            self.progress.emit(self._source_id, total)
        return total

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._cancel_flag = False
        con = LogDatabase.open_worker_connection(self._db_path)
        try:
            name_lower = self._node.name.lower()
            is_unified = (
                name_lower.endswith(".tracev3")
                or name_lower.endswith(".logarchive")
            )
            from crush.parsers.unified_log_parser import is_ios_diagnostics_node
            _is_ios_diag = self._node.is_dir and is_ios_diagnostics_node(self._node)

            if _is_ios_diag:
                from crush.parsers.unified_log_parser import UnifiedLogConverter
                converter = UnifiedLogConverter(temp_dir=self._temp_dir)
                self._converter = converter
                self.status_update.emit(self._source_id, "Converting binary log — may take several minutes…")
                gen = converter.stream_entries_from_diagnostics(self._node, self._vfs)
                total = self._stream_to_db(con, gen, self.UL_CHUNK_SIZE)
                if not self._cancel_flag:
                    self.load_finished.emit(
                        self._source_id,
                        "Apple Unified Log (iOS acquisition)",
                        {"Log format": "Apple Unified Log (iOS acquisition)", "Total entries": str(total)},
                    )

            elif is_unified:
                from crush.parsers.unified_log_parser import UnifiedLogConverter
                converter = UnifiedLogConverter(temp_dir=self._temp_dir)
                self._converter = converter
                self.status_update.emit(self._source_id, "Converting binary log — may take several minutes…")
                gen = converter.stream_entries(self._node, self._vfs)
                total = self._stream_to_db(con, gen, self.UL_CHUNK_SIZE)
                if not self._cancel_flag:
                    self.load_finished.emit(
                        self._source_id,
                        "Apple Unified Log (binary)",
                        {"Log format": "Apple Unified Log (binary)", "Total entries": str(total)},
                    )

            elif self._profile is not None:
                from crush.parsers.multi_log_parser import CustomFormatParser
                parser: Any = CustomFormatParser(self._profile)
                result = parser.parse(self._node, self._vfs)
                entries: list[dict[str, Any]] = result.data  # type: ignore[assignment]
                total = self._stream_to_db(con, iter(entries), self.CHUNK_SIZE)
                if not self._cancel_flag:
                    self.load_finished.emit(
                        self._source_id,
                        result.metadata.get("Log format", "Unknown"),
                        result.metadata,
                    )

            else:
                from crush.parsers.log_parser import LogParser
                parser = LogParser()
                result = parser.parse(self._node, self._vfs)
                entries = result.data  # type: ignore[assignment]
                total = self._stream_to_db(con, iter(entries), self.CHUNK_SIZE)
                if not self._cancel_flag:
                    self.load_finished.emit(
                        self._source_id,
                        result.metadata.get("Log format", "Unknown"),
                        result.metadata,
                    )
        except Exception as exc:  # noqa: BLE001
            self.error.emit(self._source_id, str(exc))
        finally:
            con.close()


# ---------------------------------------------------------------------------
# Virtual table model
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Background sort worker
# ---------------------------------------------------------------------------

class _SortWorker(QThread):
    """Runs fetch_sorted_rowids() off the main thread.

    The generation counter lets the model discard results from superseded
    sort requests (e.g. rapid column-header clicks).
    """

    sort_done: Signal = Signal(int, object)   # (generation, array.array)

    def __init__(
        self,
        db_path:     str,
        filter_spec: FilterSpec,
        order_col:   str,
        order_asc:   bool,
        generation:  int,
        parent:      "QWidget | None" = None,
    ) -> None:
        super().__init__(parent)
        self._db_path     = db_path
        self._filter_spec = filter_spec
        self._order_col   = order_col
        self._order_asc   = order_asc
        self._generation  = generation

    def run(self) -> None:
        con = LogDatabase.open_worker_connection(self._db_path)
        try:
            direction = "ASC" if self._order_asc else "DESC"
            where, params = self._filter_spec.where()
            sql = (
                f"SELECT rowid FROM entries {where} "
                f"ORDER BY {self._order_col} {direction} NULLS LAST"
            )
            cur = con.execute(sql, params)
            rowids = _array.array("q", (row[0] for row in cur))
            self.sort_done.emit(self._generation, rowids)
        finally:
            con.close()


# ---------------------------------------------------------------------------
# Column filter metadata — columns that support right-click "Filter by value"
# ---------------------------------------------------------------------------

# Maps column index → (sql_column_name, display_label)
_COL_FILTER_MAP: dict[int, tuple[str, str]] = {
    _COL_LVL:  ("level",     "Level"),
    _COL_PROC: ("process",   "Process"),
    _COL_PID:  ("pid",       "PID"),
    _COL_SUB:  ("subsystem", "Subsystem"),
    _COL_CAT:  ("category",  "Category"),
    _COL_MSG:  ("message",   "Message"),
}

# Page cache: how many rows per page, and how many pages to keep in RAM
_PAGE_SIZE  = 500
_PAGE_COUNT = 8   # max 8 × 500 = 4 000 rows in RAM

# SQL column names used for ORDER BY (indexed on these columns)
_SQL_SORT_COL: dict[int, str] = {
    _COL_SRC:  "source_id",
    _COL_TS:   "ts_unix",
    _COL_LVL:  "level",
    _COL_PROC: "process",
    # pid is stored as TEXT (crush/core/log_db.py) — CAST to sort numerically
    # ("2" before "10") instead of SQLite's default TEXT collation order.
    _COL_PID:  "CAST(pid AS INTEGER)",
    _COL_SUB:  "subsystem",
    _COL_CAT:  "category",
    _COL_MSG:  "message",
}


class MultiLogModel(QAbstractTableModel):
    """QAbstractTableModel backed by LogDatabase (SQLite).

    Only a small LRU page cache is kept in RAM; all filtering and sorting
    is delegated to SQL.  The model is suitable for tens of millions of
    rows without significant memory overhead.

    Lifecycle
    ---------
    The caller (MultiLogViewer) owns the LogDatabase instance and passes it
    to the constructor.  The model does NOT close the database.
    """

    sort_started:  Signal = Signal()
    sort_finished: Signal = Signal()

    def __init__(self, db: LogDatabase, parent: "QWidget | None" = None) -> None:
        super().__init__(parent)
        self._db = db
        self._display_tz: tzinfo = timezone.utc

        # Source registry: source_id -> {name, color, visible}
        self._sources: dict[int, dict[str, Any]] = {}
        self._hidden_source_ids: set[int] = set()

        # Sorting
        self._sort_col: int  = _COL_TS
        self._sort_asc: bool = True

        # Filter state
        self._allowed_levels: frozenset[str] = frozenset(_LEVELS)
        self._ts_from: datetime | None = None
        self._ts_to:   datetime | None = None
        self._text: str = ""
        self._column_filters: dict[str, str] = {}       # sql_col → exact value (right-click)
        self._column_text_filters: dict[str, str] = {}  # sql_col → contains text (input row)

        # Sorted rowid index for the current filter+sort — rebuilt on _invalidate().
        # array.array('q') uses 8 bytes/entry; len() == visible row count.
        self._rowid_index: _array.array = _array.array("q")
        # Running total written by workers (for the count label during loading)
        self._total_inserted: int = 0

        # LRU page cache: page_num -> list of row tuples
        self._page_cache: OrderedDict[int, list[tuple[Any, ...]]] = OrderedDict()

        # Cache for source_id → source name (used in data())
        self._source_names: dict[int, str] = {}

        # Background sort state
        self._sort_generation: int = 0
        self._sort_worker: "_SortWorker | None" = None

    # ------------------------------------------------------------------
    # Source management
    # ------------------------------------------------------------------

    def register_source(self, source_id: int, name: str, color: QColor) -> None:
        self._sources[source_id] = {"name": name, "color": color, "visible": True}
        self._source_names[source_id] = name

    def set_source_visible(self, source_id: int, visible: bool) -> None:
        src = self._sources.get(source_id)
        if src is None or src["visible"] == visible:
            return
        src["visible"] = visible
        if visible:
            self._hidden_source_ids.discard(source_id)
        else:
            self._hidden_source_ids.add(source_id)
        self._invalidate()

    def source_name(self, source_id: int) -> str:
        src = self._sources.get(source_id)
        return src["name"] if src else ""

    def source_color(self, source_id: int) -> QColor | None:
        src = self._sources.get(source_id)
        return src["color"] if src else None

    # ------------------------------------------------------------------
    # QAbstractTableModel interface
    # ------------------------------------------------------------------

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rowid_index)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()

        # Fetch the page that contains this row
        page_num = row // _PAGE_SIZE
        page = self._get_page(page_num)
        if not page:
            return None
        page_row = row % _PAGE_SIZE
        if page_row >= len(page):
            return None

        # Tuple layout: (rowid, source_id, ts_unix, level, process, pid, message, subsystem, category)
        db_rowid, source_id, ts_unix, level, process, pid, message, subsystem, category = page[page_row]

        if role == Qt.ItemDataRole.DisplayRole:
            if col == _COL_SRC:
                return self._source_names.get(source_id, str(source_id))
            if col == _COL_TS:
                return _fmt_ts(_unix_to_ts(ts_unix), self._display_tz)
            if col == _COL_LVL:
                return level
            if col == _COL_PROC:
                return process
            if col == _COL_PID:
                return pid
            if col == _COL_SUB:
                return subsystem
            if col == _COL_CAT:
                return category
            if col == _COL_MSG:
                return _msg_display(message)

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == _COL_LVL:
                return _LEVEL_COLORS.get(level, _LEVEL_COLORS["UNKNOWN"])
            if col == _COL_SRC:
                color = self.source_color(source_id)
                if color:
                    return color

        if role == Qt.ItemDataRole.ToolTipRole and col == _COL_MSG:
            return message if "\n" in message else None

        if role == _ROLE_TS_DT:
            return _unix_to_ts(ts_unix)
        if role == _ROLE_LEVEL:
            return level
        if role == _ROLE_RAW:
            # Raw is only fetched on demand (not in the page query)
            detail = self._db.fetch_row_detail(db_rowid)
            return detail[0] if detail else ""
        if role == _ROLE_MSG_FULL:
            return message

        # Store the db_rowid so the viewer can call fetch_row_detail()
        if role == Qt.ItemDataRole.UserRole:
            return db_rowid

        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        self._sort_col = column
        self._sort_asc = order == Qt.SortOrder.AscendingOrder
        self._invalidate()

    # ------------------------------------------------------------------
    # Incremental loading
    # ------------------------------------------------------------------

    def on_progress(self, _source_id: int, total_inserted: int) -> None:
        """Called when the worker reports progress (entries already in DB).

        Only updates the running total for the count label — no model reset,
        no index rebuild, no page cache flush.
        """
        self._total_inserted = total_inserted

    def finalize_sort(self) -> None:
        """Invalidate page cache and reset model view after a source finishes.

        The worker has committed all its entries.  This triggers one model
        reset so the view renders the full merged timeline.
        """
        self._invalidate()

    # ------------------------------------------------------------------
    # Filter setters
    # ------------------------------------------------------------------

    def set_levels(self, levels: set[str]) -> None:
        self._allowed_levels = frozenset(levels)
        self._invalidate()

    def set_time_range(self, from_dt: datetime | None, to_dt: datetime | None) -> None:
        self._ts_from = from_dt
        self._ts_to   = to_dt
        self._invalidate()

    def set_text(self, text: str) -> None:
        self._text = text.lower()
        self._invalidate()

    def set_column_filter(self, col_name: str, value: str) -> None:
        self._column_filters[col_name] = value
        self._invalidate()

    def clear_column_filter(self, col_name: str) -> None:
        if self._column_filters.pop(col_name, None) is not None:
            self._invalidate()

    def active_column_filters(self) -> dict[str, str]:
        return dict(self._column_filters)

    def set_column_text_filter(self, col_name: str, text: str) -> None:
        if text.strip():
            self._column_text_filters[col_name] = text
        else:
            self._column_text_filters.pop(col_name, None)
        self._invalidate()

    def set_display_tz(self, tz: tzinfo) -> None:
        self._display_tz = tz
        n = len(self._rowid_index)
        if n:
            top    = self.index(0, _COL_TS)
            bottom = self.index(n - 1, _COL_TS)
            self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.DisplayRole])

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def total_count(self) -> int:
        return self._total_inserted if self._total_inserted else self._db.count_all()

    def visible_count(self) -> int:
        return len(self._rowid_index)

    def entry_at(self, proxy_row: int) -> dict[str, Any]:
        """Return a synthetic entry dict for one visible row (used by raw panel / clipboard)."""
        page_num = proxy_row // _PAGE_SIZE
        page = self._get_page(page_num)
        page_row = proxy_row % _PAGE_SIZE
        if not page or page_row >= len(page):
            return {}
        db_rowid, source_id, ts_unix, level, process, pid, message, subsystem, category = page[page_row]
        detail = self._db.fetch_row_detail(db_rowid)
        raw   = detail[0] if detail else ""
        extra = detail[1] if detail else {}
        return {
            "source_id": source_id,
            "source":    self._source_names.get(source_id, ""),
            "timestamp": _unix_to_ts(ts_unix),
            "level":     level,
            "process":   process,
            "pid":       pid,
            "subsystem": subsystem,
            "category":  category,
            "message":   message,
            "raw":       raw,
            "extra":     extra,
        }

    def timestamp_range(self) -> tuple[datetime | None, datetime | None]:
        return self._db.timestamp_range(self._make_filter())

    def replace_source_entries(self, source_id: int) -> None:
        """Delete all entries for *source_id* from the DB.

        Called before a reload-worker starts; the worker writes new entries
        directly into the DB itself.
        """
        self._db.delete_source(source_id)
        self._invalidate()

    def preview_lines_for_source(self, source_id: int, max_lines: int = 20) -> list[str]:
        """Return up to *max_lines* raw log lines for *source_id* from the DB."""
        raws = self._db.fetch_raw_lines_for_source(source_id, max_lines)
        lines: list[str] = []
        for raw in raws:
            lines.extend(raw.split("\n"))
            if len(lines) >= max_lines:
                break
        return lines[:max_lines]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _make_filter(self) -> FilterSpec:
        return FilterSpec(
            allowed_levels=      self._allowed_levels,
            hidden_source_ids=   frozenset(self._hidden_source_ids),
            ts_from=             self._ts_from,
            ts_to=               self._ts_to,
            text=                self._text,
            column_filters=      dict(self._column_filters),
            column_text_filters= dict(self._column_text_filters),
        )

    def _make_filter_for_source(self, source_id: int) -> FilterSpec:
        """Filter that shows only *source_id*, no other active filters."""
        return FilterSpec(
            allowed_levels=    frozenset(_LEVELS),
            hidden_source_ids= frozenset(
                sid for sid in self._sources if sid != source_id
            ),
            ts_from=None,
            ts_to=None,
            text="",
        )

    def _invalidate(self) -> None:
        """Rebuild the sorted rowid index off the main thread.

        Increments the generation counter so any in-flight sort worker whose
        result arrives late is silently discarded.  The page cache is cleared
        immediately; the view resets only when the worker delivers results.
        """
        self._page_cache.clear()
        self._sort_generation += 1
        gen = self._sort_generation
        order_col = _SQL_SORT_COL.get(self._sort_col, "ts_unix")

        worker = _SortWorker(
            self._db.path,
            self._make_filter(),
            order_col,
            self._sort_asc,
            gen,
            self,
        )
        worker.sort_done.connect(self._on_sort_done)
        self._sort_worker = worker
        self.sort_started.emit()
        worker.start()

    def _on_sort_done(self, generation: int, rowids: "_array.array[int]") -> None:
        if generation != self._sort_generation:
            return   # stale result from a superseded request — discard
        self._rowid_index = rowids
        self.sort_finished.emit()
        self.beginResetModel()
        self.endResetModel()

    def _get_page(self, page_num: int) -> list[tuple[Any, ...]]:
        """Return page *page_num* from cache, fetching from DB on a miss.

        Uses rowid-based lookup (O(1) per page) instead of OFFSET.
        """
        if page_num in self._page_cache:
            self._page_cache.move_to_end(page_num)
            return self._page_cache[page_num]

        start = page_num * _PAGE_SIZE
        end   = start + _PAGE_SIZE
        page_rowids = self._rowid_index[start:end]
        rows = self._db.fetch_by_rowids(page_rowids)
        self._page_cache[page_num] = rows
        self._page_cache.move_to_end(page_num)
        if len(self._page_cache) > _PAGE_COUNT:
            self._page_cache.popitem(last=False)
        return rows


# ---------------------------------------------------------------------------
# Viewer widget
# ---------------------------------------------------------------------------

class MultiLogViewer(QWidget):
    """Multi-Log Studio viewer — Phase 3 (multiple sources, virtual model, async load).

    The first source is loaded immediately from the VFSNode passed to the
    constructor.  Additional sources can be added at any time via add_source()
    or via the "Add Source" button in the source bar.

    Public API (used by main_window for VFS-tree "Add to Multi-Log Studio"):
        add_source(node, vfs) — load an additional log source into this viewer.
    """

    def __init__(
        self,
        node: VFSNode,
        vfs: VFS,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._db                 = LogDatabase()
        self._model              = MultiLogModel(self._db, self)
        self._display_tz: tzinfo = timezone.utc
        self._workers: dict[int, LogLoaderWorker] = {}
        self._source_chips: dict[int, QPushButton] = {}
        self._source_nodes: dict[int, tuple[VFSNode, VFS]] = {}
        self._load_start_times: dict[int, float] = {}
        self._next_source_id     = 0

        # Colour-cycling animation for the status label during binary conversion
        self._status_anim_colors = [
            "#e8a020",  # amber
            "#e07030",  # orange
            "#c040a0",  # magenta
            "#4080e0",  # blue
            "#20b080",  # teal
            "#60c030",  # green
        ]
        self._status_anim_idx   = 0
        self._status_anim_timer = QTimer(self)
        self._status_anim_timer.setInterval(450)
        self._status_anim_timer.timeout.connect(self._on_status_anim_tick)

        self._build_ui()
        self.add_source(node, vfs)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    def _log_temp_dir() -> str | None:
        """Configured base directory for log conversion's intermediate files
        (Tools -> Log Temp Directory...), or None to use the OS default temp
        location."""
        value = QSettings("Crush DFIR", "Crush").value("log_temp_dir", "", type=str)
        return value.strip() or None

    def closeEvent(self, event: Any) -> None:
        for w in self._workers.values():
            if w.isRunning():
                w.cancel()
        for w in self._workers.values():
            if w.isRunning():
                w.wait(10_000)
        self._db.close()
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_source(self, node: VFSNode, vfs: VFS) -> None:
        """Load an additional log source and merge it into the timeline."""
        sid   = self._next_source_id
        self._next_source_id += 1
        color = _SOURCE_COLORS[sid % len(_SOURCE_COLORS)]

        self._source_nodes[sid] = (node, vfs)
        self._load_start_times[sid] = time.monotonic()
        self._model.register_source(sid, node.name, color)
        self._add_source_chip(sid, node.name, color)
        _log.info("[Multi-Log] Loading: %s", node.name)

        worker = LogLoaderWorker(node, vfs, sid, self._db.path, parent=self, temp_dir=self._log_temp_dir())
        worker.progress.connect(self._on_progress)
        worker.load_finished.connect(self._on_load_finished)
        worker.error.connect(self._on_error)
        worker.status_update.connect(self._on_status_update)
        self._workers[sid] = worker

        self._progress.setVisible(True)
        self._table.setSortingEnabled(False)
        worker.start()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_source_bar())

        # Progress bar — shown during loading, hidden when all workers finish
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)          # indeterminate
        self._progress.setFixedHeight(4)
        self._progress.setTextVisible(False)
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        # Time bar — hidden until timestamps are confirmed
        self._time_bar = self._build_time_bar()
        self._time_bar.setVisible(False)
        root.addWidget(self._time_bar)

        # Column filter bar — shown when at least one column filter is active
        self._col_filter_bar = self._build_col_filter_bar()
        self._col_filter_bar.setVisible(False)
        root.addWidget(self._col_filter_bar)

        # Column text filter row — always visible, one QLineEdit per filterable column
        root.addWidget(self._build_col_text_filter_row())

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSortingEnabled(False)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        install_horizontal_wheel_scroll(self._table)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_MSG, QHeaderView.ResizeMode.Stretch
        )
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.verticalHeader().hide()
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        self._table.horizontalHeader().setSortIndicator(_COL_TS, Qt.SortOrder.AscendingOrder)
        splitter.addWidget(self._table)

        self._raw_panel = QPlainTextEdit()
        self._raw_panel.setReadOnly(True)
        self._raw_panel.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._raw_panel.setPlaceholderText("Select a row to see the original line…")
        self._raw_panel.setMinimumHeight(40)
        self._raw_panel.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        splitter.addWidget(self._raw_panel)

        splitter.setStretchFactor(0, 10)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter)

        self._model.modelReset.connect(self._update_count)
        self._model.rowsInserted.connect(self._update_count)
        self._model.sort_started.connect(self._on_sort_started)
        self._model.sort_finished.connect(self._on_sort_finished)

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(36)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        layout.addWidget(QLabel("Level:"))
        self._level_btns: dict[str, QPushButton] = {}
        for lvl in _LEVELS:
            btn = QPushButton(lvl)
            btn.setCheckable(True)
            btn.setChecked(True)
            btn.setMaximumWidth(62)          # preferred cap; can shrink when window is narrow
            color = _LEVEL_COLORS.get(lvl, QColor("#bdc3c7"))
            btn.setStyleSheet(
                f"QPushButton:checked {{ background-color: {color.name()}; color: white; }}"
            )
            btn.toggled.connect(self._on_level_toggled)
            layout.addWidget(btn)
            self._level_btns[lvl] = btn

        layout.addSpacing(8)

        layout.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter message / process / extra…")
        self._search.setClearButtonEnabled(True)
        self._search.setMinimumWidth(80)     # can grow/shrink with window width
        self._search.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._search.textChanged.connect(self._on_search_changed)
        layout.addWidget(self._search)

        layout.addSpacing(8)
        fmt_btn = QPushButton("Format…")
        fmt_btn.setToolTip("Define or apply a custom log format profile")
        fmt_btn.clicked.connect(self._on_format_clicked)
        layout.addWidget(fmt_btn)

        layout.addStretch()

        self._fmt_label = QLabel("")
        layout.addWidget(self._fmt_label)

        layout.addSpacing(8)

        self._count_label = QLabel("")
        layout.addWidget(self._count_label)

        return bar

    def _build_source_bar(self) -> QWidget:
        """Bar with an 'Add Source' button and one colour chip per loaded source."""
        outer = QWidget()
        outer.setFixedHeight(36)
        outer_layout = QHBoxLayout(outer)
        outer_layout.setContentsMargins(4, 2, 4, 2)
        outer_layout.setSpacing(6)

        add_btn = QPushButton("+ Add Source")
        add_btn.setFixedHeight(26)
        add_btn.clicked.connect(self._on_add_source_clicked)
        outer_layout.addWidget(add_btn)

        # Scrollable area for chips (handles many sources gracefully)
        scroll = QScrollArea()
        scroll.setFrameStyle(0)
        # widgetResizable=False: chip_container keeps its natural width so the
        # scroll area's own size hint doesn't grow when chips are added, which
        # would otherwise force the window to widen.
        scroll.setWidgetResizable(False)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        install_horizontal_wheel_scroll(scroll, smooth_item_scroll=False)
        scroll.setFixedHeight(32)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        chip_container = QWidget()
        self._chip_layout = QHBoxLayout(chip_container)
        self._chip_layout.setContentsMargins(0, 0, 0, 0)
        self._chip_layout.setSpacing(4)
        self._chip_layout.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        # No addStretch() — container width = sum of chip widths; scroll area
        # shows a scrollbar only when chips overflow the available space.

        scroll.setWidget(chip_container)
        outer_layout.addWidget(scroll)

        return outer

    def _add_source_chip(self, source_id: int, name: str, color: QColor) -> None:
        chip = QPushButton(name)
        chip.setCheckable(True)
        chip.setChecked(True)
        chip.setFixedHeight(22)
        chip.setStyleSheet(
            f"QPushButton:checked {{ background-color: {color.name()}; color: white; "
            f"border-radius: 3px; padding: 0 6px; }}"
            f"QPushButton {{ border-radius: 3px; padding: 0 6px; }}"
        )
        chip.toggled.connect(
            lambda checked, sid=source_id: self._model.set_source_visible(sid, checked)
        )
        self._chip_layout.addWidget(chip)
        # Force the chip container to resize immediately.  Without this call the
        # scroll area (setWidgetResizable=False) keeps the container at its
        # original 0-size until the event loop runs a full paint cycle, so chips
        # added in a tight loop (e.g. folder-discovery mode) would be invisible.
        self._chip_layout.parentWidget().adjustSize()
        self._source_chips[source_id] = chip

    def _build_time_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(36)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        self._time_filter_cb = QCheckBox("Time range:")
        self._time_filter_cb.setChecked(False)
        self._time_filter_cb.toggled.connect(self._on_time_filter_toggled)
        layout.addWidget(self._time_filter_cb)

        self._dt_from = QDateTimeEdit()
        self._dt_from.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._dt_from.setCalendarPopup(True)
        self._dt_from.setEnabled(False)
        self._dt_from.setTimeSpec(Qt.TimeSpec.UTC)
        layout.addWidget(self._dt_from)

        layout.addWidget(QLabel("–"))

        self._dt_to = QDateTimeEdit()
        self._dt_to.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._dt_to.setCalendarPopup(True)
        self._dt_to.setEnabled(False)
        self._dt_to.setTimeSpec(Qt.TimeSpec.UTC)
        layout.addWidget(self._dt_to)

        self._time_reset_btn = QPushButton("Reset")
        self._time_reset_btn.setEnabled(False)
        self._time_reset_btn.clicked.connect(self._reset_time_filter)
        layout.addWidget(self._time_reset_btn)

        layout.addSpacing(16)

        layout.addWidget(QLabel("Display TZ:"))
        self._tz_combo = QComboBox()
        self._tz_combo.addItem("UTC", timezone.utc)
        self._tz_combo.addItem("Local", None)
        self._tz_combo.currentIndexChanged.connect(self._on_tz_changed)
        layout.addWidget(self._tz_combo)

        self._dt_from.dateTimeChanged.connect(self._apply_time_filter)
        self._dt_to.dateTimeChanged.connect(self._apply_time_filter)

        layout.addStretch()
        return bar

    def _build_col_text_filter_row(self) -> QWidget:
        """A thin row of QLineEdit inputs — one per filterable column — for contains-style filtering."""
        row = QWidget()
        row.setFixedHeight(28)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(4)
        self._col_text_inputs: dict[str, QLineEdit] = {}
        for _col_idx, (sql_col, label) in _COL_FILTER_MAP.items():
            edit = QLineEdit()
            edit.setPlaceholderText(label)
            edit.setFixedHeight(22)
            edit.setClearButtonEnabled(True)
            edit.textChanged.connect(
                lambda text, c=sql_col: self._on_col_text_filter_changed(c, text)
            )
            self._col_text_inputs[sql_col] = edit
            layout.addWidget(edit)
        return row

    def _on_col_text_filter_changed(self, col: str, text: str) -> None:
        self._model.set_column_text_filter(col, text)

    def _build_col_filter_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(30)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(6)
        layout.addWidget(QLabel("Active filters:"))
        self._col_filter_chip_layout = QHBoxLayout()
        self._col_filter_chip_layout.setSpacing(4)
        layout.addLayout(self._col_filter_chip_layout)
        clear_all_btn = QPushButton("Clear all")
        clear_all_btn.setFixedHeight(22)
        clear_all_btn.clicked.connect(self._clear_all_col_filters)
        layout.addWidget(clear_all_btn)
        layout.addStretch()
        return bar

    def _refresh_col_filter_bar(self) -> None:
        # Remove existing chips
        while self._col_filter_chip_layout.count():
            item = self._col_filter_chip_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        filters = self._model.active_column_filters()
        for col_name, value in filters.items():
            label = f"{col_name} = {value!r}"
            chip = QPushButton(f"✕  {label}")
            chip.setFixedHeight(22)
            chip.setToolTip(f"Remove filter: {label}")
            chip.clicked.connect(
                lambda _checked=False, c=col_name: self._remove_col_filter(c)
            )
            self._col_filter_chip_layout.addWidget(chip)

        self._col_filter_bar.setVisible(bool(filters))

    def _remove_col_filter(self, col_name: str) -> None:
        self._model.clear_column_filter(col_name)
        self._refresh_col_filter_bar()

    def _clear_all_col_filters(self) -> None:
        for col_name in list(self._model.active_column_filters()):
            self._model.clear_column_filter(col_name)
        self._refresh_col_filter_bar()

    # ------------------------------------------------------------------
    # Sort indicator handlers
    # ------------------------------------------------------------------

    def _on_sort_started(self) -> None:
        if all(not w.isRunning() for w in self._workers.values()):
            self._progress.setVisible(True)

    def _on_sort_finished(self) -> None:
        if all(not w.isRunning() for w in self._workers.values()):
            self._progress.setVisible(False)
        self._update_count()

    # ------------------------------------------------------------------
    # Worker signal handlers
    # ------------------------------------------------------------------

    def _on_progress(self, source_id: int, total_inserted: int) -> None:
        self._stop_status_anim()
        self._model.on_progress(source_id, total_inserted)
        self._update_count()

    def _on_status_update(self, source_id: int, text: str) -> None:
        self._count_label.setText(text)
        self._status_anim_idx = 0
        if not self._status_anim_timer.isActive():
            self._status_anim_timer.start()
        src_name = self._model.source_name(source_id)
        _log.info("[Multi-Log] %s — %s", src_name, text)

    def _on_status_anim_tick(self) -> None:
        color = self._status_anim_colors[
            self._status_anim_idx % len(self._status_anim_colors)
        ]
        self._status_anim_idx += 1
        self._count_label.setStyleSheet(
            f"QLabel {{ color: {color}; font-weight: bold; }}"
        )

    def _stop_status_anim(self) -> None:
        self._status_anim_timer.stop()
        self._count_label.setStyleSheet("")

    def _on_load_finished(self, source_id: int, fmt: str, metadata: dict[str, Any]) -> None:
        self._stop_status_anim()
        self._model.finalize_sort()
        self._update_count()

        elapsed = time.monotonic() - self._load_start_times.pop(source_id, time.monotonic())
        src_name = self._model.source_name(source_id)
        total = metadata.get("Total entries", str(self._model.total_count()))
        _log.info(
            "[Multi-Log] %s — %s entries loaded (%s) in %.1fs",
            src_name, total, fmt, elapsed,
        )

        # Resize fixed columns (idempotent; cheap after finalize_sort).
        # Cap source and process at 200 px — long subsystem/tag names or deep
        # file paths would otherwise push the table far beyond the window width.
        _COL_CAPS = {_COL_SRC: 200, _COL_PROC: 200, _COL_SUB: 240, _COL_CAT: 160}
        for col in (_COL_SRC, _COL_TS, _COL_LVL, _COL_PROC, _COL_PID, _COL_SUB, _COL_CAT):
            self._table.resizeColumnToContents(col)
            cap = _COL_CAPS.get(col)
            if cap and self._table.columnWidth(col) > cap:
                self._table.setColumnWidth(col, cap)

        # Append source info to the format label
        new_entry = f"{src_name}: {fmt}"
        existing = self._fmt_label.text()
        self._fmt_label.setText(new_entry if not existing else f"{existing}  |  {new_entry}")

        # Enable sorting + hide progress once every worker has finished
        if all(not w.isRunning() for w in self._workers.values()):
            self._table.setSortingEnabled(True)
            self._progress.setVisible(False)

        # Show / expand time bar to cover the full merged range
        ts_min, ts_max = self._model.timestamp_range()
        if ts_min is not None and ts_max is not None:
            self._dt_from.setDateTime(
                QDateTime.fromSecsSinceEpoch(int(ts_min.timestamp()), Qt.TimeSpec.UTC)
            )
            self._dt_to.setDateTime(
                QDateTime.fromSecsSinceEpoch(int(ts_max.timestamp()), Qt.TimeSpec.UTC)
            )
            self._time_bar.setVisible(True)

    def _on_error(self, source_id: int, message: str) -> None:
        self._stop_status_anim()
        src_name = self._model.source_name(source_id) or "?"
        self._fmt_label.setText(f"Error ({src_name}): {message}")
        _log.error("[Multi-Log] Error loading %s: %s", src_name, message)
        if all(not w.isRunning() for w in self._workers.values()):
            self._progress.setVisible(False)

    # ------------------------------------------------------------------
    # Slot handlers — Format button (Phase 4)
    # ------------------------------------------------------------------

    def _on_format_clicked(self) -> None:
        if not self._source_nodes:
            return
        # Build source list for the dialog's "Apply to source" combo
        sources = [
            (sid, self._model.source_name(sid))
            for sid in sorted(self._source_nodes)
        ]
        # Collect preview lines from the first source using already-loaded entries
        first_sid = sources[0][0]
        preview_lines = self._model.preview_lines_for_source(
            first_sid, DefineFormatDialog.PREVIEW_LINES
        )
        dlg = DefineFormatDialog(preview_lines, sources, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            profile = dlg.result_profile()
            if profile is not None:
                self.reload_source_with_profile(dlg.result_source_id(), profile)

    def reload_source_with_profile(self, source_id: int, profile: Any) -> None:
        """Re-parse an existing source using a custom format profile.

        Cancels the existing worker for that source (if still running),
        clears its entries from the model, then starts a fresh worker
        backed by ``profile``.
        """
        if source_id not in self._source_nodes:
            return
        node, vfs = self._source_nodes[source_id]

        # Stop the old worker if it is still loading
        old_worker = self._workers.get(source_id)
        if old_worker is not None and old_worker.isRunning():
            old_worker.cancel()
            old_worker.wait()   # brief block — parse is typically fast

        # Clear existing entries for this source from the DB
        self._model.replace_source_entries(source_id)

        # Launch a fresh worker with the custom profile
        worker = LogLoaderWorker(
            node, vfs, source_id, self._db.path, profile=profile, parent=self, temp_dir=self._log_temp_dir()
        )
        worker.progress.connect(self._on_progress)
        worker.load_finished.connect(self._on_load_finished)
        worker.error.connect(self._on_error)
        self._workers[source_id] = worker

        self._progress.setVisible(True)
        self._table.setSortingEnabled(False)
        worker.start()

    # ------------------------------------------------------------------
    # Slot handlers — Add Source button
    # ------------------------------------------------------------------

    def _on_add_source_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Add Log Source",
            "",
            "Log files (*.log *.txt *.json *.jsonl *.csv);;All files (*)",
        )
        if not path:
            return
        from crush.core.vfs import FileVFS
        vfs  = FileVFS(path)
        self.add_source(vfs.root(), vfs)

    # ------------------------------------------------------------------
    # Slot handlers — filters
    # ------------------------------------------------------------------

    def _on_level_toggled(self) -> None:
        allowed = {lvl for lvl, btn in self._level_btns.items() if btn.isChecked()}
        self._model.set_levels(allowed)

    def _on_search_changed(self, text: str) -> None:
        self._model.set_text(text)

    def _on_time_filter_toggled(self, checked: bool) -> None:
        self._dt_from.setEnabled(checked)
        self._dt_to.setEnabled(checked)
        self._time_reset_btn.setEnabled(checked)
        if checked:
            self._apply_time_filter()
        else:
            self._model.set_time_range(None, None)

    def _apply_time_filter(self) -> None:
        if not self._time_filter_cb.isChecked():
            return
        from_dt = datetime.fromtimestamp(
            self._dt_from.dateTime().toSecsSinceEpoch(), tz=timezone.utc
        )
        to_dt = datetime.fromtimestamp(
            self._dt_to.dateTime().toSecsSinceEpoch(), tz=timezone.utc
        )
        self._model.set_time_range(from_dt, to_dt)

    def _reset_time_filter(self) -> None:
        ts_min, ts_max = self._model.timestamp_range()
        spec = Qt.TimeSpec.UTC if self._display_tz is timezone.utc else Qt.TimeSpec.LocalTime
        if ts_min:
            self._dt_from.setDateTime(
                QDateTime.fromSecsSinceEpoch(int(ts_min.timestamp()), spec)
            )
        if ts_max:
            self._dt_to.setDateTime(
                QDateTime.fromSecsSinceEpoch(int(ts_max.timestamp()), spec)
            )
        self._model.set_time_range(None, None)

    def _on_tz_changed(self, index: int) -> None:
        tz_data = self._tz_combo.itemData(index)
        self._display_tz = tz_data if tz_data is not None else datetime.now().astimezone().tzinfo
        self._model.set_display_tz(self._display_tz)
        spec = Qt.TimeSpec.UTC if tz_data is timezone.utc else Qt.TimeSpec.LocalTime
        if self._time_bar.isVisible():
            for widget in (self._dt_from, self._dt_to):
                widget.setTimeSpec(spec)
            self._reset_time_filter()

    # ------------------------------------------------------------------
    # Slot handlers — table interaction
    # ------------------------------------------------------------------

    def _on_selection(self) -> None:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            self._raw_panel.clear()
            return
        entry = self._model.entry_at(indexes[0].row())
        parts = [entry.get("raw", "")]
        extra: dict[str, str] = entry.get("extra") or {}
        if extra:
            parts.append("\n--- Extra Fields ---")
            parts.extend(f"{k}: {v}" for k, v in extra.items())
        self._raw_panel.setPlainText("\n".join(parts))

    def _on_context_menu(self, pos: object) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        col = index.column()
        entry = self._model.entry_at(row)

        menu = QMenu(self)
        copy_msg  = menu.addAction("Copy message")
        copy_raw  = menu.addAction("Copy raw line")
        copy_rows = menu.addAction("Copy selection (TSV)")

        # Column filter action — only for filterable columns
        filter_action = None
        col_info = _COL_FILTER_MAP.get(col)
        if col_info is not None:
            sql_col, display_label = col_info
            # Determine cell value from entry dict
            _col_entry_keys: dict[str, str] = {
                "level": "level", "process": "process", "pid": "pid",
                "subsystem": "subsystem", "category": "category", "message": "message",
            }
            cell_val = entry.get(_col_entry_keys.get(sql_col, ""), "")
            if cell_val:
                menu.addSeparator()
                filter_action = menu.addAction(
                    f"Filter: {display_label} = {cell_val!r}"
                )

        action = menu.exec(self._table.viewport().mapToGlobal(pos))

        if action == copy_msg:
            QApplication.clipboard().setText(_msg_display(entry.get("message", "")))
        elif action == copy_raw:
            QApplication.clipboard().setText(entry.get("raw", ""))
        elif action == copy_rows:
            rows = sorted({i.row() for i in self._table.selectedIndexes()})
            lines: list[str] = []
            for r in rows:
                e = self._model.entry_at(r)
                lines.append("\t".join([
                    e.get("source", ""),
                    _fmt_ts(e.get("timestamp"), self._display_tz),
                    e.get("level", ""),
                    e.get("process", ""),
                    e.get("pid", ""),
                    e.get("subsystem", ""),
                    e.get("category", ""),
                    _msg_display(e.get("message", "")),
                ]))
            QApplication.clipboard().setText("\n".join(lines))
        elif filter_action is not None and action == filter_action:
            self._model.set_column_filter(sql_col, cell_val)
            self._refresh_col_filter_bar()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_count(self) -> None:
        total   = self._model.total_count()
        visible = self._model.visible_count()
        loading = any(w.isRunning() for w in self._workers.values())
        if total == 0:
            if not loading:
                self._count_label.setText("")
            # else: status_update already set the label text
        elif loading:
            # visible is 0 during silent loading; show total so user sees progress
            word = "entry" if total == 1 else "entries"
            self._count_label.setText(f"Loading… {total:,} {word}")
        elif visible == total:
            word = "entry" if total == 1 else "entries"
            self._count_label.setText(f"{total:,} {word}")
        else:
            self._count_label.setText(f"{visible:,} of {total:,} entries")


# ---------------------------------------------------------------------------
# Phase 5 — Folder log discovery
# ---------------------------------------------------------------------------

_LOG_EXTENSIONS: frozenset[str] = frozenset({
    ".log", ".txt", ".json", ".jsonl", ".syslog",
})

_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".db", ".sqlite", ".sqlite3", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".mp4", ".mov", ".avi", ".mkv", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".plist", ".dylib", ".so",
    ".exe", ".bin", ".dmg", ".ipa", ".realm", ".db-wal", ".db-shm",
    ".a", ".o", ".class", ".jar", ".apk", ".dex", ".wasm",
})

# Patterns counted during the slow-path probe (each regex is worth one hit).
# Two or more distinct hits → file accepted as a log.
_PROBE_RE: list[re.Pattern] = [  # type: ignore[type-arg]
    re.compile(r"\d{4}-\d{2}-\d{2}"),                                    # ISO date
    re.compile(r"\b\d{1,2}/\w{3}/\d{4}"),                                # Apache/syslog date
    re.compile(
        r"\b(ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|CRITICAL|FATAL|NOTICE)\b",
        re.IGNORECASE,
    ),
    re.compile(r"<\d+>"),                                                  # syslog PRI
    re.compile(r"\d{2}:\d{2}:\d{2}"),                                     # HH:MM:SS
    re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", re.MULTILINE),  # BSD syslog header
]

_PROBE_PEEK_BYTES: int = 4_096
_PROBE_LINES:      int = 40
_PROBE_THRESHOLD:  int = 2


def _file_ext(name: str) -> str:
    """Return the lowercase extension including the dot, or '' if none."""
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def _probe_is_log(node: VFSNode, vfs: VFS) -> bool:
    """Return True if *node* looks like a log file.

    Fast path — accept immediately for known log extensions; reject
    immediately for known binary types.  Slow path — read up to
    ``_PROBE_PEEK_BYTES`` bytes and count how many probe patterns fire;
    accept if the score reaches ``_PROBE_THRESHOLD``.
    """
    ext = _file_ext(node.name)
    if ext in _LOG_EXTENSIONS:
        return True
    if ext in _BINARY_EXTENSIONS:
        return False
    try:
        raw = vfs.read(node)[:_PROBE_PEEK_BYTES]
        if b"\x00" in raw[:512]:        # binary sentinel
            return False
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()[:_PROBE_LINES]
        hits = sum(1 for rx in _PROBE_RE if any(rx.search(ln) for ln in lines))
        return hits >= _PROBE_THRESHOLD
    except Exception:  # noqa: BLE001
        return False


def _discover_log_nodes(root: VFSNode, vfs: VFS) -> list[VFSNode]:
    """Walk the VFS subtree rooted at *root* and return file nodes that look like logs.

    The walk is depth-first; results are sorted by path for a predictable
    display order in the discovery dialog.
    """
    results: list[VFSNode] = []
    stack: list[VFSNode] = list(root.children)
    while stack:
        node = stack.pop()
        if node.is_dir:
            stack.extend(node.children)
        elif _probe_is_log(node, vfs):
            results.append(node)
    results.sort(key=lambda n: n.path)
    return results


class FolderDiscoveryDialog(QDialog):
    """Confirmation dialog shown before loading logs from a folder.

    Displays a checklist of discovered log files (all checked by default).
    The user can deselect individual files; the "Load N files" button label
    updates live to reflect the current selection count.

    After ``exec()`` returns ``Accepted``, call ``selected_nodes()`` to
    retrieve the user-approved list.
    """

    def __init__(
        self,
        folder_name: str,
        nodes: list[VFSNode],
        parent: QWidget | None = None,
        title: str = "Open Logs in Multi-Log Studio",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(540, 420)
        self._nodes = nodes
        self._build_ui(folder_name)

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def selected_nodes(self) -> list[VFSNode]:
        """Return the nodes whose checkboxes are still checked."""
        result: list[VFSNode] = []
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                result.append(item.data(Qt.ItemDataRole.UserRole))
        return result

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self, folder_name: str) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        n = len(self._nodes)
        header = QLabel(
            f"Found <b>{n}</b> log file{'s' if n != 1 else ''} in "
            f"<b>{folder_name}</b>. Select the files to load:"
        )
        header.setWordWrap(True)
        root.addWidget(header)

        # Select All / Deselect All
        sel_row = QHBoxLayout()
        all_btn  = QPushButton("Select All")
        none_btn = QPushButton("Deselect All")
        all_btn.setFixedWidth(100)
        none_btn.setFixedWidth(100)
        sel_row.addWidget(all_btn)
        sel_row.addWidget(none_btn)
        sel_row.addStretch()
        root.addLayout(sel_row)

        # Checklist
        self._list = QListWidget()
        self._list.setAlternatingRowColors(True)
        self._list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        for node in self._nodes:
            item = QListWidgetItem(node.path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, node)
            self._list.addItem(item)
        self._list.itemChanged.connect(self._update_load_btn)
        root.addWidget(self._list)

        # Bottom buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._load_btn = QPushButton()
        self._load_btn.setDefault(True)
        self._load_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self._load_btn)
        btn_row.addWidget(cancel_btn)
        root.addLayout(btn_row)

        all_btn.clicked.connect(self._select_all)
        none_btn.clicked.connect(self._deselect_all)

        self._update_load_btn()

    def _select_all(self) -> None:
        for i in range(self._list.count()):
            self._list.item(i).setCheckState(Qt.CheckState.Checked)

    def _deselect_all(self) -> None:
        for i in range(self._list.count()):
            self._list.item(i).setCheckState(Qt.CheckState.Unchecked)

    def _update_load_btn(self) -> None:
        n = sum(
            1 for i in range(self._list.count())
            if self._list.item(i).checkState() == Qt.CheckState.Checked
        )
        self._load_btn.setText(f"Load {n} file{'s' if n != 1 else ''}")
        self._load_btn.setEnabled(n > 0)
