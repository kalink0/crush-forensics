# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Table viewer — displays SQLite tables as a sortable, searchable grid."""
from __future__ import annotations

from typing import Any

import csv
import re
import sqlite3
import zlib
from contextlib import contextmanager
import struct
import time
from collections import Counter
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QRegularExpression,
    QSortFilterProxyModel,
    QStringListModel,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QKeyEvent,
    QKeySequence,
    QStandardItem,
    QStandardItemModel,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from crush.core.sqlite_freeblocks import scan_database_freeblocks
from crush.core.sqlite_freelist import (
    carve_freelist_rows,
    column_affinity,
    read_raw_page as _read_freelist_page,
    value_matches_affinity,
    walk_freelist_pages,
)
from crush.core.sqlite_unallocated import scan_database_unallocated
from crush.core.sqlite_wal import (
    build_page_table_map,
    build_wal_page_overlay,
    parse_table_leaf_page,
)
from crush.core.ts_decode import TS_FORMATS as _TS_FORMATS
from crush.core.ts_decode import decode_ts as _decode_ts
from crush.core.work_priority import (
    acquire_foreground_io,
    foreground_io,
    release_foreground_io,
)
from crush.ui.busy_dialog import run_with_busy_dialog
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.blob_inspector import BlobInspector


_MAX_COL_WIDTH = 400
_QUERY_ROW_LIMIT = 10_000
_COLUMN_SIZE_SAMPLE = 250
_VIRTUAL_PATH_BAD_CHARS = re.compile(r"[\\/:\x00-\x1f]+")


def _virtual_path_component(value: object, fallback: str) -> str:
    text = str(value or "").strip()
    text = _VIRTUAL_PATH_BAD_CHARS.sub("_", text)
    text = text.strip(" .")
    return text or fallback


class _QueryResultModel(QAbstractTableModel):
    """Virtual SQL result model that creates cell values only when requested."""

    def __init__(
        self,
        columns: list[str],
        rows: list[list[Any]],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._headers = ["Row"] + columns
        self._rows = rows
        self._ts_formats: dict[int, str] = {}

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._headers)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation != Qt.Orientation.Horizontal or role != Qt.ItemDataRole.DisplayRole:
            return None
        header = self._headers[section]
        fmt = self._ts_formats.get(section)
        if fmt is None:
            return header
        suffix = next(s for key, _, s in _TS_FORMATS if key == fmt)
        return f"{header} [{suffix}]"

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        col = index.column()
        value: Any = index.row() + 1 if col == 0 else self._rows[index.row()][col - 1]

        if role == Qt.ItemDataRole.DisplayRole:
            if value is None:
                return ""
            if isinstance(value, (bytes, bytearray, memoryview)):
                return f"<BLOB {len(value):,} B>"
            fmt = self._ts_formats.get(col)
            if fmt is not None and isinstance(value, (int, float)):
                decoded = _decode_ts(value, fmt)
                if decoded is not None:
                    return decoded
            return str(value)
        if role == Qt.ItemDataRole.UserRole:
            if isinstance(value, memoryview):
                return value.tobytes()
            if isinstance(value, bytearray):
                return bytes(value)
            return value
        if role == Qt.ItemDataRole.ForegroundRole:
            if value is None:
                return Qt.GlobalColor.gray
            if isinstance(value, (bytes, bytearray, memoryview)):
                return Qt.GlobalColor.blue
        return None

    def set_timestamp_format(self, col: int, fmt: str | None) -> None:
        if fmt is None:
            self._ts_formats.pop(col, None)
        else:
            self._ts_formats[col] = fmt
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, col, col)
        if self._rows:
            self.dataChanged.emit(
                self.index(0, col),
                self.index(len(self._rows) - 1, col),
                [Qt.ItemDataRole.DisplayRole],
            )


def _cap_columns(view: QTableView) -> None:
    """Clamp every column to _MAX_COL_WIDTH so wide cells don't force horizontal scrolling."""
    header = view.horizontalHeader()
    for col in range(view.model().columnCount()):
        if header.sectionSize(col) > _MAX_COL_WIDTH:
            header.resizeSection(col, _MAX_COL_WIDTH)


def _wal_diag(db_path: "str | None", parser_diag: str = "") -> str:
    """Return a short diagnostic string explaining why WAL parsing failed."""
    if db_path is None:
        return "db_path is None"
    wal_path = Path(str(db_path) + "-wal")
    if not wal_path.exists():
        suffix = f" (parser: {parser_diag})" if parser_diag else ""
        return f"WAL file not found at temp path{suffix}"
    size = wal_path.stat().st_size
    if size < 32:
        suffix = f" — parser: {parser_diag}" if parser_diag else ""
        return f"WAL too small ({size} B){suffix}"
    try:
        magic = struct.unpack_from(">I", wal_path.read_bytes(), 0)[0]
    except Exception as exc:
        return f"read error: {exc}"
    if magic not in _WAL_MAGIC:
        return f"invalid magic 0x{magic:08x}"
    return f"WAL ok (size={size} B, magic=0x{magic:08x}) — frames list empty"


def _format_wal_frame_content(rows: list[tuple[int, list[Any]]], col_names: list[str]) -> str:
    """Render decoded (rowid, values) tuples from a WAL frame's page as one
    compact string for the Content column — real column names when the
    frame's page maps to a known table with a matching column count,
    positional otherwise."""
    parts: list[str] = []
    for rowid, values in rows:
        if col_names and len(col_names) == len(values):
            body = ", ".join(f"{c}={v}" for c, v in zip(col_names, values))
        else:
            body = ", ".join(str(v) for v in values)
        parts.append(f"{rowid}: [{body}]")
    return "; ".join(parts)


class _SqlHighlighter(QSyntaxHighlighter):
    _KEYWORDS = (
        "SELECT FROM WHERE INSERT UPDATE DELETE CREATE DROP TABLE VIEW INDEX TRIGGER "
        "JOIN LEFT RIGHT INNER OUTER CROSS ON AS AND OR NOT IN IS NULL LIKE GLOB "
        "LIMIT OFFSET ORDER BY GROUP HAVING DISTINCT UNION ALL WITH PRAGMA BETWEEN "
        "CASE WHEN THEN ELSE END EXISTS PRIMARY KEY FOREIGN REFERENCES UNIQUE "
        "INTO VALUES SET BEGIN COMMIT ROLLBACK REPLACE UPSERT RETURNING "
        "COUNT SUM AVG MIN MAX COALESCE IFNULL NULLIF CAST TYPEOF LENGTH "
        "SUBSTR TRIM UPPER LOWER DATE TIME DATETIME STRFTIME"
    ).split()

    def __init__(self, document: object) -> None:
        super().__init__(document)
        is_dark = QApplication.palette().window().color().lightness() < 128

        def fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        if is_dark:
            kw  = fmt("#569cd6", bold=True)
            str_ = fmt("#ce9178")
            num  = fmt("#b5cea8")
            cmt  = fmt("#6a9955", italic=True)
        else:
            kw  = fmt("#0000cc", bold=True)
            str_ = fmt("#a31515")
            num  = fmt("#098658")
            cmt  = fmt("#008000", italic=True)

        ci = QRegularExpression.PatternOption.CaseInsensitiveOption
        kw_rx = r"\b(?:" + "|".join(self._KEYWORDS) + r")\b"
        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = [
            (QRegularExpression(kw_rx, ci),         kw),
            (QRegularExpression(r"'(?:[^'\\]|\\.)*'"),  str_),
            (QRegularExpression(r'"(?:[^"\\]|\\.)*"'),  str_),
            (QRegularExpression(r"\[([^\]]*)\]"),        str_),
            (QRegularExpression(r"\b\d+\.?\d*\b"),       num),
            (QRegularExpression(r"--[^\n]*"),            cmt),
        ]

    def highlightBlock(self, text: str) -> None:
        for rx, fmt in self._rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


class _SqlEditor(QPlainTextEdit):
    """Plain-text SQL editor with F5 run and context-aware identifier autocomplete."""

    run_requested = Signal()

    # After FROM/JOIN/INTO/UPDATE/TABLE and before any clause-breaking keyword
    # → complete table names only.
    _TABLE_CTX_RX = re.compile(r"\b(FROM|JOIN|INTO|UPDATE|TABLE)\b", re.IGNORECASE)
    _BREAK_CTX_RX = re.compile(
        r"\b(SELECT|SET|WHERE|ON|HAVING|LIMIT|OFFSET|ORDER|GROUP|AND|OR|CASE|WHEN|THEN|ELSE)\b",
        re.IGNORECASE,
    )
    # FROM/JOIN table_name [AS] alias  → captures (table_name, as_alias, bare_alias)
    _ALIAS_RX = re.compile(
        r"\b(?:FROM|JOIN)\s+(\w+)(?:\s+AS\s+(\w+)|\s+(\w+))?",
        re.IGNORECASE,
    )
    _ALIAS_KW = frozenset({
        "ON", "WHERE", "SET", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS",
        "NATURAL", "JOIN", "HAVING", "GROUP", "ORDER", "LIMIT", "OFFSET",
        "UNION", "INTERSECT", "EXCEPT", "SELECT", "AND", "OR", "NOT",
        "AS", "FROM", "INTO", "UPDATE", "TABLE",
    })

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._completer: QCompleter | None = None
        self._completer_model: QStringListModel | None = None
        self._schema: dict[str, list[str]] = {}

    def set_schema(self, schema: dict[str, list[str]]) -> None:
        """Set the DB schema for context-aware autocomplete. schema = {table: [col, ...]}."""
        self._schema = schema
        if not schema:
            return
        all_words = sorted(
            set(list(schema.keys()) + [c for cols in schema.values() for c in cols])
        )
        self._completer_model = QStringListModel(all_words, self)
        if self._completer is not None:
            self._completer.setParent(None)
        self._completer = QCompleter(self._completer_model, self)
        self._completer.setWidget(self)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._completer.activated.connect(self._insert_completion)

    def _get_context(self) -> tuple[str, str, str]:
        """Return (mode, prefix, table_name).

        mode 'table'  → complete table/view names only (after FROM/JOIN/…)
        mode 'column' → complete columns of table_name (dot notation: table.col)
        mode 'any'    → complete tables + all columns
        """
        text = self.toPlainText()
        pos = self.textCursor().position()

        start = pos
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            start -= 1
        prefix = text[start:pos]

        # Dot notation: users.na or alias.na → complete columns of resolved table
        if start > 0 and text[start - 1] == ".":
            tbl_end = start - 1
            tbl_start = tbl_end
            while tbl_start > 0 and (text[tbl_start - 1].isalnum() or text[tbl_start - 1] == "_"):
                tbl_start -= 1
            identifier = text[tbl_start:tbl_end]
            # Resolve alias (e.g. 'o' → 'orders') using FROM/JOIN declarations in the text
            aliases = self._parse_aliases(text)
            table_name = aliases.get(identifier.lower(), identifier)
            return "column", prefix, table_name

        # FROM/JOIN context: last table-keyword has no clause-breaking keyword after it
        before = text[:start]
        last_tbl_kw = None
        for m in self._TABLE_CTX_RX.finditer(before):
            last_tbl_kw = m
        if last_tbl_kw and not self._BREAK_CTX_RX.search(before[last_tbl_kw.end():]):
            return "table", prefix, ""

        return "any", prefix, ""

    def _parse_aliases(self, text: str) -> dict[str, str]:
        """Return {alias_lower: table_name} for all FROM/JOIN references in text."""
        result: dict[str, str] = {}
        for m in self._ALIAS_RX.finditer(text):
            table_name = m.group(1)
            alias = m.group(2) or m.group(3)
            if alias and alias.upper() not in self._ALIAS_KW:
                result[alias.lower()] = table_name
        return result

    def _words_for_context(self, mode: str, table_name: str) -> list[str]:
        if mode == "column":
            cols = self._schema.get(table_name)
            if cols is None:
                for t, c in self._schema.items():
                    if t.lower() == table_name.lower():
                        cols = c
                        break
            return sorted(cols or [])
        if mode == "table":
            return sorted(self._schema.keys())
        return sorted(
            set(list(self._schema.keys()) + [c for cols in self._schema.values() for c in cols])
        )

    def _insert_completion(self, completion: str) -> None:
        cursor = self.textCursor()
        text = self.toPlainText()
        pos = cursor.position()
        start = pos
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            start -= 1
        cursor.setPosition(start)
        cursor.setPosition(pos, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertText(completion)
        self.setTextCursor(cursor)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        run_modifiers = (
            Qt.KeyboardModifier.ControlModifier
            | Qt.KeyboardModifier.MetaModifier
        )
        if event.key() == Qt.Key.Key_F5 or (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and event.modifiers() & run_modifiers
        ):
            self.run_requested.emit()
            return

        # Let the completer popup consume its own navigation keys
        if self._completer and self._completer.popup().isVisible():
            if event.key() in (
                Qt.Key.Key_Return, Qt.Key.Key_Enter,
                Qt.Key.Key_Escape, Qt.Key.Key_Tab, Qt.Key.Key_Backtab,
            ):
                event.ignore()
                return

        super().keyPressEvent(event)

        if not self._completer or not self._schema:
            return

        mode, prefix, table_name = self._get_context()

        if not prefix:
            self._completer.popup().hide()
            return

        words = self._words_for_context(mode, table_name)
        if not words:
            self._completer.popup().hide()
            return

        assert self._completer_model is not None
        self._completer_model.setStringList(words)
        self._completer.setCompletionPrefix(prefix)
        self._completer.popup().setCurrentIndex(
            self._completer.completionModel().index(0, 0)
        )

        if self._completer.completionCount() == 0:
            self._completer.popup().hide()
            return

        # Show popup only when user typed an identifier char or used backspace
        ch = event.text()
        if (ch and (ch.isalnum() or ch == "_")) or event.key() == Qt.Key.Key_Backspace:
            rect = self.cursorRect()
            rect.setWidth(
                self._completer.popup().sizeHintForColumn(0)
                + self._completer.popup().verticalScrollBar().sizeHint().width()
            )
            self._completer.complete(rect)
        else:
            self._completer.popup().hide()


_WAL_MAGIC = (0x377F0682, 0x377F0683)

# (pragma, display label, kind, enum_map | None, description)
# kind values: "int" | "bool" | "enum" | "str"
_PRAGMA_CATALOG: list[tuple[str, str, str, dict[int, str] | None, str]] = [
    # File format
    ("application_id",     "Application ID",           "int",  None,
     "32-bit magic number identifying the application that created this database"),
    ("user_version",       "User version",             "int",  None,
     "Application-defined schema version number"),
    ("schema_version",     "Schema version",           "int",  None,
     "Internal counter incremented on every schema change"),
    ("encoding",           "Encoding",                 "str",  None,
     "Text encoding for all string data in this database"),
    ("page_size",          "Page size (B)",            "int",  None,
     "Size of each B-tree page; fixed at database creation time"),
    ("page_count",         "Page count",               "int",  None,
     "Total allocated pages; multiply by page_size to get expected file size"),
    ("freelist_count",     "Free pages",               "int",  None,
     "Unallocated pages that may contain deleted data — forensically significant. "
     "See the 'Freelist Recovery' tab to carve any leftover rows"),
    # Journal / safety
    ("journal_mode",       "Journal mode",             "str",  None,
     "Rollback journal strategy (delete / wal / truncate / persist / memory / off). "
     "Only the WAL/non-WAL distinction is stored in the file header — that part is "
     "reliable; any other value is this connection's default, not necessarily what "
     "was active historically (though the specific non-WAL sub-mode has no effect "
     "on recoverable data, only on journal file cleanup)"),
    # Vacuum / storage
    ("auto_vacuum",        "Auto vacuum",              "enum",
     {0: "NONE", 1: "FULL", 2: "INCREMENTAL"},
     "Automatic reclamation of free pages after DELETE"),
]


class TableViewer(QWidget):
    """Viewer for SQLite databases.

    data shape:
        {
          "table_name": {
              "columns": ["col1", "col2", ...],
              "rows":    [[val, val, ...], ...]
          },
          ...
        }
    """
    open_bytes_requested = Signal(bytes, str)
    open_bytes_with_format_requested = Signal(bytes, str, object, dict)

    def __init__(
        self,
        data: dict[str, Any],
        parent: QWidget | None = None,
        show_db_tabs: bool = True,
        summary_nav_table: str | None = None,
        source_name: str = "sqlite",
    ) -> None:
        super().__init__(parent)
        self._data = data
        self._source_name = source_name
        self._show_db_tabs = show_db_tabs
        self._summary_nav_table = summary_nav_table
        self._col_ts_formats: dict[int, str] = {}
        db_path_value = data.get("__db_path") if isinstance(data, dict) else None
        if isinstance(db_path_value, str) and db_path_value:
            candidate = Path(db_path_value)
            self._db_path = candidate if candidate.is_file() else None
        else:
            self._db_path = None
        self._db_conn: sqlite3.Connection | None = None
        self._summary_label = "Summary (generated)"
        self._db_structure_label = "DB Structure (generated)"
        self._db_info_label = "DB Info (generated)"
        self._wal_label = "WAL Frames (generated)"
        self._freelist_label = "Freelist Recovery (generated)"
        self._freeblocks_label = "Freeblocks (generated)"
        self._unallocated_label = "Unallocated Space (generated)"
        self._wal_frames_cache: list[dict] | None = None
        self._wal_page_size: int = 0
        self._db_page_size: int = 0
        self._wal_data_loaded = False
        self._wal_data_cache: bytes | None = None
        self._wal_page_overlay_cache: dict[int, bytes] | None = None
        self._freelist_cache: tuple[list[dict], list[dict]] | None = None
        self._freelist_render_state: (
            tuple[list[dict], list[dict], dict[str, list[tuple[str, str]]]] | None
        ) = None
        self._freeblocks_cache: list[dict] | None = None
        self._unallocated_cache: list[dict] | None = None
        self._page_table_map: dict[int, str] = {}  # page_num → table_name
        self._table_interaction_active = False
        self._build_ui()
        if data:
            table_names = [k for k in data.keys() if not k.startswith("__")]
            if self._db_path:
                self._table_combo.clear()
                if show_db_tabs:
                    self._table_combo.addItem(self._summary_label)
                    self._table_combo.addItem(self._db_structure_label)
                    self._table_combo.addItem(self._db_info_label)
                    if self._db_path and Path(str(self._db_path) + "-wal").exists():
                        self._table_combo.addItem(self._wal_label)
                    self._table_combo.addItem(self._freelist_label)
                    self._table_combo.addItem(self._freeblocks_label)
                    self._table_combo.addItem(self._unallocated_label)
                self._table_combo.addItems(table_names)
                if show_db_tabs:
                    conn = self._ensure_db()
                    if conn:
                        try:
                            view_names = [
                                r[0] for r in conn.execute(
                                    "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
                                ).fetchall()
                            ]
                            if view_names:
                                self._table_combo.insertSeparator(self._table_combo.count())
                                self._table_combo.addItems(view_names)
                        except Exception:
                            pass
                    self._load_summary()
                else:
                    if table_names:
                        self._load_table(table_names[0])
                    self._refresh_sql_completions()
            else:
                if table_names:
                    self._load_table(table_names[0])

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar row: table selector + row count + search
        toolbar = QWidget()
        toolbar.setFixedHeight(36)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)
        toolbar_layout.setSpacing(8)

        toolbar_layout.addWidget(QLabel("Table:"))

        self._table_combo = QComboBox()
        self._table_combo.addItems([k for k in self._data.keys() if not k.startswith("__")])
        self._table_combo.currentTextChanged.connect(self._load_table)
        toolbar_layout.addWidget(self._table_combo)

        self._row_count_label = QLabel("")
        toolbar_layout.addWidget(self._row_count_label)

        self._wal_toggle = QCheckBox("Show WAL history")
        self._wal_toggle.setVisible(False)
        self._wal_toggle.stateChanged.connect(self._on_wal_toggle)
        toolbar_layout.addWidget(self._wal_toggle)

        self._prev_ref_toggle = QCheckBox("Show diff to prev ref")
        self._prev_ref_toggle.setVisible(False)
        self._prev_ref_toggle.stateChanged.connect(self._on_prev_ref_toggle)
        toolbar_layout.addWidget(self._prev_ref_toggle)

        self._freelist_table_filter_label = QLabel("View as:")
        self._freelist_table_filter_label.setVisible(False)
        toolbar_layout.addWidget(self._freelist_table_filter_label)

        self._freelist_table_filter = QComboBox()
        self._freelist_table_filter.setVisible(False)
        self._freelist_table_filter.setMinimumWidth(160)
        self._freelist_table_filter.currentTextChanged.connect(
            self._on_freelist_table_filter_changed
        )
        toolbar_layout.addWidget(self._freelist_table_filter)

        toolbar_layout.addStretch()

        search_label = QLabel("Search:")
        toolbar_layout.addWidget(search_label)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rows…")
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        toolbar_layout.addWidget(self._search)

        layout.addWidget(toolbar)

        # SQL section: input row + status row below
        sql_bar = QWidget()
        sql_outer = QVBoxLayout(sql_bar)
        sql_outer.setContentsMargins(8, 4, 8, 2)
        sql_outer.setSpacing(2)

        sql_row = QWidget()
        sql_layout = QHBoxLayout(sql_row)
        sql_layout.setContentsMargins(0, 0, 0, 0)
        sql_layout.setSpacing(8)
        sql_layout.addWidget(QLabel("SQL:"))
        self._sql_input = _SqlEditor()
        self._sql_input.run_requested.connect(self._run_sql)
        self._sql_input.setPlaceholderText("SELECT * FROM table LIMIT 100;")
        line_h = self._sql_input.fontMetrics().lineSpacing()
        self._sql_input.setMinimumHeight(line_h * 6 + 8)
        self._sql_highlighter = _SqlHighlighter(self._sql_input.document())
        sql_layout.addWidget(self._sql_input, stretch=1)

        run_controls = QWidget()
        run_controls_layout = QVBoxLayout(run_controls)
        run_controls_layout.setContentsMargins(0, 0, 0, 0)
        run_controls_layout.setSpacing(4)
        self._run_sql_btn = QPushButton("Run")
        self._run_sql_btn.setToolTip("Run query (F5 or Command+Enter / Ctrl+Enter)")
        self._run_sql_btn.clicked.connect(self._run_sql)
        run_controls_layout.addWidget(self._run_sql_btn)
        self._auto_limit = QCheckBox("Auto limit")
        self._auto_limit.setChecked(True)
        self._auto_limit.setToolTip(
            f"Cap query results at {_QUERY_ROW_LIMIT:,} rows. Turn off to fetch every row."
        )
        run_controls_layout.addWidget(self._auto_limit)
        run_controls_layout.addStretch()
        sql_layout.addWidget(run_controls)

        export_controls = QWidget()
        export_controls_layout = QVBoxLayout(export_controls)
        export_controls_layout.setContentsMargins(0, 0, 0, 0)
        export_controls_layout.setSpacing(4)
        self._export_btn = QPushButton("Export CSV…")
        self._export_btn.clicked.connect(self._export_csv)
        export_controls_layout.addWidget(self._export_btn)
        export_controls_layout.addStretch()
        sql_layout.addWidget(export_controls)
        sql_outer.addWidget(sql_row)

        self._sql_status = QLabel("")
        self._sql_status.setContentsMargins(4, 0, 0, 2)
        self._sql_status.setWordWrap(True)
        self._sql_status.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Fixed,
        )
        self._sql_status.setMinimumWidth(0)
        sql_outer.addWidget(self._sql_status)

        # Table view
        self._source_model = QStandardItemModel()
        self._query_model: _QueryResultModel | None = None
        self._query_results_active = False
        self._last_executed_query = ""
        self._proxy_model = _NumericSortProxy()
        self._proxy_model.setSourceModel(self._source_model)
        self._proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy_model.setFilterKeyColumn(-1)  # Search all columns

        self._table_view = QTableView()
        self._table_view.setModel(self._proxy_model)
        self._table_view.setSortingEnabled(True)
        self._table_view.setAlternatingRowColors(True)
        self._table_view.setSelectionBehavior(
            QTableView.SelectionBehavior.SelectRows
        )
        self._table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table_view.customContextMenuRequested.connect(self._on_context_menu)
        self._table_view.horizontalHeader().setStretchLastSection(True)
        self._table_view.horizontalHeader().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table_view.horizontalHeader().customContextMenuRequested.connect(self._on_header_context_menu)
        self._table_view.verticalHeader().setDefaultSectionSize(22)
        self._table_view.doubleClicked.connect(self._on_table_double_clicked)
        install_horizontal_wheel_scroll(
            self._table_view, on_wheel=self._on_table_scroll_activity
        )
        self._table_view.verticalScrollBar().valueChanged.connect(
            self._on_table_scroll_activity
        )
        self._table_view.horizontalScrollBar().valueChanged.connect(
            self._on_table_scroll_activity
        )
        self._table_interaction_timer = QTimer(self)
        self._table_interaction_timer.setSingleShot(True)
        self._table_interaction_timer.setInterval(250)
        self._table_interaction_timer.timeout.connect(self._end_table_interaction)

        # Cell detail panel — shown below the table, updates on selection
        cell_detail = QWidget()
        cell_detail_layout = QVBoxLayout(cell_detail)
        cell_detail_layout.setContentsMargins(4, 2, 4, 2)
        cell_detail_layout.setSpacing(2)
        self._cell_detail_label = QLabel("—  No cell selected")
        self._cell_detail_label.setStyleSheet("color: gray; font-size: 11px;")
        cell_detail_layout.addWidget(self._cell_detail_label)
        self._cell_detail_view = QPlainTextEdit()
        self._cell_detail_view.setReadOnly(True)
        self._cell_detail_view.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._cell_detail_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        cell_detail_layout.addWidget(self._cell_detail_view, stretch=1)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(sql_bar)
        splitter.addWidget(self._table_view)
        splitter.addWidget(cell_detail)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        splitter.setSizes([140, 500, 80])
        layout.addWidget(splitter, stretch=1)

        self._table_view.selectionModel().currentChanged.connect(
            self._on_current_cell_changed
        )

    def _load_table(self, table_name: str) -> None:
        """Populate the model with the selected table's data.

        Disables the proxy model's dynamic sorting for the duration of the
        population loop below (which does self._reset_source_model() +
        many appendRow() calls) and re-sorts once at the end, instead of
        re-sorting incrementally on every single row insertion -- for a
        table with hundreds/thousands of rows and wide text columns (e.g.
        the Freeblocks tab's raw carved bytes), incremental re-sort turned
        an already-fast, cached data fetch into a many-second UI freeze on
        every tab switch.
        """
        # Switching tables must not leave the previous table's last-selected
        # cell visible in the detail box below — nothing is selected in the
        # freshly loaded table yet, so the box should say so too (#73).
        self._cell_detail_label.setText("—  No cell selected")
        self._cell_detail_view.setPlainText("")

        # Same bug class: the status line below the SQL box is tab-specific
        # (e.g. WAL Frames' "double-click to open in hex viewer", Freelist
        # Recovery's carve summary) but was never cleared on switch, so it
        # kept describing the *previous* tab after landing on a plain table
        # -- which never sets it itself and so never overwrote the leftover
        # text. Every generated tab sets its own status right after loading,
        # so clearing here is always immediately superseded except for plain
        # tables, which is exactly the case that needs it cleared.
        self._sql_status.setText("")
        self._sql_status.setStyleSheet("")

        # _activate_standard_model() itself turns dynamic sorting back on
        # (when leaving query-results mode), so it must run *before* it's
        # switched off here, or that reset would win.
        self._activate_standard_model()
        self._proxy_model.setDynamicSortFilter(False)
        try:
            self._load_table_impl(table_name)
        finally:
            self._proxy_model.setDynamicSortFilter(True)
            self._proxy_model.sort(
                self._proxy_model.sortColumn(), self._proxy_model.sortOrder()
            )

    def _load_table_impl(self, table_name: str) -> None:
        self._freelist_table_filter.setVisible(False)
        self._freelist_table_filter_label.setVisible(False)
        if table_name == self._summary_label:
            self._load_summary()
            return
        if table_name == self._db_structure_label:
            self._load_db_structure()
            return
        if table_name == self._db_info_label:
            self._load_db_info()
            return
        if table_name == self._wal_label:
            self._wal_toggle.setVisible(False)
            self._load_wal_frames()
            return
        if table_name == self._freelist_label:
            self._wal_toggle.setVisible(False)
            self._load_freelist_recovery()
            return
        if table_name == self._freeblocks_label:
            self._wal_toggle.setVisible(False)
            self._load_freeblocks()
            return
        if table_name == self._unallocated_label:
            self._wal_toggle.setVisible(False)
            self._load_unallocated_space()
            return
        table = self._data.get(table_name)
        if table is None:
            # Not pre-loaded (e.g. a view) — query live from the DB
            conn = self._ensure_db()
            if conn is None:
                return
            try:
                cur = conn.execute(f"SELECT * FROM [{table_name}] LIMIT 10001")  # noqa: S608
                raw_rows = cur.fetchall()
                was_truncated = len(raw_rows) > 10_000
                table = {
                    "columns": [d[0] for d in cur.description or []],
                    "rows": [list(r) for r in raw_rows[:10_000]],
                    "truncated": was_truncated,
                }
            except Exception as exc:
                self._sql_status.setStyleSheet("color: red;")
                self._sql_status.setText(str(exc))
                return

        # Ensure _page_table_map is populated before checking has_wal (cached after first call)
        self._get_wal_frames()

        # Show WAL toggle only for real tables that have WAL data
        has_wal = bool(self._page_table_map) and any(
            v == table_name for v in self._page_table_map.values()
        )
        self._wal_toggle.setVisible(has_wal)

        # Show prev-ref diff toggle only for tables that have inactive-ref data
        _prev_ref_all: dict | None = (
            self._data.get("__prev_ref_data") if isinstance(self._data, dict) else None
        )
        has_prev_ref = bool(_prev_ref_all and _prev_ref_all.get(table_name))
        self._prev_ref_toggle.setVisible(has_prev_ref)

        self._col_ts_formats.clear()
        columns: list[str] = table["columns"]
        rows: list[list[Any]] = table["rows"]

        self._reset_source_model()
        show_wal = has_wal and self._wal_toggle.isChecked()
        show_prev_ref = has_prev_ref and self._prev_ref_toggle.isChecked()
        show_source_col = show_wal or show_prev_ref
        source_col_name = "WAL Source" if show_wal else "Source"
        headers = ["Row"] + columns + ([source_col_name] if show_source_col else [])
        self._source_model.setHorizontalHeaderLabels(headers)

        def _append_row(row_data: list[Any], source_label: str | None = None,
                        row_color: object = None) -> None:
            row_index = self._source_model.rowCount() + 1
            row_item = QStandardItem(str(row_index))
            row_item.setEditable(False)
            row_item.setData(row_index, Qt.ItemDataRole.UserRole)
            if row_color:
                row_item.setForeground(row_color)
            items = [row_item]
            for val in row_data:
                if val is None:
                    cell = QStandardItem("")
                    cell.setForeground(Qt.GlobalColor.gray)
                elif isinstance(val, (bytes, bytearray, memoryview)):
                    blob = val if isinstance(val, bytes) else bytes(val)
                    cell = QStandardItem(f"<BLOB {len(blob):,} B>")
                    cell.setForeground(Qt.GlobalColor.blue)
                    cell.setData(blob, Qt.ItemDataRole.UserRole)
                elif (
                    isinstance(val, tuple) and len(val) == 2
                    and isinstance(val[0], str) and isinstance(val[1], (bytes, bytearray))
                ):
                    display, raw = val[0], val[1] if isinstance(val[1], bytes) else bytes(val[1])
                    cell = QStandardItem(display)
                    cell.setData(raw, Qt.ItemDataRole.UserRole)
                    if row_color:
                        cell.setForeground(row_color)
                elif isinstance(val, list):
                    # Realm List/Set/LinkList columns decode to a Python list.
                    # Flag it visibly -- it otherwise looks like plain bracketed
                    # text, and in SQL exports the same value is JSON text
                    # (queryable via json_each(), or already resolved in the
                    # auto-generated "v_<table>" view).
                    cell = QStandardItem(str(val) if val else "[]")
                    cell.setForeground(Qt.GlobalColor.gray if not val else QColor("#8844cc"))
                    cell.setToolTip(
                        f"List/Set column — {len(val)} item(s). Stored as JSON text in "
                        "SQL exports; query with json_each(...) or use the matching "
                        "\"v_<table>\" view for already-resolved link names."
                    )
                    cell.setData(val, Qt.ItemDataRole.UserRole)
                elif isinstance(val, dict):
                    # Realm Dictionary<K,Mixed> columns decode to a Python dict.
                    cell = QStandardItem(str(val) if val else "{}")
                    cell.setForeground(Qt.GlobalColor.gray if not val else QColor("#2a9d8f"))
                    cell.setToolTip(
                        f"Dictionary column — {len(val)} entrie(s). Stored as JSON text in "
                        "SQL exports; query with json_each(..., 'value')."
                    )
                    cell.setData(val, Qt.ItemDataRole.UserRole)
                else:
                    cell = QStandardItem(str(val))
                    if row_color:
                        cell.setForeground(row_color)
                if isinstance(val, (int, float)):
                    try:
                        cell.setData(val, Qt.ItemDataRole.UserRole)
                    except (OverflowError, Exception):
                        pass
                cell.setEditable(False)
                items.append(cell)
            if show_source_col:
                src = QStandardItem(source_label or "")
                src.setEditable(False)
                if row_color:
                    src.setForeground(row_color)
                items.append(src)
            self._source_model.appendRow(items)

        if show_prev_ref:
            prev_ref_table = (_prev_ref_all or {}).get(table_name, {})
            prev_obj_keys_set = {
                k for k in (prev_ref_table.get("__obj_keys") or []) if k is not None
            }
            active_obj_keys: list = (self._data.get(table_name) or {}).get("__obj_keys") or []
            _added_color = QColor("#228833")
            for r, row_data in enumerate(rows):
                objkey = active_obj_keys[r] if r < len(active_obj_keys) else None
                if objkey is not None and objkey not in prev_obj_keys_set:
                    _append_row(row_data, "added", _added_color)
                else:
                    _append_row(row_data)
        else:
            for row_data in rows:
                _append_row(row_data)

        wal_row_count = 0
        if show_wal:
            wal_row_count = self._inject_wal_rows(table_name, columns, _append_row)

        prev_ref_count = 0
        if show_prev_ref:
            prev_ref_count = self._inject_prev_ref_rows(table_name, columns, _append_row)

        self._resize_and_cap()
        table_meta = self._data.get(table_name, {}) if isinstance(self._data, dict) else {}
        was_truncated = isinstance(table_meta, dict) and table_meta.get("truncated", False)
        total = len(rows)
        row_word = "row" if total == 1 else "rows"
        label = f"(first {total:,} {row_word} — use SQL to load more)" if was_truncated \
            else f"({total:,} {row_word})"
        if wal_row_count:
            label += f"  +{wal_row_count} from WAL"
        if prev_ref_count:
            label += f"  +{prev_ref_count} from prev ref"
        self._row_count_label.setText(label)

    def _inject_wal_rows(
        self,
        table_name: str,
        columns: list[str],
        append_row: object,
    ) -> int:
        """Parse non-Active WAL frames for *table_name* and inject their rows.

        Returns the number of rows injected.
        """
        frames = self._get_wal_frames()
        if not frames or self._db_path is None or self._wal_page_size == 0:
            return 0

        _status_color: dict[str, object] = {
            "Superseded":  QColor("#cc8800"),
            "Uncommitted": QColor("#4488ff"),
            "WAL slack":   Qt.GlobalColor.darkGray,
        }

        try:
            wal_data = Path(str(self._db_path) + "-wal").read_bytes()
        except OSError:
            return 0

        injected = 0
        for f in frames:
            if f["status"] == "Active":
                continue
            if self._page_table_map.get(f["page"]) != table_name:
                continue

            page_start = f["offset"] + 24
            page_bytes = wal_data[page_start: page_start + self._wal_page_size]
            parsed = parse_table_leaf_page(page_bytes)
            if not parsed:
                continue

            color = _status_color.get(f["status"])
            label = f"WAL {f['status']} (frame {f['frame']})"
            n_cols = len(columns)
            for _rowid, values in parsed:
                padded: list[Any] = (values + [None] * n_cols)[:n_cols]
                append_row(padded, label, color)  # type: ignore[operator]
                injected += 1

        return injected

    def _on_wal_toggle(self, _state: int) -> None:
        """Re-load the current table when the WAL history toggle changes."""
        current = self._table_combo.currentText()
        if current and current not in (
            self._summary_label,
            self._db_structure_label,
            self._db_info_label,
            self._wal_label,
            self._freelist_label,
            self._freeblocks_label,
            self._unallocated_label,
        ):
            self._load_table(current)

    def _on_prev_ref_toggle(self, _state: int) -> None:
        """Re-load the current table when the prev-ref diff toggle changes."""
        current = self._table_combo.currentText()
        if current and current not in (
            self._summary_label,
            self._db_structure_label,
            self._db_info_label,
            self._wal_label,
            self._freelist_label,
            self._freeblocks_label,
            self._unallocated_label,
        ):
            self._load_table(current)

    def _inject_prev_ref_rows(
        self,
        table_name: str,
        columns: list[str],
        append_row: object,
    ) -> int:
        """Append deleted and modified-previous-version rows from the inactive Realm ref.

        Color coding mirrors the WAL viewer:
          - deleted  (in prev ref, not in active): red
          - prev version (modified row, previous state): orange
        Returns the number of rows injected.
        """
        prev_ref_all: dict | None = (
            self._data.get("__prev_ref_data") if isinstance(self._data, dict) else None
        )
        if not prev_ref_all:
            return 0
        prev_data = prev_ref_all.get(table_name)
        if not prev_data:
            return 0

        active_data = self._data.get(table_name) or {}
        active_obj_keys: list = active_data.get("__obj_keys") or []
        active_rows: list = active_data.get("rows") or []
        prev_obj_keys: list = prev_data.get("__obj_keys") or []
        prev_rows: list = prev_data.get("rows") or []

        active_by_key = {
            k: list(r) for k, r in zip(active_obj_keys, active_rows) if k is not None
        }
        prev_by_key = {
            k: list(r) for k, r in zip(prev_obj_keys, prev_rows) if k is not None
        }

        n_cols = len(columns)
        del_color = QColor("#cc3333")
        mod_color = QColor("#cc8800")
        injected = 0

        for key, prev_row in prev_by_key.items():
            padded_prev = (prev_row + [None] * n_cols)[:n_cols]
            if key not in active_by_key:
                append_row(padded_prev, "deleted", del_color)  # type: ignore[operator]
                injected += 1
            else:
                padded_active = (active_by_key[key] + [None] * n_cols)[:n_cols]
                if padded_prev != padded_active:
                    append_row(padded_prev, "prev version", mod_color)  # type: ignore[operator]
                    injected += 1

        return injected

    def _load_summary(self) -> None:
        """Show tables and views with row counts; label includes full schema object counts."""
        conn = self._ensure_db()
        if conn is None:
            return
        cursor = conn.cursor()
        try:
            rows_tv = cursor.execute(
                "SELECT name, type FROM sqlite_master "
                "WHERE type IN ('table', 'view') ORDER BY type, name"
            ).fetchall()
            counts = dict(
                cursor.execute(
                    "SELECT type, COUNT(*) FROM sqlite_master "
                    "WHERE type IN ('table', 'view', 'index', 'trigger') GROUP BY type"
                ).fetchall()
            )
        except Exception as exc:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(str(exc))
            return

        self._reset_source_model()
        self._source_model.setHorizontalHeaderLabels(["Name (generated)", "Type", "Rows"])
        self._sql_status.setStyleSheet("")

        for name, obj_type in rows_tv:
            try:
                count = cursor.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]  # noqa: S608
            except Exception:
                count = "?"
            name_item = QStandardItem(name)
            name_item.setEditable(False)
            type_item = QStandardItem(obj_type)
            type_item.setEditable(False)
            row_word = "row" if count == 1 else "rows"
            count_text = f"{count:,} {row_word}" if isinstance(count, int) else "?"
            count_item = QStandardItem(count_text)
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            count_item.setEditable(False)
            if isinstance(count, int):
                count_item.setData(count, Qt.ItemDataRole.UserRole)
            self._source_model.appendRow([name_item, type_item, count_item])

        self._resize_and_cap()

        def _c(key: str) -> int:
            return counts.get(key, 0)

        parts = [
            f"{_c('table')} table{'s' if _c('table') != 1 else ''}",
            f"{_c('view')} view{'s' if _c('view') != 1 else ''}",
            f"{_c('index')} index{'es' if _c('index') != 1 else ''}",
            f"{_c('trigger')} trigger{'s' if _c('trigger') != 1 else ''}",
        ]
        summary = ", ".join(parts)
        self._row_count_label.setText(f"({summary})")
        self._sql_status.setText(summary)
        self._refresh_sql_completions()

    def _load_db_structure(self) -> None:
        """Show all schema objects (tables, views, indexes, triggers) with structural info."""
        conn = self._ensure_db()
        if conn is None:
            return
        cursor = conn.cursor()
        try:
            objects = cursor.execute(
                "SELECT name, type, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'view', 'index', 'trigger') ORDER BY type, name"
            ).fetchall()
        except Exception as exc:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(str(exc))
            return

        self._reset_source_model()
        self._source_model.setHorizontalHeaderLabels(["Name (generated)", "Type", "Info"])
        self._sql_status.setStyleSheet("")

        for name, obj_type, tbl_name, sql in objects:
            name_item = QStandardItem(name)
            name_item.setEditable(False)
            type_item = QStandardItem(obj_type)
            type_item.setEditable(False)

            if obj_type == "table":
                try:
                    cols = cursor.execute(f"PRAGMA table_info([{name}])").fetchall()
                    col_names = ", ".join(r[1] for r in cols)
                    info_text = f"({col_names})"
                except Exception:
                    info_text = ""
            elif obj_type == "view":
                info_text = (sql or "").replace("\n", " ").strip()
            elif obj_type == "index":
                try:
                    idx_rows = cursor.execute(f"PRAGMA index_info([{name}])").fetchall()
                    cols = ", ".join(r[2] for r in idx_rows if r[2]) or "(expression)"
                    info_text = f"ON {tbl_name} ({cols})"
                except Exception:
                    info_text = f"ON {tbl_name}"
            elif obj_type == "trigger":
                first_line = (sql or "").split("\n")[0].strip()
                info_text = first_line if first_line else f"ON {tbl_name}"
            else:
                info_text = ""

            info_item = QStandardItem(info_text)
            info_item.setEditable(False)
            self._source_model.appendRow([name_item, type_item, info_item])

        self._resize_and_cap()
        total = self._source_model.rowCount()
        word = "object" if total == 1 else "objects"
        self._row_count_label.setText(f"({total} schema {word})")
        self._sql_status.setText("")

    def _get_wal_frames(self) -> list[dict] | None:
        """Parse WAL file and return classified frame list (cached)."""
        if self._wal_frames_cache is not None:
            return self._wal_frames_cache
        if self._db_path is None:
            return None
        wal_path = Path(str(self._db_path) + "-wal")
        if not wal_path.exists():
            return None
        try:
            data = wal_path.read_bytes()
        except OSError:
            return None
        if len(data) < 32:
            return None

        magic = struct.unpack_from(">I", data, 0)[0]
        if magic not in _WAL_MAGIC:
            return None

        page_size = struct.unpack_from(">I", data, 8)[0]
        self._wal_page_size = page_size
        salt1     = struct.unpack_from(">I", data, 16)[0]
        salt2     = struct.unpack_from(">I", data, 20)[0]

        frame_size = 24 + page_size
        offset = 32
        raw: list[dict] = []

        while offset + frame_size <= len(data):
            page_num = struct.unpack_from(">I", data, offset)[0]
            db_size  = struct.unpack_from(">I", data, offset + 4)[0]
            f_salt1  = struct.unpack_from(">I", data, offset + 8)[0]
            f_salt2  = struct.unpack_from(">I", data, offset + 12)[0]
            raw.append({
                "frame":     len(raw) + 1,
                "page":      page_num,
                "db_size":   db_size,
                "is_commit": db_size > 0,
                "salt_ok":   f_salt1 == salt1 and f_salt2 == salt2,
                "offset":    offset,
                "tx":        None,
                "status":    "",
            })
            offset += frame_size

        # Assign transaction numbers to salt-valid frames
        tx = 0
        for f in raw:
            if not f["salt_ok"]:
                continue
            f["tx"] = tx + 1
            if f["is_commit"]:
                tx += 1

        # Find last committed frame index (salt-valid + is_commit)
        last_commit_idx = -1
        for i, f in enumerate(raw):
            if f["salt_ok"] and f["is_commit"]:
                last_commit_idx = i

        # For committed range: track last occurrence of each page → active
        page_latest: dict[int, int] = {}
        for i, f in enumerate(raw):
            if f["salt_ok"] and i <= last_commit_idx:
                page_latest[f["page"]] = i

        # Classify
        for i, f in enumerate(raw):
            if not f["salt_ok"]:
                f["status"] = "WAL slack"
            elif i > last_commit_idx:
                f["status"] = "Uncommitted"
            elif page_latest.get(f["page"]) == i:
                f["status"] = "Active"
            else:
                f["status"] = "Superseded"

        self._wal_frames_cache = raw

        # Build page→table map (best-effort; silently ignore errors)
        conn = self._ensure_db()
        if conn is not None:
            try:
                self._page_table_map = build_page_table_map(conn, data, page_size)
            except Exception:
                self._page_table_map = {}

        return raw

    def _load_wal_frames(self) -> None:
        """Show full WAL frame inventory."""
        frames = self._get_wal_frames()
        self._reset_source_model()
        self._source_model.setHorizontalHeaderLabels(
            ["Frame", "Page", "Transaction", "Status", "Table", "Offset (B)", "Content"]
        )
        if not frames:
            parser_diag = self._data.get("__wal_diag", "") if isinstance(self._data, dict) else ""
            diag = _wal_diag(self._db_path, parser_diag)
            item = QStandardItem(f"No WAL file found or format not recognised — {diag}")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        _status_color: dict[str, object] = {
            "Superseded":  QColor("#cc8800"),
            "Uncommitted": QColor("#4488ff"),
            "WAL slack":   Qt.GlobalColor.darkGray,
        }

        wal_data = self._get_wal_data()

        schema_col_names: dict[str, list[str]] = {}
        conn = self._ensure_db()
        if conn is not None:
            schema_col_names = {
                name: [col for col, _aff in cols]
                for name, cols in self._table_schema_columns(conn).items()
            }

        for f in frames:
            color = _status_color.get(f["status"])
            table_name = self._page_table_map.get(f["page"], "—")

            content_text = "—"
            if f["salt_ok"] and wal_data is not None and self._wal_page_size:
                page_start = f["offset"] + 24
                page_bytes = wal_data[page_start: page_start + self._wal_page_size]
                decoded = parse_table_leaf_page(page_bytes, page_size=self._wal_page_size)
                if decoded is None:
                    content_text = "(not a leaf page)"
                elif not decoded:
                    content_text = "(empty leaf page)"
                else:
                    content_text = _format_wal_frame_content(
                        decoded, schema_col_names.get(table_name, [])
                    )

            def _item(text: str, sort_val: object = None, _c: object = color) -> QStandardItem:
                it = QStandardItem(text)
                it.setEditable(False)
                if sort_val is not None:
                    it.setData(sort_val, Qt.ItemDataRole.UserRole)
                if _c is not None:
                    it.setForeground(_c)
                return it

            self._source_model.appendRow([
                _item(str(f["frame"]),                   f["frame"]),
                _item(str(f["page"]),                    f["page"]),
                _item(str(f["tx"]) if f["tx"] else "—",  f["tx"] or 0),
                _item(f["status"]),
                _item(table_name),
                _item(str(f["offset"]),                  f["offset"]),
                _item(content_text),
            ])

        self._resize_and_cap()


        counts = Counter(f["status"] for f in frames)
        parts = [f"{len(frames)} total"]
        for status in ("Active", "Superseded", "Uncommitted", "WAL slack"):
            n = counts.get(status, 0)
            if n:
                parts.append(f"{n} {status.lower()}")
        self._row_count_label.setText(f"({', '.join(parts)})")
        self._sql_status.setText(
            "Double-click a row to open the raw page in the hex viewer — "
            "click a Content cell to see the full decoded value below"
        )

    def _get_wal_data(self) -> bytes | None:
        """Return (and cache) the raw -wal sidecar's bytes, or None if there
        isn't one. Shared by every caller that needs the live WAL's content
        (as opposed to _get_wal_frames()'s classified, page-size-validated
        frame list) so the file is only read once per viewer instance."""
        if self._wal_data_loaded:
            return self._wal_data_cache
        self._wal_data_loaded = True
        if self._db_path is not None:
            try:
                self._wal_data_cache = Path(str(self._db_path) + "-wal").read_bytes()
            except OSError:
                self._wal_data_cache = None
        return self._wal_data_cache

    def _get_wal_page_overlay(self) -> dict[int, bytes]:
        """Return (and cache) {page_num: bytes} for whatever the live -wal
        file has committed but not yet checkpointed into the base file.

        Every SQLite-recovery scanner (sqlite_freelist, sqlite_freeblocks,
        sqlite_unallocated) reads the base file's raw bytes directly rather
        than through sqlite3, so none of them see WAL content on their own —
        a page whose current, forensically-relevant content sits only in a
        not-yet-checkpointed WAL frame would otherwise look stale, missing,
        or (for the freelist header itself) simply absent even though
        PRAGMA freelist_count on a live connection already reports it.
        """
        if self._wal_page_overlay_cache is not None:
            return self._wal_page_overlay_cache
        page_size = self._get_page_size()
        self._wal_page_overlay_cache = build_wal_page_overlay(self._get_wal_data(), page_size)
        return self._wal_page_overlay_cache

    def _get_page_size(self) -> int:
        """Return (and cache) the database's page size via PRAGMA."""
        if self._db_page_size:
            return self._db_page_size
        conn = self._ensure_db()
        if conn is None:
            return 0
        try:
            row = conn.execute("PRAGMA page_size").fetchone()
            self._db_page_size = int(row[0]) if row else 0
        except Exception:
            self._db_page_size = 0
        return self._db_page_size

    def _get_freelist_data(self) -> tuple[list[dict], list[dict]]:
        """Return (and cache) (freelist entries, carved leftover rows)."""
        if self._freelist_cache is not None:
            return self._freelist_cache
        page_size = self._get_page_size()
        if self._db_path is None or page_size == 0:
            self._freelist_cache = ([], [])
            return self._freelist_cache
        wal_pages = self._get_wal_page_overlay()
        entries = walk_freelist_pages(self._db_path, page_size, wal_pages)
        carved = carve_freelist_rows(self._db_path, page_size, entries, wal_pages)
        self._freelist_cache = (entries, carved)
        return self._freelist_cache

    def _table_schema_columns(
        self, conn: sqlite3.Connection
    ) -> dict[str, list[tuple[str, str]]]:
        """Return {table_name: [(column_name, column_affinity), ...]} for
        every table in the schema, columns in declaration order."""
        result: dict[str, list[tuple[str, str]]] = {}
        try:
            names = [
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
        except Exception:
            return result
        for name in names:
            try:
                cols = conn.execute(f"PRAGMA table_info([{name}])").fetchall()  # noqa: S608
                result[name] = [(c[1], column_affinity(c[2])) for c in cols]
            except Exception:
                continue
        return result

    def _load_freelist_recovery(self) -> None:
        """Carve leftover table-leaf rows out of freed (freelist) pages.

        SQLite does not zero freed pages by default, so a page that used to
        hold table data can still carry its old cells until reused. Since a
        freed page is no longer referenced by any B-tree, the table it
        originally belonged to cannot be determined with certainty —
        "Candidate Tables" is a heuristic match by column count, refined by
        whether each value's storage class is possible under the candidate
        column's type affinity (see column_affinity()/value_matches_affinity()
        in sqlite_freelist.py). All matches are shown, tiered by confidence,
        rather than guessing a single one.
        """
        self._reset_source_model()
        conn = self._ensure_db()
        page_size = self._get_page_size()

        if conn is None or self._db_path is None or page_size == 0:
            self._source_model.setHorizontalHeaderLabels(["Freelist Recovery (generated)"])
            item = QStandardItem("Database file or page size unavailable")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        # Fast path: already cached, populate directly.
        if self._freelist_cache is not None:
            entries, carved = self._freelist_cache
            schema_cols = self._table_schema_columns(conn)
            self._render_freelist_recovery(entries, carved, schema_cols)
            return

        # Slow path: walk_freelist_pages/carve_freelist_rows haven't run yet
        # for this database -- do the full scan off the UI thread.
        def _work() -> tuple[list[dict], list[dict], dict[str, list[tuple[str, str]]]]:
            entries, carved = self._get_freelist_data()
            schema_cols = self._table_schema_columns(self._ensure_db())
            return entries, carved, schema_cols

        def _on_done(result: object) -> None:
            entries, carved, schema_cols = result  # type: ignore[misc]
            self._render_freelist_recovery(entries, carved, schema_cols)

        def _on_error(message: str) -> None:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(f"Error scanning freelist pages: {message}")

        run_with_busy_dialog(self, "Scanning freelist pages…", _work, _on_done, _on_error)

    def _render_freelist_recovery(
        self,
        entries: list[dict],
        carved: list[dict],
        schema_cols: dict[str, list[tuple[str, str]]],
    ) -> None:
        """Store freshly (re)scanned freelist data and (re)populate the
        table, refreshing the 'View as' pivot options against it."""
        self._freelist_render_state = (entries, carved, schema_cols)
        self._refresh_freelist_table_filter_options(carved, schema_cols)
        self._populate_freelist_recovery_table(
            entries, carved, schema_cols, self._freelist_table_filter.currentText()
        )

    def _refresh_freelist_table_filter_options(
        self, carved: list[dict], schema_cols: dict[str, list[tuple[str, str]]]
    ) -> None:
        """Populate the 'View as' combo with every table that is a candidate
        (either tier) for at least one carved row, keeping the current
        selection if it is still valid."""
        candidate_tables: set[str] = set()
        for c in carved:
            for _rowid, values in c["rows"]:
                full, count_only = self._candidate_table_tiers(values, schema_cols)
                candidate_tables.update(full)
                candidate_tables.update(count_only)

        previous = self._freelist_table_filter.currentText()
        self._freelist_table_filter.blockSignals(True)
        self._freelist_table_filter.clear()
        self._freelist_table_filter.addItem(self._FREELIST_FILTER_ALL)
        self._freelist_table_filter.addItems(sorted(candidate_tables))
        idx = self._freelist_table_filter.findText(previous)
        self._freelist_table_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self._freelist_table_filter.blockSignals(False)

        visible = bool(candidate_tables)
        self._freelist_table_filter.setVisible(visible)
        self._freelist_table_filter_label.setVisible(visible)

    def _on_freelist_table_filter_changed(self, _text: str) -> None:
        if self._freelist_render_state is None:
            return
        self._cell_detail_label.setText("—  No cell selected")
        self._cell_detail_view.setPlainText("")
        entries, carved, schema_cols = self._freelist_render_state
        self._populate_freelist_recovery_table(
            entries, carved, schema_cols, self._freelist_table_filter.currentText()
        )

    @staticmethod
    def _candidate_table_tiers(
        values: tuple, schema_cols: dict[str, list[tuple[str, str]]]
    ) -> tuple[list[str], list[str]]:
        """Split tables whose column count matches *values* into (types also
        match, count only) candidate-name lists, both sorted."""
        full: list[str] = []
        count_only: list[str] = []
        for name, cols in schema_cols.items():
            if len(cols) != len(values):
                continue
            if all(value_matches_affinity(v, aff) for v, (_name, aff) in zip(values, cols)):
                full.append(name)
            else:
                count_only.append(name)
        return sorted(full), sorted(count_only)

    _FREELIST_FILTER_ALL = "(all tables)"

    @staticmethod
    def _freelist_cell_text(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="replace")
        return str(v)

    def _populate_freelist_recovery_table(
        self,
        entries: list[dict],
        carved: list[dict],
        schema_cols: dict[str, list[tuple[str, str]]],
        selected_table: str | None = None,
    ) -> None:
        self._reset_source_model()
        if not entries:
            self._source_model.setHorizontalHeaderLabels(["Freelist Recovery (generated)"])
            item = QStandardItem("No freelist pages found")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        pivot_table = selected_table if selected_table not in (
            None, self._FREELIST_FILTER_ALL
        ) else None
        pivot_cols = schema_cols.get(pivot_table, []) if pivot_table else []

        if pivot_table:
            headers = ["Page", "Kind", "RowID", "Match"] + [name for name, _aff in pivot_cols]
        else:
            max_cols = max(
                (len(values) for c in carved for _rowid, values in c["rows"]), default=0
            )
            headers = ["Page", "Kind", "RowID", "Candidate Tables"] + [
                f"col{i}" for i in range(max_cols)
            ]
        self._source_model.setHorizontalHeaderLabels(headers)

        cand_tooltip = (
            "✓ = column count and value types both match (higher confidence). "
            "Others match column count only — value types don't rule them out, "
            "but don't confirm them either."
        )
        total_rows = 0
        with self._dynamic_sort_suspended():
            for c in carved:
                page, kind = c["page"], c["kind"]
                for rowid, values in c["rows"]:
                    full, count_only = self._candidate_table_tiers(values, schema_cols)

                    if pivot_table:
                        if pivot_table in full:
                            match_item = QStandardItem("✓ types match")
                            match_item.setForeground(QColor("#2a9d8f"))
                        elif pivot_table in count_only:
                            match_item = QStandardItem("count only")
                            match_item.setForeground(Qt.GlobalColor.gray)
                        else:
                            continue  # row isn't a candidate for the pivoted table at all
                        match_item.setToolTip(cand_tooltip)
                        lead_items = [
                            QStandardItem(str(page)),
                            QStandardItem(kind),
                            QStandardItem(str(rowid)),
                            match_item,
                        ]
                        n_value_cols = len(pivot_cols)
                    else:
                        if full and count_only:
                            cand_text = (
                                "✓ " + ", ".join(full) + "   |   " + ", ".join(count_only)
                            )
                        elif full:
                            cand_text = "✓ " + ", ".join(full)
                        elif count_only:
                            cand_text = ", ".join(count_only)
                        else:
                            cand_text = "—"
                        cand_item = QStandardItem(cand_text)
                        cand_item.setToolTip(cand_tooltip)
                        if full and not count_only:
                            cand_item.setForeground(QColor("#2a9d8f"))
                        elif count_only and not full:
                            cand_item.setForeground(Qt.GlobalColor.gray)
                        lead_items = [
                            QStandardItem(str(page)),
                            QStandardItem(kind),
                            QStandardItem(str(rowid)),
                            cand_item,
                        ]
                        n_value_cols = len(headers) - 4

                    items = lead_items
                    for i in range(n_value_cols):
                        text = self._freelist_cell_text(values[i]) if i < len(values) else ""
                        items.append(QStandardItem(text))
                    for it in items:
                        it.setEditable(False)
                    self._source_model.appendRow(items)
                    total_rows += 1

        self._resize_and_cap()
        n_pages_with_data = len({c["page"] for c in carved})
        if pivot_table:
            self._row_count_label.setText(
                f"({total_rows} rows carved matching '{pivot_table}')"
            )
            self._sql_status.setText(
                f"Showing carved rows candidate for table '{pivot_table}', columns mapped "
                "to its real names — this is still a candidate match, not a confirmed "
                "recovery. ✓ rows also match on value types (higher confidence); 'count "
                "only' rows match column count alone. Double-click a row to open the raw "
                "page in the hex viewer."
            )
        else:
            self._row_count_label.setText(
                f"({len(entries)} freelist pages, {n_pages_with_data} with recoverable data, "
                f"{total_rows} rows carved)"
            )
            if total_rows == 0:
                self._sql_status.setText(
                    f"{len(entries)} freed page(s) found, but none still carry leftover "
                    "cell data — not a parsing failure. Either a later allocation already "
                    "overwrote them, or secure_delete was enabled at write time."
                )
            else:
                self._sql_status.setText(
                    "Candidate tables are a heuristic match — the source table cannot be "
                    "determined with certainty from a freed page. ✓-marked candidates match on "
                    "both column count and value types (higher confidence); unmarked candidates "
                    "match column count only. Values spilling onto overflow "
                    "pages are reconstructed when those pages are still on the freelist "
                    "unmodified; otherwise shown as '<OVERFLOW>'. Double-click a row to open the "
                    "raw page in the hex viewer."
                )

    def _get_page_table_map(self) -> dict[int, str]:
        """Return (and cache) {page_num: table_name}, WAL-aware like
        _get_wal_frames() builds it -- unlike that method, this one is
        reachable without ever visiting the WAL Frames tab first (Freeblocks
        and Unallocated Space use it too), so it has to fetch the WAL data
        itself rather than assume _page_table_map was already populated."""
        if self._page_table_map:
            return self._page_table_map
        conn = self._ensure_db()
        page_size = self._get_page_size()
        if conn is None or page_size == 0:
            return {}
        try:
            self._page_table_map = build_page_table_map(conn, self._get_wal_data(), page_size)
        except Exception:
            self._page_table_map = {}
        return self._page_table_map

    def _get_freeblocks_data(self) -> list[dict]:
        """Return (and cache) every freeblock found anywhere in the database file."""
        if self._freeblocks_cache is not None:
            return self._freeblocks_cache
        page_size = self._get_page_size()
        if self._db_path is None or page_size == 0:
            self._freeblocks_cache = []
            return self._freeblocks_cache
        self._freeblocks_cache = scan_database_freeblocks(
            self._db_path, page_size, self._get_wal_page_overlay()
        )
        return self._freeblocks_cache

    def _load_freeblocks(self) -> None:
        """Carve leftover cell fragments out of in-page freeblocks.

        Unlike the Freelist Recovery tab (whole freed pages), this catches
        ordinary single-row DELETEs that never freed an entire page — SQLite
        splices the deleted cell into the page's freeblock list instead of
        zeroing it. The freeblock's own 4-byte header overwrites the start
        of the old cell, so the leftover bytes are shown raw rather than
        decoded into columns.
        """
        self._reset_source_model()
        conn = self._ensure_db()
        page_size = self._get_page_size()

        if conn is None or self._db_path is None or page_size == 0:
            self._source_model.setHorizontalHeaderLabels(["Freeblocks (generated)"])
            item = QStandardItem("Database file or page size unavailable")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        # Fast path: everything needed is already cached from a previous
        # visit to this or another SQLite-recovery tab -- populate directly,
        # no need for a background thread/busy dialog.
        if (
            self._freeblocks_cache is not None
            and self._page_table_map
            and self._freelist_cache is not None
        ):
            freelist_pages = {e["page"] for e in self._freelist_cache[0]}
            self._populate_freeblocks_table(
                self._freeblocks_cache, self._page_table_map, freelist_pages
            )
            return

        # Slow path: at least one of these caches is cold and needs a full
        # file scan (scan_database_freeblocks / build_page_table_map /
        # walk_freelist_pages+carve_freelist_rows) -- do that off the UI
        # thread so the window stays responsive instead of freezing for
        # however long the scan takes on this particular database.
        def _work() -> tuple[list[dict], dict[int, str], set[int]]:
            freeblocks = self._get_freeblocks_data()
            page_table_map = self._get_page_table_map()
            freelist_pages = {e["page"] for e in self._get_freelist_data()[0]}
            return freeblocks, page_table_map, freelist_pages

        def _on_done(result: object) -> None:
            freeblocks, page_table_map, freelist_pages = result  # type: ignore[misc]
            self._populate_freeblocks_table(freeblocks, page_table_map, freelist_pages)

        def _on_error(message: str) -> None:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(f"Error scanning freeblocks: {message}")

        run_with_busy_dialog(self, "Scanning for freeblocks…", _work, _on_done, _on_error)

    def _populate_freeblocks_table(
        self,
        freeblocks: list[dict],
        page_table_map: dict[int, str],
        freelist_pages: set[int],
    ) -> None:
        if not freeblocks:
            self._source_model.setHorizontalHeaderLabels(["Freeblocks (generated)"])
            item = QStandardItem("No freeblocks found")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        self._source_model.setHorizontalHeaderLabels(
            ["Page", "Table", "Offset (B)", "Size (B)", "Data"]
        )

        with self._dynamic_sort_suspended():
            for fb in freeblocks:
                page = fb["page"]
                if page in page_table_map:
                    origin = page_table_map[page]
                elif page in freelist_pages:
                    origin = "Freelist"
                else:
                    origin = "—"
                raw = fb["data"]
                if not raw:
                    text = ""
                elif not any(raw):
                    # A string of NUL bytes decodes fine but renders as an
                    # invisible blank cell in the table -- indistinguishable
                    # from "nothing here" even though Size (B) shows this
                    # freeblock is real. Say so explicitly instead (this is
                    # itself a legitimate, forensically meaningful result:
                    # e.g. secure_delete was on, or the space was never
                    # written to before being linked into the freeblock).
                    text = f"(all zero — {len(raw)} B)"
                else:
                    text = raw.decode("utf-8", errors="replace")

                items = [
                    QStandardItem(str(page)),
                    QStandardItem(origin),
                    QStandardItem(str(fb["offset"])),
                    QStandardItem(str(fb["size"])),
                    QStandardItem(text),
                ]
                for it in items:
                    it.setEditable(False)
                self._source_model.appendRow(items)

        self._resize_and_cap()
        self._row_count_label.setText(f"({len(freeblocks)} freeblocks)")
        self._sql_status.setText(
            "Raw leftover bytes from deleted cells still linked in each page's freeblock "
            "list — not decoded into columns, since the freeblock's own header overwrites "
            "the start of the original cell. Double-click a row to open the raw page in "
            "the hex viewer."
        )

    def _get_unallocated_data(self) -> list[dict]:
        """Return (and cache) every non-empty unallocated-space gap in the file."""
        if self._unallocated_cache is not None:
            return self._unallocated_cache
        page_size = self._get_page_size()
        if self._db_path is None or page_size == 0:
            self._unallocated_cache = []
            return self._unallocated_cache
        self._unallocated_cache = scan_database_unallocated(
            self._db_path, page_size, self._get_wal_page_overlay()
        )
        return self._unallocated_cache

    def _load_unallocated_space(self) -> None:
        """Show raw bytes from the gap between each table-leaf page's cell-pointer
        array and its cell-content area.

        Unlike Freeblocks, this space isn't a maintained structure — it's
        just whatever bytes happen to be sitting there, and SQLite makes no
        promise they're leftover row content rather than zeroed space or
        stale pointer values from a shrunk pointer array. Shown raw and
        unfiltered so the analyst can judge each entry themselves; entries
        that were entirely zero are not shown at all (nothing to judge).
        """
        self._reset_source_model()
        conn = self._ensure_db()
        page_size = self._get_page_size()

        if conn is None or self._db_path is None or page_size == 0:
            self._source_model.setHorizontalHeaderLabels(["Unallocated Space (generated)"])
            item = QStandardItem("Database file or page size unavailable")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        # Fast path: already cached, populate directly.
        if (
            self._unallocated_cache is not None
            and self._page_table_map
            and self._freelist_cache is not None
        ):
            freelist_pages = {e["page"] for e in self._freelist_cache[0]}
            self._populate_unallocated_table(
                self._unallocated_cache, self._page_table_map, freelist_pages
            )
            return

        # Slow path: at least one of these needs a fresh full-file scan.
        def _work() -> tuple[list[dict], dict[int, str], set[int]]:
            entries = self._get_unallocated_data()
            page_table_map = self._get_page_table_map()
            freelist_pages = {e["page"] for e in self._get_freelist_data()[0]}
            return entries, page_table_map, freelist_pages

        def _on_done(result: object) -> None:
            entries, page_table_map, freelist_pages = result  # type: ignore[misc]
            self._populate_unallocated_table(entries, page_table_map, freelist_pages)

        def _on_error(message: str) -> None:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(f"Error scanning unallocated space: {message}")

        run_with_busy_dialog(self, "Scanning unallocated space…", _work, _on_done, _on_error)

    def _populate_unallocated_table(
        self,
        entries: list[dict],
        page_table_map: dict[int, str],
        freelist_pages: set[int],
    ) -> None:
        if not entries:
            self._source_model.setHorizontalHeaderLabels(["Unallocated Space (generated)"])
            item = QStandardItem("No non-empty unallocated space found")
            item.setEditable(False)
            self._source_model.appendRow([item])
            self._row_count_label.setText("")
            return

        self._source_model.setHorizontalHeaderLabels(
            ["Page", "Table", "Offset (B)", "Size (B)", "Data"]
        )

        with self._dynamic_sort_suspended():
            for entry in entries:
                page = entry["page"]
                if page in page_table_map:
                    origin = page_table_map[page]
                elif page in freelist_pages:
                    origin = "Freelist"
                else:
                    origin = "—"
                text = entry["data"].decode("utf-8", errors="replace")

                items = [
                    QStandardItem(str(page)),
                    QStandardItem(origin),
                    QStandardItem(str(entry["offset"])),
                    QStandardItem(str(entry["size"])),
                    QStandardItem(text),
                ]
                for it in items:
                    it.setEditable(False)
                self._source_model.appendRow(items)

        self._resize_and_cap()
        self._row_count_label.setText(f"({len(entries)} pages with non-empty unallocated space)")
        self._sql_status.setText(
            "Raw bytes only, not verified as recoverable row content — SQLite doesn't "
            "guarantee anything meaningful survives here, unlike Freeblocks. Often noise "
            "(stale pointer values) or empty. Double-click a row to open the raw page in "
            "the hex viewer."
        )

    def _on_table_double_clicked(self, index: object) -> None:
        """Double-click handler: navigate to table from summary, open WAL page in hex viewer, or inspect bytes cell."""
        current = self._table_combo.currentText()

        if self._query_results_active:
            model_index = self._proxy_model.index(index.row(), index.column())  # type: ignore[union-attr]
            raw = self._proxy_model.data(model_index, Qt.ItemDataRole.UserRole)
            display = self._proxy_model.data(model_index, Qt.ItemDataRole.DisplayRole)
            blob = _coerce_blob(raw)
            display_text = str(display) if display is not None else ""
            if blob is not None:
                is_placeholder = display_text.startswith("<BLOB ") and display_text.endswith(" B>")
                self._preview_blob(
                    blob,
                    display_text=display_text if display_text and not is_placeholder else None,
                )
            elif display_text:
                self._preview_blob(
                    display_text.encode("utf-8", errors="replace"),
                    display_text=display_text,
                )
            return

        if current in (self._summary_label, self._summary_nav_table):
            src_row = self._proxy_model.mapToSource(
                self._proxy_model.index(index.row(), 0)  # type: ignore[union-attr]
            ).row()
            # _summary_label rows are built by _load_summary (no "Row" prefix col → name at col 0).
            # _summary_nav_table rows go through _load_table which prepends a "Row" col → name at col 1.
            name_col = 0 if current == self._summary_label else 1
            name_item = self._source_model.item(src_row, name_col)
            if name_item and self._table_combo.findText(name_item.text()) >= 0:
                self._table_combo.setCurrentText(name_item.text())
            return

        if current == self._freelist_label:
            if self._db_path is None:
                return
            page_size = self._get_page_size()
            if page_size == 0:
                return
            row = self._proxy_model.mapToSource(self._proxy_model.index(index.row(), 0)).row()  # type: ignore[union-attr]
            page_item = self._source_model.item(row, 0)
            if page_item is None:
                return
            try:
                page_num = int(page_item.text())
            except ValueError:
                return
            page_bytes = _read_freelist_page(
                self._db_path, page_num, page_size, self._get_wal_page_overlay()
            )
            if page_bytes:
                self.open_bytes_requested.emit(page_bytes, f"Freelist page {page_num}")
            return

        if current == self._freeblocks_label:
            if self._db_path is None:
                return
            page_size = self._get_page_size()
            if page_size == 0:
                return
            row = self._proxy_model.mapToSource(self._proxy_model.index(index.row(), 0)).row()  # type: ignore[union-attr]
            page_item = self._source_model.item(row, 0)
            if page_item is None:
                return
            try:
                page_num = int(page_item.text())
            except ValueError:
                return
            page_bytes = _read_freelist_page(
                self._db_path, page_num, page_size, self._get_wal_page_overlay()
            )
            if page_bytes:
                self.open_bytes_requested.emit(page_bytes, f"Page {page_num} (freeblock)")
            return

        if current == self._unallocated_label:
            if self._db_path is None:
                return
            page_size = self._get_page_size()
            if page_size == 0:
                return
            row = self._proxy_model.mapToSource(self._proxy_model.index(index.row(), 0)).row()  # type: ignore[union-attr]
            page_item = self._source_model.item(row, 0)
            if page_item is None:
                return
            try:
                page_num = int(page_item.text())
            except ValueError:
                return
            page_bytes = _read_freelist_page(
                self._db_path, page_num, page_size, self._get_wal_page_overlay()
            )
            if page_bytes:
                self.open_bytes_requested.emit(page_bytes, f"Page {page_num} (unallocated space)")
            return

        if current != self._wal_label:
            source = self._proxy_model.mapToSource(index)
            item = self._source_model.item(source.row(), source.column())
            if item is not None:
                blob = _coerce_blob(item.data(Qt.ItemDataRole.UserRole))
                display_val = item.text()
                if blob is not None:
                    is_blob_placeholder = display_val.startswith("<BLOB ") and display_val.endswith(" B>")
                    decoded = display_val if not is_blob_placeholder and display_val else None
                    self._preview_blob(blob, display_text=decoded)
                elif display_val:
                    # SQL result cells: no raw bytes, but display text is the decoded content
                    self._preview_blob(display_val.encode("utf-8", errors="replace"), display_text=display_val)
            return
        if self._db_path is None or self._wal_page_size == 0:
            return

        row = self._proxy_model.mapToSource(self._proxy_model.index(index.row(), 0)).row()  # type: ignore[union-attr]

        def _user(col: int) -> object:
            return self._source_model.item(row, col).data(Qt.ItemDataRole.UserRole)

        frame_num = _user(0)
        page_num  = _user(1)
        offset    = _user(5)
        if offset is None:
            return

        wal_path = Path(str(self._db_path) + "-wal")
        try:
            wal_data = wal_path.read_bytes()
            page_start = int(offset) + 24  # skip 24-byte frame header
            page_bytes = wal_data[page_start : page_start + self._wal_page_size]
        except OSError:
            return

        if page_bytes:
            self.open_bytes_requested.emit(
                page_bytes,
                f"WAL frame {frame_num} — page {page_num}",
            )

    def _load_db_info(self) -> None:
        """Show all PRAGMA settings with decoded enum values and descriptions."""
        conn = self._ensure_db()
        if conn is None:
            return
        cursor = conn.cursor()
        self._reset_source_model()
        self._source_model.setHorizontalHeaderLabels(["Setting (generated)", "Value", "Description"])

        # WAL summary block (if present)
        frames = self._get_wal_frames()
        if frames is not None:

            counts = Counter(f["status"] for f in frames)

            def _wal_row(label: str, value: str, desc: str, color: object = None) -> None:
                s = QStandardItem(label)
                s.setEditable(False)
                v = QStandardItem(value)
                v.setEditable(False)
                d = QStandardItem(desc)
                d.setForeground(Qt.GlobalColor.gray)
                d.setEditable(False)
                if color is not None:
                    for item in (s, v):
                        item.setForeground(color)
                self._source_model.appendRow([s, v, d])

            wal_path = Path(str(self._db_path) + "-wal")
            wal_size = wal_path.stat().st_size if wal_path.exists() else 0
            _wal_row("WAL file size (B)",    f"{wal_size:,}",                  "Size of the -wal companion file on disk")
            _wal_row("WAL total frames",     str(len(frames)),                 "Total frames found in WAL file")
            _wal_row("WAL active frames",    str(counts.get("Active", 0)),     "Frames currently read by SQLite (newest per page)")
            n_sup = counts.get("Superseded", 0)
            _wal_row("WAL superseded frames", str(n_sup),
                     "Older versions of pages — may contain overwritten or deleted data",
                     QColor("#cc8800") if n_sup else None)
            n_unc = counts.get("Uncommitted", 0)
            _wal_row("WAL uncommitted frames", str(n_unc),
                     "Frames beyond the last commit marker — captured mid-transaction",
                     QColor("#4488ff") if n_unc else None)
            n_slack = counts.get("WAL slack", 0)
            _wal_row("WAL slack frames",     str(n_slack),
                     "Salt-mismatch frames from a previous WAL cycle — reused WAL space",
                     Qt.GlobalColor.darkGray if n_slack else None)

            # Visual separator
            sep = QStandardItem("─" * 30)
            sep.setForeground(Qt.GlobalColor.gray)
            sep.setEditable(False)
            self._source_model.appendRow([sep, QStandardItem(""), QStandardItem("")])

        for pragma, label, ptype, enum_map, description in _PRAGMA_CATALOG:
            try:
                row = cursor.execute(f"PRAGMA {pragma}").fetchone()
                raw = row[0] if row else None
            except Exception:
                raw = None

            if raw is None:
                display = "—"
            elif ptype == "bool":
                try:
                    iv = int(raw)
                    display = f"{iv} — {'ON' if iv else 'OFF'}"
                except (ValueError, TypeError):
                    display = str(raw)
            elif ptype == "enum" and enum_map:
                try:
                    iv = int(raw)
                    label_str = enum_map.get(iv, str(iv))
                    display = f"{iv} — {label_str}"
                except (ValueError, TypeError):
                    display = str(raw)
            else:
                display = str(raw)

            setting_item = QStandardItem(label)
            setting_item.setEditable(False)
            value_item = QStandardItem(display)
            value_item.setEditable(False)
            desc_item = QStandardItem(description)
            desc_item.setForeground(Qt.GlobalColor.gray)
            desc_item.setEditable(False)
            self._source_model.appendRow([setting_item, value_item, desc_item])

        hint_item = QStandardItem("Integrity check")
        hint_item.setEditable(False)
        hint_value = QStandardItem("→ run in SQL bar: PRAGMA integrity_check")
        hint_value.setForeground(Qt.GlobalColor.gray)
        hint_value.setEditable(False)
        hint_desc = QStandardItem("Scans database for corruption (can be slow on large files)")
        hint_desc.setForeground(Qt.GlobalColor.gray)
        hint_desc.setEditable(False)
        self._source_model.appendRow([hint_item, hint_value, hint_desc])

        self._resize_and_cap()
        self._row_count_label.setText(f"({len(_PRAGMA_CATALOG)} settings)")
        self._sql_input.setPlainText("PRAGMA integrity_check;")
        self._sql_status.setText("")

    def _apply_filter(self, text: str) -> None:
        self._proxy_model.setFilterFixedString(text)
        visible = self._proxy_model.rowCount()
        source = self._proxy_model.sourceModel()
        total = source.rowCount() if source is not None else 0
        if text:
            self._row_count_label.setText(f"({visible:,} of {total:,} rows)")
        else:
            word = "row" if total == 1 else "rows"
            self._row_count_label.setText(f"({total:,} {word})")

    def _ensure_db(self) -> sqlite3.Connection | None:
        if not self._db_path or not self._db_path.exists():
            self._sql_status.setText("Database file missing")
            return None
        if self._db_conn is None:
            self._db_conn = sqlite3.connect(
                f"file:{self._db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            self._db_conn.row_factory = sqlite3.Row
        return self._db_conn

    def _refresh_sql_completions(self) -> None:
        """Populate the SQL editor autocomplete with the full DB schema."""
        conn = self._ensure_db()
        if conn is None:
            return
        schema: dict[str, list[str]] = {}
        try:
            objects = conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name"
            ).fetchall()
            for row in objects:
                name = row["name"]
                try:
                    col_rows = conn.execute(f"PRAGMA table_info([{name}])").fetchall()
                    schema[name] = [c["name"] for c in col_rows]
                except Exception:
                    schema[name] = []
        except Exception:
            pass
        self._sql_input.set_schema(schema)

    def _run_sql(self) -> None:
        cursor = self._sql_input.textCursor()
        selected = cursor.selectedText().replace("", "\n").strip()
        sql = selected if selected else self._sql_input.toPlainText().strip()
        if not sql:
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText("Enter a SELECT or PRAGMA query")
            self._sql_status.setToolTip("")
            return
        lowered = sql.lstrip().lower()
        if not (lowered.startswith("select") or lowered.startswith("with") or lowered.startswith("pragma")):
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText("Only SELECT and PRAGMA queries are allowed")
            self._sql_status.setToolTip("")
            return
        conn = self._ensure_db()
        if conn is None:
            return
        started = time.perf_counter()
        try:
            with foreground_io():
                priority_wait_elapsed = time.perf_counter() - started
                execute_started = time.perf_counter()
                cur = conn.cursor()
                cur.execute(sql)
                execute_elapsed = time.perf_counter() - execute_started
                columns = [desc[0] for desc in cur.description or []]
                fetch_started = time.perf_counter()
                fetch_cpu_started = time.process_time()
                if self._auto_limit.isChecked():
                    rows = cur.fetchmany(_QUERY_ROW_LIMIT + 1)
                else:
                    rows = cur.fetchall()
                fetch_cpu_elapsed = time.process_time() - fetch_cpu_started
                fetch_elapsed = time.perf_counter() - fetch_started
        except sqlite3.Error as exc:
            elapsed = time.perf_counter() - started
            self._sql_status.setStyleSheet("color: red;")
            self._sql_status.setText(f"{exc} (failed after {elapsed:.2f} s)")
            self._sql_status.setToolTip("")
            return

        was_truncated = self._auto_limit.isChecked() and len(rows) > _QUERY_ROW_LIMIT
        if was_truncated:
            rows = rows[:_QUERY_ROW_LIMIT]
        prepare_started = time.perf_counter()
        data = {
            "columns": columns,
            "rows": [list(row) for row in rows],
            "truncated": was_truncated,
        }
        prepare_elapsed = time.perf_counter() - prepare_started
        self._last_executed_query = sql
        model_elapsed, resize_elapsed = self._load_table_from_query(data)
        elapsed = time.perf_counter() - started

        self._sql_status.setStyleSheet("")
        word = "row" if len(rows) == 1 else "rows"
        status = f"{len(rows):,} {word} returned in {elapsed:.2f} s"
        timing_details = (
            f"Index wait: {priority_wait_elapsed:.2f} s\n"
            f"Execute: {execute_elapsed:.2f} s\n"
            f"Fetch: {fetch_elapsed:.2f} s wall / {fetch_cpu_elapsed:.2f} s CPU\n"
            f"Rows: {prepare_elapsed:.2f} s\n"
            f"Model: {model_elapsed:.2f} s\n"
            f"Column sizing: {resize_elapsed:.2f} s\n"
            f"Total: {elapsed:.2f} s"
        )
        if was_truncated:
            status = f"First {status}"
            timing_details += (
                f"\n\nAuto limit capped the result at {_QUERY_ROW_LIMIT:,} rows. "
                "Add filters or turn off Auto limit to fetch more."
            )
        self._sql_status.setText(status)
        self._sql_status.setToolTip(timing_details)

    def _load_table_from_query(self, table: dict[str, Any]) -> tuple[float, float]:
        self._cell_detail_label.setText("—  No cell selected")
        self._cell_detail_view.setPlainText("")
        self._col_ts_formats.clear()
        columns: list[str] = table["columns"]
        rows: list[list[Any]] = table["rows"]

        model_started = time.perf_counter()
        old_query_model = self._query_model
        self._query_model = _QueryResultModel(columns, rows, self)
        self._query_results_active = True
        self._proxy_model.setDynamicSortFilter(False)
        self._proxy_model.sort(-1, Qt.SortOrder.AscendingOrder)
        self._proxy_model.setSourceModel(self._query_model)
        if old_query_model is not None:
            old_query_model.deleteLater()
        model_elapsed = time.perf_counter() - model_started

        resize_started = time.perf_counter()
        self._resize_and_cap()
        resize_elapsed = time.perf_counter() - resize_started
        row_word = "row" if len(rows) == 1 else "rows"
        prefix = "first " if table.get("truncated", False) else ""
        self._row_count_label.setText(f"({prefix}{len(rows):,} {row_word})")
        return model_elapsed, resize_elapsed

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                headers = [
                    self._proxy_model.headerData(i, Qt.Orientation.Horizontal)
                    for i in range(self._proxy_model.columnCount())
                ]
                writer.writerow(headers)
                for row in range(self._proxy_model.rowCount()):
                    row_values: list[str] = []
                    for col in range(self._proxy_model.columnCount()):
                        idx = self._proxy_model.index(row, col)
                        row_values.append(self._proxy_model.data(idx) or "")
                    writer.writerow(row_values)
            self._sql_status.setText(f"Exported: {path}")
        except Exception as exc:
            self._sql_status.setText(str(exc))

    def _on_context_menu(self, pos: object) -> None:
        index = self._table_view.indexAt(pos)
        if not index.isValid():
            return
        try:
            blob = self._table_view.model().data(index, Qt.ItemDataRole.UserRole)
        except OverflowError:
            blob = None
        menu = QMenu(self)
        copy_cell = menu.addAction("Copy cell")
        copy_row = menu.addAction("Copy row (TSV)")
        copy_sel = menu.addAction("Copy selection (TSV)")
        blob_preview = menu.addAction("Inspect Cell…")
        blob_hex = menu.addAction("Open in Hex")
        blob_export = menu.addAction("Export…")
        open_tab_menu = menu.addMenu("Open as new tab")
        open_tab_auto = open_tab_menu.addAction("Auto-detect")
        open_tab_hex = open_tab_menu.addAction("Hex")
        open_tab_text = open_tab_menu.addAction("Text")
        open_tab_proto = open_tab_menu.addAction("Protobuf")
        blob_bytes = _coerce_blob(blob)
        display_val = self._table_view.model().data(index, Qt.ItemDataRole.DisplayRole)
        display_str = str(display_val) if display_val is not None else ""
        has_display = bool(display_str)
        is_blob_placeholder = display_str.startswith("<BLOB ") and display_str.endswith(" B>")
        if blob_bytes is None and not has_display:
            open_tab_menu.setEnabled(False)
            blob_preview.setEnabled(False)
            blob_hex.setEnabled(False)
            blob_export.setEnabled(False)
        if blob_bytes is None and has_display:
            blob_preview.setEnabled(True)
            blob_hex.setEnabled(True)
            blob_export.setEnabled(True)
        action = menu.exec(self._table_view.viewport().mapToGlobal(pos))
        if action == copy_cell:
            cell_val = self._table_view.model().data(index, Qt.ItemDataRole.UserRole)
            blob_bytes = _coerce_blob(cell_val)
            if blob_bytes is not None:
                QApplication.clipboard().setText(blob_bytes.hex())
            else:
                QApplication.clipboard().setText(str(self._table_view.model().data(index)))
        elif action == copy_row:
            self._copy_rows([index.row()])
        elif action == copy_sel:
            rows = sorted({i.row() for i in self._table_view.selectedIndexes()})
            self._copy_rows(rows)
        elif action == blob_preview:
            decoded = display_str if (blob_bytes is not None and not is_blob_placeholder and display_str) else None
            if blob_bytes is not None:
                self._preview_blob(blob_bytes, display_text=decoded)
            elif has_display:
                self._preview_blob(display_str.encode("utf-8", errors="replace"))
        elif action == blob_hex:
            if blob_bytes is not None:
                self._open_blob_hex(blob_bytes)
            elif has_display:
                self._open_blob_hex(str(display_val).encode("utf-8", errors="replace"))
        elif action == blob_export:
            if blob_bytes is not None:
                self._export_blob(blob_bytes)
            elif has_display:
                self._export_blob(str(display_val).encode("utf-8", errors="replace"))
        elif action in {open_tab_auto, open_tab_hex, open_tab_text, open_tab_proto}:
            data_to_open = blob_bytes
            if data_to_open is None and has_display:
                data_to_open = str(display_val).encode("utf-8", errors="replace")
            if data_to_open is not None:
                col_header = self._table_view.model().headerData(
                    index.column(), Qt.Orientation.Horizontal
                ) or "blob"
                artifact_path, artifact_meta = self._virtual_cell_path_and_metadata(index, col_header)
                if action == open_tab_auto:
                    self.open_bytes_with_format_requested.emit(
                        data_to_open, artifact_path, None, artifact_meta
                    )
                elif action == open_tab_hex:
                    self.open_bytes_with_format_requested.emit(
                        data_to_open, artifact_path, "__hex__", artifact_meta
                    )
                elif action == open_tab_text:
                    self.open_bytes_with_format_requested.emit(
                        data_to_open, artifact_path, "__text__", artifact_meta
                    )
                elif action == open_tab_proto:
                    self.open_bytes_with_format_requested.emit(
                        data_to_open, artifact_path, "Protobuf (schema-less)", artifact_meta
                    )

    def _virtual_cell_path_and_metadata(
        self, index: QModelIndex, col_header: object
    ) -> tuple[str, dict[str, str]]:
        """Build the tab-dedup path (kept short and technical — it's shown
        verbatim in the tab tooltip) plus a separate, fully readable
        provenance dict for the Properties panel (table/query, column, row).
        Query text especially is never truncated here or in the path, since
        it can be arbitrarily long — see the Properties panel, not the path
        or the tooltip, for that."""
        db_name = _virtual_path_component(self._source_name, "sqlite")
        query_text = self._last_executed_query if self._query_results_active else ""
        if query_text:
            table_name = f"query-{zlib.crc32(query_text.encode('utf-8')):08x}"
        elif self._query_results_active:
            table_name = "query"
        else:
            table_name = self._table_combo.currentText()
        table = _virtual_path_component(table_name, "table")
        column_text = str(col_header)
        column = _virtual_path_component(column_text, "column")
        row_index = self._table_view.model().index(index.row(), 0)
        row_value = self._table_view.model().data(row_index, Qt.ItemDataRole.DisplayRole)
        row = _virtual_path_component(row_value, str(index.row() + 1))
        path = f"/virtual/{db_name}/{table}/{column}/{row}"

        metadata: dict[str, str] = {
            "Source column": column_text,
            "Source row": str(row_value) if row_value is not None else str(index.row() + 1),
        }
        if query_text:
            metadata["Source query"] = query_text
        else:
            metadata["Source table"] = self._table_combo.currentText()
        return path, metadata

    def _on_header_context_menu(self, pos: object) -> None:
        header = self._table_view.horizontalHeader()
        col = header.logicalIndexAt(pos)
        if col <= 0:  # column 0 is "Row" — skip
            return

        menu = QMenu(self)
        ts_submenu = menu.addMenu("Decode column as timestamp")
        fmt_actions: dict[object, str] = {}
        active = self._col_ts_formats.get(col)
        for key, label, _ in _TS_FORMATS:
            act = ts_submenu.addAction(label)
            act.setCheckable(True)
            act.setChecked(active == key)
            fmt_actions[act] = key

        menu.addSeparator()
        clear_act = menu.addAction("Clear timestamp format")
        clear_act.setEnabled(col in self._col_ts_formats)

        chosen = menu.exec(header.mapToGlobal(pos))
        if chosen in fmt_actions:
            self._col_ts_formats[col] = fmt_actions[chosen]
            self._apply_col_ts_format(col)
        elif chosen == clear_act:
            self._col_ts_formats.pop(col, None)
            self._revert_col_ts_format(col)

    def _apply_col_ts_format(self, col: int) -> None:
        fmt = self._col_ts_formats.get(col)
        if fmt is None:
            return
        if self._query_results_active and self._query_model is not None:
            self._query_model.set_timestamp_format(col, fmt)
            return
        for row in range(self._source_model.rowCount()):
            item = self._source_model.item(row, col)
            if item is None:
                continue
            raw = item.data(Qt.ItemDataRole.UserRole)
            if not isinstance(raw, (int, float)):
                continue
            decoded = _decode_ts(raw, fmt)
            if decoded is not None:
                item.setText(decoded)
        h_item = self._source_model.horizontalHeaderItem(col)
        if h_item is not None:
            base = h_item.data(Qt.ItemDataRole.UserRole) or h_item.text()
            h_item.setData(base, Qt.ItemDataRole.UserRole)
            suffix = next(s for k, _, s in _TS_FORMATS if k == fmt)
            h_item.setText(f"{base} [{suffix}]")

    def _revert_col_ts_format(self, col: int) -> None:
        if self._query_results_active and self._query_model is not None:
            self._query_model.set_timestamp_format(col, None)
            return
        for row in range(self._source_model.rowCount()):
            item = self._source_model.item(row, col)
            if item is None:
                continue
            raw = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(raw, (int, float)):
                item.setText(str(raw))
        h_item = self._source_model.horizontalHeaderItem(col)
        if h_item is not None:
            base = h_item.data(Qt.ItemDataRole.UserRole)
            if base:
                h_item.setText(str(base))

    def _copy_rows(self, rows: list[int]) -> None:
        lines: list[str] = []
        for row in rows:
            values = []
            for col in range(self._proxy_model.columnCount()):
                idx = self._proxy_model.index(row, col)
                values.append(str(self._proxy_model.data(idx) or ""))
            lines.append("\t".join(values))
        QApplication.clipboard().setText("\n".join(lines))

    def _open_blob_hex(self, blob: bytes) -> None:
        from crush.viewers.hex_viewer import HexViewer
        dialog = QDialog(self)
        dialog.setWindowTitle(f"BLOB Hex ({len(blob):,} B)")
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(8, 8, 8, 8)
        viewer = HexViewer(blob, dialog)
        layout.addWidget(viewer)
        dialog.resize(900, 600)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.show()

    def _export_blob(self, blob: bytes) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export BLOB", "", "All files (*)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(blob)
            self._sql_status.setText(f"BLOB exported: {path}")
        except Exception as exc:
            self._sql_status.setText(str(exc))

    def _preview_blob(self, blob: bytes, *, display_text: str | None = None) -> None:
        BlobInspector(blob, self, display_text=display_text).show()

    def _resize_and_cap(self) -> None:
        model = self._table_view.model()
        if model.rowCount() <= _COLUMN_SIZE_SAMPLE:
            self._table_view.resizeColumnsToContents()
            _cap_columns(self._table_view)
            return

        metrics = self._table_view.fontMetrics()
        for col in range(model.columnCount()):
            header = model.headerData(col, Qt.Orientation.Horizontal) or ""
            width = metrics.horizontalAdvance(str(header)) + 28
            for row in range(_COLUMN_SIZE_SAMPLE):
                value = model.data(model.index(row, col), Qt.ItemDataRole.DisplayRole)
                width = max(width, metrics.horizontalAdvance(str(value or "")) + 20)
            self._table_view.setColumnWidth(col, min(width, _MAX_COL_WIDTH))

    def _reset_source_model(self) -> None:
        """Replace self._source_model with a fresh, empty QStandardItemModel
        instead of calling .clear() on the existing one.

        A tab that carved a wide/heavily-populated result (e.g. Freelist
        Recovery on a table with many columns) can leave _source_model
        holding hundreds of thousands of QStandardItem cells --
        QStandardItemModel.clear() on a model that size is drastically
        slow (tens of seconds), since it has to synchronously tear down
        every cell before the caller can start repopulating it. Swapping
        in a fresh model and deferring destruction of the old one via
        deleteLater() avoids that synchronous cost entirely -- the same
        pattern _load_table_from_query() already uses for _query_model.
        """
        old_model = self._source_model
        self._source_model = QStandardItemModel(self)
        self._proxy_model.setSourceModel(self._source_model)
        old_model.deleteLater()

    @contextmanager
    def _dynamic_sort_suspended(self):
        """Disable the proxy model's incremental re-sort for a bulk
        appendRow() loop, re-enabling it (and sorting once) afterward.

        _load_table()'s own wrapper does this too, but only around the
        *synchronous* portion of a tab load -- a tab whose data comes back
        via run_with_busy_dialog() populates its rows later, after that
        wrapper has already re-enabled dynamic sorting. Any appendRow loop
        that might run asynchronously needs its own copy of this guard
        rather than relying on the wrapper's timing.
        """
        self._proxy_model.setDynamicSortFilter(False)
        try:
            yield
        finally:
            self._proxy_model.setDynamicSortFilter(True)
            self._proxy_model.sort(
                self._proxy_model.sortColumn(), self._proxy_model.sortOrder()
            )

    def _activate_standard_model(self) -> None:
        if not self._query_results_active:
            return
        old_query_model = self._query_model
        self._proxy_model.setSourceModel(self._source_model)
        self._proxy_model.setDynamicSortFilter(True)
        self._query_model = None
        self._query_results_active = False
        self._last_executed_query = ""
        if old_query_model is not None:
            old_query_model.deleteLater()

    def _on_current_cell_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            self._cell_detail_label.setText("—  No cell selected")
            self._cell_detail_view.setPlainText("")
            return

        col = current.column()
        col_name = self._proxy_model.headerData(col, Qt.Orientation.Horizontal) or ""
        row_num = current.row() + 1
        self._cell_detail_label.setText(f"Row {row_num}  ·  {col_name}")

        display_val = self._proxy_model.data(current, Qt.ItemDataRole.DisplayRole)
        blob = self._proxy_model.data(current, Qt.ItemDataRole.UserRole)
        blob_bytes = _coerce_blob(blob)

        display_str = str(display_val) if display_val is not None else ""
        is_blob_placeholder = display_str.startswith("<BLOB ") and display_str.endswith(" B>")
        if not is_blob_placeholder and display_str:
            self._cell_detail_view.setPlainText(display_str)
        elif blob_bytes is not None:
            try:
                self._cell_detail_view.setPlainText(blob_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                preview = blob_bytes[:256].hex(" ", 1)
                if len(blob_bytes) > 256:
                    preview += f"\n… ({len(blob_bytes):,} B total — use Inspect Cell for full view)"
                self._cell_detail_view.setPlainText(preview)
        else:
            self._cell_detail_view.setPlainText(display_str)

    def _on_table_scroll_activity(self, _value: int = 0) -> None:
        if not self._table_interaction_active:
            acquire_foreground_io()
            self._table_interaction_active = True
        self._table_interaction_timer.start()

    def _end_table_interaction(self) -> None:
        if not self._table_interaction_active:
            return
        self._table_interaction_active = False
        release_foreground_io()

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "matches") and event.matches(QKeySequence.StandardKey.Copy):
            rows = sorted({i.row() for i in self._table_view.selectedIndexes()})
            if not rows and self._table_view.currentIndex().isValid():
                rows = [self._table_view.currentIndex().row()]
            if rows:
                self._copy_rows(rows)
            return
        super().keyPressEvent(event)  # type: ignore[arg-type]

    def closeEvent(self, event: object) -> None:  # type: ignore[override]
        self._table_interaction_timer.stop()
        self._end_table_interaction()
        if self._db_conn is not None:
            self._db_conn.close()
            self._db_conn = None
        if self._db_path:
            for suffix in ("", "-wal", "-shm"):
                companion = Path(str(self._db_path) + suffix)
                if companion.exists():
                    try:
                        companion.unlink()
                    except Exception:
                        pass
        super().closeEvent(event)  # type: ignore[arg-type]


class _NumericSortProxy(QSortFilterProxyModel):
    def lessThan(self, left, right) -> bool:  # type: ignore[override]
        try:
            left_data = self.sourceModel().data(left, Qt.ItemDataRole.UserRole)
            right_data = self.sourceModel().data(right, Qt.ItemDataRole.UserRole)
        except OverflowError:
            left_data = None
            right_data = None
        if isinstance(left_data, (int, float)) and isinstance(right_data, (int, float)):
            return left_data < right_data
        # Also handle TEXT columns that store numeric-looking strings (SQLite TEXT
        # affinity returns Python str, so no UserRole is set for those values).
        left_str = self.sourceModel().data(left, Qt.ItemDataRole.DisplayRole) or ""
        right_str = self.sourceModel().data(right, Qt.ItemDataRole.DisplayRole) or ""
        try:
            return float(left_str) < float(right_str)
        except (ValueError, TypeError):
            pass
        return super().lessThan(left, right)


def _coerce_blob(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return None
