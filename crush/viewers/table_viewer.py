# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Table viewer — displays SQLite tables as a sortable, searchable grid."""
from __future__ import annotations

from typing import Any

import csv
import re
import sqlite3
import struct
import time
from collections import Counter
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QEvent,
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
    QContextMenuEvent,
    QFont,
    QKeyEvent,
    QKeySequence,
    QPixmap,
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
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from crush.core.formatters import (
    bytes_to_hexview,
    pretty_object,
    try_base64_text,
    try_plist_text,
    try_xml_text,
)
from crush.core.sqlite_wal import (
    build_page_table_map,
    parse_table_leaf_page,
)
from crush.core.ts_decode import TS_FORMATS as _TS_FORMATS
from crush.core.ts_decode import decode_ts as _decode_ts
from crush.core.work_priority import (
    acquire_foreground_io,
    foreground_io,
    release_foreground_io,
)


_MAX_COL_WIDTH = 400
_QUERY_ROW_LIMIT = 10_000
_COLUMN_SIZE_SAMPLE = 250


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
    ("data_version",       "Data version",             "int",  None,
     "Increments on any write; compare across connections to detect changes"),
    ("encoding",           "Encoding",                 "str",  None,
     "Text encoding for all string data in this database"),
    ("page_size",          "Page size (B)",            "int",  None,
     "Size of each B-tree page; fixed at database creation time"),
    ("page_count",         "Page count",               "int",  None,
     "Total allocated pages; multiply by page_size to get expected file size"),
    ("freelist_count",     "Free pages",               "int",  None,
     "Unallocated pages that may contain deleted data — forensically significant"),
    ("max_page_count",     "Max page count",           "int",  None,
     "Upper limit on database size in pages (0 = default limit)"),
    # Journal / safety
    ("journal_mode",       "Journal mode",             "str",  None,
     "Rollback journal strategy (delete / wal / truncate / persist / memory / off)"),
    ("journal_size_limit", "Journal size limit (B)",   "int",  None,
     "Maximum journal file size in bytes; -1 = unlimited"),
    ("synchronous",        "Synchronous",              "enum",
     {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"},
     "How aggressively SQLite flushes writes to disk"),
    ("locking_mode",       "Locking mode",             "str",  None,
     "File locking strategy (NORMAL or EXCLUSIVE)"),
    ("wal_autocheckpoint", "WAL autocheckpoint (pages)", "int", None,
     "Pages accumulated in WAL file before automatic checkpoint is triggered"),
    # Vacuum / storage
    ("auto_vacuum",        "Auto vacuum",              "enum",
     {0: "NONE", 1: "FULL", 2: "INCREMENTAL"},
     "Automatic reclamation of free pages after DELETE"),
    ("secure_delete",      "Secure delete",            "enum",
     {0: "OFF", 1: "ON", 2: "FAST"},
     "Overwrite deleted content with zeros before freeing pages"),
    ("temp_store",         "Temp store",               "enum",
     {0: "DEFAULT", 1: "FILE", 2: "MEMORY"},
     "Storage location for temporary tables and indexes"),
    ("mmap_size",          "Memory-mapped I/O (B)",    "int",  None,
     "Maximum bytes used for memory-mapped I/O (0 = disabled)"),
    # Schema / safety flags
    ("foreign_keys",          "Foreign keys",          "bool", None,
     "Whether foreign key constraints are enforced"),
    ("recursive_triggers",    "Recursive triggers",    "bool", None,
     "Allow trigger bodies to fire additional triggers"),
    ("automatic_index",       "Automatic index",       "bool", None,
     "Query planner may create transient covering indexes"),
    ("trusted_schema",        "Trusted schema",        "bool", None,
     "Allow SQL functions in schema objects (security-relevant setting)"),
    ("read_uncommitted",      "Read uncommitted",      "bool", None,
     "Read without waiting for shared-cache write locks"),
    ("defer_foreign_keys",    "Defer foreign keys",    "bool", None,
     "Delay FK enforcement until end of outermost transaction"),
    ("query_only",            "Query only",            "bool", None,
     "Prevents any data modification in this connection"),
    # Cache (included for completeness)
    ("cache_size",            "Cache size (pages)",    "int",  None,
     "Pages kept in the in-memory page cache; negative value = KiB"),
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
    def __init__(
        self,
        data: dict[str, Any],
        parent: QWidget | None = None,
        show_db_tabs: bool = True,
        summary_nav_table: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._data = data
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
        self._wal_frames_cache: list[dict] | None = None
        self._wal_page_size: int = 0
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
        self._table_view.viewport().installEventFilter(self)
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
        """Populate the model with the selected table's data."""
        self._activate_standard_model()
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

        self._source_model.clear()
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

        self._source_model.clear()
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

        self._source_model.clear()
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
        self._source_model.clear()
        self._source_model.setHorizontalHeaderLabels(
            ["Frame", "Page", "Transaction", "Status", "Table", "Offset (B)"]
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

        for f in frames:
            color = _status_color.get(f["status"])
            table_name = self._page_table_map.get(f["page"], "—")

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
            ])

        self._resize_and_cap()


        counts = Counter(f["status"] for f in frames)
        parts = [f"{len(frames)} total"]
        for status in ("Active", "Superseded", "Uncommitted", "WAL slack"):
            n = counts.get(status, 0)
            if n:
                parts.append(f"{n} {status.lower()}")
        self._row_count_label.setText(f"({', '.join(parts)})")
        self._sql_status.setText("Double-click a row to open the raw page in the hex viewer")

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
        self._source_model.clear()
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
        selected = cursor.selectedText().replace(" ", "\n").strip()
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
        open_tab = menu.addAction("Open as new tab")
        blob_bytes = _coerce_blob(blob)
        display_val = self._table_view.model().data(index, Qt.ItemDataRole.DisplayRole)
        has_display = display_val is not None and str(display_val) != ""
        if blob_bytes is None and not has_display:
            open_tab.setEnabled(False)
            blob_preview.setEnabled(False)
            blob_hex.setEnabled(False)
            blob_export.setEnabled(False)
            open_tab.setEnabled(False)
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
            display_str = str(display_val) if display_val is not None else ""
            is_blob_placeholder = display_str.startswith("<BLOB ") and display_str.endswith(" B>")
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
        elif action == open_tab:
            data_to_open = blob_bytes
            if data_to_open is None and has_display:
                data_to_open = str(display_val).encode("utf-8", errors="replace")
            if data_to_open is not None:
                col_header = self._table_view.model().headerData(
                    index.column(), Qt.Orientation.Horizontal
                ) or "blob"
                self.open_bytes_requested.emit(data_to_open, str(col_header))

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

    def _activate_standard_model(self) -> None:
        if not self._query_results_active:
            return
        old_query_model = self._query_model
        self._proxy_model.setSourceModel(self._source_model)
        self._proxy_model.setDynamicSortFilter(True)
        self._query_model = None
        self._query_results_active = False
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

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Wheel:
            self._on_table_scroll_activity()
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:  # type: ignore[union-attr]
                hbar = self._table_view.horizontalScrollBar()
                hbar.setValue(hbar.value() - event.angleDelta().y() // 2)  # type: ignore[union-attr]
                return True
        return super().eventFilter(watched, event)

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
        if self._db_path and self._db_path.exists():
            try:
                self._db_path.unlink()
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


# Column layout produced by bytes_to_hexview (e.g. "0000000a: 48 65 6c 6c 6f  Hello"):
# cols  0-7   offset (8 hex digits)
# col   8     ':'
# col   9     space
# cols 10-56  hex section (16 bytes × 3 − 1 = 47 chars, space-padded)
# cols 57-58  two spaces
# cols 59+    ASCII (up to 16 printable chars)
_BLOB_HEX_START = 10
_BLOB_HEX_END = 57
_BLOB_ASCII_START = 59


class _BlobViewerEdit(QPlainTextEdit):
    """QPlainTextEdit with a hex-aware context menu for the BLOB inspector."""

    def __init__(self, inspector: "BlobInspector") -> None:
        super().__init__()
        self._inspector = inspector

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = self.createStandardContextMenu()
        cursor = self.textCursor()
        if cursor.hasSelection() and self._inspector._is_hex_mode():
            menu.addSeparator()
            menu.addAction("Copy Selected Hex").triggered.connect(
                self._inspector._copy_selected_hex
            )
            menu.addAction("Copy Selected ASCII").triggered.connect(
                self._inspector._copy_selected_ascii
            )
        menu.addSeparator()
        menu.addAction("Copy All").triggered.connect(self._inspector._copy_all)
        menu.exec(event.globalPos())


class BlobInspector(QDialog):
    def __init__(
        self,
        blob: bytes,
        parent: QWidget | None = None,
        *,
        display_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._blob = blob
        self._display_text = display_text
        self._build_ui()
        self._apply_view()

    def _build_ui(self) -> None:
        self.setWindowTitle(f"BLOB Inspector ({len(self._blob):,} B)")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        top = QWidget()
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(6)

        top_layout.addWidget(QLabel("Open as:"))
        self._format = QComboBox()
        base_formats = [
            "Auto",
            "Hex",
            "UTF-8 text",
            "Latin-1 text",
            "Base64 (decode)",
            "JSON",
            "Plist / bplist",
            "XML",
            "Protobuf (schema-less)",
            "Android Binary XML (ABX)",
            "Image (PNG / JPEG / GIF)",
        ]
        if self._display_text is not None:
            self._format.addItems(["Decoded (from table)"] + base_formats)
        else:
            self._format.addItems(base_formats)
        self._format.currentIndexChanged.connect(self._apply_view)
        top_layout.addWidget(self._format)

        self._copy_btn = QPushButton("Copy")
        self._copy_btn.clicked.connect(self._copy_current)
        top_layout.addWidget(self._copy_btn)
        top_layout.addStretch()
        layout.addWidget(top)

        # Stack: page 0 = text, page 1 = image
        self._stack = QStackedWidget()

        self._viewer = _BlobViewerEdit(self)
        self._viewer.setReadOnly(True)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._stack.addWidget(self._viewer)

        self._img_scroll = QScrollArea()
        self._img_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img_scroll.setWidgetResizable(False)
        self._img_label = QLabel()
        self._img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img_scroll.setWidget(self._img_label)
        self._stack.addWidget(self._img_scroll)

        layout.addWidget(self._stack, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _apply_view(self) -> None:
        fmt = self._format.currentText()

        if fmt == "Decoded (from table)":
            self._stack.setCurrentIndex(0)
            self._copy_btn.setEnabled(True)
            self._viewer.setPlainText(self._display_text or "")
            return

        if fmt == "Image (PNG / JPEG / GIF)":
            self._show_image(self._blob)
            return

        if fmt == "Auto" and _is_image(self._blob):
            self._show_image(self._blob)
            return

        # All other formats — switch to text page
        self._stack.setCurrentIndex(0)
        self._copy_btn.setEnabled(True)

        content = ""
        if fmt == "Auto":
            content = (
                self._try_plist()
                or self._try_xml()
                or self._try_json()
                or self._try_utf8()
                or self._try_latin1()
                or self._hex()
            )
        elif fmt == "Hex":
            content = self._hex()
        elif fmt == "UTF-8 text":
            content = self._try_utf8() or "[decode error]"
        elif fmt == "Latin-1 text":
            content = self._try_latin1() or "[decode error]"
        elif fmt == "Base64 (decode)":
            content = self._try_base64() or "[decode error]"
        elif fmt == "JSON":
            content = self._try_json() or "[parse error]"
        elif fmt == "Plist / bplist":
            content = self._try_plist() or "[parse error]"
        elif fmt == "XML":
            content = self._try_xml() or "[parse error]"
        elif fmt == "Protobuf (schema-less)":
            content = self._try_protobuf() or "[parse error]"
        elif fmt == "Android Binary XML (ABX)":
            content = self._try_abx() or "[parse error]"
        self._viewer.setPlainText(content[:500_000])

    def _show_image(self, data: bytes) -> None:
        from PySide6.QtCore import QByteArray
        px = QPixmap()
        if px.loadFromData(QByteArray(data)):
            self._img_label.setPixmap(px)
            self._img_label.resize(px.size())
            self._stack.setCurrentIndex(1)
            self._copy_btn.setEnabled(False)
        else:
            self._stack.setCurrentIndex(0)
            self._copy_btn.setEnabled(True)
            self._viewer.setPlainText("[not a recognised image format]")

    def _is_hex_mode(self) -> bool:
        fmt = self._format.currentText()
        return fmt in ("Hex", "Auto")

    def _copy_current(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())

    def _copy_all(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())

    def _copy_selected_hex(self) -> None:
        cursor = self._viewer.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        tokens: list[str] = []
        for line in text.split("\u2029"):
            hex_section = line[_BLOB_HEX_START:_BLOB_HEX_END]
            for part in hex_section.split():
                if len(part) == 2 and all(c in "0123456789ABCDEFabcdef" for c in part):
                    tokens.append(part.upper())
        QApplication.clipboard().setText(" ".join(tokens))

    def _copy_selected_ascii(self) -> None:
        cursor = self._viewer.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        parts: list[str] = []
        for line in text.split("\u2029"):
            if len(line) > _BLOB_ASCII_START:
                parts.append(line[_BLOB_ASCII_START:])
        QApplication.clipboard().setText("".join(parts))

    def _hex(self) -> str:
        return _bytes_to_hexview(self._blob, max_bytes=200_000)

    def _try_utf8(self) -> str:
        try:
            return self._blob.decode("utf-8")
        except Exception:
            return ""

    def _try_latin1(self) -> str:
        try:
            return self._blob.decode("latin-1")
        except Exception:
            return ""

    def _try_base64(self) -> str:
        return try_base64_text(self._blob) or ""

    def _try_json(self) -> str:
        import json
        try:
            text = self._blob.decode("utf-8")
        except Exception:
            return ""
        unescaped = text.replace('\\"', '"')
        for candidate in (text, unescaped):
            try:
                return json.dumps(json.loads(candidate), indent=2, ensure_ascii=False)
            except Exception:
                pass
        # Truncated / partial JSON — show unescaped text with a warning header
        candidate = unescaped if '\\"' in text else text
        if candidate.lstrip().startswith(("{", "[")):
            return "[partial / truncated JSON — pretty-print not possible]\n\n" + candidate
        return ""

    def _try_plist(self) -> str:
        return try_plist_text(self._blob) or ""

    def _try_xml(self) -> str:
        return try_xml_text(self._blob) or ""

    def _try_protobuf(self) -> str:
        try:
            from crush.parsers.protobuf_parser import _decode_message
            decoded, warning, _text = _decode_message(self._blob)
            result = _render_protobuf(decoded.get("entries", []))
            if warning:
                result = f"# Warning: {warning}\n\n{result}"
            return result
        except Exception:
            return ""

    def _try_abx(self) -> str:
        try:
            from crush.parsers.abx_decoder import decode_abx
            return decode_abx(self._blob).xml
        except Exception:
            return ""


def _is_image(data: bytes) -> bool:
    return (
        data[:8] == b"\x89PNG\r\n\x1a\n"       # PNG
        or data[:3] == b"\xff\xd8\xff"          # JPEG
        or data[:6] in (b"GIF87a", b"GIF89a")   # GIF
    )


_INTERP_SKIP = {"uint64", "uint32"}  # already shown as the primary value


def _render_protobuf(entries: list, indent: int = 0) -> str:
    """Render protobuf wire-decoded entries as protoc --decode_raw style text."""
    lines: list[str] = []
    pad = "  " * indent
    ipad = pad + "    "  # indent for interpretation hints
    for entry in entries:
        field = entry.get("field", "?")
        wt = entry.get("wire_type", "?")
        val = entry.get("value")
        interpretations = [i for i in entry.get("interpretations", []) if i.label not in _INTERP_SKIP]

        if isinstance(val, dict):
            vtype = val.get("type")
            if vtype == "message":
                lines.append(f"{pad}{field} {{")
                lines.append(_render_protobuf(val.get("entries", []), indent + 1))
                lines.append(f"{pad}}}")
            elif vtype == "string":
                lines.append(f'{pad}{field}: "{val.get("text", "")}"')
            else:  # bytes preview
                lines.append(f"{pad}{field}: <{val.get('hex_preview', '')}>")
        elif isinstance(val, bytes):
            lines.append(f"{pad}{field}: {val[:32].hex()}" + ("…" if len(val) > 32 else ""))
        else:
            lines.append(f"{pad}{field} [{wt}]: {val}")

        for interp in interpretations:
            lines.append(f"{ipad}# {interp.label}: {interp.value}")
    return "\n".join(lines)


def _pretty(obj: object) -> str:
    return pretty_object(obj)


def _bytes_to_hexview(b: bytes, width: int = 16, max_bytes: int = 200_000) -> str:
    return bytes_to_hexview(b, width=width, max_bytes=max_bytes)


def _coerce_blob(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return None
