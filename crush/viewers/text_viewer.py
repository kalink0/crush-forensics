# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Text viewer — plain text and JSON with line numbers."""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QRect,
    QRegularExpression,
    QSize,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QFont,
    QPainter,
    QPalette,
    QColor,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QPlainTextEdit,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QLineEdit,
    QToolButton,
    QTextEdit,
    QCheckBox,
)

from crush.core.encodings import detect_encoding as _detect_encoding
from crush.core.formatters import pretty_json
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.ui.i18n import translate


class _LineNumberArea(QWidget):
    def __init__(self, editor: "_CodeEditor") -> None:
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:  # type: ignore[override]
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event: object) -> None:  # type: ignore[override]
        self._editor.line_number_area_paint(event)


class _CodeEditor(QPlainTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self._line_number_area = _LineNumberArea(self)
        self._line_number_area.setVisible(True)
        self.blockCountChanged.connect(self._update_line_number_area_width)
        self.updateRequest.connect(self._update_line_number_area)
        self._update_line_number_area_width(0)
        self.refresh_line_numbers()

    def line_number_area_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 8 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_line_number_area_width(self, _: int) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)
        self._line_number_area.update()

    def _update_line_number_area(self, rect: QRect, dy: int) -> None:
        if dy:
            self._line_number_area.scroll(0, dy)
        else:
            self._line_number_area.update(0, rect.y(), self._line_number_area.width(), rect.height())

        if rect.contains(self.viewport().rect()):
            self._update_line_number_area_width(0)

    def refresh_line_numbers(self) -> None:
        self._update_line_number_area_width(0)
        self._line_number_area.update()
        self.viewport().update()

    def setPlainText(self, text: str) -> None:  # type: ignore[override]
        super().setPlainText(text)
        self.refresh_line_numbers()

    def resizeEvent(self, event: object) -> None:  # type: ignore[override]
        super().resizeEvent(event)  # type: ignore[arg-type]
        cr = self.contentsRect()
        self._line_number_area.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height())
        )

    def line_number_area_paint(self, event: object) -> None:
        painter = QPainter(self._line_number_area)
        bg = self.palette().color(QPalette.ColorRole.AlternateBase)
        painter.fillRect(event.rect(), bg)

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(self.palette().color(QPalette.ColorRole.Text))
                painter.drawText(
                    0,
                    top,
                    self._line_number_area.width() - 4,
                    self.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight,
                    number,
                )
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

    def _highlight_current_line(self) -> None:
        return


class _SearchResultModel(QAbstractTableModel):
    """Every search hit as a row. Line, column and preview are computed only
    for the rows the table actually shows, so a search with hundreds of
    thousands of hits lists all of them without building them up front."""

    def __init__(self, editor: QPlainTextEdit) -> None:
        super().__init__(editor)
        self._editor = editor
        self._starts: list[int] = []

    def set_hits(self, starts: list[int]) -> None:
        self.beginResetModel()
        self._starts = starts
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._starts)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else 3

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        if orientation != Qt.Orientation.Horizontal or role != Qt.ItemDataRole.DisplayRole:
            return None
        return (
            translate("TextView", "Line"),
            translate("TextView", "Col"),
            translate("TextView", "Preview"),
        )[section]

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        start = self._starts[index.row()]
        block = self._editor.document().findBlock(start)
        if index.column() == 0:
            return str(block.blockNumber() + 1)
        if index.column() == 1:
            return str(start - block.position() + 1)
        return block.text().strip()


class TextView(QWidget):
    """Viewer for plain text and JSON content."""

    def __init__(self, data: str | bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw_text = ""
        # Every hit of the current search, as document positions (sorted,
        # non-overlapping, so both lists are ascending).
        self._hit_starts: list[int] = []
        self._hit_ends: list[int] = []
        self._current_hit_index: int = -1
        # (first, last visible position, hit count) the highlights were drawn for.
        self._highlighted_range: tuple[int, int, int] | None = None
        self._build_ui()

        if isinstance(data, bytes):
            text, enc = _detect_encoding(data)
            self._encoding_label.setText(enc)
        else:
            text = str(data)
            self._encoding_label.setText("str")  # i18n: keep -- Python str input, no encoding

        # Pretty-print JSON if possible
        if text.lstrip().startswith(("{", "[")):
            pretty = pretty_json(text)
            if pretty is not None:
                text = pretty

        self._raw_text = text
        self._editor.setPlainText(text)
        self._editor.refresh_line_numbers()
        self._apply_auto_highlight()
        self._refresh_search()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QWidget()
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)
        tb_layout.addWidget(QLabel(translate("TextView", "Highlight:")))
        self._highlight_combo = QComboBox()
        # Item data is the mode key; only "Auto" and "None" are words to
        # translate, the rest are format names.
        for label, mode in [
            (translate("TextView", "Auto"), "Auto"),
            (translate("TextView", "None"), "None"),
            ("JSON", "JSON"), ("XML", "XML"), ("SQL", "SQL"), ("INI/CONF", "INI/CONF"),
            ("YAML", "YAML"), ("LOG", "LOG"), ("CSV", "CSV"),
        ]:
            self._highlight_combo.addItem(label, mode)
        self._highlight_combo.currentIndexChanged.connect(
            lambda _index: self._on_highlight_changed(self._highlight_combo.currentData())
        )
        tb_layout.addWidget(self._highlight_combo)
        tb_layout.addStretch()
        tb_layout.addWidget(QLabel(translate("TextView", "Encoding:")))
        self._encoding_label = QLabel("")
        self._encoding_label.setStyleSheet("color: gray;")
        tb_layout.addWidget(self._encoding_label)
        layout.addWidget(toolbar)

        search_bar = QWidget()
        sb_layout = QHBoxLayout(search_bar)
        sb_layout.setContentsMargins(8, 4, 8, 4)
        sb_layout.setSpacing(8)
        sb_layout.addWidget(QLabel(translate("TextView", "Search:")))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText(translate("TextView", "Text, * wildcard, or regex"))
        self._search_input.returnPressed.connect(self._find_next)
        # Each search scans the whole text: wait for a pause in typing.
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._refresh_search)
        self._search_input.textChanged.connect(lambda _text: self._search_timer.start())
        sb_layout.addWidget(self._search_input, 1)
        self._search_regex = QCheckBox(translate("TextView", "Regex"))
        self._search_regex.toggled.connect(self._refresh_search)
        sb_layout.addWidget(self._search_regex)
        self._search_case = QCheckBox(translate("TextView", "Case"))
        self._search_case.toggled.connect(self._refresh_search)
        sb_layout.addWidget(self._search_case)
        self._search_prev = QToolButton()
        self._search_prev.setText(translate("TextView", "Up"))
        self._search_prev.clicked.connect(self._find_prev)
        sb_layout.addWidget(self._search_prev)
        self._search_next = QToolButton()
        self._search_next.setText(translate("TextView", "Down"))
        self._search_next.clicked.connect(self._find_next)
        sb_layout.addWidget(self._search_next)
        self._search_count = QLabel("")
        sb_layout.addWidget(self._search_count)
        self._show_all_btn = QToolButton()
        self._show_all_btn.setText(translate("TextView", "Show all"))
        self._show_all_btn.setCheckable(True)
        self._show_all_btn.toggled.connect(self._toggle_result_panel)
        sb_layout.addWidget(self._show_all_btn)
        layout.addWidget(search_bar)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._editor = _CodeEditor()
        self._editor.setReadOnly(True)
        # setReadOnly() only grants mouse-based selection in Qt6 — keyboard
        # cursor movement and Shift-selection need TextSelectableByKeyboard too.
        self._editor.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._editor, smooth_item_scroll=False)

        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._editor.setFont(font)

        self._highlighter = _SyntaxHighlighter(self._editor.document())
        self._splitter.addWidget(self._editor)

        self._result_panel = QWidget()
        rp_layout = QVBoxLayout(self._result_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(0)
        self._result_model = _SearchResultModel(self._editor)
        self._result_table = QTableView()
        self._result_table.setModel(self._result_model)
        self._result_table.horizontalHeader().setStretchLastSection(True)
        self._result_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._result_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._result_table.activated.connect(lambda index: self._jump_to_result_row(index.row()))
        self._result_table.doubleClicked.connect(lambda index: self._jump_to_result_row(index.row()))
        rp_layout.addWidget(self._result_table)
        self._result_panel.setVisible(False)
        self._splitter.addWidget(self._result_panel)

        layout.addWidget(self._splitter)

        # Highlights are drawn for the visible part of the text only.
        self._editor.verticalScrollBar().valueChanged.connect(
            lambda _value: self._update_visible_highlights()
        )
        self._editor.updateRequest.connect(lambda _rect, _dy: self._update_visible_highlights())

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "matches") and event.matches(QKeySequence.StandardKey.Find):
            self._search_input.setFocus()
            self._search_input.selectAll()
            return
        super().keyPressEvent(event)  # type: ignore[arg-type]

    def _apply_auto_highlight(self) -> None:
        text = self._raw_text.lstrip()
        if text.startswith(("{", "[")):
            self._set_highlight_mode("JSON")
            self._select_highlight("JSON")
            return
        if text.startswith("<"):
            self._set_highlight_mode("XML")
            self._select_highlight("XML")
            return
        self._set_highlight_mode("None")
        self._select_highlight("None")

    def _select_highlight(self, mode: str) -> None:
        self._highlight_combo.setCurrentIndex(self._highlight_combo.findData(mode))

    def _on_highlight_changed(self, value: str) -> None:
        if value == "Auto":
            self._apply_auto_highlight()
            return
        self._set_highlight_mode(value)

    def _set_highlight_mode(self, mode: str) -> None:
        self._highlighter.set_mode(mode.lower())

    def _refresh_search(self) -> None:
        """Find every hit of the search in the whole text."""
        self._search_timer.stop()
        pattern = self._search_input.text() if hasattr(self, "_search_input") else ""
        self._hit_starts = []
        self._hit_ends = []
        self._current_hit_index = -1
        self._search_count.setText("")
        regex = self._build_search_regex(pattern) if pattern else None
        if regex is not None:
            matches = regex.globalMatch(self._editor.toPlainText())
            while matches.hasNext():
                m = matches.next()
                if m.capturedEnd() > m.capturedStart():  # an empty match marks nothing
                    self._hit_starts.append(m.capturedStart())
                    self._hit_ends.append(m.capturedEnd())
            self._search_count.setText(f"{len(self._hit_starts)}")  # i18n: keep -- number
        self._result_model.set_hits(self._hit_starts)
        self._highlighted_range = None
        self._update_visible_highlights()
        self._sync_result_selection()

    def _build_search_regex(self, pattern: str) -> QRegularExpression | None:
        if not self._search_regex.isChecked():
            # Escape and allow * wildcard
            escaped = QRegularExpression.escape(pattern)
            escaped = escaped.replace("\\*", ".*")
            pattern = escaped
        regex = QRegularExpression(pattern)
        if not self._search_case.isChecked():
            regex.setPatternOptions(QRegularExpression.PatternOption.CaseInsensitiveOption)
        if not regex.isValid():
            self._search_count.setText(translate("TextView", "Invalid regex"))
            return None
        return regex

    def _update_visible_highlights(self) -> None:
        """Mark the hits in the visible part of the text (all hits are
        found; drawing them all at once would slow the editor down)."""
        if not self._hit_starts:
            if self._highlighted_range is not None or self._editor.extraSelections():
                self._highlighted_range = None
                self._editor.setExtraSelections([])
            return
        first = self._editor.firstVisibleBlock().position()
        last_block = self._editor.cursorForPosition(
            self._editor.viewport().rect().bottomRight()
        ).block()
        last = last_block.position() + last_block.length()
        visible = (first, last, len(self._hit_starts))
        if visible == self._highlighted_range:
            return
        self._highlighted_range = visible
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(255, 230, 128))
        doc = self._editor.document()
        selections: list[QTextEdit.ExtraSelection] = []
        for i in range(bisect_right(self._hit_ends, first), bisect_left(self._hit_starts, last)):
            cursor = QTextCursor(doc)
            cursor.setPosition(self._hit_starts[i])
            cursor.setPosition(self._hit_ends[i], QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cursor
            sel.format = fmt
            selections.append(sel)
        self._editor.setExtraSelections(selections)

    def _ensure_search_current(self) -> None:
        if self._search_timer.isActive():
            self._refresh_search()

    def _select_hit(self, i: int) -> None:
        cursor = QTextCursor(self._editor.document())
        cursor.setPosition(self._hit_starts[i])
        cursor.setPosition(self._hit_ends[i], QTextCursor.MoveMode.KeepAnchor)
        self._current_hit_index = i
        self._editor.setTextCursor(cursor)
        self._sync_result_selection()

    def _find_next(self) -> None:
        self._ensure_search_current()
        if not self._hit_starts:
            return
        i = bisect_right(self._hit_starts, self._editor.textCursor().position())
        self._select_hit(i if i < len(self._hit_starts) else 0)  # wrap

    def _find_prev(self) -> None:
        self._ensure_search_current()
        if not self._hit_starts:
            return
        i = bisect_left(self._hit_ends, self._editor.textCursor().position()) - 1
        self._select_hit(i if i >= 0 else len(self._hit_starts) - 1)  # wrap

    def _toggle_result_panel(self, checked: bool) -> None:
        self._result_panel.setVisible(checked)
        if checked:
            self._sync_result_selection()

    def _sync_result_selection(self) -> None:
        if not self._result_panel.isVisible():
            return
        idx = self._current_hit_index
        if 0 <= idx < len(self._hit_starts):
            self._result_table.selectRow(idx)
            self._result_table.scrollTo(self._result_model.index(idx, 0))

    def _jump_to_result_row(self, row: int) -> None:
        if row < 0 or row >= len(self._hit_starts):
            return
        self._select_hit(row)
        self._editor.centerCursor()


class _SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document: object) -> None:
        super().__init__(document)  # type: ignore[arg-type]
        self._mode = "none"
        self._rules: dict[str, list[tuple[re.Pattern[str], QTextCharFormat]]] = {}
        self._init_formats()
        self._init_rules()

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        rules = self._rules.get(self._mode)
        if not rules:
            return
        for pattern, fmt in rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)

    def _init_formats(self) -> None:
        self._fmt_key = QTextCharFormat()
        self._fmt_key.setForeground(QColor("#0066cc"))
        self._fmt_string = QTextCharFormat()
        self._fmt_string.setForeground(QColor("#2a7b2e"))
        self._fmt_number = QTextCharFormat()
        self._fmt_number.setForeground(QColor("#b35c00"))
        self._fmt_keyword = QTextCharFormat()
        self._fmt_keyword.setForeground(QColor("#8a2be2"))
        self._fmt_tag = QTextCharFormat()
        self._fmt_tag.setForeground(QColor("#005a9c"))
        self._fmt_attr = QTextCharFormat()
        self._fmt_attr.setForeground(QColor("#7a3e9d"))
        self._fmt_attr_value = QTextCharFormat()
        self._fmt_attr_value.setForeground(QColor("#2a7b2e"))
        self._fmt_comment = QTextCharFormat()
        self._fmt_comment.setForeground(QColor("#6b7280"))
        self._fmt_section = QTextCharFormat()
        self._fmt_section.setForeground(QColor("#0f766e"))
        self._fmt_level = QTextCharFormat()
        self._fmt_level.setForeground(QColor("#b91c1c"))
        self._fmt_timestamp = QTextCharFormat()
        self._fmt_timestamp.setForeground(QColor("#0f766e"))
        self._fmt_delim = QTextCharFormat()
        self._fmt_delim.setForeground(QColor("#6b7280"))
        self._fmt_sql_keyword = QTextCharFormat()
        self._fmt_sql_keyword.setForeground(QColor("#7c3aed"))
        self._fmt_sql_func = QTextCharFormat()
        self._fmt_sql_func.setForeground(QColor("#0f766e"))
        self._fmt_yaml_key = QTextCharFormat()
        self._fmt_yaml_key.setForeground(QColor("#2563eb"))
        self._fmt_list_marker = QTextCharFormat()
        self._fmt_list_marker.setForeground(QColor("#6b7280"))

    def _init_rules(self) -> None:
        import re
        self._rules["json"] = [
            (re.compile(r"\"([^\"\\]|\\.)*\"(?=\s*:)"), self._fmt_key),
            (re.compile(r"\"([^\"\\]|\\.)*\""), self._fmt_string),
            (re.compile(r"(?<![\w\.\-])(-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?)"), self._fmt_number),
            (re.compile(r"\b(true|false|null)\b"), self._fmt_keyword),
        ]
        self._rules["xml"] = [
            (re.compile(r"</?\s*[^>\s/]+"), self._fmt_tag),
            (re.compile(r"\s+([A-Za-z_:\-][\w:.-]*)\s*="), self._fmt_attr),
            (re.compile(r"=\s*\"([^\"\\]|\\.)*\""), self._fmt_attr_value),
        ]
        sql_keywords = r"\b(select|from|where|join|left|right|inner|outer|on|group|by|having|order|limit|offset|insert|into|values|update|set|delete|create|table|index|drop|alter|as|distinct|union|all|and|or|not|null|is|in|like|between|case|when|then|else|end)\b"
        sql_funcs = r"\b(count|sum|min|max|avg|substr|coalesce|length|lower|upper|strftime|datetime|date)\b"
        self._rules["sql"] = [
            (re.compile(r"--.*$"), self._fmt_comment),
            (re.compile(r"/\\*.*?\\*/"), self._fmt_comment),
            (re.compile(r"'([^'\\]|\\.)*'"), self._fmt_string),
            (re.compile(r"\"([^\"\\]|\\.)*\""), self._fmt_string),
            (re.compile(r"(?<![\w\.\-])(-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?)"), self._fmt_number),
            (re.compile(sql_keywords, re.IGNORECASE), self._fmt_sql_keyword),
            (re.compile(sql_funcs, re.IGNORECASE), self._fmt_sql_func),
        ]
        self._rules["ini/conf"] = [
            (re.compile(r"^[ \\t]*[;#].*$"), self._fmt_comment),
            (re.compile(r"^\s*\[[^\]]+\]"), self._fmt_section),
            (re.compile(r"^\s*[^=\s]+(?=\s*=)"), self._fmt_key),
            (re.compile(r"=\s*\"([^\"\\]|\\.)*\""), self._fmt_string),
        ]
        self._rules["yaml"] = [
            (re.compile(r"^[ \\t]*#.*$"), self._fmt_comment),
            (re.compile(r"^\s*-\s+"), self._fmt_list_marker),
            (re.compile(r"^\s*[^:#\s][^:]*?(?=\s*:)"), self._fmt_yaml_key),
            (re.compile(r"\"([^\"\\]|\\.)*\""), self._fmt_string),
            (re.compile(r"'([^'\\]|\\.)*'"), self._fmt_string),
            (re.compile(r"(?<![\w\.\-])(-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?)"), self._fmt_number),
            (re.compile(r"\b(true|false|null|yes|no)\b", re.IGNORECASE), self._fmt_keyword),
        ]
        self._rules["log"] = [
            (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), self._fmt_timestamp),
            (re.compile(r"\b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|CRITICAL|FATAL)\b"), self._fmt_level),
        ]
        self._rules["csv"] = [
            (re.compile(r","), self._fmt_delim),
            (re.compile(r"\"([^\"\\]|\\.)*\""), self._fmt_string),
        ]
