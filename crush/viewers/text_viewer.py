# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Text viewer — plain text and JSON with line numbers."""
from __future__ import annotations

import re

from PySide6.QtCore import QRect, QSize, Qt, QRegularExpression
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
    QPlainTextEdit,
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


class TextView(QWidget):
    """Viewer for plain text and JSON content."""

    def __init__(self, data: str | bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw_text = ""
        self._search_hits: list[QTextCursor] = []
        self._build_ui()

        if isinstance(data, bytes):
            text, enc = _detect_encoding(data)
            self._encoding_label.setText(enc)
        else:
            text = str(data)
            self._encoding_label.setText("str")

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
        tb_layout.addWidget(QLabel("Highlight:"))
        self._highlight_combo = QComboBox()
        self._highlight_combo.addItems(
            ["Auto", "None", "JSON", "XML", "SQL", "INI/CONF", "YAML", "LOG", "CSV"]
        )
        self._highlight_combo.currentTextChanged.connect(self._on_highlight_changed)
        tb_layout.addWidget(self._highlight_combo)
        tb_layout.addStretch()
        tb_layout.addWidget(QLabel("Encoding:"))
        self._encoding_label = QLabel("")
        self._encoding_label.setStyleSheet("color: gray;")
        tb_layout.addWidget(self._encoding_label)
        layout.addWidget(toolbar)

        search_bar = QWidget()
        sb_layout = QHBoxLayout(search_bar)
        sb_layout.setContentsMargins(8, 4, 8, 4)
        sb_layout.setSpacing(8)
        sb_layout.addWidget(QLabel("Search:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Text, * wildcard, or regex")
        self._search_input.returnPressed.connect(self._find_next)
        self._search_input.textChanged.connect(self._refresh_search)
        sb_layout.addWidget(self._search_input, 1)
        self._search_regex = QCheckBox("Regex")
        self._search_regex.toggled.connect(self._refresh_search)
        sb_layout.addWidget(self._search_regex)
        self._search_case = QCheckBox("Case")
        self._search_case.toggled.connect(self._refresh_search)
        sb_layout.addWidget(self._search_case)
        self._search_prev = QToolButton()
        self._search_prev.setText("Up")
        self._search_prev.clicked.connect(self._find_prev)
        sb_layout.addWidget(self._search_prev)
        self._search_next = QToolButton()
        self._search_next.setText("Down")
        self._search_next.clicked.connect(self._find_next)
        sb_layout.addWidget(self._search_next)
        self._search_count = QLabel("")
        sb_layout.addWidget(self._search_count)
        layout.addWidget(search_bar)

        self._editor = _CodeEditor()
        self._editor.setReadOnly(True)
        self._editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._editor, smooth_item_scroll=False)

        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._editor.setFont(font)

        self._highlighter = _SyntaxHighlighter(self._editor.document())
        layout.addWidget(self._editor)

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
            self._highlight_combo.setCurrentText("JSON")
            return
        if text.startswith("<"):
            self._set_highlight_mode("XML")
            self._highlight_combo.setCurrentText("XML")
            return
        self._set_highlight_mode("None")
        self._highlight_combo.setCurrentText("None")

    def _on_highlight_changed(self, value: str) -> None:
        if value == "Auto":
            self._apply_auto_highlight()
            return
        self._set_highlight_mode(value)

    def _set_highlight_mode(self, mode: str) -> None:
        self._highlighter.set_mode(mode.lower())

    def _refresh_search(self) -> None:
        pattern = self._search_input.text() if hasattr(self, "_search_input") else ""
        self._search_hits = []
        self._search_count.setText("")
        self._apply_search_highlights([])
        if not pattern:
            return
        regex = self._build_search_regex(pattern)
        if regex is None:
            return
        doc = self._editor.document()
        cursor = QTextCursor(doc)
        max_hits = 5000
        hits = 0
        while True:
            cursor = doc.find(regex, cursor)
            if cursor.isNull():
                break
            self._search_hits.append(cursor)
            hits += 1
            if hits >= max_hits:
                break
        self._apply_search_highlights(self._search_hits)
        if hits >= max_hits:
            self._search_count.setText(f"{len(self._search_hits)}+")
        else:
            self._search_count.setText(f"{len(self._search_hits)}")

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
            self._search_count.setText("Invalid regex")
            return None
        return regex

    def _apply_search_highlights(self, cursors: list[QTextCursor]) -> None:
        selections: list[QTextEdit.ExtraSelection] = []
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(255, 230, 128))
        for c in cursors:
            sel = QTextEdit.ExtraSelection()
            sel.cursor = c
            sel.format = fmt
            selections.append(sel)
        self._editor.setExtraSelections(selections)

    def _find_next(self) -> None:
        if not self._search_hits:
            return
        current = self._editor.textCursor()
        for hit in self._search_hits:
            if hit.selectionStart() > current.position():
                self._editor.setTextCursor(hit)
                return
        # wrap
        self._editor.setTextCursor(self._search_hits[0])

    def _find_prev(self) -> None:
        if not self._search_hits:
            return
        current = self._editor.textCursor()
        for hit in reversed(self._search_hits):
            if hit.selectionEnd() < current.position():
                self._editor.setTextCursor(hit)
                return
        # wrap
        self._editor.setTextCursor(self._search_hits[-1])


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
