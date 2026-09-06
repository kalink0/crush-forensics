# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Hex viewer — displays raw bytes as hex + ASCII, 16 bytes per row."""
from __future__ import annotations

from PySide6.QtCore import QRegularExpression, Qt
from PySide6.QtGui import (
    QColor,
    QContextMenuEvent,
    QFont,
    QRegularExpressionValidator,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from crush.ui.wheel_scroll import install_horizontal_wheel_scroll


_BYTES_PER_ROW = 16
_PAGE_BYTES = 1024 * 256  # 256 KB per page

# Hex dump line layout (see _load_page):
# cols  0-7   offset (8 hex digits)
# cols  8-9   two spaces
# cols 10-57  hex section (hex_left<23> + "  " + hex_right<23> = 48 chars)
# cols 58-59  two spaces
# cols 60+    ASCII (up to 16 printable chars)
_HEX_START = 10
_HEX_END = 58
_ASCII_START = 60

_COLOR_HIT = QColor(255, 230, 80)     # yellow — all matches
_COLOR_CURRENT = QColor(255, 140, 0)  # orange — current match


class _HexPlainTextEdit(QPlainTextEdit):
    """QPlainTextEdit with a custom context menu for hex/ASCII copy actions."""

    def __init__(self, viewer: "HexViewer") -> None:
        super().__init__()
        self._viewer = viewer

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = self.createStandardContextMenu()
        cursor = self.textCursor()
        if cursor.hasSelection():
            menu.addSeparator()
            menu.addAction("Copy Selected Hex").triggered.connect(
                self._viewer._copy_selected_hex
            )
            menu.addAction("Copy Selected ASCII").triggered.connect(
                self._viewer._copy_selected_ascii
            )
            menu.addSeparator()
            menu.addAction("Search Selected as ASCII").triggered.connect(
                self._viewer._search_selected_as_ascii
            )
            menu.addAction("Search Selected as Hex").triggered.connect(
                self._viewer._search_selected_as_hex
            )
        menu.addSeparator()
        menu.addAction("Copy All").triggered.connect(self._viewer._copy_all)
        menu.exec(event.globalPos())


class HexViewer(QWidget):
    """Simple hex + ASCII dump viewer with search, highlights, and result panel."""

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._page = 0
        self._search_hits: list[int] = []   # byte offsets of all matches
        self._current_hit: int = -1          # index into _search_hits
        self._match_len: int = 0
        self._build_ui()
        self._load_page()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Two rows instead of one -- crammed into a single QHBoxLayout, this
        # toolbar's ~15 widgets forced a combined minimum width of ~1177px
        # (the sum of every button's own minimum), which a QTabWidget then
        # propagates as ITS minimum width even for tabs that never show this
        # HexViewer at all (Qt sizes a tab widget from the largest page, not
        # just the current one) -- most visible in the Realm viewer, which
        # embeds a HexViewer in both its "Hex Preview" and "Freed Data" tabs
        # alongside much narrower ones. Splitting into two rows roughly
        # halves that floor.
        toolbar = QVBoxLayout()
        toolbar.setContentsMargins(6, 6, 6, 0)
        toolbar.setSpacing(4)

        search_row = QHBoxLayout()
        search_row.setSpacing(8)

        search_row.addWidget(QLabel("Search as:"))
        self._search_mode = QComboBox()
        self._search_mode.addItems(["ASCII", "Hex"])
        self._search_mode.currentIndexChanged.connect(self._on_search_mode_changed)
        search_row.addWidget(self._search_mode)

        self._hex_validator = QRegularExpressionValidator(
            QRegularExpression(r"[0-9a-fA-F\s:]*")
        )
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search text…")
        self._search_input.returnPressed.connect(self._do_search)
        search_row.addWidget(self._search_input, stretch=1)

        self._find_btn = QPushButton("Find")
        self._find_btn.clicked.connect(self._do_search)
        search_row.addWidget(self._find_btn)

        self._search_prev_btn = QToolButton()
        self._search_prev_btn.setText("↑")
        self._search_prev_btn.setToolTip("Previous match")
        self._search_prev_btn.clicked.connect(self._find_prev)
        search_row.addWidget(self._search_prev_btn)

        self._search_next_btn = QToolButton()
        self._search_next_btn.setText("↓")
        self._search_next_btn.setToolTip("Next match")
        self._search_next_btn.clicked.connect(self._find_next)
        search_row.addWidget(self._search_next_btn)

        self._count_label = QLabel("")
        self._count_label.setMinimumWidth(90)
        search_row.addWidget(self._count_label)

        self._show_all_btn = QToolButton()
        self._show_all_btn.setText("Show all")
        self._show_all_btn.setCheckable(True)
        self._show_all_btn.toggled.connect(self._toggle_result_panel)
        search_row.addWidget(self._show_all_btn)

        self._status = QLabel("")
        search_row.addWidget(self._status)
        search_row.addStretch(1)
        toolbar.addLayout(search_row)

        nav_row = QHBoxLayout()
        nav_row.setSpacing(8)

        self._prev_btn = QPushButton("◀ Prev")
        self._prev_btn.clicked.connect(self._prev_page)
        nav_row.addWidget(self._prev_btn)

        self._page_label = QLabel("")
        nav_row.addWidget(self._page_label)

        self._next_btn = QPushButton("Next ▶")
        self._next_btn.clicked.connect(self._next_page)
        nav_row.addWidget(self._next_btn)

        nav_row.addSpacing(8)

        self._copy_hex_btn = QPushButton("Copy Hex")
        self._copy_hex_btn.clicked.connect(self._copy_hex)
        nav_row.addWidget(self._copy_hex_btn)

        self._copy_ascii_btn = QPushButton("Copy ASCII")
        self._copy_ascii_btn.clicked.connect(self._copy_ascii)
        nav_row.addWidget(self._copy_ascii_btn)

        self._copy_all_btn = QPushButton("Copy All")
        self._copy_all_btn.clicked.connect(self._copy_all)
        nav_row.addWidget(self._copy_all_btn)
        nav_row.addStretch(1)
        toolbar.addLayout(nav_row)

        layout.addLayout(toolbar)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._text = _HexPlainTextEdit(self)
        self._text.setReadOnly(True)
        # setReadOnly() only grants mouse-based selection in Qt6 — keyboard
        # cursor movement and Shift-selection need TextSelectableByKeyboard too.
        self._text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._text, smooth_item_scroll=False)

        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(font)

        self._splitter.addWidget(self._text)

        # Result panel — hidden until user clicks "Show all"
        self._result_panel = QWidget()
        rp_layout = QVBoxLayout(self._result_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(0)
        self._result_table = QTableWidget(0, 3)
        self._result_table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII"])
        self._result_table.horizontalHeader().setStretchLastSection(True)
        self._result_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._result_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._result_table.cellActivated.connect(self._jump_to_result_row)
        self._result_table.cellDoubleClicked.connect(self._jump_to_result_row)
        rp_layout.addWidget(self._result_table)
        self._result_panel.setVisible(False)
        self._splitter.addWidget(self._result_panel)

        layout.addWidget(self._splitter)

    # ------------------------------------------------------------------
    # Page navigation
    # ------------------------------------------------------------------

    def _page_count(self) -> int:
        return max(1, (len(self._data) + _PAGE_BYTES - 1) // _PAGE_BYTES)

    def _page_data(self) -> bytes:
        start = self._page * _PAGE_BYTES
        return self._data[start : start + _PAGE_BYTES]

    def _load_page(self) -> None:
        page_data = self._page_data()
        base_offset = self._page * _PAGE_BYTES
        lines: list[str] = []

        for i in range(0, len(page_data), _BYTES_PER_ROW):
            chunk = page_data[i : i + _BYTES_PER_ROW]
            off_str = f"{base_offset + i:08X}"
            hex_parts = [f"{b:02X}" for b in chunk]
            hex_left  = " ".join(hex_parts[:8])
            hex_right = " ".join(hex_parts[8:])
            hex_str   = f"{hex_left:<23}  {hex_right:<23}"
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"{off_str}  {hex_str}  {ascii_str}")

        self._text.setPlainText("\n".join(lines))
        self._update_highlights()

        pages = self._page_count()
        self._page_label.setText(f"Page {self._page + 1} / {pages}")
        self._prev_btn.setEnabled(self._page > 0)
        self._next_btn.setEnabled(self._page < pages - 1)
        start = base_offset
        end = base_offset + len(page_data)
        self._status.setText(f"0x{start:X}–0x{end:X}  ({len(self._data):,} B total)")

    def set_data(self, data: bytes) -> None:
        """Replace the displayed bytes and reset to page 0."""
        self._data = data
        self._page = 0
        self._search_hits = []
        self._current_hit = -1
        self._match_len = 0
        self._count_label.setText("")
        self._load_page()

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._load_page()

    def _next_page(self) -> None:
        if self._page < self._page_count() - 1:
            self._page += 1
            self._load_page()

    def _scroll_to_offset(self, page_offset: int) -> None:
        line = page_offset // _BYTES_PER_ROW
        block = self._text.document().findBlockByNumber(line)
        if not block.isValid():
            return
        cursor = self._text.textCursor()
        cursor.setPosition(block.position())
        self._text.setTextCursor(cursor)
        self._text.centerCursor()

    # ------------------------------------------------------------------
    # Search — collect / navigate
    # ------------------------------------------------------------------

    def _on_search_mode_changed(self) -> None:
        self._search_input.clear()
        self._search_hits = []
        self._current_hit = -1
        self._count_label.setText("")
        self._update_highlights()
        if self._search_mode.currentText() == "Hex":
            self._search_input.setPlaceholderText("Hex pattern… (e.g. de ad be ef)")
            self._search_input.setValidator(self._hex_validator)
        else:
            self._search_input.setPlaceholderText("Search text…")
            self._search_input.setValidator(None)

    def _collect_hits(self) -> bool:
        """Find all matches for the current query. Returns True if any found."""
        self._search_hits = []
        self._match_len = 0
        query = self._search_input.text().strip()
        if not query:
            self._count_label.setText("")
            return False

        mode = self._search_mode.currentText()
        if mode == "Hex":
            pattern = _parse_hex_query(query)
            if pattern is None:
                self._count_label.setText("Invalid hex")
                return False
            self._match_len = len(pattern)
            offset = 0
            while True:
                idx = self._data.find(pattern, offset)
                if idx < 0:
                    break
                self._search_hits.append(idx)
                offset = idx + 1
        else:
            text = self._data.decode("latin-1")
            self._match_len = len(query)
            offset = 0
            while True:
                idx = text.find(query, offset)
                if idx < 0:
                    break
                self._search_hits.append(idx)
                offset = idx + 1

        return len(self._search_hits) > 0

    def _do_search(self) -> None:
        """Re-collect all hits for the current query and jump to the first."""
        if not self._collect_hits():
            self._count_label.setText("Not found")
            self._update_highlights()
            self._update_result_panel()
            return
        self._current_hit = 0
        self._jump_to_hit(0)
        self._update_count_label()
        self._update_highlights()
        self._update_result_panel()
        self._sync_result_selection()

    def _find_next(self) -> None:
        if not self._search_hits:
            return
        self._current_hit = (self._current_hit + 1) % len(self._search_hits)
        self._jump_to_hit(self._current_hit)
        self._update_count_label()
        self._update_highlights()
        self._sync_result_selection()

    def _find_prev(self) -> None:
        if not self._search_hits:
            return
        self._current_hit = (self._current_hit - 1) % len(self._search_hits)
        self._jump_to_hit(self._current_hit)
        self._update_count_label()
        self._update_highlights()
        self._sync_result_selection()

    def _jump_to_hit(self, hit_idx: int) -> None:
        byte_idx = self._search_hits[hit_idx]
        target_page = byte_idx // _PAGE_BYTES
        if target_page != self._page:
            self._page = target_page
            self._load_page()
        page_offset = byte_idx - self._page * _PAGE_BYTES
        self._scroll_to_offset(page_offset)

    def _update_count_label(self) -> None:
        n = len(self._search_hits)
        if n == 0:
            self._count_label.setText("Not found")
        elif self._current_hit >= 0:
            self._count_label.setText(f"{self._current_hit + 1} / {n}")
        else:
            self._count_label.setText(f"{n} found")

    # ------------------------------------------------------------------
    # Highlights
    # ------------------------------------------------------------------

    def _update_highlights(self) -> None:
        fmt_hit = QTextCharFormat()
        fmt_hit.setBackground(_COLOR_HIT)
        fmt_current = QTextCharFormat()
        fmt_current.setBackground(_COLOR_CURRENT)

        page_start = self._page * _PAGE_BYTES
        page_end = page_start + len(self._page_data())

        selections: list[QTextEdit.ExtraSelection] = []
        for i, hit_offset in enumerate(self._search_hits):
            hit_end = hit_offset + self._match_len
            if hit_end <= page_start or hit_offset >= page_end:
                continue
            fmt = fmt_current if i == self._current_hit else fmt_hit
            clip_start = max(hit_offset, page_start) - page_start
            clip_end = min(hit_end, page_end) - page_start
            self._append_match_selections(selections, fmt, clip_start, clip_end)

        self._text.setExtraSelections(selections)

    def _append_match_selections(
        self,
        selections: list[QTextEdit.ExtraSelection],
        fmt: QTextCharFormat,
        byte_start: int,
        byte_end: int,
    ) -> None:
        doc = self._text.document()
        start_line = byte_start // _BYTES_PER_ROW
        end_line = (byte_end - 1) // _BYTES_PER_ROW
        for line_num in range(start_line, end_line + 1):
            line_start_byte = line_num * _BYTES_PER_ROW
            seg_start = max(byte_start, line_start_byte) - line_start_byte
            seg_end = min(byte_end, line_start_byte + _BYTES_PER_ROW) - line_start_byte
            block = doc.findBlockByNumber(line_num)
            if not block.isValid():
                continue
            line_pos = block.position()
            # ASCII column
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            c = QTextCursor(doc)
            c.setPosition(line_pos + _ASCII_START + seg_start)
            c.setPosition(line_pos + _ASCII_START + seg_end, QTextCursor.MoveMode.KeepAnchor)
            sel.cursor = c
            selections.append(sel)
            # Hex column — each byte individually (gap between groups at cols 33–34)
            for b in range(seg_start, seg_end):
                hpos = (line_pos + _HEX_START + b * 3) if b < 8 else (line_pos + 35 + (b - 8) * 3)
                sel_h = QTextEdit.ExtraSelection()
                sel_h.format = fmt
                ch = QTextCursor(doc)
                ch.setPosition(hpos)
                ch.setPosition(hpos + 2, QTextCursor.MoveMode.KeepAnchor)
                sel_h.cursor = ch
                selections.append(sel_h)

    # ------------------------------------------------------------------
    # Result panel
    # ------------------------------------------------------------------

    def _toggle_result_panel(self, checked: bool) -> None:
        self._result_panel.setVisible(checked)
        if checked:
            self._update_result_panel()

    def _update_result_panel(self) -> None:
        if not self._result_panel.isVisible():
            return
        self._result_table.setRowCount(0)
        for i, offset in enumerate(self._search_hits):
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            off_item = QTableWidgetItem(f"0x{offset:08X}")
            off_item.setData(Qt.ItemDataRole.UserRole, i)
            self._result_table.setItem(row, 0, off_item)
            chunk = self._data[offset : offset + self._match_len]
            self._result_table.setItem(
                row, 1, QTableWidgetItem(" ".join(f"{b:02X}" for b in chunk))
            )
            self._result_table.setItem(
                row, 2,
                QTableWidgetItem(
                    "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
                ),
            )
        self._sync_result_selection()

    def _sync_result_selection(self) -> None:
        if not self._result_panel.isVisible():
            return
        if 0 <= self._current_hit < self._result_table.rowCount():
            self._result_table.selectRow(self._current_hit)
            item = self._result_table.item(self._current_hit, 0)
            if item is not None:
                self._result_table.scrollToItem(item)

    def _jump_to_result_row(self, row: int, _col: int = 0) -> None:
        off_item = self._result_table.item(row, 0)
        if off_item is None:
            return
        hit_idx = off_item.data(Qt.ItemDataRole.UserRole)
        self._current_hit = hit_idx
        self._jump_to_hit(hit_idx)
        self._update_count_label()
        self._update_highlights()

    # ------------------------------------------------------------------
    # Copy helpers
    # ------------------------------------------------------------------

    def _copy_hex(self) -> None:
        QApplication.clipboard().setText(
            " ".join(f"{b:02X}" for b in self._page_data())
        )

    def _copy_ascii(self) -> None:
        QApplication.clipboard().setText(
            "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in self._page_data())
        )

    def _copy_all(self) -> None:
        QApplication.clipboard().setText(self._text.toPlainText())

    def _selection_byte_range(self) -> tuple[int, int] | None:
        cursor = self._text.textCursor()
        if not cursor.hasSelection():
            return None
        doc = self._text.document()

        def col_to_byte(col: int) -> int:
            if col <= _HEX_START:
                return 0
            if col <= 32:                       # hex left (bytes 0–7)
                return min((col - _HEX_START) // 3, 7)
            if col <= 34:                       # gap between hex groups
                return 7
            if col < _HEX_END:                  # hex right (bytes 8–15)
                return min(8 + (col - 35) // 3, 15)
            if col < _ASCII_START:              # gap before ASCII
                return 15
            return min(col - _ASCII_START, 15)  # ASCII column

        page_start = self._page * _PAGE_BYTES
        s_block = doc.findBlock(cursor.selectionStart())
        s_byte = s_block.blockNumber() * _BYTES_PER_ROW + col_to_byte(
            cursor.selectionStart() - s_block.position()
        )
        e_block = doc.findBlock(cursor.selectionEnd())
        e_byte = e_block.blockNumber() * _BYTES_PER_ROW + col_to_byte(
            cursor.selectionEnd() - e_block.position()
        )
        return page_start + s_byte, page_start + e_byte

    def _search_selected_as_ascii(self) -> None:
        rng = self._selection_byte_range()
        if rng is None:
            return
        chunk = self._data[rng[0] : rng[1] + 1]
        query = chunk.decode("latin-1")
        if query:
            self._search_mode.setCurrentText("ASCII")
            self._search_input.setText(query)
            self._do_search()

    def _search_selected_as_hex(self) -> None:
        rng = self._selection_byte_range()
        if rng is None:
            return
        chunk = self._data[rng[0] : rng[1] + 1]
        if chunk:
            self._search_mode.setCurrentText("Hex")
            self._search_input.setText(" ".join(f"{b:02X}" for b in chunk))
            self._do_search()

    def _selection_start_column(self) -> int:
        """Column (0-based) within its row that the selection's first
        character sits at.

        A multi-row selection's first row is a *partial* row whenever the
        drag didn't start at column 0 (the normal case -- nobody drags from
        exactly the left edge) -- Qt's selectedText() still hands back that
        row's text starting from wherever the selection actually begins, not
        from column 0. Slicing that fragment at the usual fixed column
        offsets (_HEX_START, _ASCII_START, ...) would then cut from the
        wrong place, or make it look like there was nothing to take from
        that row at all. Every row after the first is unaffected (a
        multi-row selection always starts each subsequent row at its true
        column 0), and the last row is only ever truncated on the right,
        which fixed-offset slicing already handles correctly on its own.
        """
        cursor = self._text.textCursor()
        doc = self._text.document()
        start_block = doc.findBlock(cursor.selectionStart())
        return cursor.selectionStart() - start_block.position()

    def _copy_selected_hex(self) -> None:
        text = _selected_text(self._text)
        if not text:
            return
        first_col = self._selection_start_column()
        tokens: list[str] = []
        for i, line in enumerate(text.split(" ")):
            col_offset = first_col if i == 0 else 0
            hex_section = line[max(_HEX_START - col_offset, 0):max(_HEX_END - col_offset, 0)]
            for part in hex_section.split():
                if len(part) == 2 and all(c in "0123456789ABCDEFabcdef" for c in part):
                    tokens.append(part.upper())
        QApplication.clipboard().setText(" ".join(tokens))

    def _copy_selected_ascii(self) -> None:
        text = _selected_text(self._text)
        if not text:
            return
        first_col = self._selection_start_column()
        parts: list[str] = []
        for i, line in enumerate(text.split(" ")):
            col_offset = first_col if i == 0 else 0
            parts.append(line[max(_ASCII_START - col_offset, 0):])
        QApplication.clipboard().setText("".join(parts))


def _selected_text(widget: QPlainTextEdit) -> str:
    """Return the selected text, using Qt's paragraph separator \\u2029."""
    cursor = widget.textCursor()
    return cursor.selectedText() if cursor.hasSelection() else ""


def _parse_hex_query(query: str) -> bytes | None:
    cleaned = "".join(ch for ch in query if ch not in {" ", "\t", "\n", ":"})
    if len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None
