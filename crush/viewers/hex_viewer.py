# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Hex viewer — displays raw bytes as hex + ASCII, 16 bytes per row."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QContextMenuEvent, QFont

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
        menu.addAction("Copy All").triggered.connect(self._viewer._copy_all)
        menu.exec(event.globalPos())


class HexViewer(QWidget):
    """Simple hex + ASCII dump viewer."""

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._page = 0
        self._build_ui()
        self._load_page()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(6, 6, 6, 0)
        toolbar.setSpacing(8)

        self._search_mode = QComboBox()
        self._search_mode.addItems(["ASCII", "Hex"])
        toolbar.addWidget(self._search_mode)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search…")
        self._search_input.returnPressed.connect(self._search)
        toolbar.addWidget(self._search_input, stretch=1)

        self._search_btn = QPushButton("Find")
        self._search_btn.clicked.connect(self._search)
        toolbar.addWidget(self._search_btn)

        self._status = QLabel("")
        toolbar.addWidget(self._status)

        toolbar.addStretch(1)

        self._prev_btn = QPushButton("◀ Prev")
        self._prev_btn.clicked.connect(self._prev_page)
        toolbar.addWidget(self._prev_btn)

        self._page_label = QLabel("")
        toolbar.addWidget(self._page_label)

        self._next_btn = QPushButton("Next ▶")
        self._next_btn.clicked.connect(self._next_page)
        toolbar.addWidget(self._next_btn)

        toolbar.addSpacing(8)

        self._copy_hex_btn = QPushButton("Copy Hex")
        self._copy_hex_btn.clicked.connect(self._copy_hex)
        toolbar.addWidget(self._copy_hex_btn)

        self._copy_ascii_btn = QPushButton("Copy ASCII")
        self._copy_ascii_btn.clicked.connect(self._copy_ascii)
        toolbar.addWidget(self._copy_ascii_btn)

        self._copy_all_btn = QPushButton("Copy All")
        self._copy_all_btn.clicked.connect(self._copy_all)
        toolbar.addWidget(self._copy_all_btn)

        layout.addLayout(toolbar)

        self._text = _HexPlainTextEdit(self)
        self._text.setReadOnly(True)
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._text, smooth_item_scroll=False)

        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(font)

        layout.addWidget(self._text)

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
        self._load_page()

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._load_page()

    def _next_page(self) -> None:
        if self._page < self._page_count() - 1:
            self._page += 1
            self._load_page()

    def _search(self) -> None:
        query = self._search_input.text().strip()
        if not query:
            self._status.setText("Enter a search term")
            return

        mode = self._search_mode.currentText()
        if mode == "Hex":
            pattern = _parse_hex_query(query)
            if pattern is None:
                self._status.setText("Invalid hex pattern")
                return
            idx = self._data.find(pattern)
        else:
            idx = self._data.decode("latin-1").find(query)

        if idx < 0:
            self._status.setText("Not found")
            return

        # Jump to the page containing the match
        target_page = idx // _PAGE_BYTES
        if target_page != self._page:
            self._page = target_page
            self._load_page()

        page_offset = idx - self._page * _PAGE_BYTES
        self._scroll_to_offset(page_offset)
        self._status.setText(f"Found at 0x{idx:08X}")

    def _scroll_to_offset(self, page_offset: int) -> None:
        line = page_offset // _BYTES_PER_ROW
        block = self._text.document().findBlockByNumber(line)
        if not block.isValid():
            return
        cursor = self._text.textCursor()
        cursor.setPosition(block.position())
        self._text.setTextCursor(cursor)
        self._text.centerCursor()

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

    def _copy_selected_hex(self) -> None:
        text = _selected_text(self._text)
        if not text:
            return
        tokens: list[str] = []
        for line in text.split("\u2029"):
            # Extract the hex section from the fixed-column layout
            hex_section = line[_HEX_START:_HEX_END]
            for part in hex_section.split():
                if len(part) == 2 and all(c in "0123456789ABCDEFabcdef" for c in part):
                    tokens.append(part.upper())
        QApplication.clipboard().setText(" ".join(tokens))

    def _copy_selected_ascii(self) -> None:
        text = _selected_text(self._text)
        if not text:
            return
        parts: list[str] = []
        for line in text.split("\u2029"):
            if len(line) > _ASCII_START:
                parts.append(line[_ASCII_START:])
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
