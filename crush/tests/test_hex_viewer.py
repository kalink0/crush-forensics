# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the shared HexViewer (crush/viewers/hex_viewer.py), used by every
viewer with a hex/ASCII pane (LevelDB, Realm, SQLite blob cells, ...)."""
from __future__ import annotations

from PySide6.QtGui import QGuiApplication, QTextCursor

from crush.viewers.hex_viewer import HexViewer


def _make_viewer(rows: int = 5) -> HexViewer:
    text = (b"The quick brown fox jumps over the lazy dog 1234567890 " * 6)[: 16 * rows]
    return HexViewer(text)


def test_copy_selected_ascii_drag_not_starting_at_column_zero(qapp) -> None:
    """Regression: a normal mouse drag almost never starts at column 0 of a
    line -- selecting from partway into row 0's ASCII text down to partway
    into a later row used to silently drop row 0's content entirely, because
    the fixed-column slice assumed every row fragment started at column 0.
    With a 2-row selection this looked exactly like "only the last line got
    copied"."""
    hv = _make_viewer(rows=4)
    doc = hv._text.document()

    row0_pos = doc.findBlockByNumber(0).position() + 60 + 4  # a few chars into row 0's ASCII
    row3_pos = doc.findBlockByNumber(3).position() + 60 + 6  # a few chars into row 3's ASCII
    cursor = hv._text.textCursor()
    cursor.setPosition(row0_pos)
    cursor.setPosition(row3_pos, QTextCursor.MoveMode.KeepAnchor)
    hv._text.setTextCursor(cursor)

    hv._copy_selected_ascii()
    assert QGuiApplication.clipboard().text() == (
        "quick brown fox jumps over the lazy dog 1234567890"
    )


def test_copy_selected_ascii_row_aligned_selection_still_works(qapp) -> None:
    """A selection that does start at column 0 (e.g. Home then Shift+Down)
    must keep working exactly as before."""
    hv = _make_viewer(rows=4)
    cursor = hv._text.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, 3)
    cursor.movePosition(QTextCursor.MoveOperation.EndOfLine, QTextCursor.MoveMode.KeepAnchor)
    hv._text.setTextCursor(cursor)

    hv._copy_selected_ascii()
    assert QGuiApplication.clipboard().text() == (
        "The quick brown fox jumps over the lazy dog 1234567890 The quick"
    )


def test_copy_selected_hex_drag_not_starting_at_column_zero(qapp) -> None:
    """Same bug, same fix, for the hex side of a multi-row selection that
    starts mid-row (this time within the hex columns, not the ASCII ones)."""
    hv = _make_viewer(rows=3)
    doc = hv._text.document()

    start_pos = doc.findBlockByNumber(0).position() + 20  # partway into row 0's hex_left
    end_pos = doc.findBlockByNumber(2).position() + 70    # partway into row 2's ASCII
    cursor = hv._text.textCursor()
    cursor.setPosition(start_pos)
    cursor.setPosition(end_pos, QTextCursor.MoveMode.KeepAnchor)
    hv._text.setTextCursor(cursor)

    hv._copy_selected_hex()
    tokens = QGuiApplication.clipboard().text().split()
    assert len(tokens) > 8  # spans well past a single row's worth of bytes
    assert all(len(t) == 2 for t in tokens)


def test_selection_start_column_matches_actual_cursor_offset(qapp) -> None:
    hv = _make_viewer(rows=2)
    doc = hv._text.document()
    pos = doc.findBlockByNumber(1).position() + 17
    cursor = hv._text.textCursor()
    cursor.setPosition(pos)
    cursor.setPosition(pos + 5, QTextCursor.MoveMode.KeepAnchor)
    hv._text.setTextCursor(cursor)

    assert hv._selection_start_column() == 17
