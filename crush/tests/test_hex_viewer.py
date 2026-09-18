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


def test_offset_mode_defaults_to_hex(qapp) -> None:
    hv = _make_viewer(rows=2)
    first_line = hv._text.toPlainText().splitlines()[0]
    assert first_line.startswith("00000000")


def test_toggle_offset_mode_switches_to_decimal_and_relayouts(qapp) -> None:
    data = bytes(range(256)) * 20  # 5120 bytes -> decimal width 4
    hv = HexViewer(data)

    hv._toggle_offset_mode()

    assert hv._offset_mode == "dec"
    assert hv._offset_width == len(str(len(data)))
    first_line = hv._text.toPlainText().splitlines()[0]
    assert first_line.startswith("0000")
    # column layout must have shifted along with the new offset width
    assert hv._hex_start == hv._offset_width + 2


def test_toggle_offset_mode_round_trip_preserves_hex_layout(qapp) -> None:
    hv = _make_viewer(rows=4)
    orig_hex_start = hv._hex_start
    hv._toggle_offset_mode()
    hv._toggle_offset_mode()
    assert hv._offset_mode == "hex"
    assert hv._hex_start == orig_hex_start


def test_byte_offset_at_cursor_matches_after_switching_to_decimal(qapp) -> None:
    data = bytes(range(256)) * 20
    hv = HexViewer(data)
    hv._toggle_offset_mode()
    doc = hv._text.document()
    block = doc.findBlockByNumber(1)  # bytes 16-31

    cursor = hv._text.textCursor()
    cursor.setPosition(block.position() + hv._ascii_start + 2)
    hv._text.setTextCursor(cursor)

    assert hv._byte_offset_at_cursor() == 18


def test_goto_offset_scrolls_without_length(qapp) -> None:
    data = bytes(range(256)) * 20
    hv = HexViewer(data)
    hv._goto_offset_input.setText("200")
    hv._do_goto()
    assert hv._focus_range is None
    assert hv._goto_status.text() == ""


def test_goto_offset_with_length_highlights_range(qapp) -> None:
    data = bytes(range(256)) * 20
    hv = HexViewer(data)
    hv._goto_offset_input.setText("C8")  # hex mode (default): 0xC8 == 200
    hv._goto_length_input.setText("10")  # 0x10 == 16
    hv._do_goto()
    assert hv._focus_range == (200, 216)


def test_goto_offset_parses_decimal_when_in_decimal_mode(qapp) -> None:
    data = bytes(range(256)) * 20
    hv = HexViewer(data)
    hv._toggle_offset_mode()
    hv._goto_offset_input.setText("512")
    hv._goto_length_input.setText("16")
    hv._do_goto()
    assert hv._focus_range == (512, 528)


def test_goto_invalid_offset_reports_status_without_crashing(qapp) -> None:
    hv = _make_viewer(rows=2)
    hv._goto_offset_input.setText("zz")
    hv._do_goto()
    assert hv._goto_status.text() == "Invalid offset"


def test_goto_offset_out_of_range_reports_status(qapp) -> None:
    hv = _make_viewer(rows=2)
    hv._goto_offset_input.setText("FFFFFF")
    hv._do_goto()
    assert hv._goto_status.text() == "Invalid offset"
