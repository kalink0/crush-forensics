# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the shared HexViewer (crush/viewers/hex_viewer.py), used by every
viewer with a hex/ASCII pane (LevelDB, Realm, SQLite blob cells, ...)."""
from __future__ import annotations

import pytest
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


_ALPHABET = bytes(range(0x41, 0x5B)) + bytes(range(0x61, 0x7B))  # A-Z a-z


def _hex_col(hv: HexViewer, byte: int) -> int:
    """Column of the first hex digit of *byte* (0-15) in its row."""
    return hv._hex_start + 3 * byte + (1 if byte >= 8 else 0)


def _ascii_col(hv: HexViewer, byte: int) -> int:
    return hv._ascii_start + byte


def _select(hv: HexViewer, start: tuple[int, int], end: tuple[int, int]) -> None:
    """Select from (row, column) *start* to (row, column) *end*, end exclusive
    -- as a mouse drag between those two character positions does."""
    doc = hv._text.document()
    cursor = hv._text.textCursor()
    cursor.setPosition(doc.findBlockByNumber(start[0]).position() + start[1])
    cursor.setPosition(
        doc.findBlockByNumber(end[0]).position() + end[1], QTextCursor.MoveMode.KeepAnchor
    )
    hv._text.setTextCursor(cursor)


def _copied(hv: HexViewer) -> tuple[str, str]:
    QGuiApplication.clipboard().setText("<unchanged>")
    hv._copy_selected_hex()
    hex_text = QGuiApplication.clipboard().text()
    QGuiApplication.clipboard().setText("<unchanged>")
    hv._copy_selected_ascii()
    return hex_text, QGuiApplication.clipboard().text()


def _expected(first: int, last: int) -> tuple[str, str]:
    chunk = _ALPHABET[first : last + 1]
    return " ".join(f"{b:02X}" for b in chunk), chunk.decode("ascii")


# Which bytes a selection covers, by where it starts and ends: (start row,
# start column kind, start byte), (end row, end column kind, last byte).
_SELECTIONS = {
    "hex column, single row": ((0, "hex", 2), (0, "hex", 6)),
    "ascii column, single row": ((0, "ascii", 2), (0, "ascii", 6)),
    "hex column, multi row": ((0, "hex", 5), (1, "hex", 3)),
    "ascii column, multi row": ((0, "ascii", 5), (1, "ascii", 3)),
    "hex to ascii column": ((0, "hex", 5), (1, "ascii", 3)),
    "ascii to hex column": ((0, "ascii", 5), (1, "hex", 3)),
    "hex right group across rows": ((0, "hex", 12), (2, "hex", 9)),
}


@pytest.mark.parametrize("offset_mode", ["hex", "dec"])
@pytest.mark.parametrize("name", list(_SELECTIONS))
def test_copy_selected_takes_exactly_the_selected_bytes(qapp, name: str, offset_mode: str) -> None:
    """Copy Selected Hex/ASCII copy the bytes from the first to the last
    selected one, wherever (hex or ASCII column, which row) the selection
    starts and ends -- not the text at fixed columns of each selected row."""
    hv = HexViewer(_ALPHABET)
    hv._set_offset_mode(offset_mode)
    (s_row, s_kind, s_byte), (e_row, e_kind, e_byte) = _SELECTIONS[name]
    start_col = _hex_col(hv, s_byte) if s_kind == "hex" else _ascii_col(hv, s_byte)
    # End right after the byte's text: both hex digits, or its one character.
    end_col = _hex_col(hv, e_byte) + 2 if e_kind == "hex" else _ascii_col(hv, e_byte) + 1
    _select(hv, (s_row, start_col), (e_row, end_col))

    first, last = s_row * 16 + s_byte, e_row * 16 + e_byte
    assert hv._selection_byte_range() == (first, last)
    assert _copied(hv) == _expected(first, last)


def test_selection_ending_on_a_byte_first_hex_digit_includes_it(qapp) -> None:
    hv = HexViewer(_ALPHABET)
    _select(hv, (0, _hex_col(hv, 1)), (0, _hex_col(hv, 4) + 1))
    assert hv._selection_byte_range() == (1, 4)


def test_selection_starting_on_space_after_a_byte_starts_at_the_next(qapp) -> None:
    hv = HexViewer(_ALPHABET)
    _select(hv, (0, _hex_col(hv, 1) + 2), (0, _hex_col(hv, 3) + 2))
    assert hv._selection_byte_range() == (2, 3)


def test_selection_through_line_end_takes_the_row_to_its_last_byte(qapp) -> None:
    hv = HexViewer(_ALPHABET)
    # From row 0's byte 14 (ASCII) to the start of row 1: row 0's line end.
    _select(hv, (0, _ascii_col(hv, 14)), (1, 0))
    assert hv._selection_byte_range() == (14, 15)


def test_selection_of_offsets_only_covers_no_bytes(qapp) -> None:
    hv = HexViewer(_ALPHABET)
    _select(hv, (1, 0), (1, 4))
    assert hv._selection_byte_range() is None
    assert _copied(hv) == ("<unchanged>", "<unchanged>")


def test_selection_past_the_data_end_stops_at_the_last_byte(qapp) -> None:
    hv = HexViewer(_ALPHABET)  # 52 B: row 3 holds bytes 48-51
    _select(hv, (3, _hex_col(hv, 2)), (3, _hex_col(hv, 12) + 2))
    assert hv._selection_byte_range() == (50, 51)


@pytest.mark.parametrize("kind", ["hex", "ascii"])
def test_search_selected_takes_no_byte_past_the_selection(qapp, kind: str) -> None:
    """Regression: a selection ending in the ASCII column took the position
    after its last character as one more byte."""
    hv = HexViewer(_ALPHABET)
    _select(hv, (0, _ascii_col(hv, 2)), (0, _ascii_col(hv, 5) + 1))
    if kind == "ascii":
        hv._search_selected_as_ascii()
        assert hv._search_input.text() == "CDEF"
    else:
        hv._search_selected_as_hex()
        assert hv._search_input.text() == "43 44 45 46"


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


def _focus_backgrounds(hv: HexViewer) -> list[tuple[int, int, int, int]]:
    """Background of every focus-range selection painted on the page, in order."""
    search_colors = {(255, 230, 80, 255), (255, 140, 0, 255)}
    out = []
    for sel in hv._text.extraSelections():
        rgba = sel.format.background().color().getRgb()
        if rgba not in search_colors:
            out.append(rgba)
    return out


def test_every_focus_range_is_highlighted(qapp) -> None:
    """Regression: highlight_byte_ranges() kept only the first five ranges
    and dropped the rest without a word."""
    hv = HexViewer(bytes(range(256)))
    ranges = [(i * 16, i * 16 + 4) for i in range(8)]
    hv.highlight_byte_ranges(ranges)

    assert hv._focus_ranges == ranges
    assert hv._focus_color_idx == list(range(8))
    # One ASCII selection plus one per hex byte, for every range.
    assert len(_focus_backgrounds(hv)) == 8 * (1 + 4)


def test_range_group_is_one_color(qapp) -> None:
    """The pieces of one value (e.g. a column over several overflow pages)
    share one color; the next group gets the next."""
    hv = HexViewer(bytes(range(256)))
    pieces = [(0, 2), (32, 34), (64, 66), (96, 98), (128, 130), (160, 162)]
    hv.highlight_byte_range_groups([pieces, [(200, 202)]])

    assert hv._focus_ranges == [*pieces, (200, 202)]
    assert hv._focus_color_idx == [0] * 6 + [1]
    backgrounds = _focus_backgrounds(hv)
    assert len(set(backgrounds[: 6 * 3])) == 1
    assert backgrounds[-1] != backgrounds[0]


def test_empty_range_group_takes_no_color(qapp) -> None:
    hv = HexViewer(bytes(range(64)))
    hv.highlight_byte_range_groups([[(5, 5), (900, 910)], [(0, 4)]])

    assert hv._focus_ranges == [(0, 4)]
    assert hv._focus_color_idx == [0]


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
