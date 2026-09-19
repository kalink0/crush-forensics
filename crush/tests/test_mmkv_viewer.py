# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the MMKV viewer's large-value handling.

Regression coverage for a real bug found via a real (large) MMKV store: a
multi-megabyte decoded string value (e.g. a cached GraphQL/JSON blob) was
put directly into a table cell's display text with no cap, making Qt's text
layout/paint noticeably slow on every repaint — not just once at load. Only
the on-screen preview must be capped; the full value must stay reachable via
search, CSV export, and Copy Value.
"""
from __future__ import annotations

from PySide6.QtCore import Qt

from crush.viewers.mmkv_viewer import (
    _FULLTEXT_ROLE,
    _TEXT_PREVIEW_LEN,
    _VALUE_COL,
    _display_value,
    _full_value_text,
    MMKVRecordsWidget,
)


def _rec(
    index: int,
    key: str,
    decoded,
    raw: bytes,
    state: str = "Live",
    type_: str = "string",
    value_bytes: bytes | None = None,
) -> dict:
    # value_bytes defaults to raw for tests that don't care about the
    # raw-vs-stripped-value distinction; pass it explicitly to test that split.
    return {
        "index": index,
        "key": key,
        "decoded": decoded,
        "raw": raw,
        "value_bytes": raw if value_bytes is None else value_bytes,
        "state": state,
        "type": type_,
    }


def test_display_value_truncates_long_strings() -> None:
    long_text = "x" * 10_000
    shown = _display_value(long_text, long_text.encode())
    assert len(shown) < 10_000
    assert shown.startswith("x" * _TEXT_PREVIEW_LEN)
    assert "10,000 chars total" in shown


def test_full_value_text_is_never_truncated() -> None:
    long_text = "x" * 10_000
    assert _full_value_text(long_text, long_text.encode()) == long_text


def test_display_value_short_string_unchanged() -> None:
    assert _display_value("hello", b"hello") == "hello"


def test_search_finds_match_past_the_display_truncation_cutoff(qapp) -> None:
    """The bug this guards against: searching only the (capped) display text
    would silently miss a match sitting past the cutoff in a huge value."""
    long_text = ("filler " * 100) + "NEEDLE" + ("filler " * 2000)
    assert len(long_text) > _TEXT_PREVIEW_LEN
    records = [
        _rec(0, "big_blob", long_text, long_text.encode()),
        _rec(1, "other_key", "unrelated short value", b"unrelated short value"),
    ]
    widget = MMKVRecordsWidget(records)
    widget._proxy.set_text("needle")

    visible_keys = []
    for proxy_row in range(widget._proxy.rowCount()):
        src_row = widget._proxy.mapToSource(widget._proxy.index(proxy_row, 1)).row()
        visible_keys.append(widget._model.item(src_row, 1).text())
    assert visible_keys == ["big_blob"]


def test_value_item_carries_full_text_role_for_copy_value(qapp) -> None:
    long_text = "y" * 5000
    records = [_rec(0, "k", long_text, long_text.encode())]
    widget = MMKVRecordsWidget(records)
    value_item = widget._model.item(0, _VALUE_COL)
    assert value_item.text() != long_text  # display is truncated
    assert value_item.data(_FULLTEXT_ROLE) == long_text  # full text preserved


def test_csv_export_uses_full_value_not_truncated_preview(tmp_path, qapp, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    long_text = "z" * 5000
    records = [_rec(0, "k", long_text, long_text.encode())]
    widget = MMKVRecordsWidget(records)

    out_path = tmp_path / "out.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out_path), ""))
    widget._export_csv()

    content = out_path.read_text(encoding="utf-8")
    assert long_text in content


def test_value_bar_never_silently_truncates_past_its_own_explicit_note(qapp) -> None:
    """QLineEdit.setText() silently truncates at its 32,767-char maxLength with
    no indication anything was cut — a real bug found on an 8 MB real-world
    value. The value bar must use the already-bounded display text (which
    carries its own explicit "(N chars total)" note) rather than feeding the
    untruncated full text straight into a widget with a hidden length cap."""
    huge_text = "q" * 50_000  # comfortably past QLineEdit's 32,767 default maxLength
    records = [_rec(0, "k", huge_text, huge_text.encode())]
    widget = MMKVRecordsWidget(records)
    widget._table.selectRow(0)

    shown = widget._value_field.text()
    assert len(shown) < 32_767
    assert "50,000 chars total" in shown


def test_size_column_shows_raw_container_byte_count(qapp) -> None:
    """Real MMKV stores can have wildly different value sizes (a few bytes to
    multi-megabyte blobs) — an explicit, sortable Size column lets an examiner
    spot the outliers directly instead of having to inspect each row."""
    from crush.viewers.mmkv_viewer import _COLUMNS

    raw = b"x" * 12345
    records = [_rec(0, "k", "x" * 12345, raw)]
    widget = MMKVRecordsWidget(records)
    size_col = _COLUMNS.index("Size (B)")
    size_item = widget._model.item(0, size_col)
    assert size_item.text() == "12,345"
    assert size_item.data(Qt.ItemDataRole.UserRole) == 12345


def test_inspect_value_uses_stripped_value_bytes_not_the_raw_container(qapp) -> None:
    """Regression test: the raw value container includes MMKV's own internal
    length-prefix varint ahead of the actual content (e.g. a short string's
    container starts with a length byte that can render as a spurious-looking
    leading character, like '&' for a 38-byte value, or break re-parsing a
    JSON value entirely). Inspect Value must operate on the stripped value
    bytes, matching Copy Value — same "Decoded (from table)" default view
    already used for SEGB. Crucially, "raw" itself (_RAW_ROLE) must stay the
    complete, untouched container — nothing is ever removed from raw; the
    stripped form is a separate field used only for this action.

    QMenu.exec() can't be reliably monkeypatched in PySide6 (a real popup call
    happens regardless), so this verifies the same values _on_context_menu
    reads off the model — its _RAW_ROLE / _VALUE_BYTES_ROLE / _FULLTEXT_ROLE
    data — feed BlobInspector correctly, rather than driving the actual menu."""
    from crush.viewers.blob_inspector import BlobInspector, _BlobPanel
    from crush.viewers.mmkv_viewer import _RAW_ROLE, _VALUE_BYTES_ROLE

    decoded = '"6714298d-97ab-4655-b538-2adc5142d9b0"'
    stripped = decoded.encode()
    raw = b"\x26" + stripped  # 0x26 = 38 = len(decoded), the real-world case
    records = [_rec(0, "@OTA.UpdateIdStorage", decoded, raw, value_bytes=stripped)]
    widget = MMKVRecordsWidget(records)

    index_item = widget._model.item(0, 0)
    assert index_item.data(_RAW_ROLE) == raw  # raw stays complete, prefix included
    assert index_item.data(_VALUE_BYTES_ROLE) == stripped  # stripped form is separate

    value_item = widget._model.item(0, _VALUE_COL)
    full_value = value_item.data(_FULLTEXT_ROLE)
    assert full_value == decoded  # exactly what _on_context_menu would read

    # What _on_context_menu now passes to BlobInspector: value_bytes, not raw.
    bi = BlobInspector(stripped, display_text=full_value)
    panel = bi.findChild(_BlobPanel)
    assert panel._format_list.currentItem().data(Qt.ItemDataRole.UserRole) == "Decoded (from table)"
    assert panel._viewer.toPlainText() == decoded
    assert not panel._viewer.toPlainText().startswith("&")


# ---------------------------------------------------------------------------
# Embedded Show Hex pane: real on-disk bytes in context, not just the
# value's own bytes in isolation (see crush/parsers/mmkv_parser.py's
# _compute_entry_offsets and its own tests in test_mmkv_parser.py).
# ---------------------------------------------------------------------------

def test_selecting_a_row_highlights_its_real_file_bytes(qapp) -> None:
    file_bytes = b"\x00" * 20 + b"HELLOWORLD" + b"\x00" * 20
    rec = _rec(0, "k", "irrelevant", b"raw-container-bytes-not-shown-when-ranges-exist")
    rec["entry_range"] = (20, 30)
    rec["value_range"] = (25, 30)
    widget = MMKVRecordsWidget([rec], file_bytes=file_bytes)
    widget.show()

    index = widget._proxy.mapFromSource(widget._model.index(0, 0))
    widget._table.setCurrentIndex(index)

    assert widget._hex_val._data == file_bytes
    assert widget._hex_val._focus_ranges == [(20, 30), (25, 30)]


def test_removed_entry_zero_width_value_range_is_not_highlighted(qapp) -> None:
    """A zero-width value_range (Removed entry, empty container) must not be
    passed to highlight_byte_ranges() as a degenerate empty highlight."""
    file_bytes = b"\x00" * 20 + b"KEY" + b"\x00" * 20
    rec = _rec(0, "gone", "", b"")
    rec["entry_range"] = (20, 23)
    rec["value_range"] = (23, 23)  # zero-width
    widget = MMKVRecordsWidget([rec], file_bytes=file_bytes)
    widget.show()

    index = widget._proxy.mapFromSource(widget._model.index(0, 0))
    widget._table.setCurrentIndex(index)

    assert widget._hex_val._focus_ranges == [(20, 23)]  # entry only, no zero-width value


def test_falls_back_to_isolated_value_bytes_without_offsets(qapp) -> None:
    """No entry_range/value_range on the record (offset walk unavailable) --
    must fall back to the value's own isolated bytes, never blank."""
    raw = b"isolated-value-bytes"
    rec = _rec(0, "k", "v", raw)  # no entry_range/value_range set
    widget = MMKVRecordsWidget([rec], file_bytes=b"unrelated file content here")
    widget.show()

    index = widget._proxy.mapFromSource(widget._model.index(0, 0))
    widget._table.setCurrentIndex(index)

    assert widget._hex_val._data == raw
    assert widget._hex_val._focus_ranges == []


def _overview_value(viewer, label: str) -> str:
    from crush.viewers.tree_viewer import TreeViewer

    model = viewer.findChild(TreeViewer)._model
    for row in range(model.rowCount()):
        if model.item(row, 0).text() == label:
            return model.item(row, 1).text()
    raise AssertionError(f"{label!r} not in Overview")


def test_overview_shows_encrypted_verdict_with_reason_for_false_positive_flag(qapp) -> None:
    """The .crc vector said "encrypted" but the parser proved the store is plaintext:
    the Overview must show the verdict and the reason, not the raw flag."""
    from crush.viewers.mmkv_viewer import MMKVViewer

    meta_info = {
        "crc": 0, "version": 61, "sequence": 0, "actual_size": None,
        "encrypted": False, "encrypted_note": "flag treated as a false positive",
    }
    viewer = MMKVViewer({"records": [], "meta_info": meta_info})
    assert _overview_value(viewer, "Encrypted") == "no — flag treated as a false positive"


def test_overview_encrypted_plain_yes_no_without_note(qapp) -> None:
    from crush.viewers.mmkv_viewer import MMKVViewer

    base = {"crc": 0, "version": 1, "sequence": 0, "actual_size": None}
    assert _overview_value(
        MMKVViewer({"records": [], "meta_info": {**base, "encrypted": True}}), "Encrypted"
    ) == "yes"
    assert _overview_value(
        MMKVViewer({"records": [], "meta_info": {**base, "encrypted": False}}), "Encrypted"
    ) == "no"


def test_mmkv_viewer_passes_file_bytes_through_to_records_widget(qapp) -> None:
    from crush.viewers.mmkv_viewer import MMKVViewer

    file_bytes = b"the real mmkv file bytes"
    rec = _rec(0, "k", "v", b"raw")
    rec["entry_range"] = (0, 5)
    viewer = MMKVViewer({"records": [rec], "meta_info": None, "__mmkv_file_bytes": file_bytes})
    records_widget = viewer.findChild(MMKVRecordsWidget)
    assert records_widget is not None
    assert records_widget._file_bytes == file_bytes
