# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the Protobuf viewer's schema-less tree search/filter (#63)."""
from __future__ import annotations

import json

from crush.parsers.protobuf_parser import _decode_message
from crush.viewers.protobuf_viewer import (
    ProtobufTreeWidget,
    _ENTRY_ROLE,
    _entries_to_json,
    _entry_to_jsonable,
)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _visible_field_labels(widget: ProtobufTreeWidget) -> list[str]:
    model = widget._model
    root = model.invisibleRootItem()
    labels = []
    for row in range(root.rowCount()):
        if not widget._tree.isRowHidden(row, model.indexFromItem(root)):
            labels.append(root.child(row, 0).text())
    return labels


def test_filter_matches_field_value_text(qapp) -> None:
    # field 1: varint 42, field 2: string "hello world"
    raw = b"\x08\x2a" + b"\x12" + _varint(11) + b"hello world"
    decoded, warning, _ = _decode_message(raw)
    assert not warning

    widget = ProtobufTreeWidget(decoded)
    assert _visible_field_labels(widget) == ["field 1", "field 2"]

    widget._apply_filter("hello")
    assert _visible_field_labels(widget) == ["field 2"]

    widget._apply_filter("")
    assert _visible_field_labels(widget) == ["field 1", "field 2"]


def test_filter_matches_field_name(qapp) -> None:
    raw = b"\x08\x2a" + b"\x12" + _varint(11) + b"hello world"
    decoded, warning, _ = _decode_message(raw)
    assert not warning

    widget = ProtobufTreeWidget(decoded)
    widget._apply_filter("field 1")
    assert _visible_field_labels(widget) == ["field 1"]


def test_filter_matches_full_untruncated_value_past_display_cap(qapp) -> None:
    """A field's tree-cell label truncates a large bytes value at 64 bytes with '…'
    (see #60) — the search must still find text that only exists past that cutoff,
    since it matches against the full value, not the truncated display label."""
    payload = bytes(range(256)) * 2  # 512 bytes, non-utf8, well past the 64-byte cap
    raw = b"\x0a" + _varint(len(payload)) + payload  # field 1, length-delimited bytes
    decoded, warning, _ = _decode_message(raw)
    assert not warning

    widget = ProtobufTreeWidget(decoded)
    # Byte value 200 (hex "c8") only appears past offset 200 in the payload — well
    # beyond the 64-byte preview cap.
    needle = payload[200:202].hex(" ")
    widget._apply_filter(needle)
    assert _visible_field_labels(widget) == ["field 1"]


def test_filter_reveals_ancestor_when_nested_child_matches(qapp) -> None:
    # field 2: nested message containing field 5 = string "needle_zzz"; field 1 is an
    # unrelated varint that doesn't contain the search text anywhere.
    inner = bytes([0x2a]) + _varint(10) + b"needle_zzz"  # field 5, length-delimited string
    outer = b"\x08\x2a" + b"\x12" + _varint(len(inner)) + inner  # field1 varint42, field2 message
    decoded, warning, _ = _decode_message(outer)
    assert not warning

    widget = ProtobufTreeWidget(decoded)
    widget._apply_filter("needle_zzz")
    # field 2 itself doesn't contain the needle in its own label ("{ 1 field(s) }") but
    # must stay visible because its nested child field 5 matches.
    assert _visible_field_labels(widget) == ["field 2"]

    widget._apply_filter("nonexistent-needle")
    assert _visible_field_labels(widget) == []

    widget._apply_filter("")
    assert set(_visible_field_labels(widget)) == {"field 1", "field 2"}


# ---------------------------------------------------------------------------
# JSON export (#64)
# ---------------------------------------------------------------------------

def test_entry_to_jsonable_scalar() -> None:
    raw = b"\x08\x2a"  # field 1, varint 42
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    out = _entry_to_jsonable(decoded["entries"][0])
    assert out["field"] == 1
    assert out["type"] == "scalar"
    assert out["value"] == 42


def test_entry_to_jsonable_string() -> None:
    raw = b"\x0a" + _varint(5) + b"hello"
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    out = _entry_to_jsonable(decoded["entries"][0])
    assert out["type"] == "string"
    assert out["value"] == "hello"


def test_entry_to_jsonable_bytes_uses_full_raw_hex_not_capped_preview() -> None:
    """Regression companion for #60: the JSON export must contain the complete
    payload, not the parser's 64-byte-capped hex_preview used for tree display."""
    payload = bytes(range(256)) * 2  # 512 bytes, non-utf8, past the 64-byte cap
    raw = b"\x0a" + _varint(len(payload)) + payload
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    out = _entry_to_jsonable(decoded["entries"][0])
    assert out["type"] == "bytes"
    assert out["value_hex"] == payload.hex()
    assert out["length"] == len(payload)


def test_entry_to_jsonable_message_recurses() -> None:
    inner = b"\x08\x01" + b"\x10\x02"  # field1 varint1, field2 varint2
    outer = b"\x12" + _varint(len(inner)) + inner  # field 2, message
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    out = _entry_to_jsonable(decoded["entries"][0])
    assert out["type"] == "message"
    assert [e["field"] for e in out["entries"]] == [1, 2]
    assert [e["value"] for e in out["entries"]] == [1, 2]


def test_entries_to_json_is_valid_and_roundtrips() -> None:
    raw = b"\x08\x2a" + b"\x12" + _varint(5) + b"hello"
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    text = _entries_to_json(decoded["entries"])
    parsed = json.loads(text)  # must not raise
    assert len(parsed) == 2
    assert parsed[0]["value"] == 42
    assert parsed[1]["value"] == "hello"


# ---------------------------------------------------------------------------
# Export UI wiring (#64)
# ---------------------------------------------------------------------------

def test_export_subtree_enabled_only_on_field_rows_not_interpretation_rows(qapp) -> None:
    # field 1: fixed64 whose bit pattern also plausibly reads as a Cocoa timestamp,
    # so it gets an "interpretations" child row without needing an ambiguous message.
    import struct
    raw = b"\x09" + struct.pack("<d", 800_000_000.0)  # field 1, fixed64 (double)
    decoded, warning, _ = _decode_message(raw)
    assert not warning

    widget = ProtobufTreeWidget(decoded)
    root = widget._model.invisibleRootItem()
    field_item = root.child(0, 0)
    assert field_item.data(_ENTRY_ROLE) is not None  # real field row -> exportable

    if field_item.rowCount():
        interp_key_item = field_item.child(0, 0)
        assert interp_key_item.data(_ENTRY_ROLE) is None  # hint row -> not exportable


def test_export_entries_writes_text_file(qapp, tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    raw = b"\x08\x2a"
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    widget = ProtobufTreeWidget(decoded)

    out_path = tmp_path / "out.txt"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out_path), ""))
    widget._export_entries(decoded["entries"], "text", "protobuf.txt")

    assert out_path.exists()
    assert "42" in out_path.read_text(encoding="utf-8")


def test_export_entries_writes_json_file(qapp, tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    raw = b"\x08\x2a"
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    widget = ProtobufTreeWidget(decoded)

    out_path = tmp_path / "out.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out_path), ""))
    widget._export_entries(decoded["entries"], "json", "protobuf.json")

    assert out_path.exists()
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed[0]["value"] == 42


def test_export_entries_no_file_written_when_dialog_cancelled(qapp, tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    raw = b"\x08\x2a"
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    widget = ProtobufTreeWidget(decoded)

    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: ("", ""))
    widget._export_entries(decoded["entries"], "text", "protobuf.txt")  # must not raise

    assert list(tmp_path.iterdir()) == []
