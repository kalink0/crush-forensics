# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the Protobuf viewer's schema-less tree search/filter (#63)."""
from __future__ import annotations

from crush.parsers.protobuf_parser import _decode_message
from crush.viewers.protobuf_viewer import ProtobufTreeWidget


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
