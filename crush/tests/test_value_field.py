# SPDX-License-Identifier: Apache-2.0
"""The one-line "Value:" field shows a value complete or says it's cut.

QLineEdit.setText() drops everything past maxLength() (32,767 by default)
without notice; a long string or a blob of more than ~10,900 bytes as hex
used to end early in the field looking complete."""
from __future__ import annotations

import pytest

from crush.viewers.value_field import bytes_text, text_text

_LIMIT = 32_767


def test_short_values_are_shown_whole() -> None:
    assert bytes_text(b"\xde\xad\xbe\xef", _LIMIT) == "de ad be ef"
    assert text_text("hello", _LIMIT) == "hello"


@pytest.mark.parametrize("size", [10_922, 10_923, 50_000, 1_000_000])
def test_long_blob_is_cut_with_a_note_that_fits(size: int) -> None:
    data = bytes(i % 256 for i in range(size))
    text = bytes_text(data, _LIMIT)
    assert len(text) <= _LIMIT
    if len(data.hex(" ")) <= _LIMIT:
        assert text == data.hex(" ")
        return
    assert f"{size:,} B in total" in text
    shown = int(text.rsplit("the field shows the first ", 1)[1].rstrip(")").replace(",", ""))
    assert text.startswith(data[:shown].hex(" ") + " …")


def test_long_text_is_cut_with_a_note_that_fits() -> None:
    value = "x" * 40_000
    text = text_text(value, _LIMIT)
    assert len(text) <= _LIMIT
    assert "40,000 characters in total" in text
    assert text.startswith("x" * 1000)


def test_tree_viewer_shows_a_blobs_bytes_in_the_value_field(qapp) -> None:  # noqa: ARG001
    from crush.viewers.tree_viewer import TreeViewer

    viewer = TreeViewer({"blob": b"\x01\x02\xff", "big": b"\x00" * 20_000, "text": "hi"})
    model = viewer._model

    def value_for(key: str) -> str:
        row = next(r for r in range(model.rowCount()) if model.index(r, 0).data() == key)
        viewer._tree.setCurrentIndex(model.index(row, 0))
        return viewer._value_field.text()

    assert value_for("blob") == "01 02 ff"
    assert model.index(0, 1).data() == "<BLOB 3 B>"  # the cell keeps the size
    big = value_for("big")
    assert "20,000 B in total" in big
    assert len(big) <= viewer._value_field.maxLength()
    assert value_for("text") == "hi"


def test_protobuf_viewer_value_field_says_when_a_payload_is_cut(qapp) -> None:  # noqa: ARG001
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.protobuf_viewer import ProtobufTreeWidget

    # 20,480 B of 0xFF: no valid nested message, so a bytes field -- and
    # past what the field can hold as hex.
    payload = b"\xff" * 20_480
    decoded, _warning, _ = _decode_message(b"\x0a" + _varint(len(payload)) + payload)
    widget = ProtobufTreeWidget(decoded)
    widget._tree.setCurrentIndex(widget._model.index(0, 0))
    shown = widget._value_field.text()
    assert "20,480 B in total" in shown
    assert shown.startswith(payload[:64].hex(" "))
    assert len(shown) <= widget._value_field.maxLength()


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)
