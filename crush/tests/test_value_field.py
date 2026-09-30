# SPDX-License-Identifier: Apache-2.0
"""The one-line "Value:" field always holds the whole value.

QLineEdit.setText() drops everything past maxLength() (32,767 by default)
without notice; a long string or a blob of more than ~10,900 bytes as hex
used to end early in the field looking complete."""
from __future__ import annotations

from PySide6.QtWidgets import QLineEdit

from crush.viewers.value_field import show_value, value_text

_PAST_QT_DEFAULT = 40_000  # characters, above QLineEdit's default 32,767


def test_long_text_and_blob_are_shown_whole(qapp) -> None:  # noqa: ARG001
    field = QLineEdit()
    show_value(field, "x" * _PAST_QT_DEFAULT)
    assert field.text() == "x" * _PAST_QT_DEFAULT

    blob = bytes(i % 256 for i in range(50_000))
    show_value(field, blob)
    assert field.text() == blob.hex(" ")
    assert field.cursorPosition() == 0


def test_value_text_is_hex_for_bytes_and_as_is_for_text() -> None:
    assert value_text(b"\xde\xad\xbe\xef") == "de ad be ef"
    assert value_text("hello") == "hello"


def test_tree_viewer_value_field_and_copy_take_a_blobs_bytes(qapp) -> None:  # noqa: ARG001
    from crush.viewers.tree_viewer import TreeViewer

    big = bytes(range(256)) * 80  # 20,480 B: 61,439 characters as hex
    viewer = TreeViewer({"blob": b"\x01\x02\xff", "big": big, "text": "hi", "long": "y" * _PAST_QT_DEFAULT})
    model = viewer._model

    def select(key: str) -> None:
        row = next(r for r in range(model.rowCount()) if model.index(r, 0).data() == key)
        viewer._tree.setCurrentIndex(model.index(row, 0))

    select("blob")
    assert viewer._value_field.text() == "01 02 ff"
    assert viewer._current_key_value(for_copy=True) == ("blob", "01 02 ff")
    assert model.index(0, 1).data() == "<BLOB 3 B>"  # the cell keeps the size

    select("big")
    assert viewer._value_field.text() == big.hex(" ")
    assert viewer._current_key_value(for_copy=True)[1] == big.hex(" ")

    select("long")
    assert viewer._value_field.text() == "y" * _PAST_QT_DEFAULT

    select("text")
    assert viewer._value_field.text() == "hi"
    assert viewer._current_key_value(for_copy=True) == ("text", "hi")


def test_protobuf_viewer_value_field_holds_a_long_payload(qapp) -> None:  # noqa: ARG001
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.protobuf_viewer import ProtobufTreeWidget

    # 20,480 B of 0xFF: no valid nested message, so a bytes field -- and
    # past QLineEdit's default length as hex.
    payload = b"\xff" * 20_480
    decoded, _warning, _ = _decode_message(b"\x0a" + _varint(len(payload)) + payload)
    widget = ProtobufTreeWidget(decoded)
    widget._tree.setCurrentIndex(widget._model.index(0, 0))
    assert widget._value_field.text() == payload.hex(" ")


def test_no_value_field_is_filled_past_show_value() -> None:
    """Every viewer's Value field goes through show_value, which lifts
    QLineEdit's length limit -- a plain setText() there cuts silently again."""
    from pathlib import Path

    import crush.viewers

    offenders = [
        f"{path.name}:{number}"
        for path in sorted(Path(crush.viewers.__file__).parent.glob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "_value_field.setText(" in line
    ]
    assert offenders == []


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)
