# SPDX-License-Identifier: Apache-2.0
"""The BLOB Inspector shows the whole blob: its hex view and its decoder
outputs used to be cut (200,000 bytes / 500,000 characters) without saying so."""
from __future__ import annotations

from PySide6.QtWidgets import QApplication

from crush.core.formatters import bytes_to_hexview
from crush.viewers.blob_inspector import _HEX_VIEW, _BlobPanel


def test_hex_view_holds_the_whole_blob(qapp) -> None:
    data = bytes(range(256)) * 1000 + b"TAIL"  # 256,004 B, past the old 200,000 cut
    panel = _BlobPanel(data)
    panel._select_format(_HEX_VIEW)
    assert panel._stack.currentWidget() is panel._hex_view
    assert panel._hex_view._data == data

    panel._copy_current()
    copied = QApplication.clipboard().text()
    assert copied == bytes_to_hexview(data)
    assert copied.rstrip().endswith("TAIL")


def test_decoder_output_is_not_cut(qapp) -> None:
    text = '{"k": "' + "x" * 600_000 + '"}'  # past the old 500,000-character cut
    panel = _BlobPanel(text.encode())
    panel._select_format("JSON")
    shown = panel._viewer.toPlainText()
    assert len(shown) > 600_000
    assert shown == panel._cached_results["JSON"]


def test_hexview_default_is_complete() -> None:
    data = b"\x00" * 300_000
    assert bytes_to_hexview(data).count("\n") + 1 == 300_000 // 16
