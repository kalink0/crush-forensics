# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The BLOB Inspector shows Protobuf as the Protobuf viewer does: the same
tree for the same bytes, Copy / Export from the tree's export with complete
payloads, and Open in new tab working from the tree page."""
from __future__ import annotations

import json

from PySide6.QtGui import QStandardItemModel
from PySide6.QtWidgets import QApplication, QFileDialog

from crush.parsers.protobuf_parser import _decode_message
from crush.viewers.blob_inspector import _PROTOBUF, BlobInspector, _BlobPanel
from crush.viewers.protobuf_viewer import ProtobufTreeWidget, entries_to_json, entries_to_text

# field 1: "120533877" (text and a message), field 2: 100 non-text bytes
# (past the parser's 64-byte preview), field 3: varint 42.
_LONG = bytes(range(0x80, 0xE4))
_BLOB = b"\x0a\x09120533877" + b"\x12\x64" + _LONG + b"\x18\x2a"


def _texts(model: QStandardItemModel, parent=None) -> list:  # noqa: ANN001
    """Every row's three cell texts, nested, from *parent* down."""
    from PySide6.QtCore import QModelIndex

    parent = parent if parent is not None else QModelIndex()
    rows = []
    for row in range(model.rowCount(parent)):
        cells = tuple(model.index(row, col, parent).data() for col in range(3))
        rows.append((cells, _texts(model, model.index(row, 0, parent))))
    return rows


def _panel_on_protobuf(blob: bytes = _BLOB) -> _BlobPanel:
    panel = _BlobPanel(blob)
    panel._select_format(_PROTOBUF)
    return panel


def test_protobuf_page_is_the_protobuf_viewers_tree(qapp) -> None:
    panel = _panel_on_protobuf()
    assert panel._stack.currentWidget() is panel._protobuf_page
    view = panel._protobuf_view
    assert isinstance(view, ProtobufTreeWidget)
    # The parsed data is cached, not a text rendering of it.
    assert _PROTOBUF not in panel._cached_results
    assert panel._protobuf_readings[_PROTOBUF].decoded["entries"]

    decoded, _warning, _ = _decode_message(_BLOB)
    same = ProtobufTreeWidget(decoded, raw=_BLOB)
    assert _texts(view._model) == _texts(same._model)


def test_protobuf_page_summary_states_ambiguous_fields(qapp) -> None:
    panel = _panel_on_protobuf()
    summary = panel._protobuf_summary.text()
    assert "Protobuf (schema-less)" in summary
    assert "decode both as a nested message and as UTF-8 text" in summary


def test_protobuf_page_built_once_per_data(qapp) -> None:
    panel = _panel_on_protobuf()
    view = panel._protobuf_view
    panel._select_format("Hex view")
    panel._select_format(_PROTOBUF)
    assert panel._protobuf_view is view


def test_copy_shown_text_is_the_trees_text_export_with_full_payload(qapp) -> None:
    panel = _panel_on_protobuf()
    panel._copy_current()
    copied = QApplication.clipboard().text()
    entries = panel._protobuf_readings[_PROTOBUF].decoded["entries"]
    assert copied.endswith(entries_to_text(entries))
    assert copied.startswith("# Ambiguous fields:")
    assert _LONG.hex(" ") in copied
    assert "…" not in copied


def test_copy_json_is_the_trees_json_export_with_full_payload(qapp) -> None:
    panel = _panel_on_protobuf()
    assert panel._copy_json_action.isEnabled()
    panel._copy_protobuf_json()
    copied = QApplication.clipboard().text()
    entries = panel._protobuf_readings[_PROTOBUF].decoded["entries"]
    assert copied == entries_to_json(entries)
    assert json.loads(copied)[1]["value_hex"] == _LONG.hex()


def test_tree_actions_only_on_a_protobuf_page(qapp) -> None:
    panel = _panel_on_protobuf()
    actions = (panel._copy_json_action, panel._export_text_action, panel._export_json_action)
    assert all(a.isEnabled() for a in actions)
    panel._select_format("Hex view")
    assert not any(a.isEnabled() for a in actions)


def test_export_decoded_text_and_json_with_sidecar(qapp, tmp_path, monkeypatch) -> None:
    panel = _panel_on_protobuf()
    entries = panel._protobuf_readings[_PROTOBUF].decoded["entries"]
    for fmt, name in (("text", "out.txt"), ("json", "out.json")):
        target = tmp_path / name
        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, t=target, **k: (str(t), ""))
        panel._export_protobuf(fmt)
        content = target.read_text(encoding="utf-8")
        sidecar = json.loads((tmp_path / f"{name}.crush.json").read_text(encoding="utf-8"))
        assert sidecar["rendering"]["interpretation"] == _PROTOBUF
        assert "Ambiguous fields" in sidecar["rendering"]
        assert sidecar["inspected"]["size"] == len(_BLOB)
        if fmt == "json":
            assert content == entries_to_json(entries)
            assert sidecar["output"]["content"].startswith("JSON export")
        else:
            assert content.endswith(entries_to_text(entries))
            assert sidecar["output"]["content"].startswith("text export")
        assert _LONG.hex() in content.replace(" ", "")


def test_no_bytes_is_stated_for_protobuf(qapp) -> None:
    panel = _BlobPanel(b"")
    assert panel._protobuf_readings == {}
    assert not panel._copy_json_action.isEnabled()


def _host_with_inspector(blob: bytes):  # noqa: ANN202
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import QWidget

    class Host(QWidget):
        open_bytes_with_format_requested = Signal(bytes, str, object, dict)

    host = Host()
    received: list[tuple] = []
    host.open_bytes_with_format_requested.connect(lambda *args: received.append(args))
    dialog = BlobInspector(blob, QWidget(host), artifact_path="/virtual/blob")
    return host, dialog, dialog.findChild(_BlobPanel), received


def test_open_in_tab_from_the_protobuf_page(qapp) -> None:
    host, dialog, panel, received = _host_with_inspector(_BLOB)
    panel._select_format(_PROTOBUF)
    panel._update_bytes_actions()
    assert panel._open_btn.isEnabled()
    panel._open_in_tab("Protobuf (schema-less)")
    assert received[-1][0] == _BLOB
    assert received[-1][2] == "Protobuf (schema-less)"


def test_tree_inside_the_inspector_reaches_the_connected_viewer(qapp) -> None:
    """Inspect BLOB… / open as tab from the tree on the page goes up through
    the inspector window to the viewer that opened it."""
    from crush.viewers.open_bytes import can_open_bytes, request_open_bytes

    host, dialog, panel, received = _host_with_inspector(_BLOB)
    panel._select_format(_PROTOBUF)
    tree = panel._protobuf_view
    assert can_open_bytes(tree)
    assert request_open_bytes(tree, b"field", "/virtual/blob/field", None, {})
    assert received[-1][:2] == (b"field", "/virtual/blob/field")
    nested = BlobInspector(b"field", tree)
    assert can_open_bytes(nested.findChild(_BlobPanel))


def test_schema_decode_uses_the_protobuf_viewers_tree(qapp, monkeypatch) -> None:
    from crush.viewers.tree_viewer import TreeViewer

    calls: list[tuple] = []

    def fake_decode(pool, name, data):  # noqa: ANN001, ANN202
        calls.append((pool, name, data))
        return {"small_count": 42}, {("small_count",): {"byte_range": (0, 2)}}

    monkeypatch.setattr("crush.viewers.blob_inspector.decode_for_tree", fake_decode)
    panel = _BlobPanel(b"\x08\x2a")
    panel._schema_pool = object()
    panel._schema_message = "fixtures.Basic"
    panel._recompute()
    label = "Protobuf (schema: fixtures.Basic)"
    panel._select_format(label)

    assert calls and calls[-1][1:] == ("fixtures.Basic", b"\x08\x2a")
    assert panel._stack.currentWidget() is panel._protobuf_page
    assert isinstance(panel._protobuf_view, TreeViewer)
    assert not panel._protobuf_summary.isVisibleTo(panel)
    panel._copy_current()
    assert json.loads(QApplication.clipboard().text()) == {"small_count": 42}


def test_failed_schema_decode_says_why(qapp, monkeypatch) -> None:
    def fail(pool, name, data):  # noqa: ANN001, ANN202
        raise ValueError("Error parsing message")

    monkeypatch.setattr("crush.viewers.blob_inspector.decode_for_tree", fail)
    panel = _BlobPanel(b"\x08\x2a")
    panel._schema_pool = object()
    panel._schema_message = "fixtures.Basic"
    panel._recompute()
    panel._select_format("Protobuf (schema: fixtures.Basic)")
    shown = panel._viewer.toPlainText()
    assert "schema decode failed: Error parsing message" in shown
    assert panel._stack.currentWidget() is panel._viewer
