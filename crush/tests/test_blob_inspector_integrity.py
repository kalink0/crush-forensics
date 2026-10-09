# SPDX-License-Identifier: Apache-2.0
"""The BLOB Inspector says why a step or an interpretation doesn't apply,
reports bytes a step left undecoded, and marks the JSON reading that rests
on an assumption."""
from __future__ import annotations

import io
import json
import zlib

from crush.viewers.blob_inspector import _JSON_UNESCAPED, _BlobPanel


def _with_step(panel: _BlobPanel, step: str) -> None:
    panel._push_step()
    row = panel._steps[-1]
    for i in range(row._list.count()):
        item = row._list.item(i)
        if item.data(0x0100) == step:  # Qt.ItemDataRole.UserRole
            row._list.setCurrentItem(item)
            return
    raise AssertionError(step)


def test_failed_step_shows_the_reason(qapp) -> None:
    panel = _BlobPanel(b"aGVs!!!bG8=")
    _with_step(panel, "Base64 (decode)")
    assert "invalid character 0x21 ('!') at offset 4" in panel._steps[0]._hint.text()
    assert "failed: invalid character" in panel._viewer.toPlainText()


def test_step_hint_reports_bytes_after_the_stream(qapp) -> None:
    stream = zlib.compress(b'{"a": 1}')
    panel = _BlobPanel(stream + b"APPENDED")
    _with_step(panel, "zlib decompress")
    hint = panel._steps[0]._hint.text()
    assert "8 B after the end of the stream" in hint
    assert f"{len(stream):#x}" in hint
    assert panel._current_data == b'{"a": 1}'


def test_unrecognised_interpretation_shows_the_reason(qapp) -> None:
    panel = _BlobPanel(b"\xff\xfe not utf-8")
    panel._select_format("UTF-8 text")
    shown = panel._viewer.toPlainText()
    assert "not recognised" in shown and "invalid start byte" in shown


def test_broken_json_is_not_shown_as_json(qapp) -> None:
    panel = _BlobPanel(b'{"a": 1, "b": ')
    assert "JSON" not in panel._cached_results
    panel._select_format("JSON")
    assert "Expecting value" in panel._viewer.toPlainText()


def test_escaped_json_is_a_marked_separate_reading(qapp) -> None:
    inner = {"k": "v\nw", "n": 1}
    escaped = json.dumps(json.dumps(inner))[1:-1]  # string content, no outer quotes
    panel = _BlobPanel(escaped.encode())
    assert "JSON" not in panel._cached_results
    shown = panel._cached_results[_JSON_UNESCAPED]
    assert shown.startswith("# Assumption:")
    assert json.loads(shown.split("\n\n", 1)[1]) == inner

    # The same as a complete JSON string literal.
    quoted = _BlobPanel(json.dumps(json.dumps(inner)).encode())
    assert json.loads(quoted._cached_results[_JSON_UNESCAPED].split("\n\n", 1)[1]) == inner

    # A trailing line break (e.g. from the clipboard) is ignored, and said so.
    pasted = _BlobPanel((escaped + "\n").encode())
    shown = pasted._cached_results[_JSON_UNESCAPED]
    assert "1 whitespace character(s)" in shown
    assert json.loads(shown.split("\n\n", 1)[1]) == inner

    # Plain JSON isn't offered a second time as "unescaped".
    plain = _BlobPanel(json.dumps(inner).encode())
    assert "JSON" in plain._cached_results
    assert _JSON_UNESCAPED not in plain._cached_results


def test_image_page_uses_the_image_viewer_and_parser_metadata(qapp) -> None:
    from PIL import Image

    from crush.viewers.image_viewer import ImageViewer

    out = io.BytesIO()
    Image.new("RGB", (4, 4), "red").save(out, "WEBP")
    panel = _BlobPanel(out.getvalue())
    panel._select_format("Image")
    assert panel._stack.currentWidget() is panel._image_page
    assert isinstance(panel._image_view, ImageViewer)
    assert "WebP" in panel._image_summary.text()


def test_non_image_says_why(qapp) -> None:
    panel = _BlobPanel(b"plain text")
    panel._select_format("Image")
    assert "no image signature" in panel._viewer.toPlainText()


def test_every_step_entry_is_reachable(qapp) -> None:
    """A step's list shows at most _STEP_LIST_MAX_VISIBLE rows and scrolls
    to its last entry (no horizontal scroll bar covering it); many steps
    scroll in the column instead of being squeezed."""
    from PySide6.QtCore import QEventLoop, QTimer

    from crush.viewers.blob_inspector import BlobInspector

    dialog = BlobInspector(b"hello")
    dialog.show()
    panel = dialog.findChild(_BlobPanel)
    for _ in range(8):
        panel._push_step()
    loop = QEventLoop()
    QTimer.singleShot(30, loop.quit)
    loop.exec()

    from crush.viewers.blob_inspector import _STEP_LIST_MAX_VISIBLE

    step_list = panel._steps[0]._list
    assert not step_list.horizontalScrollBar().isVisible()
    row_h = step_list.sizeHintForRow(0)
    shown = min(step_list.count(), _STEP_LIST_MAX_VISIBLE)
    assert step_list.viewport().height() >= shown * row_h
    # Scrolled to the bottom, the last entry is fully in view.
    step_list.scrollToBottom()
    last = step_list.visualItemRect(step_list.item(step_list.count() - 1))
    assert last.bottom() < step_list.viewport().height()
    bar = panel._steps_scroll.verticalScrollBar()
    assert bar.maximum() > 0 and bar.value() == bar.maximum()  # the new step is in view
    dialog.close()


# ---------------------------------------------------------------------------
# Open in new tab, copy and export (bytes after the decode pipeline)
# ---------------------------------------------------------------------------

def _host_with_inspector(blob: bytes, **kwargs):
    """A viewer-like host with a connected open-bytes signal, and a BLOB
    Inspector opened from a widget nested inside it."""
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import QWidget

    from crush.viewers.blob_inspector import BlobInspector

    class Host(QWidget):
        open_bytes_with_format_requested = Signal(bytes, str, object, dict)

    host = Host()
    host.setProperty("crush_source_path", "/evidence/app.db")
    received: list[tuple] = []
    host.open_bytes_with_format_requested.connect(lambda *args: received.append(args))
    nested = QWidget(host)
    dialog = BlobInspector(blob, nested, **kwargs)
    return host, dialog, dialog.findChild(_BlobPanel), received


def test_open_in_tab_sends_pipeline_output_and_provenance(qapp) -> None:
    payload = b'{"a": 1}'
    host, dialog, panel, received = _host_with_inspector(
        zlib.compress(payload) + b"XY",
        artifact_path="/virtual/app.db/t/data/1",
        provenance={"Source table": "t", "Inspected bytes": "the cell's bytes"},
    )
    _with_step(panel, "zlib decompress")
    panel._open_in_tab(None)
    data, path, fmt, meta = received[-1]
    assert data == payload and fmt is None
    assert path == "/virtual/app.db/t/data/1/inspector/zlib-decompress"
    assert meta["Source table"] == "t"
    assert "zlib decompress" in meta["Decode pipeline"]
    assert "2 B after the end of the stream" in meta["Decode pipeline"]


def test_open_in_tab_disabled_without_a_connected_viewer(qapp) -> None:
    panel = _BlobPanel(b"data")
    panel._update_bytes_actions()
    assert not panel._open_btn.isEnabled()
    assert panel._open_btn.toolTip()


def test_nested_table_open_as_tab_reaches_the_connected_viewer(qapp) -> None:
    """A table inside another viewer (e.g. Realm's) used to emit into an
    unconnected signal: nothing opened."""
    from crush.viewers.open_bytes import request_open_bytes
    from crush.viewers.table_viewer import TableViewer

    host, dialog, _panel, received = _host_with_inspector(b"x")
    table = TableViewer({"t": {"columns": ["a"], "rows": [[1]]}}, host)
    assert request_open_bytes(table, b"cell", "/virtual/t", "__hex__", {})
    assert received[-1][:3] == (b"cell", "/virtual/t", "__hex__")


def test_copy_bytes_formats(qapp) -> None:
    from PySide6.QtWidgets import QApplication

    panel = _BlobPanel(b"\x00A\xff")
    for fmt, expected in (("hex", "0041ff"), ("base64", "AEH/"), ("python", "b'\\x00A\\xff'")):
        panel._copy_bytes(fmt)
        assert QApplication.clipboard().text() == expected


def test_export_writes_bytes_and_sidecar(qapp, tmp_path, monkeypatch) -> None:
    import hashlib

    from PySide6.QtWidgets import QFileDialog

    payload = b'{"a": 1}'
    inspected = zlib.compress(payload)
    host, dialog, panel, _ = _host_with_inspector(
        inspected, provenance={"Inspected bytes": "the cell's bytes"}
    )
    _with_step(panel, "zlib decompress")
    target = tmp_path / "out.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))
    panel._export_bytes()

    assert target.read_bytes() == payload
    sidecar = json.loads((tmp_path / "out.bin.crush.json").read_text(encoding="utf-8"))
    assert sidecar["schema_version"] == 1
    assert sidecar["source"]["Source file"] == "/evidence/app.db"
    assert sidecar["inspected"] == {
        "size": len(inspected), "sha256": hashlib.sha256(inspected).hexdigest()
    }
    assert [s["step"] for s in sidecar["pipeline"]] == ["zlib decompress"]
    assert sidecar["output"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert sidecar["output"]["file"] == "out.bin"
    assert sidecar["created_utc"].endswith("Z")


def test_export_rendered_image_is_labelled_png(qapp, tmp_path, monkeypatch) -> None:
    from PIL import Image
    from PySide6.QtWidgets import QFileDialog

    out = io.BytesIO()
    Image.new("RGB", (3, 2), "blue").save(out, "WEBP")
    host, dialog, panel, _ = _host_with_inspector(out.getvalue())
    panel._select_format("Image")
    target = tmp_path / "img.png"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))
    panel._export_rendered_image()

    png = target.read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert Image.open(io.BytesIO(png)).size == (3, 2)
    sidecar = json.loads((tmp_path / "img.png.crush.json").read_text(encoding="utf-8"))
    assert "rendered" in sidecar["output"]["content"]
    assert sidecar["rendering"]["frame"] == "first"
    assert sidecar["inspected"]["size"] == len(out.getvalue())


def test_failed_pipeline_disables_bytes_actions(qapp) -> None:
    panel = _BlobPanel(b"not zlib")
    _with_step(panel, "zlib decompress")
    assert panel._pipeline is None
    assert not any(a.isEnabled() for a in panel._bytes_actions)


def test_protobuf_depth_limit_is_stated(qapp) -> None:
    from crush.viewers.blob_inspector import _try_protobuf

    def varint(n: int) -> bytes:
        out = b""
        while True:
            b, n = n & 0x7F, n >> 7
            if not n:
                return out + bytes([b])
            out += bytes([b | 0x80])

    msg = b"\x08\x01"
    for _ in range(110):
        msg = b"\x0a" + varint(len(msg)) + msg
    assert "depth limit" in _try_protobuf(msg).split("\n", 1)[0]


def test_tree_inspect_says_when_bytes_are_crush_made() -> None:
    from crush.viewers.tree_viewer import TreeViewer

    assert "stored" in TreeViewer._blob_origin({"k": 1})
    assert TreeViewer._blob_origin(b"x") == "the value's bytes"


def test_sidecar_records_what_a_step_left_undecoded() -> None:
    from datetime import datetime, timezone

    from crush.core.blob_decode import decompress_lzfse
    from crush.core.blob_export import PipelineStep, build_sidecar

    import liblzfse

    stream = liblzfse.compress(b"hello world " * 20)
    step = PipelineStep("lzfse decompress", decompress_lzfse(stream + b"TAIL"))
    sidecar = build_sidecar(
        tool_version="0.0", source={}, inspected=stream + b"TAIL", steps=[step],
        output_file="x.bin", output_kind="bytes after the decode pipeline",
        output=step.result.data, created=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    assert sidecar["pipeline"][0]["not_decoded"] == {"offset": len(stream), "size": 4}
    assert sidecar["created_utc"] == "2026-01-02T03:04:05Z"


def test_unreadable_pasted_input_shows_the_reason(qapp) -> None:
    """Base64 text with Input encoding forced to Hex gives no bytes: the
    panel says why instead of showing an empty hex view."""
    from crush.ui.paste_decode_dialog import PasteDecodeDialog

    dialog = PasteDecodeDialog()
    index = dialog._encoding_combo.findData("hex")
    dialog._encoding_combo.setCurrentIndex(index)
    dialog._paste_area.setPlainText("UklGRjoAAABX")
    dialog._decode_and_update()
    panel = dialog._blob_panel
    assert panel._stack.currentWidget() is panel._viewer
    assert "[No bytes: Invalid hex input: invalid character 0x55 ('U') at offset 0]" in (
        panel._viewer.toPlainText()
    )
    assert "red" in dialog._status_label.styleSheet()
    assert not any(a.isEnabled() for a in panel._bytes_actions)

    dialog._paste_area.setPlainText("")
    dialog._decode_and_update()
    assert "gray" in dialog._status_label.styleSheet()
