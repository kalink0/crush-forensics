# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers viewer: the Protobuf tree filled lazily with FlatBuffers rows,
each mapped to its exact bytes; schema load preselects the root type;
exports write the buffer once and complete values; the BLOB Inspector
offers the same readings."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from PySide6.QtCore import QModelIndex

from crush.parsers.flatbuffers_parser import decode_buffer
from crush.tests.conftest import FIXTURES_DIR
from crush.tests.test_flatbuffers_parser import deep_chain
from crush.viewers.blob_inspector import _FB_SCHEMA_PREFIX, _FLATBUFFERS, _BlobPanel
from crush.viewers.flatbuffers_viewer import (
    FlatBuffersTreeWidget,
    FlatBuffersViewer,
    full_value_text,
    nodes_to_json,
    nodes_to_text,
    pieces_contain,
    top_nodes,
)
from crush.viewers.protobuf_viewer import _ENTRY_ROLE, _byte_highlight_ranges_from_item
from crush.viewers.tree_viewer import _PENDING_ROLE

RECORD = (FIXTURES_DIR / "flatbuffers_record.bin").read_bytes()
BFBS = FIXTURES_DIR / "flatbuffers_record.bfbs"


def _find_row(widget: FlatBuffersTreeWidget, text: str, column: int = 0) -> QModelIndex:
    """First row whose *column* shows *text*, building rows on the way."""
    model = widget._model
    stack = [QModelIndex()]
    while stack:
        parent = stack.pop()
        if model.canFetchMore(parent):
            model.fetchMore(parent)
        for row in range(model.rowCount(parent)):
            index = model.index(row, 0, parent)
            if model.index(row, column, parent).data() == text:
                return index
            stack.append(index)
    raise AssertionError(f"no row {text!r}")


def test_schema_less_tree_builds_rows_lazily(qapp, widgets) -> None:
    widget = widgets(FlatBuffersTreeWidget(decode_buffer(RECORD), raw=RECORD))
    model = widget._model
    top = [model.index(r, 0).data() for r in range(model.rowCount())]
    assert top[0] == "buffer (plain)"
    assert "unreferenced bytes" in top
    # Rows below the first levels aren't built until needed.
    pending = 0
    stack = [model.invisibleRootItem()]
    while stack:
        item = stack.pop()
        for r in range(item.rowCount()):
            child = item.child(r, 0)
            pending += bool(child.data(_PENDING_ROLE))
            stack.append(child)
    assert pending > 0


def test_row_highlights_its_exact_bytes(qapp, widgets) -> None:
    widget = widgets(FlatBuffersTreeWidget(decode_buffer(RECORD), raw=RECORD))
    index = _find_row(widget, '"evidence"', column=1)
    item = widget._model.itemFromIndex(index)
    ranges = _byte_highlight_ranges_from_item(item)
    # The 4-byte offset in the table, then the string with its length and NUL.
    assert len(ranges) == 2
    start, end = ranges[1]
    assert RECORD[start + 4:end - 1] == b"evidence"


def test_filter_finds_rows_not_built_yet(qapp, widgets) -> None:
    widget = widgets(FlatBuffersTreeWidget(decode_buffer(RECORD), raw=RECORD))
    widget._search.setText("IMG_0001")
    widget._run_filter()
    index = _find_row(widget, '"IMG_0001.HEIC"', column=1)
    assert not widget._tree.isRowHidden(index.row(), index.parent())


def test_filter_matches_hex_of_a_vector_piece_by_piece() -> None:
    pieces = iter(["00 ff 10", " 80 7f"])
    assert pieces_contain(pieces, "10 80")
    assert not pieces_contain(iter(["00 ff"]), "ff 00")


def test_value_bar_holds_the_complete_bytes_of_a_vector_reading() -> None:
    decoded = decode_buffer(RECORD)
    stack = list(decoded["buffers"])
    elements = None
    while stack:
        node = stack.pop()
        if node.get("as") == "scalars" and node["width"] == 1:
            elements = node
            break
        stack.extend(node.get("children") or [])
    assert elements is not None
    s, e = elements["value_range"]
    assert full_value_text(elements, RECORD) == RECORD[s:e].hex(" ")


def test_exports_write_the_buffer_once_and_complete_values() -> None:
    nodes = top_nodes(decode_buffer(RECORD))
    text = nodes_to_text(nodes, RECORD)
    assert text.startswith(f"# buffer ({len(RECORD):,} B), hex:\n{RECORD.hex(' ')}\n")
    assert text.count(RECORD.hex(" ")) == 1
    assert 'candidate: offset → string: evidence' in text
    data = json.loads(nodes_to_json(nodes, RECORD))
    assert bytes.fromhex(data["buffer_hex"]) == RECORD
    assert data["nodes"][0]["node"] == "buffer"


def test_deep_structure_exports_without_recursion_limit() -> None:
    # The tree's rows are built one level per expand (no recursion); the
    # exports walk the whole structure. No widget here: Qt's teardown of an
    # item tree 1200 levels deep takes over 20 s at process exit.
    levels = 1200  # past Python's default recursion limit of 1000
    raw = deep_chain(levels)
    decoded = decode_buffer(raw)
    assert nodes_to_text(top_nodes(decoded), raw).count("\n") > levels
    text = nodes_to_json(top_nodes(decoded), raw)
    # Reading it back nests as deep as the structure: Python 3.11's json
    # decoder counts that against the recursion limit.
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 20 * levels))
    try:
        json.loads(text)
    finally:
        sys.setrecursionlimit(limit)


def test_schema_decode_states_its_root_layout_like_the_schema_less_one() -> None:
    from crush.core.issues import render_value
    from crush.parsers.flatbuffers_parser import root_metadata
    from crush.parsers.flatbuffers_schema import decode_with_schema, load_schema
    from crush.viewers.blob_inspector import _flatbuffers_schema_reading
    from crush.viewers.flatbuffers_viewer import decode_summary

    schema = load_schema(FIXTURES_DIR / "flatbuffers_record.bfbs")
    root = "crush.fixtures.Record"
    roots = root_metadata(decode_with_schema(schema, root, RECORD))
    assert roots["Root"].code == "flatbuffers.root_layout"
    meta = _flatbuffers_schema_reading(schema, root, RECORD).metadata
    assert meta["Root"] == roots["Root"]
    assert meta["Root layouts not valid"] == roots["Root layouts not valid"]
    summary = decode_summary(decode_with_schema(schema, root, RECORD))
    assert render_value(roots["Root"], localized=True) in summary
    assert render_value(roots["Root layouts not valid"], localized=True) in summary


def _shared_child() -> bytes:
    """A root table whose two offset fields point to the same child table
    (one vtable at 4: 8 B, tables of 12 B, slots at +4 and +8)."""
    import struct

    buf = struct.pack("<I", 12) + struct.pack("<HHHH", 8, 12, 4, 8)
    buf += struct.pack("<iII", 12 - 4, 8, 4)  # root at 12: fields at 16, 20 -> 24
    buf += struct.pack("<iII", 24 - 4, 0, 0)  # child at 24
    return buf


def test_double_click_on_a_reference_goes_to_the_decoded_table(qapp, widgets) -> None:
    raw = _shared_child()
    decoded = decode_buffer(raw)
    stack, ref = list(decoded["buffers"]), None
    while stack and ref is None:
        node = stack.pop()
        if node.get("node") == "ref":
            ref = node
        stack.extend(node.get("children") or [])
    assert ref is not None, "the shared child wasn't referenced"
    assert not ref.get("children")  # not shown twice
    widget = widgets(FlatBuffersTreeWidget(decoded, raw=raw))
    assert widget.go_to_node(ref["target_node"])
    current = widget._model.itemFromIndex(widget._tree.currentIndex().siblingAtColumn(0))
    assert current.data(_ENTRY_ROLE).entry is ref["target_node"]


def test_viewer_loads_schema_preselects_root_type_and_decodes(qapp, widgets) -> None:
    viewer = widgets(FlatBuffersViewer({"raw": RECORD, "decoded": decode_buffer(RECORD)}))
    assert viewer.load_schema(BFBS)
    assert viewer._root_combo.currentText() == "crush.fixtures.Record"
    assert "doesn't record the flatc version" in viewer._schema_label.toolTip()
    viewer._decode_with_schema()
    tree = viewer._content_layout.itemAt(0).widget()
    assert isinstance(tree, FlatBuffersTreeWidget)
    index = _find_row(tree, "title")
    assert tree._model.index(index.row(), 1, index.parent()).data() == '"evidence"'
    assert "Decoded as crush.fixtures.Record" in viewer._status.text()


def test_viewer_schema_load_error_is_shown(qapp, widgets, tmp_path: Path) -> None:
    viewer = widgets(FlatBuffersViewer({"raw": RECORD, "decoded": decode_buffer(RECORD)}))
    broken = tmp_path / "broken.bfbs"
    broken.write_bytes(b"\x08\x00\x00\x00BFBS" + b"\x00" * 4)
    assert not viewer.load_schema(broken)
    assert viewer._status.text()
    assert not viewer._decode_btn.isEnabled()


# -- BLOB Inspector -----------------------------------------------------------


def test_blob_inspector_offers_the_schema_less_reading(qapp, widgets) -> None:
    panel = widgets(_BlobPanel(RECORD))
    panel._select_format(_FLATBUFFERS)
    assert isinstance(panel._protobuf_view, FlatBuffersTreeWidget)
    assert not panel._fb_schema_toolbar.isHidden()
    assert panel._schema_toolbar.isHidden()
    summary = panel._protobuf_summary.text()
    assert "FlatBuffers (schema-less)" in summary
    assert "heuristic" in summary


def test_blob_inspector_states_why_bytes_are_not_a_flatbuffer(qapp, widgets) -> None:
    panel = widgets(_BlobPanel(b"\x01\x02\x03"))
    panel._select_format(_FLATBUFFERS)
    assert "no root layout validates" in panel._failed_reasons[_FLATBUFFERS]


def test_blob_inspector_schema_reading(qapp, widgets) -> None:
    panel = widgets(_BlobPanel(RECORD))
    assert panel.load_fb_schema(BFBS)
    label = f"{_FB_SCHEMA_PREFIX}crush.fixtures.Record)"
    assert label in panel._protobuf_readings
    current = panel._format_list.currentItem()
    assert current is not None and current.data(256) == label
    text = panel._protobuf_readings[label].text()
    assert "\n# Schema: flatbuffers_record.bfbs: binary schema" in "\n" + text
    assert "title: evidence" in text


def test_blob_inspector_open_in_tab_offers_flatbuffers(qapp, widgets) -> None:
    panel = widgets(_BlobPanel(RECORD))
    labels = [a.text() for a in panel._open_btn.menu().actions()]
    assert "FlatBuffers (schema-less)" in labels
