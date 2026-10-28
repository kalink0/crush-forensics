# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers viewer -- schema-less structural decode, exact decode with a
loaded schema (.fbs or .bfbs).

The tree is the Protobuf viewer's (ProtobufTreeWidget: toolbar, search, hex
mapping, value bar, context menu), filled from the FlatBuffers node shape
(see crush/parsers/flatbuffers_parser.py). Every row maps to its exact bytes
in the hex view, including the vtable and the offset fields themselves.

Nodes hold byte ranges, not bytes: a row's bytes are taken from the
buffer when they are needed (value bar, Inspect BLOB, export), so a large
buffer isn't copied once per reading.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import IO, Any

from PySide6.QtCore import QT_TRANSLATE_NOOP, QModelIndex, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from crush.core.formatters import escape_control_chars
from crush.core.issues import ParseIssue, render_value
from crush.parsers.flatbuffers_parser import root_metadata
from crush.parsers.flatbuffers_schema import (
    Schema,
    SchemaLoadError,
    decode_with_schema,
    load_schema,
    typed_element_values,
)
from crush.ui.i18n import translate
from crush.viewers.generated_text import Gen, gen_item
from crush.viewers.protobuf_viewer import (
    _BYTE_RANGE_ROLE,
    _ENTRY_ROLE,
    _FULLTEXT_ROLE,
    _GRAY,
    _INTERP_FONT_SIZE_DELTA,
    ProtobufTreeWidget,
    _EntryRef,
)
from crush.viewers.tree_viewer import _PENDING_ROLE, _LazyTreeModel

Node = dict[str, Any]

_ISSUE_COLOR = QColor(200, 90, 40)

# Buffer size from which a decode or export runs behind the wait dialog: a
# decode takes up to ~0.6 s per MB (measured on TFLite models), so a larger
# buffer would freeze the window noticeably. Main window uses it for "Open as".
FLATBUFFERS_BUSY_BYTES = 1 << 20
# Bytes of a struct/slot shown in its cell; the value bar and exports hold
# all of them (the Protobuf tree's hex_preview does the same).
_CELL_PREVIEW_BYTES = 64

_LAYOUTS = {
    "plain": QT_TRANSLATE_NOOP("GeneratedView", "plain"),
    "size_prefixed": QT_TRANSLATE_NOOP("GeneratedView", "size-prefixed"),
}
_HEADERS = {
    "root_offset": QT_TRANSLATE_NOOP("GeneratedView", "root offset"),
    "size_prefix": QT_TRANSLATE_NOOP("GeneratedView", "size prefix"),
}
_VTABLE_ENTRIES = {
    "vtable_size": QT_TRANSLATE_NOOP("GeneratedView", "vtable size"),
    "inline_size": QT_TRANSLATE_NOOP("GeneratedView", "table inline size"),
}
_CANDIDATES = {
    ("scalar", ""): QT_TRANSLATE_NOOP("GeneratedView", "candidate: {width}-byte scalar"),
    ("struct", ""): QT_TRANSLATE_NOOP("GeneratedView", "candidate: inline struct ({size} B)"),
    ("string", "offset32"): QT_TRANSLATE_NOOP("GeneratedView", "candidate: offset → string"),
    ("string", "offset64"): QT_TRANSLATE_NOOP("GeneratedView", "candidate: 64-bit offset → string"),
    ("vector", "offset32"): QT_TRANSLATE_NOOP("GeneratedView", "candidate: offset → vector"),
    ("vector", "offset64"): QT_TRANSLATE_NOOP("GeneratedView", "candidate: 64-bit offset → vector"),
    ("table", "offset32"): QT_TRANSLATE_NOOP("GeneratedView", "candidate: offset → table"),
    ("vector_ref", ""): QT_TRANSLATE_NOOP(
        "GeneratedView",
        "candidate: offset → vector at {offset}, decoded where first reached "
        "(double-click to go there)",
    ),
}
_ELEMENTS = {
    "scalars": QT_TRANSLATE_NOOP("GeneratedView", "elements as {width}-byte scalars"),
    "strings": QT_TRANSLATE_NOOP("GeneratedView", "elements as offsets to strings"),
    "tables": QT_TRANSLATE_NOOP("GeneratedView", "elements as offsets to tables"),
    "nested": QT_TRANSLATE_NOOP("GeneratedView", "bytes as a nested FlatBuffer"),
}


def _hex(offset: int) -> str:
    return f"{offset:#x}"


def node_bytes(node: Node, raw: bytes) -> bytes:
    """*node*'s own value bytes, taken from the buffer *raw*."""
    rng = node.get("value_range")
    if not rng:
        return b""
    return raw[rng[0]:rng[1]]


def _preview(data: bytes) -> str:
    shown = data[:_CELL_PREVIEW_BYTES].hex(" ")
    return f"<{shown}{' …' if len(data) > _CELL_PREVIEW_BYTES else ''}>"


def _ident_text(data: bytes) -> str:
    if data and all(0x20 <= b < 0x7F for b in data):
        return f'"{data.decode("ascii")}"'
    return data.hex(" ")


def _english(text: str | Gen) -> str:
    return text.pair()[0] if isinstance(text, Gen) else text


def _display(text: str | Gen) -> str:
    return text.pair()[1] if isinstance(text, Gen) else text


# ---------------------------------------------------------------------------
# Row texts (shared by the tree and the exports)
# ---------------------------------------------------------------------------


def node_key(node: Node) -> str | Gen:
    kind = node.get("node")
    if kind == "buffer":
        return Gen(
            QT_TRANSLATE_NOOP("GeneratedView", "buffer ({layout})"),
            layout=Gen(_LAYOUTS.get(node.get("layout", ""), node.get("layout", ""))),
        )
    if kind == "header":
        field = node.get("field", "")
        if field == "file_identifier":
            start, end = node["range"]
            return Gen(
                QT_TRANSLATE_NOOP(
                    "GeneratedView", "bytes {start}–{end}: file_identifier, if the buffer has one"
                ),
                start=_hex(start), end=_hex(end - 1),
            )
        return Gen(_HEADERS.get(field, field))
    if kind == "table":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "table"))
    if kind == "vtable":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "vtable"))
    if kind == "vtable_entry":
        if node.get("entry") == "slot":
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "slot {slot}"), slot=node.get("slot"))
        return Gen(_VTABLE_ENTRIES.get(node.get("entry", ""), node.get("entry", "")))
    if kind == "field":
        name = node.get("name")
        if name:
            return str(name)  # the schema's own name
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "field {number}"), number=node.get("id"))
    if kind == "candidate":
        kind_as = node.get("as", "")
        via = node.get("via", "") if kind_as in ("string", "vector", "table") else ""
        template = _CANDIDATES.get((kind_as, via), kind_as)
        return Gen(
            template, width=node.get("width"), size=node.get("size"),
            offset=_hex(node.get("target", 0)),
        )
    if kind == "elements":
        return Gen(_ELEMENTS.get(node.get("as", ""), node.get("as", "")), width=node.get("width"))
    if kind == "element":
        return f"[{node.get('index')}]"  # i18n: keep -- index
    if kind == "ref":
        return Gen(
            QT_TRANSLATE_NOOP(
                "GeneratedView",
                "table at {offset}, decoded where first reached (double-click to go there)",
            ),
            offset=_hex(node.get("target", 0)),
        )
    if kind == "cycle":
        return Gen(
            QT_TRANSLATE_NOOP("GeneratedView", "cycle: back to the table at {offset}, which contains it"),
            offset=_hex(node.get("target", 0)),
        )
    if kind == "unreferenced":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "unreferenced bytes"))
    if kind == "unreferenced_range":
        start, end = node["range"]
        return f"{start:#x}–{end - 1:#x}"  # i18n: keep -- offsets
    if kind == "trailing":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "bytes after the size prefix's end"))
    return str(kind)


def _scalar_text(node: Node) -> str | Gen:
    value = node.get("value")
    if isinstance(value, bool):
        return "true" if value else "false"
    if "bool_byte" in node:
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "true (stored byte {byte})"), byte=node["bool_byte"])
    if node.get("enum"):
        return f"{node['enum']} ({value})"
    if isinstance(value, float):
        return repr(value)
    return str(value)


def node_value(node: Node, raw: bytes) -> str | Gen:
    """The Value column of *node* (cell text; a long hex is previewed)."""
    kind = node.get("node")
    if kind == "buffer":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "root table at {offset}"), offset=_hex(node["root"]))
    if kind == "header":
        if node.get("field") == "file_identifier":
            return _ident_text(node_bytes(node, raw))
        return str(node.get("value"))
    if kind == "table":
        stored = sum(1 for c in node.get("children", []) if c.get("node") == "field" and c.get("stored"))
        return Gen(
            QT_TRANSLATE_NOOP("GeneratedView", "{{ {stored} of {count} slot(s) stored }}"),
            stored=stored, count=node.get("slot_count", 0),
        )
    if kind == "vtable":
        return Gen(
            QT_TRANSLATE_NOOP("GeneratedView", "at {offset} (soffset {soffset})"),
            offset=_hex(node["offset"]), soffset=node.get("soffset"),
        )
    if kind == "vtable_entry":
        if node.get("entry") == "slot":
            if not node.get("value"):
                return Gen(QT_TRANSLATE_NOOP("GeneratedView", "0 (not stored)"))
            return f"+{node['value']}"  # i18n: keep -- offset
        return str(node.get("value"))
    if kind in ("field", "element"):
        return _field_value(node, raw)
    if kind == "candidate":
        return _candidate_value(node, raw)
    if kind == "elements":
        if node.get("as") == "scalars":
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{count} × {width} B"),
                       count=node.get("count"), width=node.get("width"))
        if node.get("as") == "nested":
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{count} B"), count=node.get("count"))
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{count} element(s)"), count=node.get("count"))
    if kind == "unreferenced":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{bytes:,} B in {count} range(s)"),
                   bytes=node.get("bytes", 0), count=len(node.get("children", [])))
    if kind in ("unreferenced_range", "trailing"):
        return _preview(node_bytes(node, raw))
    return ""


def _candidate_value(node: Node, raw: bytes) -> str | Gen:
    kind_as = node.get("as")
    if kind_as == "scalar":
        return str(node.get("value"))
    if kind_as == "struct":
        return _preview(node_bytes(node, raw))
    if kind_as == "string":
        text = node.get("text")
        if text is None:
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "not valid UTF-8 ({length} B)"),
                       length=node.get("length"))
        return f'"{escape_control_chars(text)}"'
    if kind_as in ("vector", "vector_ref"):
        if not node.get("count"):
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "empty vector"))
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{count} element(s)"), count=node.get("count"))
    if kind_as == "table":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "table at {offset}"), offset=_hex(node["target"]))
    return ""


def _schema_less_field(node: Node) -> bool:
    return node.get("node") == "field" and "name" not in node


def _field_value(node: Node, raw: bytes) -> str | Gen:
    """A field's (or element's) value column: schema-less -- its single
    reading or how many candidates; schema decode -- the decoded value."""
    if _schema_less_field(node):
        if not node.get("stored"):
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "not stored (absent, or equal to its default)"))
        candidates = node.get("children", [])
        if len(candidates) == 1:
            return _candidate_value(candidates[0], raw)
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{count} candidates (heuristic)"), count=len(candidates))
    if not node.get("stored", True):
        if node.get("default"):
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{value} (default — not stored)"),
                       value=_scalar_text(node))
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "not stored"))
    children = node.get("children") or []
    if "elements" in node:
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "[{count} × {type}]"),
                   count=node.get("count", 0), type=node["elements"].lower())
    if "struct" in node:
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "struct {name}"), name=node["struct"])
    if "count" in node:
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "[{count} element(s)]"), count=node["count"])
    if "value" in node:
        value = node["value"]
        if value is None:
            rng = node.get("value_range") or (0, 0)
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "not valid UTF-8 ({length} B)"),
                       length=rng[1] - rng[0])
        if isinstance(value, str):
            text: str | Gen = f'"{escape_control_chars(value)}"'
        else:
            text = _scalar_text(node)
        if node.get("union_member"):
            return Gen("{member}: {value}", member=node["union_member"], value=text)  # i18n: keep -- layout
        return text
    if children and children[0].get("node") in ("table", "ref", "cycle"):
        first = children[0]
        target: str | Gen = (
            Gen(QT_TRANSLATE_NOOP("GeneratedView", "table at {offset}"), offset=_hex(first["offset"]))
            if first.get("node") == "table" else node_key(first)
        )
        if node.get("union_member"):
            return Gen("{member}: {target}", member=node["union_member"], target=target)  # i18n: keep -- layout
        return target
    if children and children[0].get("node") == "buffer":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "nested FlatBuffer"))
    if node.get("union_member") is not None:
        return str(node["union_member"])
    if node.get("value_range"):
        # A slot the schema doesn't know: its bytes up to the next slot.
        return _preview(node_bytes(node, raw))
    return ""


def node_type(node: Node) -> str | Gen:
    kind = node.get("node")
    if kind == "field":
        if node.get("type_text"):
            text = node["type_text"]
            if node.get("deprecated"):
                return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{type} (deprecated)"), type=text)
            return str(text)
        if node.get("stored") and "gap" in node:
            return Gen(QT_TRANSLATE_NOOP("GeneratedView", "slot +{offset}, {gap} B to the next"),
                       offset=node["slot_offset"], gap=node["gap"])
        return ""
    if kind == "table" and node.get("type"):
        return str(node["type"])
    if kind == "candidate" and node.get("as") == "scalar":
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "{width} B"), width=node.get("width"))
    if kind == "candidate" and node.get("as") == "vector" and node.get("length_size") == 8:
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "64-bit length"))
    if kind == "buffer" and node.get("root_type"):
        return str(node["root_type"])
    return ""


def row_children(node: Node) -> list[Node]:
    """The rows below *node* in the tree. A table or vector decoded at
    another place first ("ref") has none: showing the shared structure again
    at every place it's reached from multiplies the tree (Expand All on a
    deep buffer runs out of memory); a double-click goes to where it is."""
    return node.get("children") or []


def _typed_scalars(node: Node) -> bool:
    return node.get("node") in ("field", "element") and "elements" in node


# Bytes per piece when a long value is produced piece by piece (search, export).
_PIECE_BYTES = 1 << 20


def _hex_pieces(data: bytes) -> Any:
    for start in range(0, len(data), _PIECE_BYTES):
        yield (" " if start else "") + data[start:start + _PIECE_BYTES].hex(" ")


def _typed_pieces(data: bytes, base_type: str, size: int) -> Any:
    step = _PIECE_BYTES - _PIECE_BYTES % size
    for start in range(0, len(data), step):
        values = typed_element_values(data[start:start + step], base_type)
        yield (", " if start else "") + ", ".join(values)


def full_value_pieces(node: Node, raw: bytes) -> Any:
    """The complete value of *node* (see full_value_text), produced piece by
    piece so a large vector is never one string in memory."""
    kind = node.get("node")
    if kind == "elements" and node.get("as") == "scalars" or (
        kind == "candidate" and node.get("as") == "struct"
    ) or kind in ("unreferenced_range", "trailing"):
        yield from _hex_pieces(node_bytes(node, raw))
        return
    if _typed_scalars(node):
        data = node_bytes(node, raw)
        if node["elements"] in ("UByte", "Byte"):
            yield from _hex_pieces(data)
        else:
            yield from _typed_pieces(data, node["elements"], node["element_size"])
        return
    if kind == "candidate" and node.get("as") == "string" and node.get("text") is not None:
        yield str(node["text"])
        return
    if kind in ("field", "element"):
        if isinstance(node.get("value"), str):
            yield str(node["value"])
            return
        if "value" not in node and "struct" not in node and not node.get("children"):
            data = node_bytes(node, raw)
            if data:
                yield from _hex_pieces(data)
                return
    yield _display(node_value(node, raw))


def full_value_text(node: Node, raw: bytes) -> str:
    """The complete value of *node* for the value bar and Copy value: every
    byte (as hex) of a scalar vector, a struct, an unknown slot or an
    unreferenced range; every element of a typed vector; the original
    (unescaped) text of a string."""
    return "".join(full_value_pieces(node, raw))


def pieces_contain(pieces: Any, needle: str) -> bool:
    """Whether the text made of *pieces* contains *needle* (lowercase),
    without joining the pieces: each piece is searched together with the
    end of the one before, so a match across two pieces is found too."""
    if not needle:
        return True
    tail = ""
    keep = len(needle) - 1
    for piece in pieces:
        window = tail + piece.lower()
        if needle in window:
            return True
        tail = window[-keep:] if keep else ""
    return False


def _bytes_row(node: Node) -> bool:
    """Whether *node*'s value is bytes (a vector, a reading of one, a struct,
    a slot the schema doesn't know, an unreferenced range): an export names
    their range; the bytes themselves are in the buffer it starts with."""
    kind = node.get("node")
    if not node.get("value_range"):
        return False
    return (
        kind in ("elements", "unreferenced_range", "trailing")
        or (kind == "candidate" and node.get("as") in ("vector", "struct"))
        or _typed_scalars(node)
        or "struct" in node
        or (kind in ("field", "element") and "value" not in node and not node.get("children"))
    )


def _export_pieces(node: Node, raw: bytes) -> Any:
    """A row's value in an export (English, complete), piece by piece.

    An export starts with the buffer's bytes once, as hex. A row whose value
    is bytes (a vector or one of its readings, a struct, an unknown slot, an
    unreferenced range) names their range in that buffer -- not the bytes
    again: overlapping readings (a vector candidate can span almost the
    whole buffer) would repeat the buffer many times. Scalars, strings,
    headers and vtable entries are written as values."""
    if _bytes_row(node):
        start, end = node["value_range"]
        shown = _english(node_value(node, raw))
        prefix = f"{shown}; " if shown and not shown.startswith("<") else ""
        yield f"{prefix}bytes {start:#x}–{end:#x} ({end - start:,} B)"  # i18n: keep -- export
        return
    kind = node.get("node")
    if kind == "candidate" and node.get("as") == "string" and node.get("text") is not None:
        yield str(node["text"])
        return
    if kind in ("field", "element") and isinstance(node.get("value"), str):
        yield str(node["value"])
        return
    yield _english(node_value(node, raw))


def _write_buffer_hex(raw: bytes, out: IO[str]) -> None:
    for piece in _hex_pieces(raw):
        out.write(piece)


# ---------------------------------------------------------------------------
# Top-level nodes, exports
# ---------------------------------------------------------------------------


def top_nodes(decoded: dict[str, Any]) -> list[Node]:
    """The tree's top-level rows: each root layout's buffer, the bytes after
    a size prefix's end, and the unreferenced ranges."""
    nodes: list[Node] = list(decoded.get("buffers", []))
    for buf in decoded.get("buffers", []):
        if buf.get("trailing"):
            s, e = buf["trailing"]
            nodes.append({"node": "trailing", "range": (s, e), "highlight": [(s, e)],
                          "value_range": (s, e)})
    unref = decoded.get("unreferenced", [])
    if unref:
        children = [{"node": "unreferenced_range", "range": (s, e), "highlight": [(s, e)],
                     "value_range": (s, e)} for s, e in unref]
        nodes.append({
            "node": "unreferenced", "range": (unref[0][0], unref[-1][1]),
            "highlight": [(s, e) for s, e in unref], "bytes": sum(e - s for s, e in unref),
            "children": children,
        })
    return nodes


def _walk(nodes: list[Node]) -> Any:
    """(depth, node) for every node, depth-first, iteratively (no recursion
    limit on deep structures)."""
    stack = [(0, n) for n in reversed(nodes)]
    while stack:
        depth, node = stack.pop()
        yield depth, node
        for child in reversed(node.get("children") or []):
            stack.append((depth + 1, child))


def write_text(nodes: list[Node], raw: bytes, out: IO[str]) -> None:
    """The tree's text export, written piece by piece: the buffer's bytes
    once as hex, then one line per row (key: value [type] @offset),
    interpretations and issues as ``#`` lines, complete values, control
    characters escaped so each row stays one line."""
    out.write(f"# buffer ({len(raw):,} B), hex:\n")  # i18n: keep -- export
    _write_buffer_hex(raw, out)
    out.write("\n")
    for depth, node in _walk(nodes):
        pad = "  " * depth
        out.write(f"\n{pad}{_english(node_key(node))}")
        lead = ": "
        for piece in _export_pieces(node, raw):
            if piece:
                # Hex and most text need no escaping (checked in C, fast).
                out.write(lead + (piece if piece.isprintable() else escape_control_chars(piece)))
                lead = ""
        typ = _english(node_type(node))
        if typ:
            out.write(f"  [{typ}]")
        if node.get("range"):
            out.write(f"  @{node['range'][0]:#x}")
        for interp in node.get("interpretations", []):
            out.write(f"\n{pad}    # {interp.label}: {interp.value}")
        if node.get("issue") is not None:
            out.write(f"\n{pad}    # issue: {render_value(node['issue'])}")  # i18n: keep -- export


def _jsonable(node: Node, raw: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"node": node.get("node")}
    for key in ("layout", "field", "entry", "slot", "id", "name", "type", "type_text", "as", "via",
                "width", "size", "length", "length_size", "count", "index", "stored", "default",
                "deprecated", "enum", "union_member", "elements", "element_size", "struct",
                "slot_offset", "gap", "kind", "root", "offset", "vtable", "target", "soffset",
                "inline_size", "slot_count"):
        if node.get(key) is not None:
            out[key] = node[key]
    if node.get("range"):
        out["range"] = list(node["range"])
    value = node.get("value")
    if isinstance(value, (bytes, bytearray)):
        out["value_hex"] = bytes(value).hex()
    elif value is not None:
        out["value"] = value
    if node.get("node") == "candidate" and node.get("as") == "string":
        out["text"] = node.get("text")
    if node.get("value_range"):
        out["value_range"] = list(node["value_range"])
        if not _bytes_row(node):
            # Scalars, strings, headers, vtable entries: their bytes too.
            out["value_hex"] = node_bytes(node, raw).hex()
    if node.get("interpretations"):
        out["interpretations"] = {i.label: i.value for i in node["interpretations"]}
    if node.get("issue") is not None:
        out["issue"] = render_value(node["issue"])
    return out


def write_json(nodes: list[Node], raw: bytes, out: IO[str]) -> None:
    """The tree's JSON export, written node by node: the buffer's bytes once
    ("buffer_hex"), then every node with its facts, children nested under
    "children" ("value_range" points into the buffer)."""
    out.write(f'{{"buffer_size": {len(raw)}, "buffer_hex": "')
    for piece in _hex_pieces(raw):
        out.write(piece.replace(" ", ""))
    out.write('", "nodes": [')
    # (children iterator, written any yet, closing text)
    stack: list[tuple[Any, list[bool], str]] = [(iter(nodes), [False], "\n]}")]
    while stack:
        it, written, closing = stack[-1]
        node = next(it, None)
        if node is None:
            out.write(closing)
            stack.pop()
            continue
        indent = "  " * len(stack)
        text = json.dumps(_jsonable(node, raw), ensure_ascii=False)
        out.write(("," if written[0] else "") + "\n" + indent)
        written[0] = True
        children = node.get("children") or []
        if children:
            out.write(text[:-1] + ', "children": [')
            stack.append((iter(children), [False], "\n" + indent + "]}"))
        else:
            out.write(text)


def nodes_to_text(nodes: list[Node], raw: bytes) -> str:
    buf = io.StringIO()
    write_text(nodes, raw, buf)
    return buf.getvalue()


def nodes_to_json(nodes: list[Node], raw: bytes) -> str:
    buf = io.StringIO()
    write_json(nodes, raw, buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tree widget
# ---------------------------------------------------------------------------


class FlatBuffersTreeWidget(ProtobufTreeWidget):
    """The Protobuf tree, filled with FlatBuffers nodes: Field / Value /
    Type / Offset columns, interpretations as dimmed child rows, a field's
    issue (schema decode) as a row of its own."""

    _EXPORT_STEM = "flatbuffers"
    _VIRTUAL_PREFIX = "/virtual/flatbuffers/"

    def __init__(
        self,
        decoded: dict[str, Any],
        raw: bytes | None = None,
        hex_visible: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        self._nodes = top_nodes(decoded)
        super().__init__(decoded, raw=raw, hex_visible=hex_visible, parent=parent)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(self._run_filter)
        self._tree.doubleClicked.connect(self._on_double_click)

    # -- references: go to where a shared table / vector is decoded -----------

    def _on_double_click(self, index: QModelIndex) -> None:
        item = self._model.itemFromIndex(index.siblingAtColumn(0))
        ref = item.data(_ENTRY_ROLE) if item is not None else None
        target = ref.entry.get("target_node") if isinstance(ref, _EntryRef) else None
        if target is not None:
            self.go_to_node(target)

    def _path_to(self, target: Node) -> list[Node] | None:
        """The nodes from a top-level row down to *target* (iterative)."""
        stack: list[tuple[Node, list[Node]]] = [(n, [n]) for n in self._nodes]
        seen: set[int] = set()
        while stack:
            node, path = stack.pop()
            if node is target:
                return path
            if id(node) in seen:
                continue
            seen.add(id(node))
            for child in row_children(node):
                stack.append((child, [*path, child]))
        return None

    def go_to_node(self, target: Node) -> bool:
        """Select the row of *target*, building and expanding only the rows
        on the way to it. False when it isn't in this tree."""
        path = self._path_to(target)
        if path is None:
            return False
        parent = QModelIndex()
        index = QModelIndex()
        for node in path:
            if self._model.canFetchMore(parent):
                self._model.fetchMore(parent)
            for row in range(self._model.rowCount(parent)):
                candidate = self._model.index(row, 0, parent)
                ref = self._model.itemFromIndex(candidate).data(_ENTRY_ROLE)
                if isinstance(ref, _EntryRef) and ref.entry is node:
                    index = candidate
                    break
            else:
                return False
            self._tree.setRowHidden(index.row(), parent, False)
            if parent.isValid():
                self._tree.expand(parent)
            parent = index
        self._tree.setCurrentIndex(index)
        self._tree.scrollTo(index)
        return True

    def _column_labels(self) -> list[str]:
        return [
            translate("FlatBuffersTreeWidget", "Field"),
            translate("FlatBuffersTreeWidget", "Value"),
            translate("FlatBuffersTreeWidget", "Type"),
            translate("FlatBuffersTreeWidget", "Offset"),
        ]

    def _export_title(self) -> str:
        return translate("FlatBuffersTreeWidget", "Export FlatBuffers")

    def _top_entries(self) -> list[dict[str, Any]]:
        return self._nodes

    def _export_content(self, entries: list[dict[str, Any]], fmt: str) -> str:
        if fmt == "json":
            return nodes_to_json(entries, self._raw)
        return nodes_to_text(entries, self._raw)

    def _write_export(self, path: str, entries: list[dict[str, Any]], fmt: str) -> None:
        from crush.ui.busy_dialog import busy_call

        def work() -> None:
            # Plain data and a file: safe off the UI thread.
            with open(path, "w", encoding="utf-8") as f:
                if fmt == "json":
                    write_json(entries, self._raw, f)
                else:
                    write_text(entries, self._raw, f)

        if len(self._raw) > FLATBUFFERS_BUSY_BYTES:
            busy_call(self, translate("FlatBuffersTreeWidget", "Exporting…"), work)
        else:
            work()

    def _node_of(self, val_item: QStandardItem) -> Node | None:
        ref = val_item.data(_ENTRY_ROLE)
        return ref.entry if isinstance(ref, _EntryRef) else None

    def _item_full_text(self, val_item: QStandardItem) -> str:
        node = self._node_of(val_item)
        if node is not None:
            return full_value_text(node, self._raw)
        return super()._item_full_text(val_item)

    def _item_raw(self, val_item: QStandardItem) -> bytes | None:
        node = self._node_of(val_item)
        if node is not None:
            return node_bytes(node, self._raw) or None
        return super()._item_raw(val_item)

    # -- rows, built when needed (expanding, the filter, a hex click) --------

    def _make_model(self) -> QStandardItemModel:
        # Child rows are built the first time they're needed, like the plist /
        # XML tree (TreeViewer): a large buffer is tens of thousands of rows.
        # Nothing is left out -- every row is built once its parent is opened.
        self._filter_text = ""
        self._hits: set[int] | None = None
        self._search_cache: dict[int, str] = {}
        self._interp_font = None
        return _LazyTreeModel(self._populate_children)

    def _populate_root(self) -> None:
        self._tree.setColumnWidth(3, 90)
        root = self._model.invisibleRootItem()
        for node in self._nodes:
            self._append_node_row(root, node)

    def _append_node_row(self, parent: QStandardItem, node: Node) -> None:
        key_item = self._text_item(node_key(node))
        val_item = self._text_item(node_value(node, self._raw))
        type_item = self._text_item(node_type(node))
        off_item = QStandardItem(_hex(node["range"][0]) if node.get("range") else "")
        ref = _EntryRef(node)
        key_item.setData(ref, _ENTRY_ROLE)
        key_item.setData(ref, _BYTE_RANGE_ROLE)
        val_item.setData(ref, _ENTRY_ROLE)
        for item in (key_item, val_item, type_item, off_item):
            item.setEditable(False)
        if node.get("issue") is not None:
            val_item.setForeground(_ISSUE_COLOR)
        if row_children(node) or node.get("interpretations") or node.get("issue") is not None:
            key_item.setData(True, _PENDING_ROLE)
        parent.appendRow([key_item, val_item, type_item, off_item])

    def _populate_children(self, item: QStandardItem, *, apply_filter: bool = True) -> None:
        """Build the child rows of *item* (its issue, interpretations and
        sub-nodes) if not built yet; filtered when a filter is active."""
        if not item.data(_PENDING_ROLE):
            return
        item.setData(None, _PENDING_ROLE)
        ref = item.data(_ENTRY_ROLE)
        if not isinstance(ref, _EntryRef):
            return
        node = ref.entry
        if node.get("issue") is not None:
            issue_text = render_value(node["issue"], localized=True)
            issue_key = gen_item(Gen("  {label}", label=Gen(  # i18n: keep -- layout
                QT_TRANSLATE_NOOP("GeneratedView", "issue"))))
            issue_val = QStandardItem(issue_text)
            issue_val.setData(issue_text, _FULLTEXT_ROLE)
            for cell in (issue_key, issue_val):
                cell.setForeground(_ISSUE_COLOR)
                cell.setEditable(False)
            issue_key.setData(ref, _BYTE_RANGE_ROLE)
            item.appendRow([issue_key, issue_val, QStandardItem(""), QStandardItem("")])
        for interp in node.get("interpretations") or []:
            if self._interp_font is None:
                font = item.font()
                font.setPointSize(max(7, font.pointSize() + _INTERP_FONT_SIZE_DELTA))
                self._interp_font = font
            lbl_item = gen_item(Gen("  {label}", label=Gen(interp.label)))  # i18n: keep -- layout
            v_item = QStandardItem(escape_control_chars(interp.value))
            v_item.setData(interp.value, _FULLTEXT_ROLE)
            for cell in (lbl_item, v_item):
                cell.setForeground(_GRAY)
                cell.setFont(self._interp_font)
                cell.setEditable(False)
            lbl_item.setData(ref, _BYTE_RANGE_ROLE)
            item.appendRow([lbl_item, v_item, QStandardItem(""), QStandardItem("")])
        for child in row_children(node):
            self._append_node_row(item, child)
        if apply_filter and self._filter_text:
            self._filter_items(item, self._filter_text)

    @staticmethod
    def _text_item(text: str | Gen) -> QStandardItem:
        return gen_item(text) if isinstance(text, Gen) else QStandardItem(text)

    # -- filter on the node data (rows not built yet included) ----------------

    def _node_label_texts(self, node: Node) -> str:
        """Lowercase key and cell texts of *node*, its issue and
        interpretation rows (short; cached)."""
        key = id(node)
        cached = self._search_cache.get(key)
        if cached is None:
            parts = [_display(node_key(node)), _display(node_value(node, self._raw))]
            if node.get("issue") is not None:
                parts.append(render_value(node["issue"], localized=True))
            for interp in node.get("interpretations") or []:
                parts.extend((_display(Gen(interp.label)), interp.value))
            cached = "\x00".join(parts).lower()
            self._search_cache[key] = cached
        return cached

    def _node_matches(self, node: Node, text: str) -> bool:
        """The filter's test for one node: its key/cell texts, or anywhere in
        its complete value (searched piece by piece, nothing cached)."""
        return text in self._node_label_texts(node) or pieces_contain(
            full_value_pieces(node, self._raw), text
        )

    def _compute_hits(self, text: str) -> set[int]:
        """ids of the nodes that match *text* or have a match below them --
        one iterative pass over every node."""
        hits: set[int] = set()
        stack: list[tuple[Node, bool]] = [(n, False) for n in self._nodes]
        done: set[int] = set()
        while stack:
            node, expanded = stack.pop()
            nid = id(node)
            if expanded:
                if any(id(c) in hits for c in row_children(node)) or self._node_matches(node, text):
                    hits.add(nid)
                done.add(nid)
                continue
            if nid in done:
                continue
            stack.append((node, True))
            for child in row_children(node):
                if id(child) not in done:
                    stack.append((child, False))
        return hits

    def _apply_filter(self, text: str) -> None:
        # As the plist / XML tree: filter once typing pauses, not per key.
        self._filter_timer.start()

    def _run_filter(self) -> None:
        """Filter the rows by the search text now. Builds the rows of every
        hit not built yet -- on the UI thread, so a short text on a large
        buffer takes a while: the wait cursor says so."""
        self._filter_timer.stop()
        self._filter_text = self._search.text().lower()
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._hits = self._compute_hits(self._filter_text) if self._filter_text else None
            self._filter_items(self._model.invisibleRootItem(), self._filter_text)
        finally:
            QApplication.restoreOverrideCursor()

    def _filter_items(self, parent: QStandardItem, text: str) -> bool:
        any_visible = False
        for row in range(parent.rowCount()):
            key_item = parent.child(row, 0)
            val_item = parent.child(row, 1)
            if key_item is None:
                continue
            ref = key_item.data(_ENTRY_ROLE)
            node = ref.entry if isinstance(ref, _EntryRef) else None
            if text and key_item.data(_PENDING_ROLE) and node is not None and self._hits is not None:
                # Rows not built yet: build them only where there's a hit.
                if id(node) in self._hits:
                    self._populate_children(key_item, apply_filter=False)
            child_visible = self._filter_items(key_item, text)
            if not text:
                visible = True
            elif node is not None and self._hits is not None:
                # The hit set covers the node and everything below it.
                visible = id(node) in self._hits
            else:
                own = (key_item.text() + "\x00" + (val_item.data(_FULLTEXT_ROLE) or val_item.text()
                                                   if val_item else "")).lower()
                visible = text in own or child_visible
            self._tree.setRowHidden(row, self._model.indexFromItem(parent), not visible)
            any_visible = any_visible or visible
        return any_visible


# ---------------------------------------------------------------------------
# Viewer
# ---------------------------------------------------------------------------


def schema_note(schema: Schema) -> str:
    """How the schema was obtained: the flatc version that compiled a .fbs,
    or that a .bfbs doesn't record it."""
    if schema.compiled_by:
        return translate("FlatBuffersViewer", "{name}: compiled by the bundled {compiler}").format(
            name=schema.source_name, compiler=schema.compiled_by
        )
    return translate(
        "FlatBuffersViewer",
        "{name}: binary schema (.bfbs); a .bfbs doesn't record the flatc version that wrote it",
    ).format(name=schema.source_name)


def decode_summary(decoded: dict[str, Any]) -> str:
    """One status line for a schema decode: layouts, mismatches, unreferenced bytes."""
    roots = root_metadata(decoded)
    if not decoded.get("buffers"):
        return render_value(roots["Parse warning"], localized=True)
    parts = [translate("FlatBuffersViewer", "Decoded as {name}").format(name=decoded.get("root_type", ""))]
    parts += [render_value(roots[key], localized=True)
              for key in ("Root", "Root layouts not valid") if key in roots]
    if decoded.get("issues"):
        parts.append(render_value(ParseIssue(
            "flatbuffers.schema.mismatches", {"count": decoded["issues"]}), localized=True))
    if decoded.get("unreferenced"):
        parts.append(render_value(ParseIssue("flatbuffers.unreferenced", {
            "bytes": sum(e - s for s, e in decoded["unreferenced"]),
            "ranges": len(decoded["unreferenced"]),
        }), localized=True))
    return " · ".join(parts)


class FlatBuffersViewer(QWidget):
    """Viewer for FlatBuffers data.

    data shape: {"raw": bytes, "decoded": <decode_buffer() result>}
    """

    open_bytes_with_format_requested = Signal(bytes, str, object, dict)

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw = data.get("raw", b"") if isinstance(data, dict) else b""
        self._decoded = data.get("decoded", {}) if isinstance(data, dict) else {}
        self._schema: Schema | None = None
        self._build_ui()
        self._show_schema_less()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QWidget()
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(8, 4, 8, 4)
        tb.setSpacing(8)
        tb.addWidget(QLabel(translate("FlatBuffersViewer", "Schema:")))
        self._schema_label = QLabel(translate("FlatBuffersViewer", "None"))
        self._schema_label.setStyleSheet("color: gray;")
        tb.addWidget(self._schema_label)
        self._load_btn = QPushButton(translate("FlatBuffersViewer", "Load .fbs / .bfbs…"))
        self._load_btn.clicked.connect(self._on_load_schema)
        tb.addWidget(self._load_btn)
        self._clear_btn = QPushButton(translate("FlatBuffersViewer", "Clear"))
        self._clear_btn.clicked.connect(self._clear_schema)
        self._clear_btn.setEnabled(False)
        tb.addWidget(self._clear_btn)
        tb.addSpacing(12)
        tb.addWidget(QLabel(translate("FlatBuffersViewer", "Root type:")))
        self._root_combo = QComboBox()
        self._root_combo.setEnabled(False)
        tb.addWidget(self._root_combo)
        self._decode_btn = QPushButton(translate("FlatBuffersViewer", "Decode"))
        self._decode_btn.clicked.connect(self._decode_with_schema)
        self._decode_btn.setEnabled(False)
        tb.addWidget(self._decode_btn)
        self._raw_btn = QPushButton(translate("FlatBuffersViewer", "Show Schema-less Decode"))
        self._raw_btn.clicked.connect(self._show_schema_less)
        tb.addWidget(self._raw_btn)
        self._status = QLabel("")
        self._status.setWordWrap(True)
        tb.addWidget(self._status, 1)
        layout.addWidget(toolbar, 0)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._content, 1)

    def _replace_view(self, widget: QWidget) -> None:
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._content_layout.addWidget(widget, 1)

    def _current_hex_visible(self) -> bool:
        if not self._content_layout.count():
            return False
        widget = self._content_layout.itemAt(0).widget()
        mapped_view = getattr(widget, "_mapped_view", None)
        return bool(mapped_view.is_hex_visible()) if mapped_view is not None else False

    def _show_schema_less(self) -> None:
        hex_visible = self._current_hex_visible()
        self._status.setText(translate("FlatBuffersViewer", "Schema-less decode"))
        self._replace_view(
            FlatBuffersTreeWidget(self._decoded, raw=self._raw, hex_visible=hex_visible, parent=self)
        )

    def _clear_schema(self) -> None:
        self._schema = None
        self._schema_label.setText(translate("FlatBuffersViewer", "None"))
        self._schema_label.setStyleSheet("color: gray;")
        self._schema_label.setToolTip("")
        self._root_combo.clear()
        self._root_combo.setEnabled(False)
        self._decode_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        self._status.setText(translate("FlatBuffersViewer", "Schema cleared"))

    def _on_load_schema(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            translate("FlatBuffersViewer", "Load FlatBuffers schema"),
            "",
            translate("FlatBuffersViewer", "FlatBuffers schema")
            + " (*.fbs *.bfbs);;"  # i18n: keep -- file filter pattern
            + translate("FlatBuffersViewer", "All files")
            + " (*)",  # i18n: keep -- file filter pattern
        )
        if path:
            self.load_schema(Path(path))

    def load_schema(self, path: Path) -> bool:
        """Load the schema at *path* and fill the root type list, the
        schema's declared root_type preselected. False (and the reason in
        the status line) when it can't be loaded."""
        from crush.ui.busy_dialog import busy_call

        def work() -> Schema | SchemaLoadError:
            # Returned, not raised: busy_call re-raises as a plain RuntimeError.
            try:
                return load_schema(path)
            except SchemaLoadError as exc:
                return exc

        # A .fbs runs the bundled flatc: off the UI thread.
        loaded = busy_call(self, translate("FlatBuffersViewer", "Loading schema…"), work)
        if isinstance(loaded, SchemaLoadError):
            self._status.setText(render_value(loaded.issue, localized=True))
            return False
        schema = loaded
        self._schema = schema
        names = schema.table_names()
        self._root_combo.clear()
        self._root_combo.addItems(names)
        if schema.root_table in names:
            self._root_combo.setCurrentText(schema.root_table)
        self._root_combo.setEnabled(True)
        self._decode_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._schema_label.setText(path.name)
        self._schema_label.setStyleSheet("color: palette(text);")
        note = schema_note(schema)
        if schema.compiler_messages:
            note += "\n" + schema.compiler_messages
        self._schema_label.setToolTip(note)
        self._status.setText(
            translate("FlatBuffersViewer", "Loaded {count} table type(s)").format(count=len(names))
            + " · " + schema_note(schema)
        )
        return True

    def _decode_with_schema(self) -> None:
        if self._schema is None:
            self._status.setText(translate("FlatBuffersViewer", "Load a schema first"))
            return
        name = self._root_combo.currentText().strip()
        if not name:
            self._status.setText(translate("FlatBuffersViewer", "Select a root type"))
            return
        from crush.ui.busy_dialog import busy_call

        schema = self._schema
        if len(self._raw) > FLATBUFFERS_BUSY_BYTES:
            decoded = busy_call(
                self, translate("FlatBuffersViewer", "Decoding as {name}…").format(name=name),
                lambda: decode_with_schema(schema, name, self._raw),
            )
        else:
            decoded = decode_with_schema(schema, name, self._raw)
        hex_visible = self._current_hex_visible()
        self._status.setText(decode_summary(decoded))
        self._replace_view(
            FlatBuffersTreeWidget(decoded, raw=self._raw, hex_visible=hex_visible, parent=self)
        )
