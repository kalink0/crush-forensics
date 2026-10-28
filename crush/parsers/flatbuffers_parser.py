# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers parser -- schema-less structural decode.

Explicit-only parser (FlatBuffers has no reliable magic; the 4-byte
file_identifier is optional). Use "Open as → FlatBuffers" or the BLOB
Inspector's FlatBuffers reading.

What is certain without a schema (FlatBuffers internals,
https://flatbuffers.dev/internals/): the root uoffset, each table's soffset
to its vtable, the vtable's size, the table's inline size and the field
slot offsets. Everything is validated against the buffer bounds and the
alignment the format requires (the checks of the FlatBuffers Verifier).

What is not recorded, and therefore heuristic: a field's width and type.
A slot's width can only be inferred from the gap to the next stored slot
(or the end of the table's inline data), and padding makes that ambiguous;
every width that fits and is aligned is offered. For each width every
structurally consistent reading is shown as a candidate: the scalar
readings (proto_interp's interpretations for 4 and 8 bytes), and for 4-byte
slots the uoffset targets that validate as a string, vector or table (8-byte
slots: 64-bit offsets to a string or vector). Vectors are read with element
widths of 1, 2, 4 and 8 bytes and as vectors of offsets to strings or
tables; byte vectors are also tried as a nested FlatBuffer.

Offset candidates are followed recursively as long as they validate -- no
depth or count limit. The decode is iterative (an explicit stack), so deep
chains don't hit Python's recursion limit. A table or vector reached a
second time is decoded once; the second place gets a "ref" node holding the
decoded one ("target_node"). uoffsets only point forward, so a table or
vector can't contain itself; the cycle guard below never fires on a buffer
that validates and is kept only as a guard.

Bytes that no structure and no candidate reading covers are listed as
unreferenced ranges (padding, or remnants of earlier data).

Node shape (``data["decoded"]["buffers"]``, plain dicts -- see
FlatBuffersViewer): every node has ``"node"`` (its kind), ``"range"``
(absolute half-open byte range), ``"highlight"`` (the exact ranges to
highlight), and kind-specific facts; ``"children"`` holds sub-nodes,
``"value_range"`` the absolute range of the node's own value bytes (taken
from ``data["raw"]`` where needed -- nodes hold no copies of the bytes).
"""
from __future__ import annotations

from collections.abc import Generator
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.flatbuffers_wire import (
    FILE_IDENTIFIER_LENGTH,
    TableError,
    VTable,
    fits,
    read_u32,
    read_u64,
    read_vtable,
    string_at,
    vector_at,
)
from crush.parsers.proto_interp import Interpretation, interpret_fixed32, interpret_fixed64

# Scalar widths a field slot or vector element can have (FlatBuffers scalars
# are 1, 2, 4 or 8 bytes; a struct can be any size, see "struct" candidates).
SCALAR_WIDTHS = (1, 2, 4, 8)

# Characters of decoded strings kept for the search index (like the
# Protobuf parser's text index; display and export are never limited).
_TEXT_INDEX_CHARS = 4000

Node = dict[str, Any]
_Task = Generator[Any, Any, Any]


def _drive(task: _Task) -> Any:
    """Run a generator-based recursive task without Python recursion: a
    sub-task is yielded, its result is sent back in -- or the exception it
    raised is thrown in, at the yield, like a raise out of a call."""
    stack: list[_Task] = [task]
    value: Any = None
    error: BaseException | None = None
    while stack:
        try:
            if error is not None:
                pending, error = error, None
                sub = stack[-1].throw(pending)
            else:
                sub = stack[-1].send(value)
        except StopIteration as stop:
            stack.pop()
            value = stop.value
            continue
        except Exception as exc:  # noqa: BLE001 -- re-raised in the caller's frame
            stack.pop()
            if not stack:
                raise
            error = exc
            continue
        stack.append(sub)
        value = None
    return value


class FlatBuffersParser(AbstractParser):
    """Schema-less FlatBuffers decoder."""

    DISPLAY_NAME = "FlatBuffers (schema-less)"
    SUPPORTED_EXTENSIONS: list[str] = []
    # Bytes in, plain dicts out.
    PARSE_OFF_UI_THREAD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False  # Explicit-only

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        decoded = decode_buffer(raw)
        meta = schema_less_metadata(decoded)
        meta["File size"] = f"{node.size:,} B"
        return ParseResult(
            viewer_type="flatbuffers",
            data={"raw": raw, "decoded": decoded},
            metadata=meta,
            text_index=decoded.get("text_index", ""),
        )


def schema_less_metadata(decoded: dict[str, Any]) -> dict[str, Any]:
    """The parser's notes on a schema-less decode -- for every place that
    shows one (the viewer tab's Properties, the BLOB Inspector's summary)."""
    meta: dict[str, Any] = {"Format": "FlatBuffers (schema-less)"}
    layouts = [b["layout"] for b in decoded.get("buffers", [])]
    if not layouts:
        meta["Parse warning"] = ParseIssue(
            "flatbuffers.no_root", {"reasons": decoded.get("root_failures", [])}
        )
    else:
        meta["Root"] = ParseIssue(
            "flatbuffers.root_both_layouts" if len(layouts) > 1 else "flatbuffers.root_layout",
            {"layout": ParseIssue(f"flatbuffers.layout_{layouts[0]}")},
        )
        if decoded.get("root_failures"):
            meta["Root layouts not valid"] = decoded["root_failures"]
    meta["Field widths"] = ParseIssue("flatbuffers.widths_heuristic")
    if decoded.get("ambiguous"):
        meta["Ambiguous fields"] = ambiguous_issue(decoded)
    if decoded.get("cycles"):
        meta["Cycles"] = ParseIssue("flatbuffers.cycles", {"count": decoded["cycles"]})
    unref = decoded.get("unreferenced", [])
    if unref:
        meta["Unreferenced bytes"] = ParseIssue(
            "flatbuffers.unreferenced",
            {"bytes": sum(e - s for s, e in unref), "ranges": len(unref)},
        )
    return meta


def ambiguous_issue(decoded: dict[str, Any]) -> ParseIssue | None:
    """Why fields show several candidates instead of a value (None when no
    field does)."""
    count = decoded.get("ambiguous", 0)
    if not count:
        return None
    return ParseIssue("flatbuffers.ambiguous_fields", {"count": count})


# ---------------------------------------------------------------------------
# Scalar readings
# ---------------------------------------------------------------------------

def interpret_scalar(raw: bytes) -> list[Interpretation]:
    """Every reading of a 1-, 2-, 4- or 8-byte little-endian scalar slot:
    unsigned and signed integer, float/double (4/8 bytes), bool (1 byte,
    0/1), plus proto_interp's timestamp candidates for 4 and 8 bytes."""
    width = len(raw)
    if width == 4:
        return interpret_fixed32(raw)
    if width == 8:
        return interpret_fixed64(raw)
    out: list[Interpretation] = []
    unsigned = int.from_bytes(raw, "little", signed=False)
    signed = int.from_bytes(raw, "little", signed=True)
    out.append(Interpretation(f"uint{width * 8}", f"{unsigned}"))
    if signed != unsigned:
        out.append(Interpretation(f"int{width * 8}", f"{signed}"))
    if width == 1 and unsigned in (0, 1):
        out.append(Interpretation("bool", "true" if unsigned else "false"))
    return out


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class _Context:
    """State shared by a buffer's decode and the nested buffers in it."""

    def __init__(self) -> None:
        # (kind, absolute position, buffer base) -> finished node
        self.memo: dict[tuple[str, int, int], Node] = {}
        self.active: set[tuple[str, int, int]] = set()
        self.covered: list[tuple[int, int]] = []
        self.ambiguous = 0
        self.cycles = 0
        self.texts: list[str] = []
        self.text_chars = 0

    def cover(self, start: int, end: int) -> None:
        if end > start:
            self.covered.append((start, end))

    def add_text(self, text: str) -> None:
        if text and self.text_chars < _TEXT_INDEX_CHARS:
            self.texts.append(text[: _TEXT_INDEX_CHARS - self.text_chars])
            self.text_chars += len(self.texts[-1])


def decode_buffer(raw: bytes) -> dict[str, Any]:
    """Schema-less decode of *raw* as a FlatBuffer: every root layout that
    validates (plain, size-prefixed) as a "buffer" node, the unreferenced
    ranges, and counts (ambiguous fields, cycles)."""
    ctx = _Context()
    buffers, failures = _drive(_buffer_readings(ctx, raw, 0))
    unreferenced = _complement(ctx.covered, 0, len(raw)) if buffers else []
    return {
        "buffers": buffers,
        "root_failures": failures,
        "unreferenced": unreferenced,
        "ambiguous": ctx.ambiguous,
        "cycles": ctx.cycles,
        "text_index": " ".join(ctx.texts),
    }


def _complement(ranges: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    pos = start
    for s, e in sorted(ranges):
        if s > pos:
            out.append((pos, min(s, end)))
        pos = max(pos, e)
        if pos >= end:
            break
    if pos < end:
        out.append((pos, end))
    return [(s, e) for s, e in out if e > s]


def root_candidates(raw: bytes) -> tuple[list[tuple[str, int, int]], list[ParseIssue]]:
    """([(layout, root table position, buffer end)], [why a layout failed])
    for both root layouts: plain (uoffset at 0) and size-prefixed (uint32
    size at 0, uoffset at 4). Positions are relative to *raw*."""
    ok: list[tuple[str, int, int]] = []
    failures: list[ParseIssue] = []
    if len(raw) < 8:
        failures.append(ParseIssue("flatbuffers.too_short", {"size": len(raw)}))
        return ok, failures
    # Plain: FlatBufferBuilder::Finish.
    root = read_u32(raw, 0)
    reason = _root_problem(raw, 0, root, len(raw))
    if reason is None:
        ok.append(("plain", root, len(raw)))
    else:
        failures.append(ParseIssue("flatbuffers.layout_failed", {
            "layout": ParseIssue("flatbuffers.layout_plain"), "reason": reason,
        }))
    # Size-prefixed: FinishSizePrefixed; the prefix counts the bytes after it
    # (Verifier::VerifySizePrefixedBuffer accepts a prefix up to the length).
    size = read_u32(raw, 0)
    if size > len(raw) - 4:
        failures.append(ParseIssue("flatbuffers.layout_failed", {
            "layout": ParseIssue("flatbuffers.layout_size_prefixed"),
            "reason": ParseIssue("flatbuffers.prefix_too_large", {
                "size": size, "available": len(raw) - 4,
            }),
        }))
    else:
        end = 4 + size
        root = 4 + read_u32(raw, 4) if size >= 4 else 0
        reason = (
            ParseIssue("flatbuffers.too_short", {"size": size})
            if size < 4 else _root_problem(raw[:end], 4, root - 4, end)
        )
        if reason is None:
            ok.append(("size_prefixed", root, end))
        else:
            failures.append(ParseIssue("flatbuffers.layout_failed", {
                "layout": ParseIssue("flatbuffers.layout_size_prefixed"), "reason": reason,
            }))
    return ok, failures


def _root_problem(buf: bytes, field_pos: int, uoffset: int, end: int) -> ParseIssue | None:
    if uoffset == 0 or uoffset >= 1 << 31:
        return ParseIssue("flatbuffers.root_offset_invalid", {"offset": uoffset})
    table = field_pos + uoffset
    if table >= end:
        return ParseIssue("flatbuffers.root_out_of_bounds", {"table": table, "size": end})
    try:
        read_vtable(buf[:end], table)
    except TableError as exc:
        return table_issue(exc)
    return None


def table_issue(exc: TableError) -> ParseIssue:
    return ParseIssue(f"flatbuffers.{exc.code}", dict(exc.params))


def vtable_node(vt: VTable, base: int) -> Node:
    """The vtable as stored, one row per uint16 (vtable size, table inline
    size, each slot's offset) -- the same in the schema-less and the schema
    decode. *base*: the buffer's absolute offset."""

    def entry(start: int, **facts: Any) -> Node:
        rng = (base + start, base + start + 2)
        return {"node": "vtable_entry", "range": rng, "highlight": [rng],
                "value_range": rng, **facts}

    rows: list[Node] = [
        entry(vt.offset, entry="vtable_size", value=vt.vtable_size),
        entry(vt.offset + 2, entry="inline_size", value=vt.inline_size),
    ]
    for slot, off in enumerate(vt.slots):
        rows.append(entry(vt.slot_range(slot)[0], entry="slot", slot=slot, value=off))
    return {
        "node": "vtable",
        "offset": base + vt.offset,
        "table": base + vt.table,
        "soffset": vt.table - vt.offset,
        "range": (base + vt.range[0], base + vt.range[1]),
        "highlight": [
            (base + vt.soffset_range[0], base + vt.soffset_range[1]),
            (base + vt.range[0], base + vt.range[1]),
        ],
        "children": rows,
    }


def _buffer_readings(
    ctx: _Context, buf: bytes, base: int
) -> _Task:
    """Buffer nodes for every root layout of *buf* (absolute offset *base*)
    that validates, plus the failure reasons of the others."""
    candidates, failures = root_candidates(buf)
    nodes: list[Node] = []
    for layout, root, end in candidates:
        dec = _Decoder(ctx, buf[:end], base)
        node = yield dec.buffer(layout, root)
        nodes.append(node)
        if end < len(buf):
            # Bytes after a size prefix's end aren't part of the buffer.
            node["trailing"] = (base + end, base + len(buf))
    return nodes, failures


class _Decoder:
    def __init__(self, ctx: _Context, buf: bytes, base: int) -> None:
        self.ctx = ctx
        self.buf = buf
        self.base = base

    def abs(self, pos: int) -> int:
        return self.base + pos

    def rng(self, start: int, end: int) -> tuple[int, int]:
        return (self.base + start, self.base + end)

    # -- buffer --------------------------------------------------------

    def buffer(self, layout: str, root: int) -> _Task:
        buf = self.buf
        children: list[Node] = []
        if layout == "size_prefixed":
            children.append(self._header("size_prefix", 0, 4, read_u32(buf, 0)))
            root_field = 4
        else:
            root_field = 0
        children.append(self._header("root_offset", root_field, root_field + 4, root - root_field))
        ident_at = root_field + 4
        if fits(buf, ident_at, FILE_IDENTIFIER_LENGTH):
            ident = buf[ident_at:ident_at + FILE_IDENTIFIER_LENGTH]
            # Optional: only a buffer finished with an identifier has one,
            # and then the root table can't start before it ends.
            if root >= ident_at + FILE_IDENTIFIER_LENGTH:
                children.append(self._header(
                    "file_identifier", ident_at, ident_at + FILE_IDENTIFIER_LENGTH, ident,
                ))
        self.ctx.cover(self.base, self.base + root_field + 4)
        table = yield self.table(root)
        children.append(table)
        return {
            "node": "buffer",
            "layout": layout,
            "root": self.abs(root),
            "range": self.rng(0, len(buf)),
            "highlight": [self.rng(root_field, root_field + 4)],
            "children": children,
        }

    def _header(self, field: str, start: int, end: int, value: Any) -> Node:
        node: Node = {
            "node": "header",
            "field": field,
            "value": value,
            "range": self.rng(start, end),
            "highlight": [self.rng(start, end)],
            "value_range": self.rng(start, end),
        }
        self.ctx.cover(self.base + start, self.base + end)
        return node

    # -- table -----------------------------------------------------------

    def table(self, pos: int) -> _Task:
        """The table at *pos* (already validated by the caller)."""
        key = ("table", self.abs(pos), self.base)
        if key in self.ctx.active:
            self.ctx.cycles += 1
            return {"node": "cycle", "target": self.abs(pos), "kind": "table",
                    "range": self.rng(pos, pos + 4), "highlight": [self.rng(pos, pos + 4)]}
        done = self.ctx.memo.get(key)
        if done is not None:
            # Decoded once; "target_node" lets a viewer show it here too.
            return {"node": "ref", "target": self.abs(pos), "kind": "table",
                    "range": done["range"], "highlight": done["highlight"],
                    "target_node": done}
        self.ctx.active.add(key)
        vt = read_vtable(self.buf, pos)
        self.ctx.cover(*self.rng(*vt.range))
        self.ctx.cover(*self.rng(*vt.inline_range))
        children: list[Node] = [self._vtable_node(vt)]
        stored = sorted((off, slot) for slot, off in enumerate(vt.slots) if off)
        gaps: dict[int, int] = {}
        for i, (off, slot) in enumerate(stored):
            nxt = stored[i + 1][0] if i + 1 < len(stored) else vt.inline_size
            gaps[slot] = nxt - off
        for slot, off in enumerate(vt.slots):
            if not off:
                children.append({
                    "node": "field", "id": slot, "stored": False,
                    "range": self.rng(*vt.slot_range(slot)),
                    "highlight": [self.rng(*vt.slot_range(slot))],
                })
                continue
            field = yield self._field(vt, slot, off, gaps[slot])
            children.append(field)
        node: Node = {
            "node": "table",
            "offset": self.abs(pos),
            "vtable": self.abs(vt.offset),
            "inline_size": vt.inline_size,
            "slot_count": len(vt.slots),
            "range": self.rng(*vt.inline_range),
            "highlight": [self.rng(*vt.inline_range)],
            "children": children,
        }
        self.ctx.active.discard(key)
        self.ctx.memo[key] = node
        return node

    def _vtable_node(self, vt: VTable) -> Node:
        return vtable_node(vt, self.base)

    # -- field slot ------------------------------------------------------

    def _field(self, vt: Any, slot: int, off: int, gap: int) -> _Task:
        pos = vt.table + off
        widths = [w for w in SCALAR_WIDTHS if w <= gap and pos % w == 0]
        candidates: list[Node] = []
        for w in widths:
            raw = self.buf[pos:pos + w]
            candidates.append({
                "node": "candidate", "as": "scalar", "width": w,
                "value": int.from_bytes(raw, "little"),
                "interpretations": interpret_scalar(raw),
                "range": self.rng(pos, pos + w), "highlight": [self.rng(pos, pos + w)],
                "value_range": self.rng(pos, pos + w),
            })
            if w == 4:
                candidates.extend((yield self._offset_targets(pos, 4)))
            elif w == 8:
                candidates.extend((yield self._offset_targets(pos, 8)))
        if gap not in SCALAR_WIDTHS:
            # A struct stored inline: any size, so the whole gap (its
            # trailing padding included -- not recorded either).
            candidates.append({
                "node": "candidate", "as": "struct", "size": gap,
                "range": self.rng(pos, pos + gap), "highlight": [self.rng(pos, pos + gap)],
                "value_range": self.rng(pos, pos + gap),
            })
        if len(candidates) > 1:
            self.ctx.ambiguous += 1
        return {
            "node": "field", "id": slot, "stored": True,
            "slot_offset": off, "gap": gap, "widths": widths,
            "range": self.rng(pos, pos + gap),
            "highlight": [self.rng(*vt.slot_range(slot)), self.rng(pos, pos + gap)],
            "children": candidates,
        }

    def _offset_targets(self, pos: int, width: int) -> _Task:
        """Candidates for the slot at *pos* read as a *width*-byte offset:
        a 32-bit uoffset to a string, vector or table; a 64-bit offset to a
        string or a vector with a 64-bit length (FlatBuffers 64-bit offsets)."""
        buf = self.buf
        value = read_u32(buf, pos) if width == 4 else read_u64(buf, pos)
        if value == 0 or value >= (1 << 31 if width == 4 else 1 << 63):
            return []
        target = pos + value
        if target >= len(buf):
            return []
        via = "offset32" if width == 4 else "offset64"
        slot_range = self.rng(pos, pos + width)
        out: list[Node] = []
        # The table reading first: a table reached again is decoded once, at
        # the first place it's reached -- an offset to it is the place it's
        # most likely really referenced from, rather than a vector reading.
        if width == 4:
            try:
                read_vtable(buf, target)
            except TableError:
                pass
            else:
                table = yield self.table(target)
                out.append({
                    "node": "candidate", "as": "table", "via": via, "target": self.abs(target),
                    "range": table["range"], "highlight": [slot_range, *table["highlight"]],
                    "children": [table],
                })
        string = string_at(buf, target)
        if string is not None:
            out.append(self._string_candidate(target, string, via, slot_range))
        # A 64-bit offset points to a vector with a 32-bit length
        # ("(offset64)") or a 64-bit one ("(vector64)"); a string keeps its
        # 32-bit length either way.
        for length_size in (4,) if width == 4 else (4, 8):
            vector = yield self._vector(target, length_size=length_size)
            if vector is not None:
                vector = dict(vector)
                vector["via"] = via
                vector["highlight"] = [slot_range, *vector["highlight"]]
                out.append(vector)
        return out

    def _string_candidate(
        self, target: int, string: tuple[int, int], via: str, slot_range: tuple[int, int]
    ) -> Node:
        start, end = string
        data = self.buf[start:end]
        self.ctx.cover(self.base + target, self.base + end + 1)
        try:
            text: str | None = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text:
            self.ctx.add_text(text)
        return {
            "node": "candidate", "as": "string", "via": via, "target": self.abs(target),
            "length": end - start, "text": text,
            "range": self.rng(target, end + 1),
            "highlight": [slot_range, self.rng(target, end + 1)],
            "value_range": self.rng(start, end),
        }

    # -- vector ----------------------------------------------------------

    def _vector(self, pos: int, *, length_size: int = 4) -> _Task:
        """The vector candidate whose length field is at *pos*, with every
        element reading that fits, or None when not even 1-byte elements
        fit. A vector reached twice is decoded once."""
        if vector_at(self.buf, pos, 1, length_size=length_size) is None:
            return None
        kind = "vector" if length_size == 4 else "vector64"
        key = (kind, self.abs(pos), self.base)
        if key in self.ctx.active:
            self.ctx.cycles += 1
            return {"node": "cycle", "target": self.abs(pos), "kind": kind, "as": "vector",
                    "range": self.rng(pos, pos + length_size),
                    "highlight": [self.rng(pos, pos + length_size)]}
        done = self.ctx.memo.get(key)
        if done is not None:
            return {"node": "candidate", "as": "vector_ref", "target": self.abs(pos),
                    "count": done["count"], "range": done["range"],
                    "highlight": list(done["highlight"]), "target_node": done}
        self.ctx.active.add(key)
        buf = self.buf
        count = read_u32(buf, pos) if length_size == 4 else read_u64(buf, pos)
        data = pos + length_size
        readings: list[Node] = []
        max_end = data
        # An empty vector has no element bytes to read in any width.
        for w in SCALAR_WIDTHS if count else ():
            fit = vector_at(buf, pos, w, length_size=length_size)
            if fit is None or data % w:
                continue
            end = fit[2]
            max_end = max(max_end, end)
            readings.append({
                "node": "elements", "as": "scalars", "width": w, "count": count,
                "range": self.rng(data, end), "highlight": [self.rng(data, end)],
                "value_range": self.rng(data, end),
            })
            if w == 1:
                nested = yield self._nested(data, end)
                if nested is not None:
                    readings.append(nested)
            if w == 4:
                readings.extend((yield self._offset_elements(data, count)))
        self.ctx.cover(self.base + pos, self.base + max_end)
        if len(readings) > 1:
            self.ctx.ambiguous += 1
        node: Node = {
            "node": "candidate", "as": "vector", "length_size": length_size,
            "target": self.abs(pos), "count": count,
            "range": self.rng(pos, max_end),
            "highlight": [self.rng(pos, pos + length_size), self.rng(data, max_end)],
            # The element bytes every reading includes: count × 1 byte (each
            # element is at least one byte; wider readings reach further,
            # each with its own range).
            "value_range": self.rng(data, data + count),
            "children": readings,
        }
        self.ctx.active.discard(key)
        self.ctx.memo[key] = node
        return node

    def _offset_elements(self, data: int, count: int) -> _Task:
        """Readings of the vector data at *data* as *count* uoffsets: to
        strings when every element is one, to tables when every element is
        one (unions and tables look alike without a schema)."""
        buf = self.buf
        targets: list[int] = []
        for i in range(count):
            at = data + 4 * i
            value = read_u32(buf, at)
            if value == 0 or value >= 1 << 31 or at + value >= len(buf):
                return []
            targets.append(at + value)
        out: list[Node] = []
        strings = [string_at(buf, t) for t in targets]
        if all(s is not None for s in strings):
            elements = []
            for i, (t, s) in enumerate(zip(targets, strings)):
                at = data + 4 * i
                assert s is not None
                cand = self._string_candidate(t, s, "offset32", self.rng(at, at + 4))
                elements.append({"node": "element", "index": i, "range": cand["range"],
                                 "highlight": cand["highlight"], "children": [cand]})
            out.append({
                "node": "elements", "as": "strings", "width": 4, "count": count,
                "range": self.rng(data, data + 4 * count),
                "highlight": [self.rng(data, data + 4 * count)],
                "children": elements,
            })
        tables_ok = True
        for t in targets:
            try:
                read_vtable(buf, t)
            except TableError:
                tables_ok = False
                break
        if tables_ok:
            elements = []
            for i, t in enumerate(targets):
                at = data + 4 * i
                table = yield self.table(t)
                elements.append({"node": "element", "index": i, "range": table["range"],
                                 "highlight": [self.rng(at, at + 4), *table["highlight"]],
                                 "children": [table]})
            out.append({
                "node": "elements", "as": "tables", "width": 4, "count": count,
                "range": self.rng(data, data + 4 * count),
                "highlight": [self.rng(data, data + 4 * count)],
                "children": elements,
            })
        return out

    def _nested(self, start: int, end: int) -> _Task:
        """A byte vector's data read as a FlatBuffer of its own
        (nested_flatbuffer), or None when no root layout validates."""
        key = ("nested", self.abs(start), self.base)
        if key in self.ctx.active or key in self.ctx.memo:
            return None
        candidates, _failures = root_candidates(self.buf[start:end])
        if not candidates:
            return None
        self.ctx.active.add(key)
        buffers, _ = yield _buffer_readings(self.ctx, self.buf[start:end], self.abs(start))
        self.ctx.active.discard(key)
        node: Node = {
            "node": "elements", "as": "nested", "width": 1, "count": end - start,
            "range": self.rng(start, end), "highlight": [self.rng(start, end)],
            "children": buffers,
        }
        self.ctx.memo[key] = node
        return node
