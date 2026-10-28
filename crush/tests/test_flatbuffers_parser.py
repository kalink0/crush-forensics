# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Schema-less FlatBuffers decode: certain structure validated, every
structurally consistent reading offered and marked heuristic, failures
explicit, no depth limit."""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue, render
from crush.core.vfs import BytesVFS
from crush.parsers.flatbuffers_parser import (
    FlatBuffersParser,
    _drive,
    decode_buffer,
    interpret_scalar,
    root_candidates,
    schema_less_metadata,
)
from crush.parsers.flatbuffers_wire import TableError, read_vtable, string_at, vector_at
from crush.tests.conftest import FIXTURES_DIR

RECORD = (FIXTURES_DIR / "flatbuffers_record.bin").read_bytes()
RECORD_SP = (FIXTURES_DIR / "flatbuffers_record_sizeprefixed.bin").read_bytes()


def _root_table(decoded: dict[str, Any], layout: str = "plain") -> dict[str, Any]:
    buffer = next(b for b in decoded["buffers"] if b["layout"] == layout)
    return buffer["children"][-1]


def _fields(table: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {c["id"]: c for c in table["children"] if c["node"] == "field"}


def _walk(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out, stack = [], list(nodes)
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(node.get("children") or [])
    return out


def deep_chain(levels: int) -> bytes:
    """A buffer of *levels* tables, each holding one offset to the next --
    deeper than Python's recursion limit when *levels* is large. One vtable
    (at 4) is shared: 6 B, tables of 8 B inline, slot 0 at +4."""
    buf = bytearray(struct.pack("<I", 12))  # root -> first table at 12
    buf += struct.pack("<HHH", 6, 8, 4) + b"\0\0"  # vtable at 4..10, pad to 12
    for i in range(levels):
        table = 12 + 8 * i
        last = i == levels - 1
        buf += struct.pack("<iI", table - 4, 0 if last else 4)
    return bytes(buf)


# -- wire --------------------------------------------------------------------


def test_read_vtable_validates_like_the_verifier() -> None:
    vt = read_vtable(RECORD, struct.unpack_from("<I", RECORD, 0)[0])
    assert vt.vtable_size >= 4 and vt.vtable_size % 2 == 0
    assert all(off == 0 or 4 <= off < vt.inline_size for off in vt.slots)
    with pytest.raises(TableError) as exc:
        read_vtable(RECORD, 2)  # not 4-aligned
    assert exc.value.code == "table_unaligned"


def test_string_and_vector_bounds() -> None:
    data = struct.pack("<I", 3) + b"abc\0"
    assert string_at(data, 0) == (4, 7)
    assert string_at(data[:-1], 0) is None  # NUL terminator missing
    assert vector_at(data, 0, 1) == (3, 4, 7)
    assert vector_at(data, 0, 2) is None  # 3 × 2 B don't fit


# -- root layouts -------------------------------------------------------------


def test_plain_buffer_has_one_root_layout_and_states_why_the_other_failed() -> None:
    ok, failures = root_candidates(RECORD)
    assert [layout for layout, _root, _end in ok] == ["plain"]
    assert [f.params["layout"].code for f in failures] == ["flatbuffers.layout_size_prefixed"]
    meta = schema_less_metadata(decode_buffer(RECORD))
    assert meta["Root"].code == "flatbuffers.root_layout"
    assert meta["Root layouts not valid"]


def test_size_prefixed_buffer_is_read_as_such() -> None:
    decoded = decode_buffer(RECORD_SP)
    assert [b["layout"] for b in decoded["buffers"]] == ["size_prefixed"]
    headers = [c for c in decoded["buffers"][0]["children"] if c["node"] == "header"]
    assert headers[0]["field"] == "size_prefix"
    assert headers[0]["value"] == len(RECORD_SP) - 4


@pytest.mark.parametrize("data", [b"", b"\x01\x02\x03", b"\xff" * 64])
def test_no_valid_root_is_an_explicit_warning_never_empty_output(data: bytes) -> None:
    decoded = decode_buffer(data)
    assert decoded["buffers"] == []
    meta = schema_less_metadata(decoded)
    assert meta["Parse warning"].code == "flatbuffers.no_root"
    assert render(meta["Parse warning"])


def test_flexbuffers_bytes_are_not_shown_as_a_flatbuffer() -> None:
    # FlexBuffers puts its root at the end: int 7 as one byte, type INT
    # (packed 0x04), root width 1.
    decoded = decode_buffer(b"\x07\x04\x01")
    assert decoded["buffers"] == []
    assert schema_less_metadata(decoded)["Parse warning"].code == "flatbuffers.no_root"


# -- structure and readings ----------------------------------------------------


def test_vtable_is_shown_as_stored_with_each_slot() -> None:
    table = _root_table(decode_buffer(RECORD))
    vtable = table["children"][0]
    assert vtable["node"] == "vtable"
    entries = vtable["children"]
    assert [e["entry"] for e in entries[:2]] == ["vtable_size", "inline_size"]
    assert len(entries) == 2 + table["slot_count"]
    # Each row maps to its own two bytes.
    assert all(e["value_range"][1] - e["value_range"][0] == 2 for e in entries)


def test_field_offers_every_consistent_reading_as_candidates() -> None:
    fields = _fields(_root_table(decode_buffer(RECORD)))
    # Slot 8 (title, a string in the schema) reads as a 4-byte scalar AND as
    # an offset to the string "evidence" -- neither is presented as the value.
    title = fields[8]
    kinds = [(c["as"], c.get("via")) for c in title["children"]]
    assert ("scalar", None) in kinds
    assert ("string", "offset32") in kinds
    assert next(c for c in title["children"] if c["as"] == "string")["text"] == "evidence"
    assert len(title["children"]) > 1


def test_8_byte_slot_offers_timestamp_interpretations() -> None:
    fields = _fields(_root_table(decode_buffer(RECORD)))
    created = fields[1]  # created_ms = 1730106000123
    scalar8 = next(c for c in created["children"] if c["as"] == "scalar" and c["width"] == 8)
    assert scalar8["value"] == 1730106000123
    labels = {i.label: i.value for i in scalar8["interpretations"]}
    assert labels["Unix timestamp (ms)"] == "2024-10-28 09:00:00.123 UTC"


def test_absent_slot_is_shown_not_dropped() -> None:
    fields = _fields(_root_table(decode_buffer(RECORD)))
    # count (slot 6) equals its default and isn't written.
    assert fields[6]["stored"] is False


def test_vector_readings_list_widths_and_offsets() -> None:
    nodes = _walk(decode_buffer(RECORD)["buffers"])
    tags = next(n for n in nodes if n.get("as") == "strings")  # [string] tags
    texts = [e["children"][0]["text"] for e in tags["children"]]
    assert texts == ["chat", "export"]
    widths = {n["width"] for n in nodes if n.get("as") == "scalars"}
    assert widths <= {1, 2, 4, 8} and 1 in widths


def test_nested_flatbuffer_is_offered_as_a_reading_of_a_byte_vector() -> None:
    nodes = _walk(decode_buffer(RECORD)["buffers"])
    nested = [n for n in nodes if n.get("as") == "nested"]
    assert nested, "the nested_flatbuffer field's bytes weren't tried as a FlatBuffer"
    inner = nested[0]["children"][0]
    assert inner["node"] == "buffer"
    # Absolute offsets: the nested buffer's ranges lie inside the outer one.
    assert nested[0]["range"][0] <= inner["range"][0] < nested[0]["range"][1]


def test_heuristic_basis_and_ambiguity_are_stated() -> None:
    decoded = decode_buffer(RECORD)
    meta = schema_less_metadata(decoded)
    assert meta["Field widths"].code == "flatbuffers.widths_heuristic"
    assert meta["Ambiguous fields"] == ParseIssue(
        "flatbuffers.ambiguous_fields", {"count": decoded["ambiguous"]}
    )


def test_unreferenced_ranges_are_listed() -> None:
    decoded = decode_buffer(RECORD)
    unref = decoded["unreferenced"]
    assert unref == sorted(unref)
    assert all(0 <= s < e <= len(RECORD) for s, e in unref)
    assert (8, 10) in unref  # padding between the identifier and the vtable
    assert schema_less_metadata(decoded)["Unreferenced bytes"].params["bytes"] == sum(
        e - s for s, e in unref
    )


def test_bytes_after_a_size_prefix_are_trailing_and_unreferenced() -> None:
    data = RECORD_SP + b"REMNANT!"
    decoded = decode_buffer(data)
    sp = next(b for b in decoded["buffers"] if b["layout"] == "size_prefixed")
    assert sp["trailing"] == (len(RECORD_SP), len(data))
    assert (len(RECORD_SP), len(data)) in decoded["unreferenced"] or any(
        s <= len(RECORD_SP) and e == len(data) for s, e in decoded["unreferenced"]
    )


def test_no_depth_limit_and_no_recursion_error() -> None:
    levels = 1200  # past Python's default recursion limit of 1000
    decoded = decode_buffer(deep_chain(levels))
    depth = 0
    table = _root_table(decoded)
    refs = 0
    while True:
        depth += 1
        offsets = [c for c in _fields(table)[0]["children"] if c["as"] == "table"]
        if not offsets:
            break
        table = offsets[0]["children"][0]
        if table["node"] == "ref":
            refs += 1
            table = table["target_node"]
    assert depth == levels
    # The offset reading is tried first: the chain is decoded along itself.
    assert refs == 0


def test_drive_rethrows_into_the_calling_task() -> None:
    def failing():  # noqa: ANN202
        raise ValueError("inner")
        yield  # pragma: no cover

    def caller():  # noqa: ANN202
        try:
            yield failing()
        except ValueError as exc:
            return f"caught {exc}"
        return "not caught"

    assert _drive(caller()) == "caught inner"


# -- readings of scalars -------------------------------------------------------


def test_scalar_interpretations_per_width() -> None:
    assert [i.label for i in interpret_scalar(b"\x01")] == ["uint8", "bool"]
    assert {i.label for i in interpret_scalar(b"\xff\xff")} == {"uint16", "int16"}
    assert "float" in {i.label for i in interpret_scalar(b"\x00\x00\x80\x3f")}
    assert "double" in {i.label for i in interpret_scalar(struct.pack("<d", 1.5))}


# -- parser ---------------------------------------------------------------------


def test_parser_is_explicit_only_and_returns_the_bytes_untouched() -> None:
    parser = FlatBuffersParser()
    assert parser.can_parse("x.tflite", RECORD[:64]) is False
    vfs = BytesVFS(RECORD, name="record.bin")
    result = parser.parse(vfs.root(), vfs)
    assert result.viewer_type == "flatbuffers"
    assert result.data["raw"] == RECORD
    assert "evidence" in result.text_index
    assert result.metadata["Format"] == "FlatBuffers (schema-less)"


def test_real_bfbs_fixture_reads_schema_less(tmp_path: Path) -> None:
    data = (FIXTURES_DIR / "flatbuffers_record.bfbs").read_bytes()
    decoded = decode_buffer(data)
    ident = next(c for c in decoded["buffers"][0]["children"] if c.get("field") == "file_identifier")
    assert data[ident["value_range"][0]:ident["value_range"][1]] == b"BFBS"
