# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers schemas: .bfbs read by Crush's own reader, .fbs compiled by the
bundled flatc into the same model; the exact decode matches flatc's own JSON
of the same bytes, and every disagreement with the schema is reported on its
field."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import crush.parsers.flatbuffers_schema as fbs
from crush.core.issues import render
from crush.parsers.flatbuffers_schema import (
    SchemaLoadError,
    decode_with_schema,
    flatc_path,
    load_schema,
    read_bfbs,
    type_text,
)
from crush.tests.flatbuffers_helpers import root_table, table_json

ROOT = "crush.fixtures.Record"


def _flatc_available() -> bool:
    try:
        flatc_path()
    except SchemaLoadError:
        return False
    return True


needs_flatc = pytest.mark.skipif(
    not _flatc_available(),
    reason="bundled flatc not present (scripts/download_flatc_binaries.py); .fbs needs it",
)


def _fields(table: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in table["children"] if c["node"] == "field" and c.get("name")}


def _issues(node: dict[str, Any]) -> list[str]:
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        if n.get("issue") is not None:
            out.append(n["issue"].code)
        stack.extend(n.get("children") or [])
    return out


# -- loading ------------------------------------------------------------------


def test_bfbs_is_read_by_content_with_root_type_and_identifier(flatbuffers_fixture: dict) -> None:
    schema = load_schema(flatbuffers_fixture["bfbs"])
    assert schema.root_table == ROOT
    assert schema.file_ident == "CRSH"
    assert ROOT in schema.table_names()
    # Structs can't be a buffer's root.
    assert "crush.fixtures.common.Point" not in schema.table_names()
    # A .bfbs doesn't record the flatc version that wrote it.
    assert schema.compiled_by is None


def test_bfbs_is_recognised_by_content_not_by_name(flatbuffers_fixture: dict, tmp_path: Path) -> None:
    renamed = tmp_path / "schema.dat"
    renamed.write_bytes(flatbuffers_fixture["bfbs"].read_bytes())
    assert load_schema(renamed).root_table == ROOT


def test_not_a_bfbs_is_an_explicit_error() -> None:
    with pytest.raises(SchemaLoadError) as exc:
        read_bfbs(b"\x10\x00\x00\x00NOPE" + b"\x00" * 16)
    assert exc.value.issue.code == "flatbuffers.schema.not_bfbs"


def test_damaged_bfbs_is_an_explicit_error(flatbuffers_fixture: dict) -> None:
    data = bytearray(flatbuffers_fixture["bfbs"].read_bytes())
    data[0:4] = (len(data) + 100).to_bytes(4, "little")  # root offset out of bounds
    with pytest.raises(SchemaLoadError) as exc:
        read_bfbs(bytes(data))
    assert exc.value.issue.code == "flatbuffers.schema.bfbs_invalid"


@needs_flatc
def test_fbs_compiles_to_the_same_model_with_its_flatc_version(flatbuffers_fixture: dict) -> None:
    from_fbs = load_schema(flatbuffers_fixture["fbs"])
    from_bfbs = load_schema(flatbuffers_fixture["bfbs"])
    assert from_fbs.objects == from_bfbs.objects
    assert from_fbs.enums == from_bfbs.enums
    assert from_fbs.compiled_by == f"flatc {fbs.get_bundled_flatc_version()}"


@needs_flatc
def test_fbs_compile_error_is_explicit_with_flatcs_message(tmp_path: Path) -> None:
    bad = tmp_path / "bad.fbs"
    bad.write_text("table T { a: NoSuchType; }\nroot_type T;\n")
    with pytest.raises(SchemaLoadError) as exc:
        load_schema(bad)
    assert exc.value.issue.code == "flatbuffers.schema.fbs_compile_failed"
    assert "NoSuchType" in exc.value.issue.detail


def test_fbs_without_bundled_flatc_says_so(
    flatbuffers_fixture: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fbs, "_BINARY_DIR", tmp_path / "no-flatc")
    with pytest.raises(SchemaLoadError) as exc:
        load_schema(flatbuffers_fixture["fbs"])
    assert exc.value.issue.code == "flatbuffers.schema.flatc_missing"
    assert "download_flatc_binaries.py" in render(exc.value.issue)


def test_type_text_spells_schema_types(flatbuffers_fixture: dict) -> None:
    schema = load_schema(flatbuffers_fixture["bfbs"])
    record = schema.object_named(ROOT)
    assert record is not None
    texts = {f.name: type_text(schema, f.type, f) for f in record.fields}
    assert texts["title"] == "string"
    assert texts["tags"] == "[string]"
    assert texts["kind"] == "crush.fixtures.common.Kind (byte)"
    assert texts["big"] == "[ubyte] (vector64)"


# -- exact decode ---------------------------------------------------------------


@pytest.mark.parametrize("key,layout", [("bin", "plain"), ("sizeprefixed", "size_prefixed")])
def test_decode_matches_flatcs_own_json(flatbuffers_fixture: dict, key: str, layout: str) -> None:
    raw = flatbuffers_fixture[key].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)
    assert [b["layout"] for b in decoded["buffers"]] == [layout]
    assert decoded["issues"] == 0
    assert table_json(root_table(decoded, layout), raw) == flatbuffers_fixture["expected"]


def test_vector64_field(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["vector64"].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)
    big = _fields(root_table(decoded))["big"]
    start, end = big["value_range"]
    assert raw[start:end] == bytes([9, 8, 7])


def test_defaults_are_marked_not_stored(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    fields = _fields(root_table(decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)))
    assert fields["count"]["stored"] is False
    assert fields["count"]["default"] is True and fields["count"]["value"] == 7
    # An optional scalar not stored has no value at all (null), not a default.
    assert fields["maybe"]["stored"] is False and "value" not in fields["maybe"]


def test_every_value_maps_to_its_bytes(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    fields = _fields(root_table(decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)))
    s, e = fields["title"]["value_range"]
    assert raw[s:e] == b"evidence"
    s, e = fields["id"]["value_range"]
    assert int.from_bytes(raw[s:e], "little") == 4242
    # The slot's vtable entry is highlighted too.
    assert len(fields["id"]["highlight"]) == 2


def test_unreferenced_bytes_are_listed_in_the_schema_decode(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)
    assert decoded["unreferenced"]
    assert all(0 <= s < e <= len(raw) for s, e in decoded["unreferenced"])


# -- disagreements are reported per field --------------------------------------


def test_older_schema_reports_the_slot_it_doesnt_know(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs_v1"]), ROOT, raw)
    table = root_table(decoded)
    unknown = [c for c in table["children"] if c["node"] == "field" and c.get("name") is None]
    assert len(unknown) == 1
    assert unknown[0]["issue"].code == "flatbuffers.schema.slot_not_in_schema"
    s, e = unknown[0]["value_range"]
    assert e - s == unknown[0]["gap"]


def test_bfbs_without_builtins_reports_flags_it_cant_resolve(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs_v1"]), ROOT, raw)
    flags = _fields(root_table(decoded))["flags"]
    assert flags["value"] == 3
    assert flags["issue"].code == "flatbuffers.schema.enum_undeclared"
    assert "--bfbs-builtins" in render(flags["issue"])


def test_with_builtins_flags_are_resolved(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)
    assert _fields(root_table(decoded))["flags"]["enum"] == "Read | Starred"


def test_required_field_not_stored_is_reported(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()
    schema = load_schema(flatbuffers_fixture["bfbs"])
    nested = _fields(root_table(decode_with_schema(schema, ROOT, raw)))["nested"]
    s, e = nested["value_range"]
    # The nested Inner buffer read as a Record: title (required) isn't there.
    decoded = decode_with_schema(schema, ROOT, raw[s:e])
    title = _fields(root_table(decoded))["title"]
    assert title["stored"] is False
    assert title["issue"].code == "flatbuffers.schema.required_missing"


def test_truncated_buffer_reports_instead_of_raising(flatbuffers_fixture: dict) -> None:
    raw = flatbuffers_fixture["bin"].read_bytes()[:200]
    decoded = decode_with_schema(load_schema(flatbuffers_fixture["bfbs"]), ROOT, raw)
    if decoded["buffers"]:
        assert decoded["issues"] > 0
        assert _issues(root_table(decoded))
    else:
        assert decoded["root_failures"]


def test_identifier_is_checked_for_the_schemas_root_type_only(flatbuffers_fixture: dict) -> None:
    raw = bytearray(flatbuffers_fixture["bin"].read_bytes())
    raw[4:8] = b"XXXX"
    schema = load_schema(flatbuffers_fixture["bfbs"])
    decoded = decode_with_schema(schema, ROOT, bytes(raw))
    header = next(c for c in decoded["buffers"][0]["children"] if c.get("field") == "file_identifier")
    assert header["issue"].code == "flatbuffers.schema.identifier_differs"
    # The nested buffer (root type Inner) has no identifier to check.
    nested = _fields(root_table(decoded))["nested"]["children"][0]
    assert all(c.get("field") != "file_identifier" for c in nested["children"])
