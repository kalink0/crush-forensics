# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers schemas: loading (.bfbs and .fbs) and exact decode.

One in-memory schema model (:class:`Schema`) is the only thing the decoder
uses. It comes from a binary schema (.bfbs, the reflection.fbs FlatBuffer
that ``flatc -b --schema`` writes), read by this module's own reader -- the
``flatbuffers`` PyPI package ships no reflection classes. A text schema
(.fbs) is first compiled to .bfbs by the bundled ``flatc``
(scripts/download_flatc_binaries.py), the same way for every platform.
Which of the two a file is, is decided from its content (the ``BFBS``
file_identifier), not its name.

The decode follows the schema's declared types; every disagreement between
the schema and the bytes (an offset or vtable out of bounds, a required
field not stored, an enum value the schema doesn't declare, a slot the
schema doesn't know) is reported on the field it concerns
(``node["issue"]``), never skipped.
"""
from __future__ import annotations

import math
import platform
import struct
import subprocess
import sys
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crush.core.issues import ParseIssue, render
from crush.parsers.flatbuffers_parser import (
    _complement,
    _drive,
    root_candidates,
    table_issue,
    vtable_node,
)
from crush.parsers.flatbuffers_wire import (
    SCALAR_FORMATS,
    SCALAR_SIZES,
    OutOfBounds,
    TableError,
    VTable,
    fits,
    read_scalar,
    read_u32,
    read_u64,
    read_vtable,
    string_at,
    vector_at,
)

Node = dict[str, Any]
_Task = Generator[Any, Any, Any]

# reflection.fbs BaseType, in declaration order (the stored byte is the index).
BASE_TYPES = (
    "None", "UType", "Bool", "Byte", "UByte", "Short", "UShort", "Int", "UInt",
    "Long", "ULong", "Float", "Double", "String", "Vector", "Obj", "Union",
    "Array", "Vector64",
)
_SCALARS = frozenset(SCALAR_FORMATS)
# Schema-language names of the scalar base types.
_TYPE_NAMES = {
    "UType": "utype", "Bool": "bool", "Byte": "byte", "UByte": "ubyte",
    "Short": "short", "UShort": "ushort", "Int": "int", "UInt": "uint",
    "Long": "long", "ULong": "ulong", "Float": "float", "Double": "double",
    "String": "string",
}


class SchemaLoadError(Exception):
    """A schema file couldn't be read, compiled or understood."""

    def __init__(self, issue: ParseIssue) -> None:
        super().__init__(render(issue))
        self.issue = issue


# ---------------------------------------------------------------------------
# Schema model (mirrors reflection.fbs)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Type:
    base_type: str
    element: str = "None"
    index: int = -1
    fixed_length: int = 0
    base_size: int = 4
    element_size: int = 0


@dataclass(frozen=True)
class Field:
    name: str
    type: Type
    id: int
    offset: int
    default_integer: int = 0
    default_real: float = 0.0
    deprecated: bool = False
    required: bool = False
    optional: bool = False
    offset64: bool = False
    attributes: dict[str, str] = field(default_factory=dict, hash=False)

    @property
    def slot(self) -> int:
        """The vtable slot of a table field (its vtable offset 4 + 2·slot)."""
        return (self.offset - 4) // 2


@dataclass(frozen=True)
class Object:
    name: str
    fields: tuple[Field, ...]
    is_struct: bool
    minalign: int
    bytesize: int
    attributes: dict[str, str] = field(default_factory=dict, hash=False)

    def field_named(self, name: str) -> Field | None:
        return next((f for f in self.fields if f.name == name), None)


@dataclass(frozen=True)
class EnumVal:
    name: str
    value: int
    union_type: Type | None


@dataclass(frozen=True)
class Enum:
    name: str
    values: tuple[EnumVal, ...]
    is_union: bool
    underlying_type: Type
    attributes: dict[str, str] = field(default_factory=dict, hash=False)

    def value_named(self, value: int) -> EnumVal | None:
        return next((v for v in self.values if v.value == value), None)


@dataclass
class Schema:
    objects: list[Object]
    enums: list[Enum]
    file_ident: str
    file_ext: str
    root_table: str | None
    # Where the schema came from and how: the file name, and the flatc
    # version that compiled it (None: a .bfbs, which doesn't record it).
    source_name: str = ""
    compiled_by: str | None = None
    compiler_messages: str = ""

    def object_named(self, name: str) -> Object | None:
        return next((o for o in self.objects if o.name == name), None)

    def table_names(self) -> list[str]:
        """Every table (structs can't be a buffer's root), sorted."""
        return sorted(o.name for o in self.objects if not o.is_struct)


# ---------------------------------------------------------------------------
# .bfbs reader (reflection.fbs, read by hand)
# ---------------------------------------------------------------------------


class _BfbsError(Exception):
    pass


class _T:
    """One table of the .bfbs, with reflection.fbs field access by slot."""

    def __init__(self, buf: bytes, pos: int) -> None:
        try:
            self.vt: VTable = read_vtable(buf, pos)
        except TableError as exc:
            raise _BfbsError(f"table at {pos:#x}: {exc.code}") from exc
        self.buf = buf
        self.pos = pos

    def _at(self, slot: int) -> int | None:
        if slot >= len(self.vt.slots) or not self.vt.slots[slot]:
            return None
        return self.pos + self.vt.slots[slot]

    def scalar(self, slot: int, base_type: str, default: Any) -> Any:
        at = self._at(slot)
        if at is None:
            return default
        try:
            return read_scalar(self.buf, at, base_type)
        except OutOfBounds as exc:
            raise _BfbsError(str(exc)) from exc

    def _target(self, slot: int) -> int | None:
        at = self._at(slot)
        if at is None:
            return None
        if not fits(self.buf, at, 4):
            raise _BfbsError(f"offset at {at:#x} out of bounds")
        value = read_u32(self.buf, at)
        if value == 0 or at + value >= len(self.buf):
            raise _BfbsError(f"offset at {at:#x} points outside the file")
        return at + value

    def string(self, slot: int, default: str | None = None) -> str | None:
        target = self._target(slot)
        if target is None:
            return default
        span = string_at(self.buf, target)
        if span is None:
            raise _BfbsError(f"string at {target:#x} invalid")
        try:
            return self.buf[span[0]:span[1]].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _BfbsError(f"string at {target:#x} not UTF-8") from exc

    def table(self, slot: int) -> _T | None:
        target = self._target(slot)
        return None if target is None else _T(self.buf, target)

    def tables(self, slot: int) -> list[_T]:
        target = self._target(slot)
        if target is None:
            return []
        fit = vector_at(self.buf, target, 4)
        if fit is None:
            raise _BfbsError(f"vector at {target:#x} invalid")
        count, data, _end = fit
        out: list[_T] = []
        for i in range(count):
            at = data + 4 * i
            value = read_u32(self.buf, at)
            if value == 0 or at + value >= len(self.buf):
                raise _BfbsError(f"vector element at {at:#x} points outside the file")
            out.append(_T(self.buf, at + value))
        return out


def _base_type(code: int) -> str:
    if not 0 <= code < len(BASE_TYPES):
        raise _BfbsError(f"unknown base type {code}")
    return BASE_TYPES[code]


def _read_type(t: _T | None) -> Type:
    if t is None:
        raise _BfbsError("required type missing")
    return Type(
        base_type=_base_type(t.scalar(0, "Byte", 0)),
        element=_base_type(t.scalar(1, "Byte", 0)),
        index=t.scalar(2, "Int", -1),
        fixed_length=t.scalar(3, "UShort", 0),
        base_size=t.scalar(4, "UInt", 4),
        element_size=t.scalar(5, "UInt", 0),
    )


def _read_attributes(t: _T, slot: int) -> dict[str, str]:
    return {kv.string(0) or "": kv.string(1) or "" for kv in t.tables(slot)}


def _required_string(t: _T, slot: int, what: str) -> str:
    value = t.string(slot)
    if value is None:
        raise _BfbsError(f"{what} without a name")
    return value


def read_bfbs(data: bytes) -> Schema:
    """The schema stored in *data*, a reflection.fbs buffer (.bfbs)."""
    if len(data) < 8 or data[4:8] != b"BFBS":
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.not_bfbs"))
    try:
        root = _T(data, read_u32(data, 0))
        objects: list[Object] = []
        for o in root.tables(0):
            fields = []
            for f in o.tables(1):
                fields.append(Field(
                    name=_required_string(f, 0, "field"),
                    type=_read_type(f.table(1)),
                    id=f.scalar(2, "UShort", 0),
                    offset=f.scalar(3, "UShort", 0),
                    default_integer=f.scalar(4, "Long", 0),
                    default_real=f.scalar(5, "Double", 0.0),
                    deprecated=bool(f.scalar(6, "Bool", 0)),
                    required=bool(f.scalar(7, "Bool", 0)),
                    optional=bool(f.scalar(11, "Bool", 0)),
                    offset64=bool(f.scalar(13, "Bool", 0)),
                    attributes=_read_attributes(f, 9),
                ))
            objects.append(Object(
                name=_required_string(o, 0, "object"),
                fields=tuple(sorted(fields, key=lambda f: (f.id, f.name))),
                is_struct=bool(o.scalar(2, "Bool", 0)),
                minalign=o.scalar(3, "Int", 0),
                bytesize=o.scalar(4, "Int", 0),
                attributes=_read_attributes(o, 5),
            ))
        enums: list[Enum] = []
        for e in root.tables(1):
            values = []
            for v in e.tables(1):
                union_type = v.table(3)
                values.append(EnumVal(
                    name=_required_string(v, 0, "enum value"),
                    value=v.scalar(1, "Long", 0),
                    union_type=_read_type(union_type) if union_type is not None else None,
                ))
            enums.append(Enum(
                name=_required_string(e, 0, "enum"),
                values=tuple(values),
                is_union=bool(e.scalar(2, "Bool", 0)),
                underlying_type=_read_type(e.table(3)),
                attributes=_read_attributes(e, 4),
            ))
        root_table = root.table(4)
        schema = Schema(
            objects=objects,
            enums=enums,
            file_ident=root.string(2) or "",
            file_ext=root.string(3) or "",
            root_table=_required_string(root_table, 0, "root table") if root_table else None,
        )
    except _BfbsError as exc:
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.bfbs_invalid", detail=str(exc))) from exc
    for obj in schema.objects:
        for fld in obj.fields:
            _check_index(schema, fld, fld.type.index, fld.type.base_type)
    if not schema.table_names():
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.no_tables"))
    return schema


def _check_index(schema: Schema, f: Field, index: int, base_type: str) -> None:
    elem = f.type.element
    if base_type == "Obj" or (base_type in ("Vector", "Vector64", "Array") and elem == "Obj"):
        if not 0 <= index < len(schema.objects):
            raise SchemaLoadError(ParseIssue(
                "flatbuffers.schema.bfbs_invalid", detail=f"field {f.name}: object index {index}"
            ))
    elif base_type in ("Union", "UType") or (
        base_type in ("Vector", "Vector64") and elem in ("Union", "UType")
    ):
        if not 0 <= index < len(schema.enums):
            raise SchemaLoadError(ParseIssue(
                "flatbuffers.schema.bfbs_invalid", detail=f"field {f.name}: enum index {index}"
            ))


# ---------------------------------------------------------------------------
# flatc (bundled): .fbs -> .bfbs
# ---------------------------------------------------------------------------

# (sys.platform, platform.machine()) -> binary file name inside _BINARY_DIR,
# as scripts/download_flatc_binaries.py writes them.
_PLATFORM_BINARY_MAP: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): "flatc-linux-x86_64",
    ("linux", "aarch64"): "flatc-linux-aarch64",
    ("darwin", "x86_64"): "flatc-macos",
    ("darwin", "arm64"): "flatc-macos",
    ("win32", "AMD64"): "flatc-windows-x86_64.exe",
    ("win32", "x86_64"): "flatc-windows-x86_64.exe",
}


def _resolve_binary_dir() -> Path:
    # PyInstaller extracts data files to sys._MEIPASS when frozen;
    # --add-data places the binary at _MEIPASS/crush/bin/flatc/.
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "crush" / "bin" / "flatc"  # type: ignore[attr-defined]
    return Path(__file__).parent.parent / "bin" / "flatc"


_BINARY_DIR = _resolve_binary_dir()


def get_bundled_flatc_version() -> str | None:
    """Version of the bundled flatc, per VERSION.txt written by
    scripts/download_flatc_binaries.py next to the binaries. None when
    running from source without the binaries."""
    version_file = _BINARY_DIR / "VERSION.txt"
    if not version_file.exists():
        return None
    return version_file.read_text().strip() or None


def flatc_path() -> Path:
    """The bundled flatc for this platform; SchemaLoadError when there is
    none (no build for the platform, or not downloaded when running from
    source)."""
    name = _PLATFORM_BINARY_MAP.get((sys.platform, platform.machine()))
    if name is None:
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.flatc_no_platform", {
            "platform": f"{sys.platform}/{platform.machine()}",
        }))
    path = _BINARY_DIR / name
    if not path.is_file():
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.flatc_missing", {"path": str(path)}))
    return path


def compile_fbs(path: Path) -> tuple[bytes, str]:
    """(.bfbs bytes, flatc's own messages) for the .fbs at *path*, compiled
    by the bundled flatc (``flatc -b --schema --bfbs-builtins``; includes
    are looked up next to the file). --bfbs-builtins keeps the built-in
    attributes the decode reads (bit_flags, nested_flatbuffer, flexbuffer),
    which a plain .bfbs leaves out."""
    from crush.core import tempdir

    binary = flatc_path()
    out_dir = tempdir.mkdtemp(prefix="crush-fbs-")
    args = [
        str(binary), "-b", "--schema", "--bfbs-builtins",
        "-I", str(path.parent), "-o", str(out_dir), str(path),
    ]
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)
    except OSError as exc:
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.flatc_failed", detail=str(exc))) from exc
    messages = "\n".join(s.strip() for s in (proc.stdout, proc.stderr) if s.strip())
    out = out_dir / (path.stem + ".bfbs")
    if proc.returncode != 0 or not out.is_file():
        raise SchemaLoadError(ParseIssue(
            "flatbuffers.schema.fbs_compile_failed", {"code": proc.returncode}, detail=messages,
        ))
    return out.read_bytes(), messages


def load_schema(path: Path) -> Schema:
    """The schema in *path*: a .bfbs read directly, anything else compiled
    as .fbs by the bundled flatc. Decided by content (the BFBS identifier at
    bytes 4-7), not by the file name."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SchemaLoadError(ParseIssue("flatbuffers.schema.unreadable", detail=str(exc))) from exc
    if len(data) >= 8 and data[4:8] == b"BFBS":
        schema = read_bfbs(data)
        schema.source_name = path.name
        return schema
    bfbs, messages = compile_fbs(path)
    schema = read_bfbs(bfbs)
    schema.source_name = path.name
    version = get_bundled_flatc_version()
    schema.compiled_by = f"flatc {version}" if version else "flatc"
    schema.compiler_messages = messages
    return schema


# ---------------------------------------------------------------------------
# Exact decode
# ---------------------------------------------------------------------------


def type_text(schema: Schema, t: Type, f: Field | None = None) -> str:
    """The schema-language spelling of *t* ("int", "[string]", "Monster",
    "Color (byte)")."""
    def elem_name(base: str, index: int) -> str:
        if base == "Obj":
            return schema.objects[index].name if 0 <= index < len(schema.objects) else "?"
        if base in ("Union", "UType") and 0 <= index < len(schema.enums):
            return schema.enums[index].name
        if base in _SCALARS and index >= 0 and index < len(schema.enums):
            return f"{schema.enums[index].name} ({_TYPE_NAMES[base]})"
        return _TYPE_NAMES.get(base, base)

    b = t.base_type
    if b in ("Vector", "Vector64"):
        inner = f"[{elem_name(t.element, t.index)}]"
        return inner + (" (vector64)" if b == "Vector64" else "")
    if b == "Array":
        return f"[{elem_name(t.element, t.index)}:{t.fixed_length}]"
    if b == "UType" and f is not None:
        return f"{elem_name(b, t.index)} (type)"
    return elem_name(b, t.index)


def typed_element_values(raw: bytes, base_type: str) -> list[str]:
    """Every element of *raw*, a vector of *base_type* scalars, as text."""
    size = SCALAR_SIZES[base_type]
    count = len(raw) // size
    code = SCALAR_FORMATS[base_type][1]
    values = struct.unpack_from(f"<{count}{code}", raw, 0) if count else ()
    if base_type == "Bool":
        return ["true" if v else "false" for v in values]
    if base_type in ("Float", "Double"):
        return [_float_text(v) for v in values]
    return [str(v) for v in values]


def _float_text(value: float) -> str:
    if math.isnan(value):
        return "nan"
    if math.isinf(value):
        return "inf" if value > 0 else "-inf"
    return repr(value)


def decode_with_schema(schema: Schema, root_type: str, raw: bytes) -> dict[str, Any]:
    """Decode *raw* as a buffer whose root is the table *root_type*, for every
    root layout that validates (plain, size-prefixed). Returns the same shape
    as the schema-less decode (``buffers``, ``root_failures``,
    ``unreferenced``) plus ``issues`` (the number of fields whose bytes
    disagree with the schema)."""
    obj = schema.object_named(root_type)
    if obj is None or obj.is_struct:
        raise ValueError(f"{root_type} is not a table of the schema")
    ctx = _SchemaContext(schema)
    candidates, failures = root_candidates(raw)
    buffers: list[Node] = []
    for layout, root, end in candidates:
        dec = _SchemaDecoder(ctx, raw[:end], 0)
        node = _drive(dec.buffer(layout, root, obj))
        if end < len(raw):
            node["trailing"] = (end, len(raw))
        buffers.append(node)
    unreferenced = _complement(ctx.covered, 0, len(raw)) if buffers else []
    return {
        "buffers": buffers,
        "root_failures": failures,
        "unreferenced": unreferenced,
        "issues": ctx.issues,
        "root_type": root_type,
    }


class _SchemaContext:
    def __init__(self, schema: Schema) -> None:
        self.schema = schema
        self.memo: dict[tuple[str, int, int], Node] = {}
        self.active: set[tuple[str, int, int]] = set()
        self.covered: list[tuple[int, int]] = []
        self.issues = 0

    def cover(self, start: int, end: int) -> None:
        if end > start:
            self.covered.append((start, end))


class _SchemaDecoder:
    def __init__(self, ctx: _SchemaContext, buf: bytes, base: int) -> None:
        self.ctx = ctx
        self.schema = ctx.schema
        self.buf = buf
        self.base = base

    def rng(self, start: int, end: int) -> tuple[int, int]:
        return (self.base + start, self.base + end)

    def _issue(self, node: Node, issue: ParseIssue) -> Node:
        node["issue"] = issue
        self.ctx.issues += 1
        return node

    # -- buffer ------------------------------------------------------------

    def buffer(self, layout: str, root: int, obj: Object) -> _Task:
        buf = self.buf
        children: list[Node] = []
        root_field = 4 if layout == "size_prefixed" else 0
        if layout == "size_prefixed":
            children.append(self._header("size_prefix", 0, 4, read_u32(buf, 0)))
        children.append(self._header("root_offset", root_field, root_field + 4, root - root_field))
        ident_at = root_field + 4
        # The schema's file_identifier belongs to its root_type only: not
        # checked for another root type (a nested buffer, or one picked).
        ident = self.schema.file_ident if obj.name == self.schema.root_table else ""
        if ident and fits(buf, ident_at, 4):
            stored = buf[ident_at:ident_at + 4]
            node = self._header("file_identifier", ident_at, ident_at + 4, stored)
            if stored != ident.encode("utf-8"):
                self._issue(node, ParseIssue("flatbuffers.schema.identifier_differs", {
                    "stored": stored.decode("latin-1"), "expected": ident,
                }))
            children.append(node)
        table = yield self.table(root, obj)
        children.append(table)
        return {
            "node": "buffer", "layout": layout, "root": self.base + root,
            "root_type": obj.name,
            "range": self.rng(0, len(buf)),
            "highlight": [self.rng(root_field, root_field + 4)],
            "children": children,
        }

    def _header(self, name: str, start: int, end: int, value: Any) -> Node:
        self.ctx.cover(*self.rng(start, end))
        return {"node": "header", "field": name, "value": value,
                "range": self.rng(start, end), "highlight": [self.rng(start, end)],
                "value_range": self.rng(start, end)}

    # -- table -------------------------------------------------------------

    def table(self, pos: int, obj: Object) -> _Task:
        key = (obj.name, self.base + pos, self.base)
        stub: Node = {"node": "table", "type": obj.name, "offset": self.base + pos,
                      "range": self.rng(pos, pos + 4), "highlight": [self.rng(pos, pos + 4)],
                      "children": []}
        if key in self.ctx.active:
            return self._issue({"node": "cycle", "target": self.base + pos, "kind": "table",
                                "type": obj.name, "range": stub["range"],
                                "highlight": stub["highlight"]},
                               ParseIssue("flatbuffers.schema.cycle", {"offset": self.base + pos}))
        done = self.ctx.memo.get(key)
        if done is not None:
            return {"node": "ref", "target": self.base + pos, "kind": "table", "type": obj.name,
                    "range": done["range"], "highlight": done["highlight"],
                    "target_node": done}
        try:
            vt = read_vtable(self.buf, pos)
        except TableError as exc:
            return self._issue(stub, table_issue(exc))
        self.ctx.active.add(key)
        self.ctx.cover(*self.rng(*vt.range))
        self.ctx.cover(*self.rng(*vt.inline_range))
        children: list[Node] = [self._vtable_node(vt)]
        known_slots = set()
        for f in obj.fields:
            known_slots.add(f.slot)
            field_node = yield self._table_field(vt, obj, f)
            children.append(field_node)
        stored = sorted(off for off in vt.slots if off)
        for slot, off in enumerate(vt.slots):
            if off and slot not in known_slots:
                # Not in the schema: its width isn't known either; the bytes
                # up to the next stored slot (or the table's end) are shown.
                at = vt.table + off
                nxt = next((o for o in stored if o > off), vt.inline_size)
                end = vt.table + nxt
                children.append(self._issue({
                    "node": "field", "id": slot, "name": None, "stored": True,
                    "gap": nxt - off, "slot_offset": off,
                    "range": self.rng(at, end), "value_range": self.rng(at, end),
                    "highlight": [self.rng(*vt.slot_range(slot)), self.rng(at, end)],
                }, ParseIssue("flatbuffers.schema.slot_not_in_schema", {
                    "slot": slot, "offset": self.base + at, "gap": nxt - off,
                })))
        self.ctx.active.discard(key)
        node: Node = {
            "node": "table", "type": obj.name, "offset": self.base + pos,
            "vtable": self.base + vt.offset, "inline_size": vt.inline_size,
            "slot_count": len(vt.slots),
            "range": self.rng(*vt.inline_range), "highlight": [self.rng(*vt.inline_range)],
            "children": children,
        }
        self.ctx.memo[key] = node
        return node

    def _vtable_node(self, vt: VTable) -> Node:
        return vtable_node(vt, self.base)

    def _field_base(self, f: Field) -> Node:
        node: Node = {"node": "field", "id": f.id, "name": f.name,
                      "type_text": type_text(self.schema, f.type, f), "stored": True}
        if f.deprecated:
            node["deprecated"] = True
        return node

    def _table_field(self, vt: VTable, obj: Object, f: Field) -> _Task:
        node = self._field_base(f)
        slot = f.slot
        off = vt.slots[slot] if slot < len(vt.slots) else 0
        slot_hl = [self.rng(*vt.slot_range(slot))] if slot < len(vt.slots) else []
        if not off:
            node["stored"] = False
            node["range"] = slot_hl[0] if slot_hl else self.rng(vt.offset, vt.offset)
            node["highlight"] = slot_hl
            b = f.type.base_type
            if b in _SCALARS and not f.optional:
                node["value"] = self._default(f)
                node["default"] = True
            if f.required:
                self._issue(node, ParseIssue("flatbuffers.schema.required_missing", {"field": f.name}))
            return node
        pos = vt.table + off
        node["slot_offset"] = off
        try:
            yield self._value(node, pos, f.type, f, obj, vt)
        except OutOfBounds as exc:
            node.setdefault("range", self.rng(pos, pos))
            node.setdefault("highlight", slot_hl)
            self._issue(node, ParseIssue("flatbuffers.schema.out_of_bounds", {
                "offset": self.base + exc.offset, "size": exc.size,
            }))
        node["highlight"] = slot_hl + node.get("highlight", [])
        return node

    def _default(self, f: Field) -> Any:
        b = f.type.base_type
        if b in ("Float", "Double"):
            return f.default_real
        if b == "Bool":
            return bool(f.default_integer)
        return f.default_integer

    # -- values --------------------------------------------------------------

    def _value(
        self, node: Node, pos: int, t: Type, f: Field | None, obj: Object | None,
        vt: VTable | None,
    ) -> _Task:
        """Fill *node* with the value of type *t* stored at *pos* (inline in
        a table or struct)."""
        b = t.base_type
        buf = self.buf
        if b in _SCALARS:
            size = SCALAR_SIZES[b]
            value = read_scalar(buf, pos, b)
            node["value_range"] = self.rng(pos, pos + size)
            node["range"] = self.rng(pos, pos + size)
            node["highlight"] = [self.rng(pos, pos + size)]
            node["value"] = value
            self._enum_value(node, t, value, b)
            return None
        if b == "Obj":
            target_obj = self.schema.objects[t.index]
            if target_obj.is_struct:
                yield self._struct(node, pos, target_obj)
                return None
            target = self._follow(pos, 4)
            node["range"] = self.rng(pos, pos + 4)
            node["highlight"] = [self.rng(pos, pos + 4)]
            if target is None:
                return self._issue(node, ParseIssue("flatbuffers.schema.offset_invalid", {
                    "offset": self.base + pos,
                }))
            table = yield self.table(target, target_obj)
            node["children"] = [table]
            node["highlight"] = node["highlight"] + table["highlight"]
            return None
        if b == "String":
            width = 8 if f is not None and f.offset64 else 4
            target = self._follow(pos, width)
            node["range"] = self.rng(pos, pos + width)
            node["highlight"] = [self.rng(pos, pos + width)]
            if target is None:
                return self._issue(node, ParseIssue("flatbuffers.schema.offset_invalid", {
                    "offset": self.base + pos,
                }))
            self._string(node, target)
            return None
        if b in ("Vector", "Vector64"):
            width = 8 if b == "Vector64" or (f is not None and f.offset64) else 4
            target = self._follow(pos, width)
            node["range"] = self.rng(pos, pos + width)
            node["highlight"] = [self.rng(pos, pos + width)]
            if target is None:
                return self._issue(node, ParseIssue("flatbuffers.schema.offset_invalid", {
                    "offset": self.base + pos,
                }))
            yield self._vector(node, target, t, f, obj, vt, length_size=8 if b == "Vector64" else 4)
            return None
        if b == "Union":
            yield self._union(node, pos, t, f, obj, vt)
            return None
        return self._issue(node, ParseIssue("flatbuffers.schema.type_unsupported", {"type": b}))

    def _enum_value(self, node: Node, t: Type, value: Any, b: str) -> None:
        if b == "Bool" and value not in (0, 1):
            node["bool_byte"] = value
        if t.index < 0 or b in ("Float", "Double", "Bool"):
            return
        enum = self.schema.enums[t.index] if t.index < len(self.schema.enums) else None
        if enum is None:
            return
        if "bit_flags" in enum.attributes:
            names = [v.name for v in enum.values if v.value and (value & v.value) == v.value]
            rest = value
            for v in enum.values:
                if v.value and (value & v.value) == v.value:
                    rest &= ~v.value
            node["enum"] = " | ".join(names) if names else ("0" if value == 0 else "")
            if rest:
                self._issue(node, ParseIssue("flatbuffers.schema.flags_undeclared", {
                    "bits": rest, "enum": enum.name,
                }))
            return
        member = enum.value_named(int(value))
        if member is None:
            self._issue(node, ParseIssue("flatbuffers.schema.enum_undeclared", {
                "value": value, "enum": enum.name,
            }))
        else:
            node["enum"] = member.name

    def _follow(self, pos: int, width: int) -> int | None:
        """Target of the offset (uoffset, or a 64-bit offset) at *pos*, or
        None when it is 0, negative as a signed offset or out of bounds."""
        buf = self.buf
        if not fits(buf, pos, width):
            raise OutOfBounds(pos, width, len(buf))
        value = read_u32(buf, pos) if width == 4 else read_u64(buf, pos)
        if value == 0 or value >= (1 << 31 if width == 4 else 1 << 63):
            return None
        if pos + value >= len(buf):
            return None
        return pos + value

    def _string(self, node: Node, target: int) -> None:
        span = string_at(self.buf, target)
        if span is None:
            self._issue(node, ParseIssue("flatbuffers.schema.string_invalid", {
                "offset": self.base + target,
            }))
            return
        start, end = span
        data = self.buf[start:end]
        self.ctx.cover(*self.rng(target, end + 1))
        node["value_range"] = self.rng(start, end)
        node["target"] = self.base + target
        node["highlight"] = node.get("highlight", []) + [self.rng(target, end + 1)]
        try:
            node["value"] = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            node["value"] = None
            self._issue(node, ParseIssue("flatbuffers.schema.string_not_utf8", {
                "offset": self.base + start + exc.start,
            }))

    def _struct(self, node: Node, pos: int, obj: Object) -> _Task:
        size = obj.bytesize
        if not fits(self.buf, pos, size):
            raise OutOfBounds(pos, size, len(self.buf))
        self.ctx.cover(*self.rng(pos, pos + size))
        node["value_range"] = self.rng(pos, pos + size)
        node["range"] = self.rng(pos, pos + size)
        node["highlight"] = [self.rng(pos, pos + size)]
        node["struct"] = obj.name
        children: list[Node] = []
        for f in sorted(obj.fields, key=lambda x: x.offset):
            child = self._field_base(f)
            at = pos + f.offset
            if f.type.base_type == "Array":
                yield self._array(child, at, f.type)
            else:
                yield self._value(child, at, f.type, f, obj, None)
            children.append(child)
        node["children"] = children
        return None

    def _array(self, node: Node, pos: int, t: Type) -> _Task:
        elem = t.element
        if elem == "Obj":
            sobj = self.schema.objects[t.index]
            esize = sobj.bytesize
        else:
            esize = SCALAR_SIZES[elem]
        total = esize * t.fixed_length
        if not fits(self.buf, pos, total):
            raise OutOfBounds(pos, total, len(self.buf))
        node["range"] = self.rng(pos, pos + total)
        node["highlight"] = [self.rng(pos, pos + total)]
        node["value_range"] = self.rng(pos, pos + total)
        node["count"] = t.fixed_length
        if elem != "Obj":
            node["elements"] = elem
            node["element_size"] = esize
            return None
        children = []
        for i in range(t.fixed_length):
            child: Node = {"node": "element", "index": i}
            yield self._struct(child, pos + i * esize, self.schema.objects[t.index])
            children.append(child)
        node["children"] = children
        return None

    def _vector(
        self, node: Node, target: int, t: Type, f: Field | None, obj: Object | None,
        vt: VTable | None, *, length_size: int,
    ) -> _Task:
        elem = t.element
        if elem in _SCALARS:
            esize = SCALAR_SIZES[elem]
        elif elem == "Obj" and self.schema.objects[t.index].is_struct:
            esize = self.schema.objects[t.index].bytesize
        else:
            esize = 4
        fit = vector_at(self.buf, target, esize, length_size=length_size)
        if fit is None:
            return self._issue(node, ParseIssue("flatbuffers.schema.vector_invalid", {
                "offset": self.base + target,
            }))
        count, data, end = fit
        self.ctx.cover(*self.rng(target, end))
        node["target"] = self.base + target
        node["count"] = count
        node["highlight"] = node.get("highlight", []) + [self.rng(target, end)]
        if elem in _SCALARS:
            node["value_range"] = self.rng(data, end)
            node["elements"] = elem
            node["element_size"] = esize
            nested = f.attributes.get("nested_flatbuffer") if f is not None else None
            if nested is not None:
                yield self._nested(node, data, end, nested, obj)
            if f is not None and "flexbuffer" in f.attributes:
                self._issue(node, ParseIssue("flatbuffers.schema.flexbuffer_not_decoded"))
            if t.index >= 0 and elem != "UType":
                node["enum_elements"] = self.schema.enums[t.index].name
            return None
        children: list[Node] = []
        if elem == "Obj" and self.schema.objects[t.index].is_struct:
            sobj = self.schema.objects[t.index]
            for i in range(count):
                child: Node = {"node": "element", "index": i}
                yield self._struct(child, data + i * esize, sobj)
                children.append(child)
        elif elem in ("Obj", "String"):
            for i in range(count):
                at = data + 4 * i
                child = {"node": "element", "index": i, "range": self.rng(at, at + 4),
                         "highlight": [self.rng(at, at + 4)]}
                target_i = self._follow(at, 4)
                if target_i is None:
                    self._issue(child, ParseIssue("flatbuffers.schema.offset_invalid", {
                        "offset": self.base + at,
                    }))
                elif elem == "String":
                    self._string(child, target_i)
                else:
                    table = yield self.table(target_i, self.schema.objects[t.index])
                    child["children"] = [table]
                    child["highlight"] = child["highlight"] + table["highlight"]
                children.append(child)
        elif elem == "Union":
            types = self._companion_vector(f, obj, vt)
            if types is not None and len(types) != count:
                self._issue(node, ParseIssue("flatbuffers.schema.union_type_count_mismatch", {
                    "field": f.name if f else "?", "types": len(types), "values": count,
                }))
            for i in range(count):
                at = data + 4 * i
                child = {"node": "element", "index": i, "range": self.rng(at, at + 4),
                         "highlight": [self.rng(at, at + 4)]}
                if types is None or i >= len(types):
                    self._issue(child, ParseIssue("flatbuffers.schema.union_type_missing", {
                        "field": f.name if f else "?",
                    }))
                else:
                    yield self._union_member(child, at, t.index, types[i])
                children.append(child)
        else:
            return self._issue(node, ParseIssue("flatbuffers.schema.type_unsupported", {"type": elem}))
        node["children"] = children
        return None

    def _companion_vector(self, f: Field | None, obj: Object | None, vt: VTable | None) -> list[int] | None:
        """The values of the ``<name>_type`` vector a vector of unions is
        paired with, or None when it isn't stored."""
        if f is None or obj is None or vt is None:
            return None
        tf = obj.field_named(f.name + "_type")
        if tf is None or tf.slot >= len(vt.slots) or not vt.slots[tf.slot]:
            return None
        pos = vt.table + vt.slots[tf.slot]
        target = self._follow(pos, 4)
        if target is None:
            return None
        fit = vector_at(self.buf, target, 1)
        if fit is None:
            return None
        count, data, end = fit
        return list(self.buf[data:end])

    def _union(
        self, node: Node, pos: int, t: Type, f: Field | None, obj: Object | None,
        vt: VTable | None,
    ) -> _Task:
        node["range"] = self.rng(pos, pos + 4)
        node["highlight"] = [self.rng(pos, pos + 4)]
        type_value: int | None = None
        if f is not None and obj is not None and vt is not None:
            tf = obj.field_named(f.name + "_type")
            if tf is not None and tf.slot < len(vt.slots) and vt.slots[tf.slot]:
                type_value = int(read_scalar(self.buf, vt.table + vt.slots[tf.slot], "UType"))
        if type_value is None:
            return self._issue(node, ParseIssue("flatbuffers.schema.union_type_missing", {
                "field": f.name if f else "?",
            }))
        yield self._union_member(node, pos, t.index, type_value)
        return None

    def _union_member(self, node: Node, pos: int, enum_index: int, type_value: int) -> _Task:
        enum = self.schema.enums[enum_index]
        member = enum.value_named(type_value)
        if member is None or member.union_type is None:
            return self._issue(node, ParseIssue("flatbuffers.schema.union_member_undeclared", {
                "value": type_value, "enum": enum.name,
            }))
        node["union_member"] = member.name
        if type_value == 0:
            return None  # NONE: nothing stored
        ut = member.union_type
        target = self._follow(pos, 4)
        if target is None:
            return self._issue(node, ParseIssue("flatbuffers.schema.offset_invalid", {
                "offset": self.base + pos,
            }))
        if ut.base_type == "String":
            self._string(node, target)
            return None
        if ut.base_type == "Obj":
            uobj = self.schema.objects[ut.index]
            if uobj.is_struct:
                # A struct in a union is stored out of line, behind the offset.
                child: Node = {"node": "element", "index": 0}
                yield self._struct(child, target, uobj)
                node["children"] = [child]
                return None
            table = yield self.table(target, uobj)
            node["children"] = [table]
            node["highlight"] = node.get("highlight", []) + table["highlight"]
            return None
        return self._issue(node, ParseIssue("flatbuffers.schema.type_unsupported", {
            "type": ut.base_type,
        }))

    def _nested(
        self, node: Node, start: int, end: int, root_name: str, owner: Object | None,
    ) -> _Task:
        """A [ubyte] declared nested_flatbuffer: decoded as its own buffer
        with the declared root type."""
        obj = self._lookup_type(root_name, owner)
        if obj is None or obj.is_struct:
            self._issue(node, ParseIssue("flatbuffers.schema.nested_type_unknown", {"type": root_name}))
            return None
        sub = self.buf[start:end]
        candidates, failures = root_candidates(sub)
        buffers = []
        for layout, root, sub_end in candidates:
            dec = _SchemaDecoder(self.ctx, sub[:sub_end], self.base + start)
            buffers.append((yield dec.buffer(layout, root, obj)))
        if not buffers:
            self._issue(node, ParseIssue("flatbuffers.schema.nested_no_root", {
                "reasons": failures,
            }))
            return None
        node["children"] = buffers
        return None

    def _lookup_type(self, name: str, owner: Object | None) -> Object | None:
        """The type *name* refers to where *owner* is declared, resolved as
        flatc does: in owner's namespace, then each enclosing one, then the
        name as written (schema objects carry their qualified names)."""
        parts = owner.name.split(".")[:-1] if owner is not None else []
        for depth in range(len(parts), -1, -1):
            obj = self.schema.object_named(".".join([*parts[:depth], name]))
            if obj is not None:
                return obj
        return None
