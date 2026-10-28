# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FlatBuffers binary primitives, bounds-checked.

The layout follows the FlatBuffers internals documentation
(https://flatbuffers.dev/internals/): little-endian scalars; a buffer starts
with a uoffset_t (uint32) to the root table; a table starts with a soffset_t
(int32) that is subtracted from the table's position to find its vtable; a
vtable is uint16 vtable size, uint16 table inline size, then one uint16
offset per field slot (0 = not stored); strings and vectors start with a
uint32 element count, a string ends with a NUL byte that the count excludes.

Every read checks the buffer bounds and returns None (or raises
:class:`OutOfBounds`) instead of reading past the end, so callers can report
the exact offset that doesn't fit.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

# Scalar struct formats by FlatBuffers base type name (reflection.fbs BaseType).
SCALAR_FORMATS: dict[str, str] = {
    "UType": "<B",
    "Bool": "<B",
    "Byte": "<b",
    "UByte": "<B",
    "Short": "<h",
    "UShort": "<H",
    "Int": "<i",
    "UInt": "<I",
    "Long": "<q",
    "ULong": "<Q",
    "Float": "<f",
    "Double": "<d",
}
SCALAR_SIZES: dict[str, int] = {name: struct.calcsize(fmt) for name, fmt in SCALAR_FORMATS.items()}

UOFFSET_SIZE = 4
SOFFSET_SIZE = 4
VOFFSET_SIZE = 2
FILE_IDENTIFIER_LENGTH = 4


class OutOfBounds(ValueError):
    """A read of *size* bytes at *offset* doesn't fit the buffer."""

    def __init__(self, offset: int, size: int, buffer_size: int) -> None:
        super().__init__(f"{size} B at offset {offset:#x} exceed the buffer ({buffer_size:,} B)")
        self.offset = offset
        self.size = size
        self.buffer_size = buffer_size


def fits(buf: bytes, offset: int, size: int) -> bool:
    return 0 <= offset and size >= 0 and offset + size <= len(buf)


def read_scalar(buf: bytes, offset: int, base_type: str) -> int | float:
    """The scalar of *base_type* at *offset*; raises OutOfBounds."""
    fmt = SCALAR_FORMATS[base_type]
    size = SCALAR_SIZES[base_type]
    if not fits(buf, offset, size):
        raise OutOfBounds(offset, size, len(buf))
    value: int | float = struct.unpack_from(fmt, buf, offset)[0]
    return value


def read_u8(buf: bytes, offset: int) -> int:
    return int(read_scalar(buf, offset, "UByte"))


def read_u16(buf: bytes, offset: int) -> int:
    return int(read_scalar(buf, offset, "UShort"))


def read_u32(buf: bytes, offset: int) -> int:
    return int(read_scalar(buf, offset, "UInt"))


def read_i32(buf: bytes, offset: int) -> int:
    return int(read_scalar(buf, offset, "Int"))


def read_u64(buf: bytes, offset: int) -> int:
    return int(read_scalar(buf, offset, "ULong"))


@dataclass(frozen=True)
class VTable:
    """A table's vtable as stored: where it is, its two header fields and
    the field slot offsets (relative to the table; 0 = not stored)."""

    table: int
    offset: int
    vtable_size: int
    inline_size: int
    slots: tuple[int, ...]

    @property
    def soffset_range(self) -> tuple[int, int]:
        return (self.table, self.table + SOFFSET_SIZE)

    @property
    def range(self) -> tuple[int, int]:
        return (self.offset, self.offset + self.vtable_size)

    @property
    def inline_range(self) -> tuple[int, int]:
        return (self.table, self.table + self.inline_size)

    def slot_range(self, slot: int) -> tuple[int, int]:
        start = self.offset + 2 * VOFFSET_SIZE + slot * VOFFSET_SIZE
        return (start, start + VOFFSET_SIZE)


class TableError(ValueError):
    """Why the bytes at a position are not a table: a short reason code
    and the facts (offsets) it is about."""

    def __init__(self, code: str, **params: int) -> None:
        super().__init__(code)
        self.code = code
        self.params = params


def read_vtable(buf: bytes, table: int, *, start: int = 0) -> VTable:
    """The vtable of the table at *table*, validated against the buffer
    (*start* .. end) as the FlatBuffers verifier does (VerifyTableStart:
    the soffset fits, the vtable lies in the buffer and is 2-aligned, its
    size is even and at least 4, the table's inline data fits). Raises
    TableError with the reason otherwise."""
    if (table - start) % 4:
        raise TableError("table_unaligned", table=table)
    if table < start or not fits(buf, table, SOFFSET_SIZE):
        raise TableError("table_out_of_bounds", table=table)
    vt = table - read_i32(buf, table)
    if vt < start or not fits(buf, vt, 2 * VOFFSET_SIZE):
        raise TableError("vtable_out_of_bounds", table=table, vtable=vt)
    if (vt - start) % 2:
        raise TableError("vtable_unaligned", table=table, vtable=vt)
    vt_size = read_u16(buf, vt)
    inline_size = read_u16(buf, vt + VOFFSET_SIZE)
    if vt_size < 2 * VOFFSET_SIZE or vt_size % 2:
        raise TableError("vtable_size_invalid", table=table, vtable=vt, size=vt_size)
    if not fits(buf, vt, vt_size):
        raise TableError("vtable_out_of_bounds", table=table, vtable=vt)
    if inline_size < SOFFSET_SIZE or not fits(buf, table, inline_size):
        raise TableError("table_inline_out_of_bounds", table=table, size=inline_size)
    count = (vt_size - 2 * VOFFSET_SIZE) // VOFFSET_SIZE
    slots = tuple(read_u16(buf, vt + 2 * VOFFSET_SIZE + i * VOFFSET_SIZE) for i in range(count))
    for slot, off in enumerate(slots):
        if off and (off < SOFFSET_SIZE or off >= inline_size):
            raise TableError(
                "slot_outside_table", table=table, slot=slot, offset=off, size=inline_size
            )
    return VTable(table, vt, vt_size, inline_size, slots)


def string_at(buf: bytes, pos: int, *, start: int = 0, length_size: int = 4) -> tuple[int, int] | None:
    """(data start, data end) of a string whose length field is at *pos*,
    or None when it isn't one: length field 4-aligned and in bounds, the
    data and the NUL terminator in bounds, terminator 0 (Verifier::VerifyString)."""
    if pos < start or (pos - start) % 4 or not fits(buf, pos, length_size):
        return None
    length = read_u32(buf, pos) if length_size == 4 else read_u64(buf, pos)
    data = pos + length_size
    if not fits(buf, data, length + 1) or buf[data + length] != 0:
        return None
    return (data, data + length)


def vector_at(
    buf: bytes, pos: int, element_size: int, *, start: int = 0, length_size: int = 4
) -> tuple[int, int, int] | None:
    """(element count, data start, data end) of a vector whose length field
    is at *pos* with elements of *element_size* bytes, or None when it
    doesn't fit (Verifier::VerifyVectorOrString)."""
    if pos < start or (pos - start) % 4 or not fits(buf, pos, length_size):
        return None
    count = read_u32(buf, pos) if length_size == 4 else read_u64(buf, pos)
    data = pos + length_size
    if not fits(buf, data, count * element_size):
        return None
    return (count, data, data + count * element_size)
