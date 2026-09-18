# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Minimal read-only CBOR decoder (RFC 8949), pure Python.

Used to decode C2PA claim/assertion/signature payloads, which are plain
CBOR maps and arrays -- no need for a third-party dependency just to read
a handful of well-known structures.
"""
from __future__ import annotations

import struct
from typing import Any

CBORValue = Any


def cbor_decode(data: bytes, pos: int = 0) -> tuple[CBORValue, int]:
    """Decode one CBOR data item starting at *pos*. Returns (value, next_pos)."""
    b0 = data[pos]
    major = b0 >> 5
    info = b0 & 0x1F
    pos += 1

    length: int | None
    if info < 24:
        length = info
    elif info == 24:
        length = data[pos]
        pos += 1
    elif info == 25:
        length = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
    elif info == 26:
        length = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
    elif info == 27:
        length = int.from_bytes(data[pos:pos + 8], "big")
        pos += 8
    elif info == 31:
        length = None  # indefinite length
    else:
        raise ValueError(f"reserved additional info {info}")

    if major == 0:  # unsigned integer
        assert length is not None, "indefinite length is not valid for major type 0"
        return length, pos
    if major == 1:  # negative integer
        assert length is not None, "indefinite length is not valid for major type 1"
        return -1 - length, pos
    if major == 2:  # byte string
        return _decode_string(data, pos, length, bytes)
    if major == 3:  # text string
        raw, pos = _decode_string(data, pos, length, bytes)
        return raw.decode("utf-8", errors="replace"), pos
    if major == 4:  # array
        return _decode_array(data, pos, length)
    if major == 5:  # map
        return _decode_map(data, pos, length)
    if major == 6:  # tagged value -- tag itself is forensically uninteresting here
        return cbor_decode(data, pos)
    if major == 7:  # simple values / floats
        return _decode_simple(data, pos, info, length)
    raise ValueError(f"unsupported major type {major}")


def _decode_string(
    data: bytes, pos: int, length: int | None, _t: type,
) -> tuple[bytes, int]:
    if length is not None:
        return data[pos:pos + length], pos + length
    out = bytearray()
    while data[pos] != 0xFF:
        chunk, pos = cbor_decode(data, pos)
        out += chunk if isinstance(chunk, bytes) else chunk.encode("utf-8")
    return bytes(out), pos + 1


def _decode_array(data: bytes, pos: int, length: int | None) -> tuple[list[CBORValue], int]:
    items: list[CBORValue] = []
    if length is None:
        while data[pos] != 0xFF:
            item, pos = cbor_decode(data, pos)
            items.append(item)
        return items, pos + 1
    for _ in range(length):
        item, pos = cbor_decode(data, pos)
        items.append(item)
    return items, pos


def _decode_map(data: bytes, pos: int, length: int | None) -> tuple[dict[CBORValue, CBORValue], int]:
    result: dict[CBORValue, CBORValue] = {}
    if length is None:
        while data[pos] != 0xFF:
            k, pos = cbor_decode(data, pos)
            v, pos = cbor_decode(data, pos)
            result[k] = v
        return result, pos + 1
    for _ in range(length):
        k, pos = cbor_decode(data, pos)
        v, pos = cbor_decode(data, pos)
        result[k] = v
    return result, pos


def _decode_simple(
    data: bytes, pos: int, info: int, length: int | None,
) -> tuple[CBORValue, int]:
    if info == 20:
        return False, pos
    if info == 21:
        return True, pos
    if info in (22, 23):
        return None, pos
    if info == 26:
        return struct.unpack_from(">f", data, pos - 4)[0], pos
    if info == 27:
        return struct.unpack_from(">d", data, pos - 8)[0], pos
    return length, pos
