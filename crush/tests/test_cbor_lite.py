# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the minimal CBOR decoder used by the C2PA reader."""
from __future__ import annotations

from crush.parsers.cbor_lite import cbor_decode


def test_unsigned_integers() -> None:
    assert cbor_decode(bytes([0x00]))[0] == 0
    assert cbor_decode(bytes([0x17]))[0] == 23
    assert cbor_decode(bytes([0x18, 0xFF]))[0] == 255
    assert cbor_decode(bytes([0x19, 0x01, 0x00]))[0] == 256
    assert cbor_decode(bytes([0x1A, 0x00, 0x01, 0x00, 0x00]))[0] == 65536


def test_negative_integers() -> None:
    assert cbor_decode(bytes([0x20]))[0] == -1
    assert cbor_decode(bytes([0x29]))[0] == -10


def test_byte_string() -> None:
    data = bytes([0x44, 0x01, 0x02, 0x03, 0x04])
    val, pos = cbor_decode(data)
    assert val == b"\x01\x02\x03\x04"
    assert pos == len(data)


def test_text_string() -> None:
    data = bytes([0x64]) + b"c2pa"
    val, pos = cbor_decode(data)
    assert val == "c2pa"
    assert pos == len(data)


def test_array() -> None:
    # [1, 2, 3]
    data = bytes([0x83, 0x01, 0x02, 0x03])
    val, pos = cbor_decode(data)
    assert val == [1, 2, 3]
    assert pos == len(data)


def test_map() -> None:
    # {"a": 1}
    data = bytes([0xA1, 0x61, ord("a"), 0x01])
    val, pos = cbor_decode(data)
    assert val == {"a": 1}
    assert pos == len(data)


def test_bool_and_null() -> None:
    assert cbor_decode(bytes([0xF4]))[0] is False
    assert cbor_decode(bytes([0xF5]))[0] is True
    assert cbor_decode(bytes([0xF6]))[0] is None


def test_tagged_value_is_transparent() -> None:
    # tag 0 (date/time string) wrapping a text string -- tag itself is
    # ignored, only the wrapped value matters for our use case.
    data = bytes([0xC0, 0x61, ord("x")])
    val, pos = cbor_decode(data)
    assert val == "x"
    assert pos == len(data)


def test_nested_map_matches_real_c2pa_claim_shape() -> None:
    # {"claim_generator": "acme/1.0", "assertions": ["a", "b"]}
    import struct

    def tstr(s: str) -> bytes:
        b = s.encode()
        return bytes([0x60 | len(b)]) + b if len(b) < 24 else struct.pack("B", 0x78) + bytes([len(b)]) + b

    data = bytes([0xA2])
    data += tstr("claim_generator") + tstr("acme/1.0")
    data += tstr("assertions") + bytes([0x82]) + tstr("a") + tstr("b")

    val, pos = cbor_decode(data)
    assert val == {"claim_generator": "acme/1.0", "assertions": ["a", "b"]}
    assert pos == len(data)
