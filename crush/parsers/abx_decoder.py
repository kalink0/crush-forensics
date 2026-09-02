# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Best-effort ABX (Android Binary XML) decoder."""
from __future__ import annotations

import base64
import re
import struct
from dataclasses import dataclass


PROTOCOL_MAGIC_VERSION_0 = b"ABX\x00"

# Token types (lower nibble) match XmlPullParser constants.
START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4
CDSECT = 5
ENTITY_REF = 6
IGNORABLE_WHITESPACE = 7
PROCESSING_INSTRUCTION = 8
COMMENT = 9
DOCDECL = 10
ATTRIBUTE = 15

# Data types (upper nibble)
TYPE_NULL = 1 << 4
TYPE_STRING = 2 << 4
TYPE_STRING_INTERNED = 3 << 4
TYPE_BYTES_HEX = 4 << 4
TYPE_BYTES_BASE64 = 5 << 4
TYPE_INT = 6 << 4
TYPE_INT_HEX = 7 << 4
TYPE_LONG = 8 << 4
TYPE_LONG_HEX = 9 << 4
TYPE_FLOAT = 10 << 4
TYPE_DOUBLE = 11 << 4
TYPE_BOOLEAN_TRUE = 12 << 4
TYPE_BOOLEAN_FALSE = 13 << 4


@dataclass
class AbxDecodeResult:
    xml: str
    warnings: list[str]


def decode_abx(data: bytes) -> AbxDecodeResult:
    """Decode ABX bytes into XML (best-effort)."""
    warnings: list[str] = []
    if not data.startswith(PROTOCOL_MAGIC_VERSION_0):
        return AbxDecodeResult("", ["Missing ABX magic header"])

    reader = _AbxReader(data)
    reader.pos = len(PROTOCOL_MAGIC_VERSION_0)

    out: list[str] = ["<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"]
    tag_stack: list[str] = []
    open_tag = False
    root_element_count = 0
    token_start_pos = reader.pos

    try:
        while reader.pos < len(data):
            token_start_pos = reader.pos
            token_byte = reader.read_u8()
            token = token_byte & 0x0F
            dtype = token_byte & 0xF0

            if token == START_DOCUMENT:
                continue
            if token == END_DOCUMENT:
                break

            if token == START_TAG:
                if open_tag:
                    out.append(">")
                    open_tag = False
                if not tag_stack:
                    root_element_count += 1
                name = _to_string(reader.read_value(dtype))
                if not name:
                    name = "unknown"
                    warnings.append("Empty start tag name")
                out.append(f"<{_xml_escape(name, warnings)}")
                open_tag = True
                tag_stack.append(name)

                # Consume attributes immediately following start tag.
                while reader.pos < len(data):
                    next_byte = reader.peek_u8()
                    if (next_byte & 0x0F) != ATTRIBUTE:
                        break
                    reader.read_u8()  # consume
                    attr_type = next_byte & 0xF0
                    attr_name = _to_string(reader.read_interned_utf())
                    attr_val = reader.read_value(attr_type)
                    attr_val_str = _to_string(attr_val)
                    out.append(
                        f' {_xml_escape(attr_name, warnings)}="{_xml_escape(attr_val_str, warnings)}"'
                    )
                continue

            if token == END_TAG:
                name = _to_string(reader.read_value(dtype))
                if open_tag and tag_stack and tag_stack[-1] == name:
                    out.append("/>")
                    open_tag = False
                    tag_stack.pop()
                    continue
                if open_tag:
                    out.append(">")
                    open_tag = False
                if tag_stack:
                    tag_stack.pop()
                out.append(f"</{_xml_escape(name, warnings)}>")
                continue

            if token == TEXT:
                text = _to_string(reader.read_value(dtype))
                if open_tag:
                    out.append(">")
                    open_tag = False
                out.append(_xml_escape(text, warnings))
                continue

            if token == CDSECT:
                text = _to_string(reader.read_value(dtype))
                if open_tag:
                    out.append(">")
                    open_tag = False
                out.append(f"<![CDATA[{_sanitize_control_chars(text, warnings)}]]>")
                continue

            if token == COMMENT:
                text = _to_string(reader.read_value(dtype))
                if open_tag:
                    out.append(">")
                    open_tag = False
                out.append(f"<!--{_xml_escape(text, warnings)}-->")
                continue

            if token == IGNORABLE_WHITESPACE:
                # Per XmlPullParser semantics this is formatting whitespace
                # between structural elements — safe to discard, matches how
                # any XML serializer would treat it. Not a data loss.
                _ = reader.read_value(dtype)
                continue

            if token in (ENTITY_REF, PROCESSING_INSTRUCTION, DOCDECL):
                # These carry semantic content unlike IGNORABLE_WHITESPACE.
                # Android's BinaryXmlSerializer is not known to emit them, so
                # we don't guess at exact re-encoded syntax (would be a
                # heuristic) — surface the raw value visibly instead of
                # silently dropping it, and flag it so it gets a second look.
                token_name = {
                    ENTITY_REF: "ENTITY_REF",
                    PROCESSING_INSTRUCTION: "PROCESSING_INSTRUCTION",
                    DOCDECL: "DOCDECL",
                }[token]
                value = _to_string(reader.read_value(dtype))
                warnings.append(f"Unsupported {token_name} token encountered (rare/unverified format)")
                if open_tag:
                    out.append(">")
                    open_tag = False
                out.append(f"<!--{token_name}: {_xml_escape(value, warnings)}-->")
                continue

            if token == ATTRIBUTE:
                # Attribute outside of a start tag; best-effort skip.
                _ = reader.read_interned_utf()
                _ = reader.read_value(dtype)
                warnings.append("Dangling attribute token")
                continue

            warnings.append(f"Unknown token: {token}")
            _ = reader.read_value(dtype)

        if open_tag:
            out.append(">")
    except Exception as exc:
        remaining = len(data) - token_start_pos
        warnings.insert(
            0,
            f"TRUNCATED: decode error at offset {token_start_pos} (0x{token_start_pos:x}): "
            f"{exc} — {remaining} of {len(data)} bytes not decoded",
        )
        if open_tag:
            out.append(">")
            open_tag = False
        out.append(
            f"<!--ABX-DECODE-TRUNCATED at offset {token_start_pos}: "
            f"{remaining} bytes not decoded ({_xml_escape(str(exc), warnings)})-->"
        )

    if root_element_count > 1:
        warnings.append(
            f"Multiple root elements ({root_element_count}) found; wrapped in "
            f"synthetic <abx-root> for well-formed XML"
        )
        out.insert(1, "<abx-root>")
        out.append("</abx-root>")

    return AbxDecodeResult("".join(out), warnings)


class _AbxReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self._string_pool: list[str] = []

    def read_u8(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val

    def peek_u8(self) -> int:
        return self.data[self.pos]

    def read_u16(self) -> int:
        val = (self.data[self.pos] << 8) | self.data[self.pos + 1]
        self.pos += 2
        return val

    def read_i32(self) -> int:
        val = int(struct.unpack(">i", self.data[self.pos : self.pos + 4])[0])
        self.pos += 4
        return val

    def read_i64(self) -> int:
        val = int(struct.unpack(">q", self.data[self.pos : self.pos + 8])[0])
        self.pos += 8
        return val

    def read_f32(self) -> float:
        val = float(struct.unpack(">f", self.data[self.pos : self.pos + 4])[0])
        self.pos += 4
        return val

    def read_f64(self) -> float:
        val = float(struct.unpack(">d", self.data[self.pos : self.pos + 8])[0])
        self.pos += 8
        return val

    def read_bytes(self, length: int) -> bytes:
        val = self.data[self.pos : self.pos + length]
        self.pos += length
        return val

    def read_utf(self) -> str:
        length = self.read_u16()
        return _decode_modified_utf8(self.read_bytes(length))

    def read_interned_utf(self) -> str:
        ref = self.read_u16()
        if ref == 0xFFFF:
            s = self.read_utf()
            if len(self._string_pool) < 0xFFFF:
                self._string_pool.append(s)
            return s
        if ref < len(self._string_pool):
            return self._string_pool[ref]
        raise ValueError(f"Invalid ABX string pool reference: {ref}")

    def read_value(self, dtype: int) -> object | None:
        if dtype == TYPE_NULL:
            return None
        if dtype == TYPE_STRING:
            return self.read_utf()
        if dtype == TYPE_STRING_INTERNED:
            return self.read_interned_utf()
        if dtype == TYPE_BYTES_HEX:
            size = self.read_u16()
            return self.read_bytes(size).hex()
        if dtype == TYPE_BYTES_BASE64:
            size = self.read_u16()
            raw = self.read_bytes(size)
            return base64.b64encode(raw).decode("ascii")
        if dtype == TYPE_INT:
            return self.read_i32()
        if dtype == TYPE_INT_HEX:
            return _int_to_hex(self.read_i32())
        if dtype == TYPE_LONG:
            return self.read_i64()
        if dtype == TYPE_LONG_HEX:
            return _int_to_hex(self.read_i64())
        if dtype == TYPE_FLOAT:
            return self.read_f32()
        if dtype == TYPE_DOUBLE:
            return self.read_f64()
        if dtype == TYPE_BOOLEAN_TRUE:
            return True
        if dtype == TYPE_BOOLEAN_FALSE:
            return False
        raise ValueError(f"Unknown ABX value type: 0x{dtype:02x}")


def _int_to_hex(value: int) -> str:
    if value < 0:
        return f"-{abs(value):x}"
    return f"{value:x}"


def _to_string(value: object | None) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _xml_escape(text: str, warnings: list[str] | None = None) -> str:
    escaped = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
    )
    return _sanitize_control_chars(escaped, warnings)


# XML 1.0 only permits #x9 | #xA | #xD | [#x20-...]; raw control bytes below
# that (as can occur in real-world settings_secure.xml values) break any
# downstream well-formed-XML parse. Rather than silently stripping forensic
# byte content, re-encode each one visibly so it survives the round-trip.
_INVALID_XML_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _sanitize_control_chars(text: str, warnings: list[str] | None = None) -> str:
    if not _INVALID_XML_CHARS.search(text):
        return text
    control_char_warning = (
        "Raw XML-illegal control character(s) found in decoded value(s); "
        "re-encoded as \\xHH to keep the XML well-formed"
    )
    if warnings is not None and control_char_warning not in warnings:
        warnings.append(control_char_warning)
    return _INVALID_XML_CHARS.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def _decode_modified_utf8(data: bytes) -> str:
    codes: list[int] = []
    i = 0
    length = len(data)
    while i < length:
        b = data[i]
        if b < 0x80:
            codes.append(b)
            i += 1
        elif (b & 0xE0) == 0xC0 and i + 1 < length:
            b2 = data[i + 1]
            code = ((b & 0x1F) << 6) | (b2 & 0x3F)
            codes.append(code)
            i += 2
        elif (b & 0xF0) == 0xE0 and i + 2 < length:
            b2 = data[i + 1]
            b3 = data[i + 2]
            code = ((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
            codes.append(code)
            i += 3
        else:
            codes.append(0xFFFD)
            i += 1

    # Combine surrogate pairs if present
    out_chars: list[str] = []
    i = 0
    while i < len(codes):
        code = codes[i]
        if 0xD800 <= code <= 0xDBFF and i + 1 < len(codes):
            low = codes[i + 1]
            if 0xDC00 <= low <= 0xDFFF:
                combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                out_chars.append(chr(combined))
                i += 2
                continue
        out_chars.append(chr(code))
        i += 1
    return "".join(out_chars)
