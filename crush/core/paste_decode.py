# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Pure-Python helpers for Tools → BLOB Inspector (pasted input) — no Qt dependency."""
from __future__ import annotations

import re

from crush.core.blob_decode import HEX_SEPARATORS, DecodeError, decode_base64, decode_hex

# (display_label, filename_hint, parser_display_name)
#   filename_hint        — passed to BytesVFS so extension-based parsers activate
#   parser_display_name  — None = auto-detect, "__hex__" = always open as raw hex
FORMATS: list[tuple[str, str, str | None]] = [
    ("Auto-detect",                    "data.bin",      None),
    ("Binary plist (bplist)",          "data.bplist",   "Property list (plist)"),
    ("XML / Text plist",               "data.plist",    "Property list (plist)"),
    ("JSON",                           "data.json",     "JSON document"),
    ("XML",                            "data.xml",      "XML document"),
    ("SQLite database",                "data.db",       "SQLite database"),
    ("Realm database",                 "data.realm",    "Realm Database"),
    ("Android Binary XML (ABX)",       "data.abx",      "Android Binary XML (ABX)"),
    ("SEGB / Biome",                   "data.segb",     "SEGB (v1/v2)"),
    ("Protobuf (schema-less)",         "data.bin",      "Protobuf (schema-less)"),
    ("Hex view (raw bytes)",           "data.bin",      "__hex__"),
]


# Stable encoding keys for try_decode_input(). Never translate these — they
# are an internal contract with the UI combo (see paste_decode_dialog.py),
# not display text, and must stay stable regardless of the UI language.
ENCODING_AUTO = "auto"
ENCODING_HEX = "hex"
ENCODING_BASE64 = "base64"
ENCODING_UTF8 = "utf8"

_HEX_CHARS = HEX_SEPARATORS | frozenset(b"0123456789abcdefABCDEF")


def try_decode_input(text: str, encoding: str) -> tuple[bytes | None, str]:
    """Decode *text* according to *encoding*.

    Returns ``(bytes_or_None, status_message)``.
    encoding is one of the ENCODING_* constants above. Hex and Base64 are
    decoded strictly (blob_decode); text is taken as it is, untrimmed.
    """
    stripped = text.strip()
    if not stripped:
        return None, "Paste data above"

    if encoding in (ENCODING_HEX, ENCODING_AUTO):
        # Auto only tries hex when nothing but hex digits and separators is there.
        if encoding == ENCODING_HEX or all(
            c in _HEX_CHARS for c in stripped.encode("utf-8", errors="replace")
        ):
            try:
                data = decode_hex(stripped.encode("utf-8", errors="replace")).data
                return data, f"{len(data):,} bytes  (hex)"
            except DecodeError as exc:
                if encoding == ENCODING_HEX:
                    return None, f"Invalid hex input: {exc}"

    if encoding in (ENCODING_BASE64, ENCODING_AUTO):
        # Line breaks are MIME wrapping; any other whitespace means plain
        # text to Auto (and is invalid Base64 when forced).
        if encoding == ENCODING_BASE64 or (
            len(stripped) >= 4 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", stripped)
        ):
            try:
                data = decode_base64(stripped.encode("utf-8", errors="replace")).data
                return data, f"{len(data):,} bytes  (base64)"
            except DecodeError as exc:
                if encoding == ENCODING_BASE64:
                    return None, f"Invalid base64 input: {exc}"

    # UTF-8 text: the text as pasted, leading/trailing whitespace included
    data = text.encode("utf-8", errors="replace")
    return data, f"{len(data):,} bytes  (UTF-8 text)"
