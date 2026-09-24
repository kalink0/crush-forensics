# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Pure-Python helpers for the Paste & Decode feature — no Qt dependency."""
from __future__ import annotations

import base64
import re

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


def try_decode_input(text: str, encoding: str) -> tuple[bytes | None, str]:
    """Decode *text* according to *encoding*.

    Returns ``(bytes_or_None, status_message)``.
    encoding is one of the ENCODING_* constants above.
    """
    text = text.strip()
    if not text:
        return None, "Paste data above"

    if encoding in (ENCODING_HEX, ENCODING_AUTO):
        cleaned = re.sub(r"[\s:_-]", "", text)
        if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
            try:
                data = bytes.fromhex(cleaned)
                return data, f"{len(data):,} bytes  (hex)"
            except ValueError:
                pass
        if encoding == ENCODING_HEX:
            return None, "Invalid hex input"

    if encoding in (ENCODING_BASE64, ENCODING_AUTO):
        # Strip line breaks (MIME wrapping) but not spaces — spaces indicate plain text
        b64_candidate = re.sub(r"[\r\n]", "", text)
        if re.fullmatch(r"[A-Za-z0-9+/=]+", b64_candidate) and len(b64_candidate) >= 4:
            try:
                data = base64.b64decode(b64_candidate + "==")
                return data, f"{len(data):,} bytes  (base64)"
            except Exception:
                pass
        if encoding == ENCODING_BASE64:
            return None, "Invalid base64 input"

    # UTF-8 text fallback
    data = text.encode("utf-8", errors="replace")
    return data, f"{len(data):,} bytes  (UTF-8 text)"
