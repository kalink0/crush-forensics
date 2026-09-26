# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Pure formatting/parsing helpers (non-Qt) for viewers and parsers."""
from __future__ import annotations

from typing import Any


def pretty_json(text: str) -> str | None:
    try:
        import json
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return None


def try_base64_text(blob: bytes) -> str | None:
    try:
        import base64
        decoded = base64.b64decode(blob, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def try_plist_text(blob: bytes) -> str | None:
    try:
        import plistlib
        from io import BytesIO
        obj = plistlib.loads(blob)
        if isinstance(obj, dict) and obj.get("$archiver") in ("NSKeyedArchiver", "NRKeyedArchiver"):
            try:
                from crush.third_party.ccl_bplist import (
                    load as bplist_load,
                    deserialise_NsKeyedArchiver,
                    set_object_converter,
                )
                from crush.parsers.plist_parser import _nska_converter
                from typing import cast, Any as _Any
                cast(_Any, set_object_converter)(_nska_converter)
                raw = cast(_Any, bplist_load)(BytesIO(blob))
                obj = cast(_Any, deserialise_NsKeyedArchiver)(raw)
            except Exception:
                pass
        return pretty_object(obj)
    except Exception:
        return None


def try_xml_text(blob: bytes) -> str | None:
    try:
        from lxml import etree
        root = etree.fromstring(blob)
        return etree.tostring(root, pretty_print=True, encoding="unicode")
    except Exception:
        return None


def pretty_object(obj: Any) -> str:
    try:
        import pprint
        return pprint.pformat(obj, width=120)
    except Exception:
        return str(obj)


def bytes_to_hexview(b: bytes, width: int = 16, max_bytes: int = -1) -> str:
    """Hex + ASCII dump of *b*, all of it unless the caller passes *max_bytes*
    (then the caller has to say the dump is cut)."""
    if max_bytes > -1:
        b = b[:max_bytes]
    offset = 0
    lines: list[str] = []
    while offset < len(b):
        chunk = b[offset:offset + width]
        ascii_part = "".join(chr(x) if 0x20 <= x < 0x7F else "." for x in chunk)
        hex_part = " ".join(f"{x:02x}" for x in chunk).ljust(width * 3 - 1)
        lines.append(f"{offset:08x}: {hex_part}  {ascii_part}")
        offset += width
    return "\n".join(lines)
