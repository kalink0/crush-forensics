# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Protobuf parser — schema-less wire decode.

Explicit-only parser. Use "Open as Protobuf Viewer" from the context menu.
"""
from __future__ import annotations

from typing import Any

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.proto_interp import Interpretation, interpret_fixed32, interpret_fixed64, interpret_varint
from crush.parsers.proto_wire import read_varint


class ProtobufParser(AbstractParser):
    """Schema-less Protobuf decoder (wire format only)."""

    DISPLAY_NAME = "Protobuf (schema-less)"
    SUPPORTED_EXTENSIONS: list[str] = []

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False  # Explicit-only

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        decoded, warning, text_index = _decode_message(raw)
        meta: dict[str, Any] = {
            "Format": "Protobuf (schema-less)",
            "File size": f"{node.size:,} B",
            "Entries": str(len(decoded.get("entries", []))),
        }
        if warning:
            meta["Parse warning"] = warning
        return ParseResult(
            viewer_type="protobuf",
            data={"raw": raw, "decoded": decoded},
            metadata=meta,
            text_index=text_index,
        )


# ---------------------------------------------------------------------------
# Wire-format decoder (schema-less)
# ---------------------------------------------------------------------------


def _decode_message(
    raw: bytes,
    *,
    depth: int = 0,
    max_depth: int = 6,
    max_entries: int = 50_000,
) -> tuple[dict[str, Any], str, str]:
    """Decode a protobuf message into a structured dict.

    Returns: (decoded, warning, text_index)
    """
    entries: list[dict[str, Any]] = []
    warning = ""
    text_parts: list[str] = []

    idx = 0
    try:
        while idx < len(raw):
            if len(entries) >= max_entries:
                warning = f"Entry limit reached ({max_entries:,})"
                break
            key, idx = _read_varint(raw, idx)
            if key is None:
                warning = "Truncated varint key"
                break
            field_no = key >> 3
            wire_type = key & 0x7

            if wire_type == 0:  # varint
                val, idx = _read_varint(raw, idx)
                if val is None:
                    warning = "Truncated varint value"
                    break
                entries.append({
                    "field": field_no,
                    "wire_type": "varint",
                    "value": val,
                    "interpretations": interpret_varint(val),
                })

            elif wire_type == 1:  # 64-bit
                if idx + 8 > len(raw):
                    warning = "Truncated 64-bit value"
                    break
                chunk = raw[idx:idx + 8]
                val = int.from_bytes(chunk, "little", signed=False)
                idx += 8
                entries.append({
                    "field": field_no,
                    "wire_type": "fixed64",
                    "value": val,
                    "interpretations": interpret_fixed64(chunk),
                })

            elif wire_type == 5:  # 32-bit
                if idx + 4 > len(raw):
                    warning = "Truncated 32-bit value"
                    break
                chunk = raw[idx:idx + 4]
                val = int.from_bytes(chunk, "little", signed=False)
                idx += 4
                entries.append({
                    "field": field_no,
                    "wire_type": "fixed32",
                    "value": val,
                    "interpretations": interpret_fixed32(chunk),
                })

            elif wire_type == 2:  # length-delimited
                length, idx = _read_varint(raw, idx)
                if length is None:
                    warning = "Truncated length-delimited size"
                    break
                if idx + length > len(raw):
                    warning = "Truncated length-delimited payload"
                    break
                payload = raw[idx:idx + length]
                idx += length

                entry: dict[str, Any] = {
                    "field": field_no,
                    "wire_type": "length-delimited",
                    "length": length,
                }

                if payload:
                    nested_ok = False
                    if depth < max_depth:
                        nested, nested_warn, nested_text = _decode_message(
                            payload, depth=depth + 1, max_depth=max_depth, max_entries=max_entries
                        )
                        if not nested_warn and nested.get("entries"):
                            entry["value"] = {"type": "message", "entries": nested["entries"]}
                            if nested_text:
                                text_parts.append(nested_text)
                            nested_ok = True
                            # A length-delimited field decodes as a "message" just
                            # because its bytes happen to be grammatically valid
                            # protobuf — wire type 2 doesn't declare whether the
                            # payload really is a submessage. Always show the raw
                            # bytes alongside it (like the scalar interpretations
                            # below), instead of presenting the guess as fact.
                            entry["interpretations"] = [
                                Interpretation("raw bytes", _bytes_preview(payload)["hex_preview"])
                            ]
                    if not nested_ok:
                        if _looks_like_utf8(payload):
                            text = payload.decode("utf-8", errors="replace")
                            entry["value"] = {"type": "string", "text": text}
                            text_parts.append(text)
                        else:
                            entry["value"] = _bytes_preview(payload)
                else:
                    entry["value"] = {"type": "bytes", "length": 0, "hex_preview": ""}

                # Full payload, independent of the (possibly truncated) preview above —
                # so a viewer's "Inspect BLOB…" / expanded-value display never shows less
                # than the field actually contains.
                entry["raw"] = payload

                entries.append(entry)

            elif wire_type == 3:  # start group — deprecated; skip and continue
                idx, ok = _skip_group(raw, idx, field_no)
                if not ok:
                    warning = f"Truncated group field {field_no}"
                    break

            elif wire_type == 4:  # end group — unexpected at top level
                warning = f"Unexpected end-group tag for field {field_no}"
                break

            else:
                warning = f"Unknown wire type: {wire_type}"
                break

    except Exception as exc:  # noqa: BLE001
        warning = f"Decode error: {exc}"

    decoded = {"entries": entries}
    text_index = " ".join(_limit_text(text_parts))
    return decoded, warning, text_index


_read_varint = read_varint


def _skip_group(data: bytes, idx: int, field_no: int) -> tuple[int, bool]:
    """Skip a deprecated group (wire types 3/4) and return (new_idx, ok).

    Reads fields until the matching end-group tag (wire_type=4, same field_no).
    Returns ok=False on truncation or field-number mismatch.
    """
    while idx < len(data):
        key, idx = _read_varint(data, idx)
        if key is None:
            return idx, False
        f = key >> 3
        wt = key & 0x7
        if wt == 4:  # end group — must match opening field number
            return idx, f == field_no
        elif wt == 0:  # varint
            val, idx = _read_varint(data, idx)
            if val is None:
                return idx, False
        elif wt == 1:  # fixed64
            if idx + 8 > len(data):
                return idx, False
            idx += 8
        elif wt == 2:  # length-delimited
            length, idx = _read_varint(data, idx)
            if length is None or idx + length > len(data):
                return idx, False
            idx += length
        elif wt == 3:  # nested start group
            idx, ok = _skip_group(data, idx, f)
            if not ok:
                return idx, False
        elif wt == 5:  # fixed32
            if idx + 4 > len(data):
                return idx, False
            idx += 4
        else:
            return idx, False
    return idx, False  # EOF without matching end-group tag


def _looks_like_utf8(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except Exception:
        return False
    if not text:
        return False
    # Heuristic: mostly printable
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / max(1, len(text)) > 0.9


def _bytes_preview(data: bytes, max_len: int = 64) -> dict[str, Any]:
    preview = data[:max_len].hex(" ")
    if len(data) > max_len:
        preview = f"{preview} …"
    return {"type": "bytes", "length": len(data), "hex_preview": preview}


def _limit_text(parts: list[str], max_chars: int = 4000) -> list[str]:
    out: list[str] = []
    total = 0
    for part in parts:
        if not part:
            continue
        if total + len(part) > max_chars:
            out.append(part[: max_chars - total])
            break
        out.append(part)
        total += len(part)
    return out
