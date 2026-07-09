# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SEGB v1/v2 parser (vendored from ccl-segb, MIT)."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.proto_interp import interpret_fixed64
from crush.parsers.proto_wire import read_varint as _read_varint
from crush.third_party.ccl_segb import ccl_segb1, ccl_segb2

_logger = logging.getLogger(__name__)

_COLUMNS_V1 = [
    "Index", "Offset", "State",
    "Timestamp1", "Timestamp2",
    "CRC Stored", "CRC Calc", "CRC Passed",
    "Payload Size",
    "Payload",
]

_COLUMNS_V2 = [
    "Index", "Offset", "State",
    "Creation",
    "Trailer Offset", "Entry End Offset",
    "CRC Stored", "CRC Calc", "CRC Passed",
    "Payload Size",
    "Payload",
]


class SegbParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".segb", ".segb1", ".segb2", ".biome"]
    DISPLAY_NAME = "SEGB (v1/v2)"

    _SEGB_V1_MAGIC_OFFSET = 52

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        if any(path.lower().endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
            return True
        if peek_bytes.startswith(b"SEGB"):
            return True
        end = self._SEGB_V1_MAGIC_OFFSET + 4
        if len(peek_bytes) >= end and peek_bytes[self._SEGB_V1_MAGIC_OFFSET:end] == b"SEGB":
            return True
        return False

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        try:
            raw = vfs.read(node)
            result = _detect_and_read(BytesIO(raw))
            if result is None:
                return ParseResult(
                    viewer_type="hex",
                    data=raw,
                    metadata={
                        "Parse error": "Not a recognized SEGB v1/v2 file",
                        "Format": "SEGB (unrecognized)",
                        "File size": f"{node.size:,} B",
                    },
                )
            version, columns, rows, parse_error = result
            meta: dict[str, Any] = {
                "Format": "SEGB",
                "Version": version,
                "File size": f"{node.size:,} B",
                "Records": f"{len(rows):,}",
            }
            if parse_error:
                meta["Parse warning"] = parse_error
            data: dict[str, Any] = {"SEGB": {"columns": columns, "rows": rows}}
            tmp = _create_segb_sqlite(columns, rows)
            if tmp:
                data["__db_path"] = str(tmp)
            return ParseResult(
                viewer_type="table",
                data=data,
                metadata=meta,
                viewer_hints={"show_db_tabs": False},
            )
        except Exception as exc:
            _logger.warning("SEGB parse error for %s: %s", node.path, exc)
            try:
                raw_bytes = vfs.read(node)
            except Exception:
                raw_bytes = b""
            return ParseResult(
                viewer_type="hex",
                data=raw_bytes,
                metadata={
                    "Parse error": str(exc),
                    "Format": "SEGB (parse failed)",
                    "File size": f"{node.size:,} B",
                },
            )


_JSON_SAFE_INT_MAX = 2 ** 53


def _json_safe(val: object) -> object:
    """Coerce a value to something SQLite JSON can handle without precision loss."""
    if isinstance(val, int) and (val > _JSON_SAFE_INT_MAX or val < -_JSON_SAFE_INT_MAX):
        return str(val)
    return val


def _scalar_to_json(val: Any) -> Any:
    """Convert a single protobuf field value to a JSON-serializable object.

    Floats are kept as JSON numbers (never swapped for a formatted-date string,
    even when they fall in a plausible Cocoa-timestamp range) so a field's type
    stays consistent for callers doing json_extract() comparisons."""
    if isinstance(val, bytes):
        sub = _parse_protobuf(val)
        if sub:
            return {str(fn): _scalar_to_json(fv) for fn, fv in sub.items()}
        return val.hex()
    return _json_safe(val)


def _proto_to_json(data: bytes) -> str:
    """Serialize a protobuf payload as JSON for sql json_extract() querying.
    Always returns valid JSON — empty object if the payload cannot be decoded.
    Repeated fields (same field number) are stored as JSON arrays."""
    try:
        fields = _parse_protobuf(data)
        obj: dict[str, Any] = {}
        for field_num, val in fields.items():
            key = str(field_num)
            if isinstance(val, list):
                obj[key] = [_scalar_to_json(v) for v in val]
            else:
                obj[key] = _scalar_to_json(val)
        return json.dumps(obj, ensure_ascii=True)
    except Exception:
        return "{}"


def _create_segb_sqlite(columns: list[str], rows: list[list[Any]]) -> Path | None:
    """Dump SEGB rows into a temp SQLite file for SQL querying. Returns path or None.

    The Payload column stores the human-readable rendered text.
    A companion "Payload JSON" column stores the protobuf fields as JSON so
    callers can use json_extract("Payload JSON", '$.N') for field queries.
    """
    try:
        p_idx = columns.index("Payload")
    except ValueError:
        p_idx = -1

    ext_cols = list(columns)
    if p_idx >= 0:
        ext_cols.insert(p_idx + 1, "Payload JSON")

    def _sql_val(v: object, is_json_col: bool = False) -> object:
        if isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], bytes):
            if is_json_col:
                return _proto_to_json(v[1])
            return v[0] if v[0] else f"<{len(v[1])} B>"  # rendered text or size hint
        if is_json_col:
            raw = v if isinstance(v, (bytes, bytearray)) else b""
            return _proto_to_json(bytes(raw))
        if isinstance(v, (bytes, bytearray)):
            return v  # store as SQLite BLOB
        return v

    def _expand_row(row: list[Any]) -> list[Any]:
        if p_idx < 0:
            return [_sql_val(v) for v in row]
        out: list[Any] = []
        for i, v in enumerate(row):
            out.append(_sql_val(v, is_json_col=False))
            if i == p_idx:
                out.append(_sql_val(v, is_json_col=True))
        return out

    try:
        fd, path_str = tempfile.mkstemp(suffix=".db", prefix="crush_segb_")
        os.close(fd)
        conn = sqlite3.connect(path_str)
        col_defs = ", ".join(f'"{c}"' for c in ext_cols)
        conn.execute(f'CREATE TABLE "SEGB" ({col_defs})')  # noqa: S608
        placeholders = ", ".join("?" * len(ext_cols))
        conn.executemany(
            f'INSERT INTO "SEGB" VALUES ({placeholders})',  # noqa: S608
            [_expand_row(row) for row in rows],
        )
        conn.commit()
        conn.close()
        return Path(path_str)
    except Exception:
        return None


def _detect_and_read(
    stream: BytesIO,
) -> tuple[str, list[str], list[list[Any]], str] | None:
    """Detect SEGB version and parse; returns (version, columns, rows, error) or None."""
    if ccl_segb2.stream_matches_segbv2_signature(stream):
        stream.seek(0)
        columns, rows, error = _read_v2(stream)
        return "v2", columns, rows, error
    stream.seek(0)
    if ccl_segb1.stream_matches_segbv1_signature(stream):
        stream.seek(0)
        columns, rows, error = _read_v1(stream)
        return "v1", columns, rows, error
    return None


def _read_v1(stream: BytesIO) -> tuple[list[str], list[list[Any]], str]:
    rows: list[list[Any]] = []
    error = ""
    try:
        for idx, entry in enumerate(ccl_segb1.read_segb1_stream(stream)):
            try:
                rendered = _render_proto_payload(entry.data)
                rows.append([
                    idx,
                    entry.data_start_offset,
                    entry.state.name,
                    _fmt_ts(entry.timestamp1),
                    _fmt_ts(entry.timestamp2),
                    entry.metadata_crc,
                    entry.actual_crc,
                    entry.crc_passed,
                    len(entry.data),
                    (rendered, entry.data),
                ])
            except Exception as exc:
                error = f"Record {idx} failed: {exc}"
                break
    except Exception as exc:
        error = str(exc)
    return _COLUMNS_V1, rows, error


def _read_v2(stream: BytesIO) -> tuple[list[str], list[list[Any]], str]:
    rows: list[list[Any]] = []
    error = ""
    try:
        for idx, entry in enumerate(ccl_segb2.read_segb2_stream(stream)):
            try:
                rendered = _render_proto_payload(entry.data)
                rows.append([
                    idx,
                    entry.data_start_offset,
                    entry.state.name,
                    _fmt_ts(entry.metadata.creation),
                    entry.metadata.metadata_offset,
                    entry.metadata.end_offset,
                    entry.metadata_crc,
                    entry.actual_crc,
                    entry.crc_passed,
                    len(entry.data),
                    (rendered, entry.data),
                ])
            except Exception as exc:
                error = f"Record {idx} failed: {exc}"
                break
    except Exception as exc:
        error = str(exc)
    return _COLUMNS_V2, rows, error


def _fmt_ts(ts: object) -> str:
    try:
        return str(ts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Minimal protobuf wire-format decoder (no external dependency)
# ---------------------------------------------------------------------------



def _parse_protobuf(data: bytes) -> dict[int, Any]:
    """Parse protobuf wire format into {field_number: value}. Best-effort, stops on error.

    Repeated fields (same field number more than once) are collected into a list.
    Field numbers up to 2^29-1 are accepted (the protobuf spec maximum).
    """
    result: dict[int, Any] = {}
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        if tag is None:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7
        if field_num == 0 or field_num >= (1 << 29):
            break
        val: Any
        if wire_type == 0:  # varint
            val, pos = _read_varint(data, pos)
            if val is None:
                break
        elif wire_type == 1:  # 64-bit (double)
            if pos + 8 > len(data):
                break
            val = struct.unpack_from("<d", data, pos)[0]
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            if length is None or pos + length > len(data):
                break
            chunk = data[pos:pos + length]
            try:
                val = chunk.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                val = chunk
            pos += length
        elif wire_type == 5:  # 32-bit (float)
            if pos + 4 > len(data):
                break
            val = struct.unpack_from("<f", data, pos)[0]
            pos += 4
        else:
            break
        # Accumulate repeated fields into a list
        if field_num in result:
            existing = result[field_num]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[field_num] = [existing, val]
        else:
            result[field_num] = val
    return result


def _cocoa_hint(val: float) -> str | None:
    """Labeled Cocoa-timestamp hint for a double field, or None if out of the
    plausible range. Delegates the range check and conversion to proto_interp's
    interpret_fixed64 so every schema-less protobuf decoder in this codebase
    agrees on what counts as a plausible timestamp, instead of each keeping its
    own hand-picked threshold."""
    for interp in interpret_fixed64(struct.pack("<d", val)):
        if interp.label == "Cocoa timestamp":
            return interp.value
    return None


def _render_field(field_num: int, val: object, *, nested: bool = False) -> str | None:
    """Render a single protobuf field as a string, or return None to skip it."""
    sep = ":" if nested else ": "
    if isinstance(val, list):
        parts = [r for v in val if (r := _render_field(field_num, v, nested=nested)) is not None]
        return parts[0] if len(parts) == 1 else (f"{field_num}{sep}[{', '.join(p.split(sep, 1)[1] for p in parts)}]" if parts else None)
    if isinstance(val, str):
        return f'{field_num}{sep}"{val}"'
    if isinstance(val, float):
        hint = _cocoa_hint(val)
        suffix = f" [possible Cocoa timestamp: {hint}]" if hint else ""
        return f"{field_num}{sep}{val:.6g}{suffix}"
    if isinstance(val, bytes):
        sub = _parse_protobuf(val)
        preview = val[:16].hex() + ("…" if len(val) > 16 else "")
        if not sub:
            return f"{field_num}{sep}<{len(val)} B: {preview}>"
        inner = ", ".join(
            r for fn, fv in sorted(sub.items())
            if (r := _render_field(fn, fv, nested=True)) is not None
        )
        # Wire type 2 doesn't declare whether these bytes really are a nested
        # message — they just happen to be grammatically valid protobuf.
        # Always show the raw bytes alongside it (same convention as the
        # standalone Protobuf Viewer), instead of presenting the guess as fact.
        return f"{field_num}{sep}{{{inner}}} [raw: {len(val)} B: {preview}]"
    return f"{field_num}{sep}{val}"


def _render_proto_payload(data: bytes) -> str:
    """Return a compact single-line protobuf representation, or '' if decoding fails."""
    try:
        fields = _parse_protobuf(data)
        if not fields:
            return ""
        parts = [
            r for fn, fv in sorted(fields.items())
            if (r := _render_field(fn, fv)) is not None
        ]
        return "  |  ".join(parts)
    except Exception:
        return ""
