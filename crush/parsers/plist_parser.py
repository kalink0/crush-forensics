"""plist parser — handles both binary and XML plist files."""
from __future__ import annotations

from io import BytesIO
import json
import logging
import plistlib
from typing import Any, cast

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.third_party.ccl_bplist import (
    load as bplist_load,
    deserialise_NsKeyedArchiver,
    NSKeyedArchiver_common_objects_convertor,
    set_object_converter,
)

_BPLIST_MAGIC = b"bplist"
_XML_PLIST_SIG = b"<?xml"


class PlistParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".plist", ".sfl", ".archive"]
    DISPLAY_NAME = "Property list (plist)"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        if peek_bytes[:6] == _BPLIST_MAGIC:
            return True
        if peek_bytes[:5] == _XML_PLIST_SIG:
            return _is_plist_xml(peek_bytes)
        return False

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        try:
            raw = vfs.read(node)
            raw_text: str | bytes
            nska_issue: ParseIssue | None = None
            fmt: str | ParseIssue
            if raw[:6] == _BPLIST_MAGIC:
                fmt = "binary"
                _set_object_converter = cast(Any, set_object_converter)
                _bplist_load = cast(Any, bplist_load)
                _deserialize = cast(Any, deserialise_NsKeyedArchiver)
                _set_object_converter(_nska_converter)
                data = _bplist_load(BytesIO(raw))
                if isinstance(data, dict) and data.get("$archiver") in ("NSKeyedArchiver", "NRKeyedArchiver"):
                    try:
                        data = _deserialize(data)
                        fmt = "binary (NSKeyedArchiver)"
                    except Exception as nska_exc:
                        fmt = ParseIssue("plist.format_nska_failed")
                        nska_issue = ParseIssue("plist.nska_failed", detail=str(nska_exc))
                        logging.getLogger(__name__).warning(
                            "NSKeyedArchiver deserialization failed for %s: %s", node.path, nska_exc
                        )
                # Binary plists have no source text of their own — reconstruct
                # a readable form of the decoded structure for the Text tab.
                raw_text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
            else:
                fmt = "XML"
                data = plistlib.loads(raw)
                raw_text = raw
            meta: dict[str, Any] = {"Format": fmt, "File size": f"{node.size:,} B"}
            if nska_issue is not None:
                meta["Status"] = nska_issue
            return ParseResult(
                viewer_type="tree_text",
                data=data,
                metadata=meta,
                text_index=_flatten_text(data),
                viewer_hints={"raw_text": raw_text},
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("Plist parse error for %s: %s", node.path, exc)
            try:
                raw_bytes = vfs.read(node)
            except Exception:
                raw_bytes = b""
            return ParseResult(
                viewer_type="hex",
                data=raw_bytes,
                metadata={
                    "Parse error": ParseIssue("plist.parse_failed", detail=str(exc)),
                    "Format": ParseIssue("plist.format_parse_failed"),
                    "File size": f"{node.size:,} B",
                },
            )


def _nska_converter(obj: Any) -> Any:
    """Wrapper around ccl_bplist's converter adding NSData, NSNull and NSDateComponents."""
    result = cast(Any, NSKeyedArchiver_common_objects_convertor)(obj)
    if result is not obj or not isinstance(obj, dict):
        return result
    classname = ""
    class_meta = obj.get("$class")
    if isinstance(class_meta, dict):
        classname = class_meta.get("$classname", "")
    if classname in ("NSData", "NSMutableData"):
        return obj.get("NS.data", b"")
    if classname == "NSNull":
        return None
    if classname == "NSDateComponents":
        _COMPONENT_LABELS = [
            ("NS.year", "year"), ("NS.month", "month"), ("NS.day", "day"),
            ("NS.hour", "hour"), ("NS.minute", "min"), ("NS.second", "sec"),
            ("NS.weekday", "weekday"), ("NS.weekOfYear", "week"),
        ]
        parts = [
            f"{label}={obj[field]}"
            for field, label in _COMPONENT_LABELS
            if field in obj and obj[field] not in (None, -1)
        ]
        return f"NSDateComponents({', '.join(parts)})"
    return result


def _flatten_text(obj: Any, max_chars: int = 4000) -> str:
    parts: list[str] = []
    _walk(obj, parts, max_chars)
    return " ".join(parts)


def _walk(obj: Any, parts: list[str], limit: int) -> None:
    if len(" ".join(parts)) >= limit:
        return
    if isinstance(obj, str):
        parts.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            parts.append(str(k))
            _walk(v, parts, limit)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _walk(item, parts, limit)


def _is_plist_xml(peek_bytes: bytes) -> bool:
    text = peek_bytes[:2048].decode("utf-8", errors="ignore")
    return "<plist" in text.lower()
