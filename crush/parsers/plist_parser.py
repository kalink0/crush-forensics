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
from crush.parsers.nska_archive import archive_stats, is_keyed_archive, root_class
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
    # parse() sets ccl_bplist's module-global object converter, as do
    # crush/core/ios_keybag.py (a different converter) and
    # crush/core/formatters.py. Off the UI thread this is only safe because
    # busy_call's dialog is ApplicationModal: nothing else can start a
    # bplist decode meanwhile. Running any of those in the background too
    # would race.
    PARSE_OFF_UI_THREAD = True

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
            nska_issue: ParseIssue | list[ParseIssue] | None = None
            fmt: str | ParseIssue
            if raw[:6] == _BPLIST_MAGIC:
                fmt = "binary"
                _set_object_converter = cast(Any, set_object_converter)
                _bplist_load = cast(Any, bplist_load)
                _deserialize = cast(Any, deserialise_NsKeyedArchiver)
                _set_object_converter(_nska_converter)
                data = _bplist_load(BytesIO(raw))
                loaded = data
                text_index: str | None = None
                raw_text = ""
                stats = archive_stats(data) if is_keyed_archive(data) else None
                # ccl_bplist resolves lazily, so a UID past the end of
                # $objects fails only when something reaches it -- a later
                # step, or expanding Decoded -- and a cycle never ends (Text
                # tab, Expand All, the filter). Not resolving such an archive
                # at all is the one deterministic way to keep that from
                # surfacing halfway; Decoded then shows the archive as stored.
                unresolvable: list[ParseIssue] = []
                if stats is not None and stats.missing_references:
                    unresolvable.append(ParseIssue(
                        "plist.nska_missing_refs", {"count": stats.missing_references}
                    ))
                if stats is not None and stats.has_cycle:
                    unresolvable.append(ParseIssue("plist.nska_cycle"))
                if unresolvable:
                    fmt = ParseIssue("plist.format_nska_unresolved")
                    nska_issue = unresolvable[0] if len(unresolvable) == 1 else unresolvable
                elif is_keyed_archive(data):
                    try:
                        resolved = _deserialize(data)
                        # Built from the resolved tree inside this try: a
                        # failure there is a failed resolve too, not a failed
                        # plist (which would fall back to hex, counts and the
                        # Stored archive tab lost).
                        raw_text = _text_tab(resolved)
                        text_index = _flatten_text(resolved)
                        data = resolved
                        fmt = "binary (NSKeyedArchiver)"
                    except Exception as nska_exc:
                        fmt = ParseIssue("plist.format_nska_failed")
                        nska_issue = ParseIssue("plist.nska_failed", detail=str(nska_exc))
                        logging.getLogger(__name__).warning(
                            "NSKeyedArchiver deserialization failed for %s: %s", node.path, nska_exc
                        )
                if not raw_text:
                    raw_text = _text_tab(data)
            else:
                fmt = "XML"
                data = plistlib.loads(raw)
                loaded = data
                text_index = None
                if is_keyed_archive(data):
                    fmt = ParseIssue("plist.format_nska_xml")
                    nska_issue = ParseIssue("plist.nska_xml_unresolved")
                raw_text = raw
            meta: dict[str, Any] = {"Format": fmt, "File size": f"{node.size:,} B"}
            if nska_issue is not None:
                meta["Status"] = nska_issue
            hints: dict[str, Any] = {"raw_text": raw_text}
            if is_keyed_archive(loaded):
                meta.update(_archive_metadata(loaded))
                # The archive as stored, in its own tab for every keyed
                # archive -- also where Decoded shows the same (XML, or
                # resolving failed), so it's always found in one place.
                hints["archive"] = loaded
            return ParseResult(
                viewer_type="tree_text",
                data=data,
                metadata=meta,
                text_index=text_index if text_index is not None else _flatten_text(data),
                viewer_hints=hints,
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


def _text_tab(data: Any) -> str:
    """Binary plists have no source text of their own: a readable form of
    the decoded structure for the Text tab."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _archive_metadata(archive: dict[str, Any]) -> dict[str, Any]:
    """Object-graph counts of an NSKeyedArchiver archive, every row shown
    even when 0 (it was checked). See crush/parsers/nska_archive.py."""
    stats = archive_stats(archive)
    if stats is None:
        return {"Objects": ParseIssue("plist.nska_no_graph")}
    return {
        "Root class": root_class(archive),
        "Objects": f"{stats.objects:,}",
        "Shared objects": ParseIssue(
            "plist.nska_shared", {"count": stats.shared, "classes": stats.shared_classes}
        ),
        "Unreachable objects": f"{stats.unreachable:,}",
        "Missing references": f"{stats.missing_references:,}",
        "Top keys": ", ".join(stats.top_keys) or ParseIssue("plist.nska_top_empty"),
    }


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
