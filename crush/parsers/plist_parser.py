"""plist parser — handles both binary and XML plist files."""
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import json
import logging
import plistlib
from typing import Any, cast

from crush.core.derived_bytes import DerivedBytes, expand_derived
from crush.core.issues import ParseIssue
from crush.core.magic import BPLIST_MAGIC, looks_like_plist_xml, xml_plist_body
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.nska_archive import (
    Resolution,
    archive_stats,
    is_keyed_archive,
    resolve_keyed_archive,
    root_class,
    unconvertible_dates,
)
from crush.third_party.ccl_bplist import load as bplist_load

# Kind of a plist decoded from bytes inside another (DerivedBytes.kind).
_KIND_ARCHIVE = "NSKeyedArchiver"
_KIND_PLIST = "plist"


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
        return peek_bytes[:6] == BPLIST_MAGIC or looks_like_plist_xml(peek_bytes)

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        try:
            raw = vfs.read(node)
            reading = read_plist(raw)
            data = reading.data
            text_index: str | None = None
            raw_text: str | bytes = raw if reading.xml else ""
            status = reading.status
            fmt = reading.format
            if reading.resolution is not None and reading.resolution.resolved:
                try:
                    # Built from the resolved tree inside this try: a
                    # failure there is a failed resolve too, not a failed
                    # plist (which would fall back to hex, counts and the
                    # Stored archive tab lost).
                    if not reading.xml:
                        raw_text = _text_tab(data)
                    text_index = _flatten_text(data)
                except Exception as exc:
                    data = reading.loaded
                    fmt = failed_format(reading.xml)
                    status = ParseIssue("plist.nska_failed", detail=str(exc))
                    raw_text = raw if reading.xml else ""
            if reading.resolution is not None and reading.resolution.error is not None:
                logging.getLogger(__name__).warning(
                    "NSKeyedArchiver deserialization failed for %s: %s",
                    node.path, reading.resolution.error,
                )
            if not raw_text:
                raw_text = _text_tab(data)
            meta: dict[str, Any] = {"Format": fmt, "File size": f"{node.size:,} B"}
            if status is not None:
                meta["Status"] = status
            hints: dict[str, Any] = {"raw_text": raw_text}
            if status is not None:
                hints["status"] = status
            if reading.keyed:
                meta.update(_archive_metadata(reading.loaded, resolved=data is not reading.loaded))
                # The archive as stored, in its own tab for every keyed
                # archive -- also where Decoded shows the same (resolving
                # wasn't possible or failed), so it's always found in one place.
                hints["archive"] = reading.loaded
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


@dataclass
class PlistReading:
    """A plist read the one way the parser and the BLOB Inspector read it.

    *loaded*: as stored (for an NSKeyedArchiver archive, the Stored archive
    tab). *data*: what Decoded shows -- the resolved tree, or *loaded* when
    the archive wasn't resolved -- with each plist embedded in a bytes value
    decoded next to it (DerivedBytes). *status*: why an archive wasn't
    resolved; None otherwise."""

    xml: bool
    loaded: Any
    data: Any
    format: str | ParseIssue
    status: ParseIssue | list[ParseIssue] | None
    keyed: bool
    resolution: Resolution | None = None  # for a keyed archive


def read_plist(raw: bytes) -> PlistReading:
    """*raw* read as a plist (binary or XML), an NSKeyedArchiver archive
    resolved; raises with the reason if it isn't a plist."""
    xml = raw[:6] != BPLIST_MAGIC
    if not xml:
        loaded = cast(Any, bplist_load)(BytesIO(raw))
    elif looks_like_plist_xml(raw):
        # Loaded from where the XML starts (a BOM + whitespace before it,
        # no declaration); the bytes themselves stay as stored.
        loaded = plistlib.loads(xml_plist_body(raw), fmt=plistlib.FMT_XML)
    else:
        loaded = plistlib.loads(raw)  # plistlib's own detection (e.g. UTF-16)
    if not is_keyed_archive(loaded):
        return PlistReading(
            xml=xml, loaded=loaded, data=_decode_embedded(loaded),
            format="XML" if xml else "binary", status=None, keyed=False,
        )
    resolution = resolve_keyed_archive(loaded, xml=xml)
    status: ParseIssue | list[ParseIssue] | None
    if resolution.unresolvable:
        issues = list(resolution.unresolvable)
        status = issues[0] if len(issues) == 1 else issues
        fmt: str | ParseIssue = ParseIssue(
            "plist.format_nska_xml" if xml else "plist.format_nska_unresolved"
        )
        data = loaded
    elif resolution.error is not None:
        status = ParseIssue("plist.nska_failed", detail=resolution.error)
        fmt = failed_format(xml)
        data = loaded
    else:
        status = None
        fmt = "XML (NSKeyedArchiver)" if xml else "binary (NSKeyedArchiver)"
        data = _decode_embedded(resolution.tree)
    return PlistReading(
        xml=xml, loaded=loaded, data=data, format=fmt, status=status, keyed=True,
        resolution=resolution,
    )


def failed_format(xml: bool) -> ParseIssue:
    """Format of an archive whose resolving raised."""
    return ParseIssue("plist.format_nska_xml_failed" if xml else "plist.format_nska_failed")


# Why an embedded archive wasn't resolved, worded for its place in the
# tree: there the stored object table isn't shown, Inspect BLOB shows it.
_EMBEDDED_UNRESOLVABLE = {
    "plist.nska_missing_refs": "plist.embedded_nska_missing_refs",
    "plist.nska_cycle": "plist.embedded_nska_cycle",
}


def _embedded(value: bytes) -> DerivedBytes | None:
    """*value* with the plist it holds decoded next to it; None when its
    bytes don't start like a plist. A plist that can't be read, or an
    archive that can't be resolved, gets the reason as its decoded form."""
    if value[:6] != BPLIST_MAGIC and not looks_like_plist_xml(value):
        return None
    try:
        reading = read_plist(value)
    except Exception as exc:
        return DerivedBytes(value, _KIND_PLIST, ParseIssue("plist.embedded_failed", detail=str(exc)))
    if not reading.keyed:
        return DerivedBytes(value, _KIND_PLIST, reading.data)
    resolution = reading.resolution
    if resolution is not None and resolution.unresolvable:
        issues = [
            ParseIssue(_EMBEDDED_UNRESOLVABLE[issue.code], issue.params)
            for issue in resolution.unresolvable
        ]
        return DerivedBytes(value, _KIND_ARCHIVE, issues[0] if len(issues) == 1 else issues)
    if resolution is not None and resolution.error is not None:
        return DerivedBytes(value, _KIND_ARCHIVE, ParseIssue(
            "plist.embedded_nska_failed", detail=resolution.error
        ))
    return DerivedBytes(value, _KIND_ARCHIVE, reading.data, resolved_archive=True)


def _decode_embedded(data: Any) -> Any:
    """*data* with every bytes value that holds a plist (binary or XML,
    archive or not) decoded next to it, recursively: each embedded plist is
    shorter than the one holding it, so this ends without a depth limit."""
    if isinstance(data, bytes):
        return _embedded(data) or data
    stack = [data]
    seen: set[int] = set()
    while stack:
        container = stack.pop()
        if id(container) in seen:
            continue
        seen.add(id(container))
        if isinstance(container, dict):
            entries: Any = list(container.items())
        elif isinstance(container, list):
            entries = list(enumerate(container))
        else:
            continue
        for key, value in entries:
            if isinstance(value, bytes) and not isinstance(value, DerivedBytes):
                decoded = _embedded(value)
                if decoded is not None:
                    container[key] = decoded
            elif isinstance(value, (dict, list)):
                stack.append(value)
    return data


def _text_tab(data: Any) -> str:
    """Binary plists have no source text of their own: a readable form of
    the decoded structure for the Text tab."""
    return json.dumps(expand_derived(data), indent=2, ensure_ascii=False, default=str)


def _archive_metadata(archive: dict[str, Any], *, resolved: bool) -> dict[str, Any]:
    """Object-graph counts of an NSKeyedArchiver archive, every row shown
    even when 0 (it was checked). See crush/parsers/nska_archive.py."""
    stats = archive_stats(archive)
    if stats is None:
        return {"Objects": ParseIssue("plist.nska_no_graph")}
    meta: dict[str, Any] = {
        "Root class": root_class(archive),
        "Objects": f"{stats.objects:,}",
        "Shared objects": ParseIssue(
            "plist.nska_shared", {"count": stats.shared, "classes": stats.shared_classes}
        ),
        "Unreachable objects": f"{stats.unreachable:,}",
        "Missing references": f"{stats.missing_references:,}",
        "Top keys": ", ".join(stats.top_keys) or ParseIssue("plist.nska_top_empty"),
    }
    if resolved:
        # Only a resolved tree converts dates; unresolved, all is as stored.
        meta["NSDate kept as stored"] = ParseIssue(
            "plist.nska_dates_kept", {"count": unconvertible_dates(archive) or 0}
        )
    return meta


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
    elif isinstance(obj, DerivedBytes):
        _walk(obj.derived, parts, limit)
