"""Hex fallback — catches anything unrecognised and shows raw bytes."""
from __future__ import annotations

from typing import Any

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

# Parsers that never claim a file from its content, and how to reach them
# instead ("Open as" menu entry); see _parser_support.
_OPEN_AS_ONLY = {"ProtobufParser": "Protobuf", "MMKVParser": "MMKV"}


class HexFallbackParser(AbstractParser):
    DISPLAY_NAME = "Hex viewer (fallback)"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return True  # Always matches — must be registered last

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        try:
            raw = vfs.read(node)
        except Exception as exc:
            return ParseResult(
                viewer_type="hex",
                data=b"",
                metadata={
                    "Read error": ParseIssue("hexfallback.read_error", detail=str(exc)),
                    "File size": f"{node.size:,} B",
                    "Extension": node.extension or "(none)",
                },
            )

        meta: dict[str, Any] = {
            "File size": f"{node.size:,} B",
            "Extension": node.extension or "(none)",
        }

        # Identify the format even though we can't parse it. The row is
        # always there: identified, not identified, or why that failed.
        try:
            from crush.core.format_db import FormatDatabase
            fmt = FormatDatabase.get().identify(raw[:512], node.name)
        except Exception as exc:
            meta["Format (identified)"] = ParseIssue("hexfallback.identify_failed", detail=str(exc))
            fmt = None
        else:
            if fmt is None:
                meta["Format (identified)"] = ParseIssue("hexfallback.not_identified")
        if fmt:
            meta["Format (identified)"] = fmt.name
            if fmt.category:
                meta["Category"] = fmt.category
            if fmt.platforms:
                meta["Platforms"] = fmt.platforms.replace(",", ", ")
            if fmt.forensic_relevance:
                meta["Forensic relevance"] = fmt.forensic_relevance
            if fmt.links:
                meta["Reference"] = "\n".join(url for _label, url in fmt.links)
            meta["Parser support"] = _parser_support(fmt.parser_class)

        return ParseResult(viewer_type="hex", data=raw, metadata=meta)


def _parser_support(parser_class: str | None) -> ParseIssue:
    """What "supported" means for a file that ended up here anyway: a
    content-detected parser didn't match it, or the format is reached
    another way (Open as, as a source, as a folder, in Multi-Log Studio)."""
    if not parser_class:
        return ParseIssue("hexfallback.parser_none")
    if parser_class in _OPEN_AS_ONLY:
        return ParseIssue("hexfallback.parser_open_as", {"name": _OPEN_AS_ONLY[parser_class]})
    if parser_class.endswith("VFS"):
        return ParseIssue("hexfallback.parser_source")
    if parser_class == "LeveldbParser":
        return ParseIssue("hexfallback.parser_folder")
    if parser_class == "UnifiedLogConverter":
        return ParseIssue("hexfallback.parser_logs")
    return ParseIssue("hexfallback.parser_mismatch")
