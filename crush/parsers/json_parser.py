# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""JSON parser — handles JSON documents."""
from __future__ import annotations

import json
from typing import Any

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.issues import ParseIssue

# Characters shown on each side of a syntax error's position.
_EXCERPT_RADIUS = 250


class JsonParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".json", ".geojson"]
    DISPLAY_NAME = "JSON document"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        if any(path.lower().endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
            return True
        stripped = peek_bytes.lstrip()
        return stripped[:1] in (b"{", b"[")

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        encoding_issue: ParseIssue | None = None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            text = raw.decode("utf-8", errors="replace")
            encoding_issue = ParseIssue(
                "json.not_utf8", params={"offset": exc.start}, detail=exc.reason,
            )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # The tree shows a window around the error position, not the
            # file's start: the start is rarely where the problem is. The
            # key states exactly which part it is; the whole file stays
            # reachable via Open as → Text / Hex (see json.syntax_error).
            start = max(0, exc.pos - _EXCERPT_RADIUS)
            end = min(len(text), exc.pos + _EXCERPT_RADIUS)
            data = {
                "error": str(exc),
                f"excerpt (chars {start:,}–{end:,} of {len(text):,})": text[start:end],
            }
            meta: dict[str, Any] = {
                "File size": f"{node.size:,} B",
                "Format": "JSON (parse error)",
                "Status": ParseIssue("json.syntax_error", detail=str(exc)),
            }
            if encoding_issue is not None:
                meta["Encoding"] = encoding_issue
            return ParseResult(
                viewer_type="tree",
                data=data,
                metadata=meta,
                text_index="",
            )
        meta = {"File size": f"{node.size:,} B", "Format": "JSON"}
        if encoding_issue is not None:
            meta["Encoding"] = encoding_issue
        return ParseResult(
            viewer_type="tree_text",
            data=data,
            metadata=meta,
            text_index=_flatten_text(data),
            viewer_hints={"raw_text": text},
        )


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
