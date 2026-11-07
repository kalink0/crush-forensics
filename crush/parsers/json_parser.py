# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""JSON parser — handles JSON documents."""
from __future__ import annotations

import json
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

# Characters shown on each side of a syntax error's position.
_EXCERPT_RADIUS = 250


class JsonParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".json", ".geojson"]
    DISPLAY_NAME = "JSON document"
    PARSE_OFF_UI_THREAD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        if any(path.lower().endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
            return True
        return starts_like_json_container(peek_bytes)


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


# RFC 8259 §2: the only whitespace allowed around structural characters.
_JSON_WHITESPACE = b" \t\r\n"
# RFC 8259 §3: what a value can start with (object, array, string, number,
# true / false / null).
_JSON_VALUE_STARTS = frozenset(b'{["-0123456789tfn')


def starts_like_json_container(peek_bytes: bytes) -> bool:
    """Whether *peek_bytes* can begin a JSON object or array (RFC 8259).

    After whitespace, ``{`` must be followed by a member name (``"``) or
    ``}``, and ``[`` by a value or ``]``. A lone ``{`` / ``[`` is not enough:
    binary data whose first byte is 0x7B or 0x5B (a length, a count) would
    otherwise open as a broken JSON document. If the peek holds nothing but
    whitespace after the bracket, the start cannot be ruled out.
    """
    head = peek_bytes.lstrip(_JSON_WHITESPACE)
    opener = head[:1]
    if opener not in (b"{", b"["):
        return False
    rest = head[1:].lstrip(_JSON_WHITESPACE)
    if not rest:
        return True
    if opener == b"{":
        return rest[:1] in (b'"', b"}")
    return rest[:1] == b"]" or rest[0] in _JSON_VALUE_STARTS
