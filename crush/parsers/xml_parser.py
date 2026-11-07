"""XML parser."""
from __future__ import annotations

from typing import Any

from crush.core.issues import ParseIssue
from crush.core.magic import looks_like_plist_xml
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

# Characters shown on each side of a syntax error's position (as for JSON).
_EXCERPT_RADIUS = 250


class XmlParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".xml"]
    DISPLAY_NAME = "XML document"
    PARSE_OFF_UI_THREAD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        if not starts_like_xml_document(peek_bytes):
            return False
        if path.lower().endswith(".plist"):
            return False
        return not looks_like_plist_xml(peek_bytes)

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        from lxml import etree
        raw = vfs.read(node)
        try:
            root = etree.fromstring(raw)
            data = _element_to_dict(root)
            text = " ".join(str(t) for t in root.itertext())[:4000]
        except etree.XMLSyntaxError as exc:
            # A window around the error position, not the file's start (same
            # as the JSON parser); the whole file stays reachable via Open as
            # → Text / Hex (see xml.syntax_error).
            text = raw.decode("utf-8", errors="replace")
            pos = _char_offset(text, *exc.position)
            start = max(0, pos - _EXCERPT_RADIUS)
            end = min(len(text), pos + _EXCERPT_RADIUS)
            data = {
                "error": str(exc),
                f"excerpt (chars {start:,}–{end:,} of {len(text):,})": text[start:end],
            }
            return ParseResult(
                viewer_type="tree",
                data=data,
                metadata={
                    "File size": f"{node.size:,} B",
                    "Format": ParseIssue("xml.format_parse_failed"),
                    "Status": ParseIssue("xml.syntax_error", detail=str(exc)),
                },
                text_index="",
            )
        return ParseResult(
            viewer_type="tree_text",
            data=data,
            metadata={"File size": f"{node.size:,} B"},
            text_index=text,
            viewer_hints={"raw_text": raw},
        )


# XML 1.0 (Fifth Edition) §2.3 S: the only whitespace allowed before markup.
_XML_WHITESPACE = b" \t\r\n"


def starts_like_xml_document(peek_bytes: bytes) -> bool:
    """Whether *peek_bytes* can begin a UTF-8 XML document (XML 1.0 §2.1).

    A document opens, after an optional UTF-8 BOM (Appendix F) and
    whitespace, with markup: ``<?`` (XML declaration or processing
    instruction), ``<!`` (comment or DOCTYPE) or the root element's start
    tag, i.e. ``<`` followed by a NameStartChar (§2.3). A lone ``<`` is not
    enough: binary data whose first byte is 0x3C (a length, a count) would
    otherwise open as a broken XML document.
    """
    start = 3 if peek_bytes.startswith(b"\xef\xbb\xbf") else 0
    head = peek_bytes[start:].lstrip(_XML_WHITESPACE)
    if head[:1] != b"<":
        return False
    if head[1:2] in (b"?", b"!"):
        return True
    # The first character after "<", decoded as UTF-8 (at most 4 bytes).
    for length in range(1, 5):
        try:
            char = head[1:1 + length].decode("utf-8")
        except UnicodeDecodeError:
            continue
        return len(char) == 1 and _is_name_start_char(char)
    return False


def _is_name_start_char(char: str) -> bool:
    """XML 1.0 (Fifth Edition) §2.3 production [4] NameStartChar."""
    cp = ord(char)
    return (
        char in ":_"
        or "A" <= char <= "Z"
        or "a" <= char <= "z"
        or 0xC0 <= cp <= 0xD6
        or 0xD8 <= cp <= 0xF6
        or 0xF8 <= cp <= 0x2FF
        or 0x370 <= cp <= 0x37D
        or 0x37F <= cp <= 0x1FFF
        or 0x200C <= cp <= 0x200D
        or 0x2070 <= cp <= 0x218F
        or 0x2C00 <= cp <= 0x2FEF
        or 0x3001 <= cp <= 0xD7FF
        or 0xF900 <= cp <= 0xFDCF
        or 0xFDF0 <= cp <= 0xFFFD
        or 0x10000 <= cp <= 0xEFFFF
    )


def _element_to_dict(el: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"@tag": str(el.tag)}
    if el.attrib:
        result["@attribs"] = dict(el.attrib)
    if el.text and el.text.strip():
        result["@text"] = el.text.strip()
    children: list[dict[str, Any]] = []
    map_entries: dict[str, list[Any]] = {}
    for child in el:
        child_dict = _element_to_dict(child)
        children.append(child_dict)

        name_attr = _get_attrib(child, "name")
        if name_attr is not None:
            value: Any | None = _get_attrib(child, "value")
            if value is None:
                if child.text and child.text.strip():
                    value = child.text.strip()
                elif len(child):
                    value = child_dict
                else:
                    value = ""
            map_entries.setdefault(name_attr, []).append(value)

    if children:
        result["@children"] = children
    if map_entries:
        normalized_map = {
            key: values[0] if len(values) == 1 else values
            for key, values in map_entries.items()
        }
        # For Android-style <map>, show entries directly at the root
        # so users don't have to drill into @children/@map to see values.
        if _local_tag(el) == "map":
            result.update(normalized_map)
        else:
            result["@map"] = normalized_map
    return result


def _char_offset(text: str, line: int, column: int) -> int:
    """Offset in *text* of lxml's 1-based (line, column) error position."""
    offset = 0
    for _ in range(max(0, line - 1)):
        newline = text.find("\n", offset)
        if newline == -1:
            return len(text)
        offset = newline + 1
    return min(len(text), offset + max(0, column - 1))


def _local_tag(el: Any) -> str:
    tag = str(getattr(el, "tag", ""))
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _get_attrib(el: Any, name: str) -> str | None:
    for key, value in getattr(el, "attrib", {}).items():
        if key == name or key.endswith(f"}}{name}"):
            return str(value)
    return None
