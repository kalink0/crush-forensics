# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ABX (Android Binary XML) parser.

Uses the best-effort decoder in `abx_decoder` to reconstruct XML, then
parses that XML into a nested dict for the tree viewer.
"""
from __future__ import annotations

from typing import Any

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.parsers.abx_decoder import decode_abx

_MAGIC = b"ABX\x00"


class AbxParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".xml"]   # ABX files keep the .xml extension on Android
    DISPLAY_NAME = "Android Binary XML (ABX)"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[:4] == _MAGIC

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        try:
            decoded = decode_abx(raw)
            xml_str = decoded.xml
            display_xml_str = xml_str
            try:
                root = _parse_xml(xml_str)
                tree = _element_to_dict(root)
                # decode_abx emits one continuous line with no whitespace
                # between elements; re-indent for the "Reconstructed XML"
                # pane so it wraps into readable lines instead of one very
                # long unbroken one.
                display_xml_str = _pretty_print(root, fallback=xml_str)
            except Exception as exc:
                tree = {
                    "error": str(exc),
                    "hint": "XML reconstruction failed; see right pane",
                }
            meta: dict[str, Any] = {
                "Format": "Android Binary XML (ABX)",
                "File size": f"{node.size:,} B",
            }
            if decoded.warnings:
                shown = decoded.warnings[:3]
                remaining = len(decoded.warnings) - len(shown)
                summary = "; ".join(shown)
                if remaining > 0:
                    summary += f" (+{remaining} more)"
                meta["Warnings"] = summary
            return ParseResult(
                viewer_type="abx",
                data={"tree": tree, "xml_str": display_xml_str},
                metadata=meta,
                text_index=display_xml_str[:4000],
            )
        except Exception as exc:
            # Fallback: show error in tree viewer
            return ParseResult(
                viewer_type="tree",
                data={"error": str(exc), "hint": "File may be a newer ABX version"},
                metadata={"Format": "ABX (parse error)", "File size": f"{node.size:,} B"},
            )


def _parse_xml(xml_str: str) -> Any:
    from lxml import etree

    return etree.fromstring(xml_str.encode("utf-8", errors="replace"))


def _pretty_print(root: Any, fallback: str) -> str:
    from lxml import etree

    try:
        # lxml refuses xml_declaration=True with encoding="unicode", so
        # serialize to utf-8 bytes (gets the real declaration) and decode.
        return etree.tostring(
            root, pretty_print=True, xml_declaration=True, encoding="utf-8"
        ).decode("utf-8")
    except Exception:
        return fallback


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
        if _local_tag(el) == "map":
            result.update(normalized_map)
        else:
            result["@map"] = normalized_map
    return result


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
