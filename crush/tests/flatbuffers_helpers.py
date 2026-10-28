# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Test helpers: a schema decode's node tree in the shape of flatc's JSON
(``flatc --json --strict-json``), to compare against flatc's own output."""
from __future__ import annotations

from typing import Any

from crush.parsers.flatbuffers_schema import typed_element_values

Node = dict[str, Any]


def _typed(values: list[str], base_type: str) -> list[Any]:
    if base_type == "Bool":
        return [v == "true" for v in values]
    if base_type in ("Float", "Double"):
        return [float(v) for v in values]
    return [int(v) for v in values]


def _value(node: Node, raw: bytes) -> Any:
    children = node.get("children") or []
    if children and children[0].get("node") == "buffer":
        # A nested_flatbuffer: flatc writes the nested table.
        return table_json(children[0]["children"][-1], raw)
    if "elements" in node and node.get("value_range"):
        s, e = node["value_range"]
        return _typed(typed_element_values(raw[s:e], node["elements"]), node["elements"])
    if "struct" in node:
        return {c["name"]: _value(c, raw) for c in children}
    if children and children[0].get("node") == "element":
        return [_element(c, raw) for c in children]
    if children and children[0].get("node") in ("table", "ref"):
        return table_json(_resolve(children[0]), raw)
    if "count" in node and not children:
        return []  # an empty vector
    if node.get("enum"):
        # flatc writes bit flags space-separated.
        return node["enum"].replace(" | ", " ")
    return node.get("value")


def _element(element: Node, raw: bytes) -> Any:
    """One vector element: a struct, a table, or a string."""
    if "struct" in element:
        return {c["name"]: _value(c, raw) for c in element.get("children", [])}
    children = element.get("children") or []
    if children and children[0].get("node") in ("table", "ref"):
        return table_json(_resolve(children[0]), raw)
    return element.get("value")


def _resolve(node: Node) -> Node:
    """A table, or the table a "ref" (reached a second time) stands for."""
    return node.get("target_node", node) if node.get("node") == "ref" else node


def table_json(table: Node, raw: bytes) -> dict[str, Any]:
    """The stored fields of *table* (a schema decode's table node) as flatc
    writes them (a union as its _type member name plus the member)."""
    out: dict[str, Any] = {}
    for child in table.get("children", []):
        if child.get("node") != "field" or not child.get("stored") or not child.get("name"):
            continue
        out[child["name"]] = _value(child, raw)
    return out


def root_table(decoded: dict[str, Any], layout: str = "plain") -> Node:
    buffer = next(b for b in decoded["buffers"] if b["layout"] == layout)
    return buffer["children"][-1]
