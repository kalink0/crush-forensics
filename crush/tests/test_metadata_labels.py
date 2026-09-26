# SPDX-License-Identifier: Apache-2.0
"""Every metadata key the code sets is in the label catalog -- otherwise it
would silently stay English in a translated Properties panel."""
from __future__ import annotations

import ast
from pathlib import Path

from crush.core.metadata_labels import METADATA_LABELS

PACKAGE = Path(__file__).resolve().parents[1]
# Variables / keyword arguments that hold a result's (displayed) metadata.
_META_NAMES = {"meta", "metadata", "fmt_meta", "extra_metadata"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return node.attr if isinstance(node, ast.Attribute) else ""


def _str_keys(d: ast.Dict) -> list[str]:
    return [k.value for k in d.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]


def metadata_keys_set_in(path: Path) -> set[str]:
    """String keys written as meta["X"] = ..., metadata={"X": ...},
    meta = {"X": ...} or meta.update({"X": ...})."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if (
                    isinstance(t, ast.Subscript) and _name(t.value) in _META_NAMES
                    and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str)
                ):
                    found.add(t.slice.value)
            if (
                isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                and any(_name(t) in _META_NAMES for t in node.targets)
            ):
                found.update(_str_keys(node.value))
        elif (
            isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Dict)
            and _name(node.target) in _META_NAMES
        ):
            found.update(_str_keys(node.value))
        elif isinstance(node, ast.keyword) and node.arg in _META_NAMES and isinstance(node.value, ast.Dict):
            found.update(_str_keys(node.value))
        elif (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("update", "setdefault") and _name(node.func.value) in _META_NAMES
        ):
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    found.update(_str_keys(arg))
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
    return found


def test_every_metadata_key_is_in_the_catalog() -> None:
    missing: dict[str, set[str]] = {}
    for folder in ("parsers", "core", "ui", "viewers"):
        for path in (PACKAGE / folder).rglob("*.py"):
            keys = metadata_keys_set_in(path) - set(METADATA_LABELS)
            if keys:
                missing[str(path.relative_to(PACKAGE.parent))] = keys
    assert missing == {}
