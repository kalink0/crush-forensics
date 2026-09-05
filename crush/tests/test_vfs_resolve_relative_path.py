# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for resolve_relative_path() (crush/core/vfs.py) — used by the CLI's
--focus flag to locate a file inside a just-opened folder/archive."""
from __future__ import annotations

from crush.core.vfs import VFSNode, resolve_relative_path


def _dir(name: str, children: list[VFSNode] | None = None) -> VFSNode:
    return VFSNode(name=name, path=f"/{name}", is_dir=True, children=children or [])


def _file(name: str) -> VFSNode:
    return VFSNode(name=name, path=f"/{name}", is_dir=False, size=1)


def test_resolves_nested_path() -> None:
    target = _file("chat.db")
    root = _dir("root", [_dir("Documents", [target])])
    assert resolve_relative_path(root, "Documents/chat.db") is target


def test_resolves_top_level_file() -> None:
    target = _file("chat.db")
    root = _dir("root", [target])
    assert resolve_relative_path(root, "chat.db") is target


def test_accepts_backslash_separators() -> None:
    target = _file("chat.db")
    root = _dir("root", [_dir("Documents", [target])])
    assert resolve_relative_path(root, "Documents\\chat.db") is target


def test_returns_none_for_missing_segment() -> None:
    root = _dir("root", [_dir("Documents", [_file("chat.db")])])
    assert resolve_relative_path(root, "Documents/missing.db") is None
    assert resolve_relative_path(root, "NoSuchDir/chat.db") is None


def test_ignores_leading_dot_and_extra_slashes() -> None:
    target = _file("chat.db")
    root = _dir("root", [_dir("Documents", [target])])
    assert resolve_relative_path(root, "./Documents//chat.db") is target
