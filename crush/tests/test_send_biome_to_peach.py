# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for MainWindow._send_biome_to_peach (crush/ui/main_window.py) —
materializes discovered SEGB files for peach while preserving each file's
path relative to the right-clicked root, since that directory structure is
what lets peach (and Crush's own SEGB parser) derive each file's Biome
stream name."""
from __future__ import annotations

from pathlib import Path

import crush.core.peach_launcher as peach_launcher
from crush.core.vfs import DirectoryVFS
from crush.ui.main_window import MainWindow


def test_send_biome_to_peach_preserves_relative_directory_structure(
    qapp, tmp_path: Path, monkeypatch
) -> None:
    root_dir = tmp_path / "biome_root"
    stream_a = root_dir / "streams" / "restricted" / "Device.Wireless.Bluetooth" / "local"
    stream_b = root_dir / "streams" / "public" / "Backlight" / "local"
    stream_a.mkdir(parents=True)
    stream_b.mkdir(parents=True)
    (stream_a / "file_a").write_bytes(b"SEGBaaaa")
    (stream_b / "file_b").write_bytes(b"SEGBbbbb")

    vfs = DirectoryVFS(root_dir)
    root_node = vfs.root()

    def _find(node, *parts):
        for part in parts:
            node = next(c for c in node.children if c.name == part)
        return node

    node_a = _find(root_node, "streams", "restricted", "Device.Wireless.Bluetooth", "local", "file_a")
    node_b = _find(root_node, "streams", "public", "Backlight", "local", "file_b")

    captured = {}

    def fake_launch_peach(sources, *, cleanup_dirs, override_path=""):
        captured["sources"] = list(sources)
        captured["cleanup_dirs"] = list(cleanup_dirs)

    monkeypatch.setattr(peach_launcher, "launch_peach", fake_launch_peach)

    win = MainWindow()
    win._send_biome_to_peach(root_node, vfs, [node_a, node_b])

    assert len(captured["sources"]) == 1
    materialized = captured["sources"][0]
    assert materialized == captured["cleanup_dirs"][0]

    copied_a = materialized / "streams" / "restricted" / "Device.Wireless.Bluetooth" / "local" / "file_a"
    copied_b = materialized / "streams" / "public" / "Backlight" / "local" / "file_b"
    assert copied_a.read_bytes() == b"SEGBaaaa"
    assert copied_b.read_bytes() == b"SEGBbbbb"
