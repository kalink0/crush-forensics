# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for Windows-safe filename sanitization on export.

A reported bug: exporting on Windows produced "invalid results" because
node/virtual-path names coming from non-Windows acquisitions (macOS, iOS,
Android, Linux) can contain characters Windows filesystems reject
(``: " < > | ? *`` and control chars), reserved device names (``CON``,
``COM1``, ...), or trailing dots/spaces. `_safe_name` previously only
replaced path separators, and the filtered/multi export path did not call
it at all — so unsafe components reached `Path.mkdir`/`open()` untouched
and failed on Windows. Sanitization is applied unconditionally (not just
when os.name == "nt") so exports also survive being copied to exFAT/NTFS
media from Linux or macOS. Every rename must be logged and recorded in a
`crush-export-renames.txt` sidecar for forensic traceability — never silent.
"""
from __future__ import annotations

import io
from typing import IO

import pytest
from PySide6.QtWidgets import QFileDialog, QMessageBox

from crush.core.vfs import VFS, DirectoryVFS, VFSNode
from crush.ui.main_window import MainWindow, _safe_name


class _FakeVFS(VFS):
    """A VFS not backed by a real OS path.

    A DirectoryVFS can't stand in for a source containing a name that's
    invalid on the *current* host filesystem: on Windows, writing a file
    literally named "weird:name?.txt" doesn't create that name at all —
    the colon is parsed as an NTFS Alternate Data Stream separator, so the
    "unsafe" name a test tries to construct silently vanishes before the
    code under test ever sees it. Forensic VFS names (archive members,
    mobile-backup entries, parsed records) commonly aren't real host paths
    either, so this fake matches that shape.
    """

    def __init__(self, root_node: VFSNode, contents: dict[str, bytes]) -> None:
        self._root = root_node
        self._contents = contents

    def root(self) -> VFSNode:
        return self._root

    def read(self, node: VFSNode) -> bytes:
        return self._contents[node.path]

    def open(self, node: VFSNode) -> IO[bytes]:
        return io.BytesIO(self._contents[node.path])

    def file_count(self, node: VFSNode) -> int:
        return 1 if not node.is_dir else len(node.children)

    def total_size(self, node: VFSNode) -> int:
        return node.size


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("normal_name.txt", "normal_name.txt"),
        ("weird:name?.txt", "weird_name_.txt"),
        ('quote"pipe|star*.txt', "quote_pipe_star_.txt"),
        ("angle<bracket>.txt", "angle_bracket_.txt"),
        ("trailing dot.", "trailing dot"),
        ("trailing space ", "trailing space"),
        ("con\x01trol.txt", "con_trol.txt"),
    ],
)
def test_safe_name_replaces_windows_invalid_characters(raw: str, expected: str) -> None:
    cleaned, changed = _safe_name(raw)
    assert cleaned == expected
    assert changed == (cleaned != raw)


@pytest.mark.parametrize("reserved", ["CON", "con", "AUX", "NUL", "COM1", "lpt3"])
def test_safe_name_prefixes_reserved_device_names(reserved: str) -> None:
    cleaned, changed = _safe_name(reserved)
    assert changed
    assert cleaned == f"_{reserved}"

    cleaned_with_ext, changed_ext = _safe_name(f"{reserved}.txt")
    assert changed_ext
    assert cleaned_with_ext == f"_{reserved}.txt"


def test_safe_name_reports_unchanged_for_clean_names() -> None:
    cleaned, changed = _safe_name("clean_name.txt")
    assert cleaned == "clean_name.txt"
    assert changed is False


def test_safe_name_handles_empty_and_dot_names() -> None:
    assert _safe_name("") == ("_", True)
    assert _safe_name(".") == ("_", True)
    assert _safe_name("..") == ("_", True)


def _make_fake_source_with_unsafe_name() -> tuple[VFSNode, _FakeVFS]:
    child = VFSNode(name="weird:name?.txt", path="/source/weird:name?.txt", is_dir=False, size=7)
    root = VFSNode(name="source", path="/source", is_dir=True, children=[child])
    vfs = _FakeVFS(root, {child.path: b"payload"})
    return root, vfs


def test_export_node_sanitizes_unsafe_child_names_and_records_renames(
    qapp, tmp_path, monkeypatch
) -> None:
    root, vfs = _make_fake_source_with_unsafe_name()
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)

    win = MainWindow()
    try:
        win._export_node(root, vfs)
        win._export_thread.wait(5000)
        qapp.processEvents()

        target_root = dest_dir / root.name
        exported = target_root / "weird_name_.txt"
        assert exported.exists()
        assert exported.read_bytes() == b"payload"

        renames = (target_root / "crush-export-renames.txt").read_text()
        assert "weird:name?.txt" in renames
        assert "weird_name_.txt" in renames
    finally:
        win.close()


def test_export_multi_nodes_sanitizes_virtual_path_components(qapp, tmp_path, monkeypatch) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    unsafe_file = source_dir / "unsafe.txt"
    unsafe_file.write_text("payload")
    vfs = DirectoryVFS(source_dir)
    node = vfs.root().children[0]

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    # _on_export_finished pops a real "Open location?" QMessageBox on the
    # worker's finished signal — must be mocked or the test blocks waiting
    # for a real click (see conftest._no_real_external_open for the same
    # failure mode biting this suite before).
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)

    win = MainWindow()
    try:
        entries = [(node, vfs, 'weird"dir/pipe|name.txt')]
        win._export_multi_nodes(entries, "filter")
        win._export_thread.wait(5000)
        qapp.processEvents()

        export_roots = list(dest_dir.glob("crush-export-*"))
        assert len(export_roots) == 1
        export_root = export_roots[0]

        exported = export_root / "weird_dir" / "pipe_name.txt"
        assert exported.exists()
        assert exported.read_text() == "payload"

        renames = (export_root / "crush-export-renames.txt").read_text()
        assert 'weird"dir/pipe|name.txt' in renames
    finally:
        win.close()
