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

from pathlib import Path

import pytest
from PySide6.QtWidgets import QFileDialog, QMessageBox

from crush.core.vfs import DirectoryVFS
from crush.ui.main_window import MainWindow, _safe_name


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


def _make_source_with_unsafe_name(tmp_path: Path) -> tuple[Path, "DirectoryVFS"]:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "weird:name?.txt").write_text("payload")
    vfs = DirectoryVFS(source_dir)
    return source_dir, vfs


def test_export_node_sanitizes_unsafe_child_names_and_records_renames(
    qapp, tmp_path, monkeypatch
) -> None:
    source_dir, vfs = _make_source_with_unsafe_name(tmp_path)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)

    win = MainWindow()
    try:
        win._export_node(vfs.root(), vfs)
        win._export_thread.wait(5000)
        qapp.processEvents()

        target_root = dest_dir / source_dir.name
        exported = target_root / "weird_name_.txt"
        assert exported.exists()
        assert exported.read_text() == "payload"

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
