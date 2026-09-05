# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the overwrite-confirmation prompt in MainWindow._export_node
(crush/ui/main_window.py) — folder-based exports used to silently clobber an
existing same-named destination with no warning."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QMessageBox

from crush.core.vfs import DirectoryVFS
from crush.ui.main_window import MainWindow


def _make_source(tmp_path: Path) -> tuple[Path, "DirectoryVFS"]:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "file.txt").write_text("data")
    vfs = DirectoryVFS(source_dir)
    return source_dir, vfs


def test_export_node_asks_before_overwriting_existing_target(qapp, tmp_path, monkeypatch) -> None:
    source_dir, vfs = _make_source(tmp_path)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    (dest_dir / source_dir.name).mkdir()  # pre-existing collision at dest/source

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    questions = []

    def fake_question(*args, **kwargs):
        questions.append(args)
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", fake_question)

    win = MainWindow()
    win._export_node(vfs.root(), vfs)

    assert len(questions) == 1
    assert not win._thread_is_running(getattr(win, "_export_thread", None))


def test_export_node_proceeds_when_overwrite_confirmed(qapp, tmp_path, monkeypatch) -> None:
    source_dir, vfs = _make_source(tmp_path)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    (dest_dir / source_dir.name).mkdir()

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)

    win = MainWindow()
    win._export_node(vfs.root(), vfs)

    assert win._thread_is_running(win._export_thread)
    win._export_thread.wait(5000)


def test_export_node_does_not_prompt_when_target_is_new(qapp, tmp_path, monkeypatch) -> None:
    source_dir, vfs = _make_source(tmp_path)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()  # empty — no collision

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(dest_dir))
    questions = []
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: questions.append(a))

    win = MainWindow()
    win._export_node(vfs.root(), vfs)

    assert questions == []
    assert win._thread_is_running(win._export_thread)
    win._export_thread.wait(5000)
