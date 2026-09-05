# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the --focus CLI flag: argument validation (crush/__main__.py) and
the load-then-focus behavior it drives in MainWindow (crush/ui/main_window.py)."""
from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QEventLoop, QTimer

from crush.__main__ import _parse_args
from crush.ui.main_window import MainWindow


def test_focus_requires_exactly_one_open_target() -> None:
    with pytest.raises(SystemExit):
        _parse_args(["/tmp/a", "/tmp/b", "--focus", "x.db"])


def test_focus_allowed_with_single_positional_path() -> None:
    args = _parse_args(["/tmp/a", "--focus", "x.db"])
    assert args.focus_path == "x.db"


def test_focus_allowed_with_single_open_flag() -> None:
    args = _parse_args(["--open", "/tmp/a", "--focus", "x.db"])
    assert args.focus_path == "x.db"


def _load_and_wait(win: MainWindow, path: str, focus_path: str | None) -> None:
    win._load_source(path, open_after_load=True, append_to_tree=True, focus_path=focus_path)
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(lambda: loop.quit() if getattr(win, "_tree_loaded", False) else None)
    timer.start(20)
    QTimer.singleShot(10_000, loop.quit)
    loop.exec()
    assert getattr(win, "_tree_loaded", False), "tree load did not finish within timeout"


@pytest.fixture
def sample_folder(tmp_path: Path) -> Path:
    docs = tmp_path / "Documents"
    docs.mkdir()
    (docs / "note.txt").write_text("hello")
    (tmp_path / "readme.txt").write_text("other")
    return tmp_path


def test_focus_opens_the_target_file_inside_a_folder(qapp, sample_folder: Path) -> None:
    win = MainWindow()
    _load_and_wait(win, str(sample_folder), "Documents/note.txt")
    assert win._viewer_tabs.count() == 1
    assert win._viewer_tabs.tabText(0) == "note.txt"


def test_focus_missing_target_shows_explicit_status_and_opens_nothing(qapp, sample_folder: Path) -> None:
    win = MainWindow()
    _load_and_wait(win, str(sample_folder), "Documents/does_not_exist.txt")
    assert win._viewer_tabs.count() == 0
    assert "not found" in win._status.currentMessage()


def test_focus_on_single_file_target_still_opens_it(qapp, sample_folder: Path) -> None:
    """--focus doesn't make sense for a single-file target, but the file
    must still open via the existing single-file auto-open behavior —
    --focus being pointless here shouldn't block that."""
    win = MainWindow()
    single_file = sample_folder / "readme.txt"
    _load_and_wait(win, str(single_file), "whatever.txt")
    assert win._viewer_tabs.count() == 1
    assert win._viewer_tabs.tabText(0) == "readme.txt"
