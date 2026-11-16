# SPDX-License-Identifier: Apache-2.0
"""Opening a folder no viewer recognises (e.g. Android WebView's
"HTTP Cache", which only holds the caches Cache_Data and Code Cache/js)
says so in a box -- not only in the status bar, where an Open that does
nothing visible reads as a missed click."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

from crush.core.vfs import DirectoryVFS


@pytest.fixture
def warnings(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []

    def fake_warning(parent: Any, title: str, text: str, *a: Any, **k: Any) -> None:
        seen.append((title, text))

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)
    return seen


def test_opening_an_unrecognised_folder_says_so(
    qapp: QApplication,
    tmp_path: Path,
    warnings: list[tuple[str, str]],
    widgets: Callable[[Any], Any],
) -> None:
    from crush.ui.main_window import MainWindow

    folder = tmp_path / "HTTP Cache"
    (folder / "Cache_Data").mkdir(parents=True)
    (folder / "Code Cache" / "js").mkdir(parents=True)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "HTTP Cache")
    win = widgets(MainWindow())

    win._open_node(node, vfs)

    assert len(warnings) == 1
    title, text = warnings[0]
    assert title == "Cannot open folder"
    assert "HTTP Cache" in text
    assert win._status.currentMessage() == text
