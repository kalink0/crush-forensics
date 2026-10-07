# SPDX-License-Identifier: Apache-2.0
"""A file whose content can't be read (e.g. one a UFDR lists but doesn't
hold) says why when opened -- by double-click, as Hex or as Text -- rather
than nothing or a bare "can't open"."""
from __future__ import annotations

from pathlib import Path
from typing import IO, Any

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

from crush.core.vfs import DirectoryVFS, VFSNode

REASON = "Not contained in this source: its content wasn't exported"


class _UnreadableVFS(DirectoryVFS):
    def read(self, node: VFSNode) -> bytes:
        raise OSError(REASON)

    def open(self, node: VFSNode) -> IO[bytes]:
        raise OSError(REASON)

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        raise OSError(REASON)


@pytest.fixture
def warnings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def fake_warning(parent: Any, title: str, text: str, *a: Any, **k: Any) -> None:
        seen.append(text)

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)
    return seen


@pytest.mark.parametrize("mode", ["default", "hex", "text"])
def test_opening_an_unreadable_file_says_why(
    qapp: QApplication, tmp_path: Path, warnings: list[str], mode: str,
) -> None:
    from crush.ui.main_window import MainWindow

    (tmp_path / "listed.db").write_bytes(b"x" * 100)
    vfs = _UnreadableVFS(tmp_path)
    node = vfs.root().children[0]
    win = MainWindow()
    try:
        if mode == "default":
            win._open_node(node, vfs)
        else:
            win._open_node_mode(node, vfs, mode)
        assert len(warnings) == 1 and REASON in warnings[0]
    finally:
        win.close()
