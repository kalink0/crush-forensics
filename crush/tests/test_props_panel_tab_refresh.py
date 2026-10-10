# SPDX-License-Identifier: Apache-2.0
"""The Properties panel follows the viewer tab the user activates -- also
when that tab already was the current one (e.g. after a click in the file
tree showed a folder's properties) -- and shows the parser's metadata in
its own order every time (crush/ui/main_window.py)."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QApplication, QLabel

from crush.core.vfs import DirectoryVFS


def _labels(win) -> list[str]:  # noqa: ANN001
    layout = win._props_panel._layout
    return [
        layout.itemAt(i).widget().text()
        for i in range(layout.count())
        if isinstance(layout.itemAt(i).widget(), QLabel)
    ]


def _open_json(tmp_path: Path):  # noqa: ANN202
    from crush.ui.main_window import MainWindow

    (tmp_path / "a.json").write_text(json.dumps({"k": 1}))
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "a.json")
    win = MainWindow()
    win._open_node(node, vfs)
    return win, vfs, node


def test_clicking_the_current_tab_after_a_tree_click_shows_its_file_again(
    qapp: QApplication, tmp_path: Path,
) -> None:
    win, vfs, _node = _open_json(tmp_path)
    try:
        opened = _labels(win)
        assert "<b>a.json</b>" in opened

        # A click on the folder in the tree shows the folder's properties...
        win._on_node_selected(vfs.root(), vfs)
        assert "<b>a.json</b>" not in _labels(win)

        # ...and clicking the (still current) tab brings the file's back.
        bar = win._viewer_tabs.tabBar()
        bar.tabBarClicked.emit(win._viewer_tabs.currentIndex())
        assert _labels(win) == opened
    finally:
        win.close()


def test_tab_switch_keeps_the_parsers_metadata_order(
    qapp: QApplication, tmp_path: Path,
) -> None:
    """A dict stored as a Qt property came back with its keys sorted, so
    the panel's rows changed order after switching tabs."""
    win, _vfs, _node = _open_json(tmp_path)
    try:
        opened = _labels(win)
        win._on_viewer_tab_changed(win._viewer_tabs.currentIndex())
        assert _labels(win) == opened
    finally:
        win.close()
