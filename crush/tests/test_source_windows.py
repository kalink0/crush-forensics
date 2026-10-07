# SPDX-License-Identifier: Apache-2.0
"""A folder, archive, backup or disk image (a tree of its own) replaces what
the window shows, and what it replaces is closed. Opened in one go with
other items (a drop, a multi-selection, the command line), one that would
replace an item of its own batch opens in a new window instead, so opening
several at once never leaves only the last. A single file joins the tree."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from crush.core.vfs import DirectoryVFS, FileVFS


@pytest.fixture
def windows(qapp: QApplication) -> Iterator[list[Any]]:
    """[the test's window, then every window that existed before it]; the
    windows the test opens are closed after."""
    from crush.ui.main_window import MainWindow

    before = list(MainWindow._open_windows)
    first = MainWindow()
    try:
        yield [first, *before]
    finally:
        for win in list(MainWindow._open_windows):
            if win not in before:
                win.close()


def _new_windows(windows: list[Any]) -> list[Any]:
    """The windows opened since the test's own, in order."""
    from crush.ui.main_window import MainWindow

    return [w for w in MainWindow._open_windows if not any(w is k for k in windows)]


def _load(
    win: Any, vfs: Any, path: Path, *, append: bool = True, batch: object | None = None,
    source_hash: tuple[str, int, str] | None = None,
) -> None:
    """What _load_source and its worker leave behind, then the result."""
    win.session.add_source_vfs(vfs)
    win._loading_path = str(path)
    win._loading_as_disk_image = False
    win._loading_batch = batch
    win._open_after_load = False
    win._append_to_tree = append
    win._pending_focus_path = None
    win._loading_source_hash = source_hash
    win._on_load_finished(vfs)


def _folder(tmp_path: Path, name: str) -> Path:
    folder = tmp_path / name
    folder.mkdir()
    (folder / "inner.txt").write_bytes(b"x")
    return folder


def _file(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(b"x")
    return path


class _Tracked(DirectoryVFS):
    closed = False

    def close(self) -> None:
        self.closed = True
        super().close()


# -- one at a time: replaces, as before ------------------------------------------

def test_tree_source_opened_on_its_own_replaces_and_closes_what_was_shown(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    first = _Tracked(_folder(tmp_path, "first"))
    _load(win, first, tmp_path / "first", append=False)
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt")
    second = DirectoryVFS(_folder(tmp_path, "second"))
    _load(win, second, tmp_path / "second", append=False)

    assert win._fs_panel._vfs_list == [second]
    assert win.session.sources == [second]
    assert first.closed
    assert _new_windows(windows) == []


def test_replacing_clears_search_results_of_the_replaced_source(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    _load(win, DirectoryVFS(_folder(tmp_path, "first")), tmp_path / "first", append=False)
    win._fs_panel._filter.setText("inner")
    win._fs_panel._search_model.appendRow([])
    _load(win, DirectoryVFS(_folder(tmp_path, "second")), tmp_path / "second", append=False)
    assert win._fs_panel._filter.text() == ""
    assert win._fs_panel._search_model.rowCount() == 0


# -- several in one go ------------------------------------------------------------

def test_several_tree_sources_in_one_go_each_get_a_window(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    win.resize(300, 200)  # smaller than the screen, so no step is clamped away
    batch = object()
    sources = [DirectoryVFS(_folder(tmp_path, f"case{i}")) for i in range(3)]
    for i, vfs in enumerate(sources):
        _load(win, vfs, tmp_path / f"case{i}", append=False, batch=batch)

    assert win._fs_panel._vfs_list == [sources[0]]
    assert win.session.sources == [sources[0]]
    new = _new_windows(windows)
    assert [w._fs_panel._vfs_list for w in new] == [[sources[1]], [sources[2]]]
    assert [w.session.sources for w in new] == [[sources[1]], [sources[2]]]
    assert len({w.pos().toTuple() for w in new}) == 2
    assert "opened in a new window" in win._status.currentMessage()


def test_first_tree_of_a_batch_still_replaces_what_was_open_before(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    earlier = DirectoryVFS(_folder(tmp_path, "earlier"))
    _load(win, earlier, tmp_path / "earlier", append=False)
    batch = object()
    first = DirectoryVFS(_folder(tmp_path, "first"))
    _load(win, first, tmp_path / "first", append=False, batch=batch)
    assert win._fs_panel._vfs_list == [first]
    assert _new_windows(windows) == []


def test_tree_after_a_file_of_its_batch_keeps_the_file(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    batch = object()
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt", batch=batch)
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", batch=batch)
    assert win._fs_panel._vfs_list == [single]
    assert [w._fs_panel._vfs_list for w in _new_windows(windows)] == [[tree]]


def test_files_of_a_batch_join_the_tree_it_opened(
    windows: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    batch = object()
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", batch=batch)
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt", batch=batch)
    assert win._fs_panel._vfs_list == [tree, single]
    assert _new_windows(windows) == []


def test_handed_over_source_logs_its_integrity_hash_in_its_window(
    windows: list[Any], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    win = windows[0]
    batch = object()
    _load(win, DirectoryVFS(_folder(tmp_path, "first")), tmp_path / "first", batch=batch)
    second_path = _folder(tmp_path, "second")
    with caplog.at_level(logging.INFO):
        _load(
            win, DirectoryVFS(second_path), second_path, batch=batch,
            source_hash=("ab" * 32, 1, str(second_path)),
        )
    new = _new_windows(windows)[0]
    records = [r for r in caplog.records if "INTEGRITY source" in r.getMessage()]
    assert [getattr(r, "window_id", None) for r in records] == [new._window_id]
    assert "ab" * 32 in records[0].getMessage()
