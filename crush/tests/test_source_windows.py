# SPDX-License-Identifier: Apache-2.0
"""A folder, archive, backup or disk image (a tree of its own) replaces what
the window shows -- after asking, when the window shows a source: Replace
(closes them), New Window (the loaded source handed over, not loaded again)
or Cancel (the loaded source is closed, nothing changes). Opened in one go
with other items (a drop, a multi-selection, the command line), one that
would replace an item of its own batch opens in a new window instead,
without asking. A single file joins the tree."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

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


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every question asked before a replace, in any window: [window, ...].
    The answer is asked.answer ("replace" unless a test sets another)."""
    from crush.ui.main_window import MainWindow

    calls = _Asked()

    def ask(self: Any, vfs: Any) -> str:
        calls.append(self)
        return calls.answer

    monkeypatch.setattr(MainWindow, "_ask_replace_sources", ask)
    return calls


class _Asked(list):  # type: ignore[type-arg]
    answer = "replace"


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


def _tree(tmp_path: Path, name: str) -> _Tracked:
    return _Tracked(_folder(tmp_path, name))


# -- the question before a replace ------------------------------------------------

def test_replace_closes_what_was_shown_and_shows_the_new_source(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    first = _tree(tmp_path, "first")
    _load(win, first, tmp_path / "first", append=False)
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt")
    second = _tree(tmp_path, "second")
    _load(win, second, tmp_path / "second", append=False)

    assert asked == [win]
    assert win._fs_panel._vfs_list == [second]
    assert win.session.sources == [second]
    assert first.closed and not second.closed
    assert _new_windows(windows) == []


def test_new_window_keeps_what_was_shown_and_hands_the_source_over(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    asked.answer = "new_window"
    first = _tree(tmp_path, "first")
    _load(win, first, tmp_path / "first", append=False)
    second = _tree(tmp_path, "second")
    _load(win, second, tmp_path / "second", append=False)

    assert asked == [win]
    assert win._fs_panel._vfs_list == [first]
    assert win.session.sources == [first]
    assert not first.closed and not second.closed
    new = _new_windows(windows)
    # The very source loaded here, not opened again.
    assert len(new) == 1 and new[0]._fs_panel._vfs_list[0] is second
    assert new[0].session.sources == [second]
    assert "opened in a new window" in win._status.currentMessage()


def test_cancel_shows_nothing_new_and_closes_the_loaded_source(
    windows: list[Any], asked: list[Any], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    win = windows[0]
    asked.answer = "cancel"
    first = _tree(tmp_path, "first")
    _load(win, first, tmp_path / "first", append=False)
    second = _tree(tmp_path, "second")
    logger = logging.getLogger("crush")
    logger.addHandler(caplog.handler)
    try:
        _load(win, second, tmp_path / "second", append=False)
    finally:
        logger.removeHandler(caplog.handler)

    assert win._fs_panel._vfs_list == [first]
    assert win.session.sources == [first]
    assert second.closed and not first.closed
    assert _new_windows(windows) == []
    assert "cancelled" in win._status.currentMessage()
    assert any("Not opened" in r.getMessage() for r in caplog.records)


def test_enter_selects_replace(windows: list[Any], tmp_path: Path) -> None:
    win = windows[0]
    first = DirectoryVFS(_folder(tmp_path, "first"))
    _load(win, first, tmp_path / "first", append=False)
    win._loading_path = str(tmp_path / "second")
    box, answers = win._replace_sources_box(DirectoryVFS(_folder(tmp_path, "second")))
    try:
        assert answers[box.defaultButton()] == "replace"
        assert answers[box.escapeButton()] == "cancel"
        assert sorted(answers.values()) == ["cancel", "new_window", "replace"]
        assert "first" in box.informativeText()
    finally:
        box.deleteLater()


def test_the_question_answered_with_enter_replaces(
    windows: list[Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real question, answered as Enter answers it: its default button."""
    monkeypatch.setattr(QMessageBox, "exec", lambda box: box.defaultButton().click() or 0)
    win = windows[0]
    _load(win, DirectoryVFS(_folder(tmp_path, "first")), tmp_path / "first", append=False)
    second = DirectoryVFS(_folder(tmp_path, "second"))
    _load(win, second, tmp_path / "second", append=False)
    assert win._fs_panel._vfs_list == [second]


def test_no_question_for_an_empty_window(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", append=False)
    assert asked == []
    assert win._fs_panel._vfs_list == [tree]


def test_no_question_for_an_appended_file(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", append=False)
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt")
    assert asked == []
    assert win._fs_panel._vfs_list == [tree, single]


def test_replacing_clears_search_results_of_the_replaced_source(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    _load(win, DirectoryVFS(_folder(tmp_path, "first")), tmp_path / "first", append=False)
    win._fs_panel._filter.setText("inner")
    win._fs_panel._search_model.appendRow([])
    _load(win, DirectoryVFS(_folder(tmp_path, "second")), tmp_path / "second", append=False)
    assert win._fs_panel._filter.text() == ""
    assert win._fs_panel._search_model.rowCount() == 0


# -- several in one go ------------------------------------------------------------

def test_several_tree_sources_in_one_go_each_get_a_window_without_asking(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    win.resize(300, 200)  # smaller than the screen, so no step is clamped away
    batch = object()
    sources = [DirectoryVFS(_folder(tmp_path, f"case{i}")) for i in range(3)]
    for i, vfs in enumerate(sources):
        _load(win, vfs, tmp_path / f"case{i}", append=False, batch=batch)

    assert asked == []  # neither here nor in the windows that adopt them
    assert win._fs_panel._vfs_list == [sources[0]]
    assert win.session.sources == [sources[0]]
    new = _new_windows(windows)
    assert [w._fs_panel._vfs_list for w in new] == [[sources[1]], [sources[2]]]
    assert [w.session.sources for w in new] == [[sources[1]], [sources[2]]]
    assert len({w.pos().toTuple() for w in new}) == 2
    assert "opened in a new window" in win._status.currentMessage()


@pytest.mark.parametrize("answer", ["replace", "new_window", "cancel"])
def test_batch_asks_once_for_its_first_item_then_follows_the_batch_rule(
    windows: list[Any], asked: list[Any], tmp_path: Path, answer: str
) -> None:
    win = windows[0]
    asked.answer = answer
    earlier = _tree(tmp_path, "earlier")
    _load(win, earlier, tmp_path / "earlier", append=False)
    batch = object()
    first = _tree(tmp_path, "first")
    _load(win, first, tmp_path / "first", append=False, batch=batch)
    second = _tree(tmp_path, "second")
    _load(win, second, tmp_path / "second", append=False, batch=batch)

    assert asked == [win]
    here = {"replace": [first], "new_window": [earlier], "cancel": [earlier]}[answer]
    assert win._fs_panel._vfs_list == here
    elsewhere = [w._fs_panel._vfs_list[0] for w in _new_windows(windows)]
    assert elsewhere == {"replace": [second], "new_window": [first, second],
                         "cancel": [second]}[answer]
    assert first.closed == (answer == "cancel")


def test_tree_after_a_file_of_its_batch_keeps_the_file(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    batch = object()
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt", batch=batch)
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", batch=batch)
    assert asked == []
    assert win._fs_panel._vfs_list == [single]
    assert [w._fs_panel._vfs_list for w in _new_windows(windows)] == [[tree]]


def test_files_of_a_batch_join_the_tree_it_opened(
    windows: list[Any], asked: list[Any], tmp_path: Path
) -> None:
    win = windows[0]
    batch = object()
    tree = DirectoryVFS(_folder(tmp_path, "case"))
    _load(win, tree, tmp_path / "case", batch=batch)
    single = FileVFS(_file(tmp_path, "notes.txt"))
    _load(win, single, tmp_path / "notes.txt", batch=batch)
    assert asked == []
    assert win._fs_panel._vfs_list == [tree, single]
    assert _new_windows(windows) == []


def test_handed_over_source_logs_its_integrity_hash_in_its_window(
    windows: list[Any], asked: list[Any], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    win = windows[0]
    batch = object()
    _load(win, DirectoryVFS(_folder(tmp_path, "first")), tmp_path / "first", batch=batch)
    second_path = _folder(tmp_path, "second")
    # "crush" doesn't propagate to the root logger caplog listens on.
    logger = logging.getLogger("crush")
    logger.addHandler(caplog.handler)
    try:
        _load(
            win, DirectoryVFS(second_path), second_path, batch=batch,
            source_hash=("ab" * 32, 1, str(second_path)),
        )
    finally:
        logger.removeHandler(caplog.handler)
    new = _new_windows(windows)[0]
    records = [r for r in caplog.records if "INTEGRITY source" in r.getMessage()]
    assert [getattr(r, "window_id", None) for r in records] == [new._window_id]
    assert "ab" * 32 in records[0].getMessage()
