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

    def ask(self: Any, vfs: Any, state: Any) -> str:
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


def _set_loading(
    win: Any, path: Path | str, *, append: bool = True, batch: object | None = None,
    source_hash: tuple[str, int, str] | None = None, as_disk_image: bool = False,
) -> None:
    """The state _load_source leaves for the source it loads."""
    from crush.ui.loading_dialog import LoadingDialog

    win._loading_path = str(path)
    win._loading_as_disk_image = as_disk_image
    win._loading_itunes_zip_prefix = None
    win._loading_embedded_zip = False
    win._loading_batch = batch
    win._open_after_load = False
    win._append_to_tree = append
    win._pending_focus_path = None
    win._loading_focus_path = None
    win._loading_source_hash = source_hash
    win._progress = LoadingDialog(f"loading {Path(path).name}", win)


def _load(
    win: Any, vfs: Any, path: Path, *, append: bool = True, batch: object | None = None,
    source_hash: tuple[str, int, str] | None = None, as_disk_image: bool = False,
) -> None:
    """What _load_source and its worker leave behind, then the result."""
    win.session.add_source_vfs(vfs)
    _set_loading(
        win, path, append=append, batch=batch, source_hash=source_hash,
        as_disk_image=as_disk_image,
    )
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
    box, answers = win._replace_sources_box(
        DirectoryVFS(_folder(tmp_path, "second")), str(tmp_path / "second")
    )
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


# -- a dialog open while the next source is queued ----------------------------------
#
# A modal dialog runs a nested event loop, in which the finished load thread's
# signal (_on_load_thread_finished) would start the next queued source. These
# call it from inside the dialog, as that loop would.

@pytest.fixture
def started(windows: list[Any], monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """Loads started in the test's window: (path, keywords). Each leaves the
    state the real _load_source leaves, as the next source's would."""
    win = windows[0]
    calls: list[tuple[str, dict]] = []

    def load_source(path: str, **kw: Any) -> None:
        calls.append((path, kw))
        _set_loading(
            win, path, append=kw.get("append_to_tree", False), batch=kw.get("batch"),
            as_disk_image=kw.get("as_disk_image", False),
        )

    monkeypatch.setattr(win, "_load_source", load_source)
    return calls


def _queue(win: Any, path: Path, batch: object | None = None) -> None:
    """*path* queued as _load_source queues it while a load runs."""
    win._load_queue.append(
        (str(path), True, True, None, "", None, False, False, "", batch)
    )


def _answering(
    monkeypatch: pytest.MonkeyPatch, win: Any, started: list, answer: str
) -> list[bool]:
    """Every QMessageBox.exec() first lets the load thread's end through,
    then is answered with *answer*. Returns, per question, whether a load
    had started by then."""
    seen: list[bool] = []

    def exec_(box: QMessageBox) -> int:
        win._on_load_thread_finished()
        seen.append(bool(started))
        if answer == "replace":
            box.defaultButton().click()
        elif answer == "cancel":
            box.button(QMessageBox.StandardButton.Cancel).click()
        else:
            next(b for b in box.buttons() if b.text() == "New Window").click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", exec_)
    return seen


def _two_in_one_go(win: Any, tmp_path: Path) -> tuple[_Tracked, Path, Path, object]:
    """A window showing a source, then A of a batch [A, B] loaded, B queued."""
    _load(win, DirectoryVFS(_folder(tmp_path, "earlier")), tmp_path / "earlier", append=False)
    batch = object()
    a_path, b_path = _folder(tmp_path, "a"), _folder(tmp_path, "b")
    _queue(win, b_path, batch)
    return _Tracked(a_path), a_path, b_path, batch


def _finish_b(win: Any, b_path: Path) -> DirectoryVFS:
    """B's load finishing, with the state its own start left."""
    b = DirectoryVFS(b_path)
    win.session.add_source_vfs(b)
    win._on_load_finished(b)
    return b


def test_cancel_with_the_next_source_queued_concerns_the_source_asked_about(
    windows: list[Any], started: list, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    win = windows[0]
    a, a_path, b_path, batch = _two_in_one_go(win, tmp_path)
    seen = _answering(monkeypatch, win, started, "cancel")
    logger = logging.getLogger("crush")
    logger.addHandler(caplog.handler)
    try:
        _load(win, a, a_path, batch=batch, source_hash=("aa" * 32, 1, str(a_path)))
    finally:
        logger.removeHandler(caplog.handler)

    assert seen == [False]  # B held while the question was open
    not_opened = [r.getMessage() for r in caplog.records if "Not opened" in r.getMessage()]
    assert not_opened == [f"Not opened, cancelled to keep the open sources: {a_path}"]
    assert a.closed
    assert [p for p, _ in started] == [str(b_path)]  # then B, once
    assert started[0][1]["batch"] is batch

    b = _finish_b(win, b_path)
    new = _new_windows(windows)
    assert [w._fs_panel._vfs_list for w in new] == [[b]]
    assert new[0]._loading_path == str(b_path)
    assert [p for p, _ in started] == [str(b_path)]


def test_new_window_with_the_next_source_queued_hands_over_the_source_asked_about(
    windows: list[Any], started: list, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    win = windows[0]
    a, a_path, b_path, batch = _two_in_one_go(win, tmp_path)
    seen = _answering(monkeypatch, win, started, "new_window")
    a_progress: list[Any] = []
    monkeypatch.setattr(
        win, "_ask_replace_sources",
        _recording_progress(win, a_progress, win._ask_replace_sources),
    )
    _load(win, a, a_path, batch=batch, source_hash=("aa" * 32, 1, str(a_path)))

    assert seen == [False]
    adopted = _new_windows(windows)
    assert len(adopted) == 1
    assert adopted[0]._fs_panel._vfs_list == [a]
    assert adopted[0]._loading_path == str(a_path)
    assert adopted[0]._loading_source_hash == ("aa" * 32, 1, str(a_path))
    assert adopted[0]._loading_as_disk_image is False
    assert not a_progress[0].isVisible()  # A's progress dialog, not left behind
    assert [p for p, _ in started] == [str(b_path)]

    _finish_b(win, b_path)
    new = _new_windows(windows)
    assert [w._loading_path for w in new] == [str(a_path), str(b_path)]
    assert [p for p, _ in started] == [str(b_path)]


def _recording_progress(win: Any, into: list, ask: Any) -> Any:
    def wrapped(vfs: Any, state: Any) -> Any:
        into.append(state.progress)
        return ask(vfs, state)
    return wrapped


def test_replace_with_the_next_source_queued_reports_the_source_asked_about(
    windows: list[Any], started: list, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    win = windows[0]
    a, a_path, b_path, batch = _two_in_one_go(win, tmp_path)
    seen = _answering(monkeypatch, win, started, "replace")
    recent: list[str] = []
    monkeypatch.setattr(win, "_add_to_recent_files", lambda p, **kw: recent.append(p))
    statuses: list[str] = []
    win._status.messageChanged.connect(statuses.append)
    _load(win, a, a_path, batch=batch)

    assert seen == [False]
    assert win._fs_panel._vfs_list == [a]
    assert recent == [str(a_path)]
    assert f"Loaded: {a_path}" in statuses
    assert [p for p, _ in started] == [str(b_path)]  # after A was shown

    b = _finish_b(win, b_path)
    assert [w._fs_panel._vfs_list for w in _new_windows(windows)] == [[b]]
    assert [p for p, _ in started] == [str(b_path)]


def test_disk_image_warning_with_the_next_source_queued_concerns_its_source(
    windows: list[Any], started: list, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asked for as a disk image, opened as a folder: the warning says so --
    and what follows it is still about that source."""
    win = windows[0]
    a_path = _folder(tmp_path, "a")
    b_path = _folder(tmp_path, "b")
    _queue(win, b_path)
    seen: list[bool] = []

    def warning(*args: Any, **kw: Any) -> None:
        win._on_load_thread_finished()
        seen.append(bool(started))

    monkeypatch.setattr(QMessageBox, "warning", warning)
    recent: list[str] = []
    monkeypatch.setattr(win, "_add_to_recent_files", lambda p, **kw: recent.append(p))
    _load(win, DirectoryVFS(a_path), a_path, append=False, as_disk_image=True)

    assert seen == [False]
    assert recent == [str(a_path)]
    assert win._status.currentMessage().startswith(f"Loaded: {a_path}")
    assert [p for p, _ in started] == [str(b_path)]


def test_password_prompt_with_the_next_source_queued_retries_its_own_source(
    windows: list[Any], started: list, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from PySide6.QtWidgets import QInputDialog

    win = windows[0]
    a_path, b_path = _file(tmp_path, "a.ab"), _file(tmp_path, "b.zip")
    _set_loading(win, a_path)
    _queue(win, b_path)
    seen: list[bool] = []

    def get_text(*args: Any, **kw: Any) -> tuple[str, bool]:
        win._on_load_thread_finished()
        seen.append(bool(started))
        return "secret", True

    monkeypatch.setattr(QInputDialog, "getText", get_text)
    win._on_password_required(False)

    assert seen == [False]
    assert [p for p, _ in started] == [str(a_path), str(b_path)]
    assert started[0][1]["password"] == "secret"
    assert started[1][1]["password"] == ""  # A's password stays with A
