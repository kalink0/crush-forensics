# SPDX-License-Identifier: Apache-2.0
"""A source load's running count: entries listed so far (every VFSNode made
on the loading thread, the same for every source type), the step of a load
with known steps (a disk image's volumes), and the background type
indexing's done / total in the status bar. A count, never a percentage."""
from __future__ import annotations

import gzip
import zipfile
from pathlib import Path
from typing import Any

import pytest

from crush.core import load_phase
from crush.core.load_phase import (
    PHASE_DELETED_FILES,
    PHASE_READ_FILESYSTEMS,
    phase_reporter,
)
from crush.core.vfs import open_vfs
from crush.tests.conftest import FIXTURES_DIR


@pytest.fixture
def every_count(monkeypatch: pytest.MonkeyPatch) -> None:
    """No throttling, so every count reaches the callback."""
    monkeypatch.setattr(load_phase, "_MIN_INTERVAL", 0.0)


@pytest.mark.parametrize("kind", ["folder", "zip"])
def test_entries_listed_count_for_any_source(tmp_path: Path, every_count: None, kind: str) -> None:
    names = [f"f{i}.txt" for i in range(25)]
    if kind == "folder":
        src = tmp_path / "src"
        src.mkdir()
        for name in names:
            (src / name).write_bytes(b"x")
    else:
        src = tmp_path / "src.zip"
        with zipfile.ZipFile(src, "w") as zf:
            for name in names:
                zf.writestr(name, b"x")
    seen: list[tuple[int, int, int]] = []
    with phase_reporter(lambda _p: None, lambda *a: seen.append(a)):
        open_vfs(src).root()
    counts = [entries for entries, _s, _n in seen]
    assert counts == sorted(counts) and counts[-1] >= len(names)
    assert all(step == steps == 0 for _e, step, steps in seen)


def test_nothing_is_counted_without_a_reporter(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"x")
    open_vfs(tmp_path).root()  # no reporter on this thread: no error, no state left
    seen: list[Any] = []
    with phase_reporter(lambda _p: None, lambda *a: seen.append(a)):
        pass
    assert seen == []


def test_copies_of_listed_entries_are_not_counted(every_count: None) -> None:
    """A mounted source (UFD, ZIP with an iTunes backup) copies the inner
    source's nodes; the copies are made under not_counted()."""
    from crush.core.vfs import VFSNode

    seen: list[int] = []
    with phase_reporter(lambda _p: None, lambda entries, _s, _n: seen.append(entries)):
        VFSNode(name="a", path="/a", is_dir=False)
        with load_phase.not_counted():
            VFSNode(name="a", path="/copy/a", is_dir=False)
        VFSNode(name="b", path="/b", is_dir=False)
    assert seen == [1, 2]


def test_counts_are_throttled() -> None:
    seen: list[Any] = []
    with phase_reporter(lambda _p: None, lambda *a: seen.append(a)):
        for _ in range(10_000):
            load_phase.count_entry()
    assert 1 <= len(seen) < 100


def test_a_disk_image_reports_its_volumes_and_deleted_files_phase(
    tmp_path: Path, every_count: None
) -> None:
    img = tmp_path / "ntfs.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes()))
    phases: list[str] = []
    progress: list[tuple[int, int, int]] = []
    with phase_reporter(phases.append, lambda *a: progress.append(a)):
        vfs = open_vfs(img, as_disk_image=True)
    try:
        volumes = len(vfs.root().children)
        steps = {(step, n) for _e, step, n in progress if n}
        assert steps == {(i, volumes) for i in range(1, volumes + 1)}
        # Listing the deleted files is its own phase, and the next volume
        # is read under "Reading filesystems" again.
        at = phases.index(PHASE_DELETED_FILES)
        assert phases[at - 1] == PHASE_READ_FILESYSTEMS
        assert phases[at + 1] == PHASE_READ_FILESYSTEMS
        assert progress[-1][0] > 1000  # thousands of $Recovered entries
    finally:
        vfs.close()


def test_loading_dialog_shows_the_count(qapp: Any) -> None:
    from crush.ui.loading_dialog import LoadingDialog

    dialog = LoadingDialog("Loading source…")
    dialog.set_progress(12_345, 0, 0)
    assert dialog._progress.text() == "12,345 entries listed"
    dialog.set_progress(20_000, 2, 5)
    assert dialog._progress.text() == "volume 2 of 5 — 20,000 entries listed"
    dialog.set_phase(PHASE_DELETED_FILES)
    assert dialog._label.text() == "Listing deleted files…"
    dialog.close()


def test_status_bar_shows_indexed_of_total(qapp: Any) -> None:
    from crush.core.session import Session
    from crush.ui.fs_panel import FilesystemPanel

    panel = FilesystemPanel(Session())
    shown: list[str] = []
    panel.background_status.connect(shown.append)
    panel._on_prescan_activity("Indexing types", True)
    panel._on_prescan_count(1_500, 40_000)
    assert shown[-1] == "Background: Indexing types 1,500 / 40,000"
    panel._on_prescan_activity("Indexing types", False)
    assert shown[-1] == ""
    panel.close()
