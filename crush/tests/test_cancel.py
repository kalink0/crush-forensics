# SPDX-License-Identifier: Apache-2.0
"""Stopping long work: a source load, the hashing of a source or file in
integrity mode, an export, a .logarchive export, and the background type
indexing.

A stopped load opens nothing (a tree read in part would pass for the whole
source); a stopped hash is logged and the data still shows; a stopped
export keeps what it wrote, marked incomplete, with no half-written file;
a stopped indexing says so in the status bar and can be resumed.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import IO, Any

import pytest

from crush.core import load_phase
from crush.core.load_phase import LoadCancelled, phase_reporter
from crush.core.session import Session
from crush.core.vfs import DirectoryVFS, VFSNode, open_vfs
from crush.core.vfs_stream import CopyCancelledError


def _folder(tmp_path: Path, n: int = 5) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(n):
        (src / f"f{i}.txt").write_bytes(b"x" * (i + 1))
    return src


# -- load_phase ----------------------------------------------------------------

@pytest.mark.parametrize("call", [
    lambda: load_phase.count_entry(),
    lambda: load_phase.report_phase(load_phase.PHASE_READ_FILESYSTEMS),
    lambda: load_phase.report_step(1, 2),
    lambda: load_phase.check_cancelled(),
])
def test_every_checkpoint_raises_once_cancelled(call: Any) -> None:
    with phase_reporter(lambda _p: None, cancelled=lambda: True):
        with pytest.raises(LoadCancelled):
            call()
    call()  # no reporter left: no-op


def test_a_cancel_is_not_taken_for_an_error() -> None:
    """`except Exception` (one unreadable volume made a status) must not
    swallow it."""
    with phase_reporter(lambda _p: None, cancelled=lambda: True):
        with pytest.raises(LoadCancelled):
            try:
                load_phase.count_entry()
            except Exception:  # noqa: BLE001 -- what the test is about
                pytest.fail("LoadCancelled caught as an Exception")


@pytest.mark.parametrize("kind", ["folder", "zip"])
def test_any_source_stops_reading(tmp_path: Path, kind: str) -> None:
    src = _folder(tmp_path)
    if kind == "zip":
        import zipfile

        archive = tmp_path / "src.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for f in src.iterdir():
                zf.write(f, f.name)
        src = archive
    with phase_reporter(lambda _p: None, cancelled=lambda: True):
        with pytest.raises(LoadCancelled):
            open_vfs(src).root()


# -- the load worker -------------------------------------------------------------

def _run_load(worker: Any) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    worker.finished.connect(lambda *a: seen.append(("finished", *a)))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.cancelled.connect(lambda: seen.append(("cancelled",)))
    worker.hash_cancelled.connect(lambda *a: seen.append(("hash_cancelled", *a)))
    worker.hashed.connect(lambda *a: seen.append(("hashed",)))
    worker.run()
    return seen


def test_a_cancelled_load_opens_nothing(qapp: Any, tmp_path: Path) -> None:
    from crush.ui.main_window import _LoadSourceWorker

    session = Session()
    src = _folder(tmp_path)
    seen = _run_load(_LoadSourceWorker(session, str(src), False, cancel_requested=lambda: True))
    assert seen == [("cancelled",)]
    assert session.sources == []


def test_a_cancel_after_reading_is_a_cancel_of_the_load(qapp: Any, tmp_path: Path) -> None:
    """A Cancel no reading checkpoint was left to see is not taken for a
    Cancel of the hashing that follows: still not opened."""
    from crush.ui.main_window import _LoadSourceWorker

    session = Session()
    f = tmp_path / "one.bin"
    f.write_bytes(b"abc")
    flag = {"set": False}
    worker = _LoadSourceWorker(session, str(f), True, cancel_requested=lambda: flag["set"])
    # Set once the source is read, before the hash phase.
    real_add = session.add_source

    def add(*a: Any, **kw: Any) -> Any:
        vfs = real_add(*a, **kw)
        flag["set"] = True
        return vfs

    session.add_source = add  # type: ignore[method-assign]
    seen = _run_load(worker)
    assert seen == [("cancelled",)]
    assert session.sources == []


def test_a_cancelled_hash_still_opens_the_source(qapp: Any, tmp_path: Path) -> None:
    import logging

    from crush.ui.main_window import _LoadSourceWorker

    session = Session()
    f = tmp_path / "one.bin"
    f.write_bytes(b"abc" * 1000)
    flag = {"set": False}
    worker = _LoadSourceWorker(session, str(f), True, cancel_requested=lambda: flag["set"])

    def on_phase(phase: str) -> None:
        if phase == load_phase.PHASE_HASH_SOURCE:
            flag["set"] = True

    worker.phase.connect(on_phase)
    # Straight on the logger: a window opened by an earlier test stops it
    # propagating to the root logger caplog listens on.
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]
    logger = logging.getLogger("crush")
    logger.addHandler(handler)
    try:
        seen = _run_load(worker)
    finally:
        logger.removeHandler(handler)
    kinds = [s[0] for s in seen]
    assert kinds == ["hash_cancelled", "finished"]
    assert len(session.sources) == 1
    assert any(
        "INTEGRITY source not hashed: hashing cancelled by the analyst" in r.getMessage()
        for r in records
    )


def test_loading_dialog_cancel(qapp: Any, widgets: Any) -> None:
    from crush.ui.loading_dialog import LoadingDialog

    dialog = widgets(LoadingDialog("Loading source…", cancellable=True))
    assert not dialog.is_cancel_requested()
    dialog.request_cancel()
    assert dialog.is_cancel_requested()
    assert dialog._label.text() == "Cancelling…"
    dialog.set_phase(load_phase.PHASE_READ_FILESYSTEMS)
    assert dialog._label.text() == "Cancelling…"  # until the work stops


def test_loading_dialog_without_cancel_has_no_button(qapp: Any, widgets: Any) -> None:
    from crush.ui.loading_dialog import LoadingDialog

    dialog = widgets(LoadingDialog("Loading…"))
    dialog.request_cancel()
    assert not dialog.is_cancel_requested()


def test_busy_call_cancel_raises(qapp: Any, widgets: Any) -> None:
    from PySide6.QtWidgets import QWidget

    from crush.ui.busy_dialog import busy_call

    owner = widgets(QWidget())

    def work() -> None:
        while True:
            load_phase.check_cancelled()
            time.sleep(0.01)

    from PySide6.QtCore import QTimer

    def press() -> None:
        from crush.ui.loading_dialog import LoadingDialog

        for dialog in owner.findChildren(LoadingDialog):
            dialog.request_cancel()

    QTimer.singleShot(50, press)
    with pytest.raises(LoadCancelled):
        busy_call(owner, "Unlocking volumes…", work, cancellable=True)


# -- exports ---------------------------------------------------------------------

def _run_export(worker: Any) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    worker.finished.connect(lambda *a: seen.append(("finished", *a)))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.cancelled.connect(lambda *a: seen.append(("cancelled", *a)))
    worker.run()
    return seen


class _CancelAfter(DirectoryVFS):
    """Asks *worker* to stop once *n* files were opened."""

    def __init__(self, path: Path, n: int) -> None:
        super().__init__(path)
        self.worker: Any = None
        self._left = n

    def open(self, node: VFSNode) -> IO[bytes]:
        self._left -= 1
        if self._left < 0 and self.worker is not None:
            self.worker.cancel()
        return super().open(node)


def test_copy_cancelled_mid_file_leaves_nothing(tmp_path: Path) -> None:
    from crush.ui.main_window import _copy_export_file, _ExportCancelled

    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(b"z" * (3 * 1024 * 1024))
    vfs = DirectoryVFS(src)
    node = vfs.root().children[0]
    target = tmp_path / "out.bin"
    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 1  # after the first chunk

    with pytest.raises(_ExportCancelled):
        _copy_export_file(vfs, node, target, True, cancelled)
    assert not target.exists()


@pytest.mark.parametrize("integrity", [True, False])
def test_tree_export_cancelled_is_marked_incomplete(
    qapp: Any, tmp_path: Path, integrity: bool
) -> None:
    from crush.ui.main_window import _EXPORT_CANCELLED_FILE, _ExportWorker

    vfs = _CancelAfter(_folder(tmp_path), 2)
    root = vfs.root()
    dest = tmp_path / "dest"
    dest.mkdir()
    worker = _ExportWorker(vfs, root, str(dest), integrity)
    vfs.worker = worker
    seen = _run_export(worker)

    target = dest / root.name
    assert seen == [("cancelled", str(target), 2)]
    marker = (target / _EXPORT_CANCELLED_FILE).read_text(encoding="utf-8")
    assert "cancelled by the analyst" in marker
    assert "files exported before the cancel: 2" in marker
    exported = sorted(p.name for p in target.iterdir() if p.name.startswith("f"))
    assert len(exported) == 2
    hashes = target / "crush-export-hashes.txt"
    if integrity:
        text = hashes.read_text(encoding="utf-8")
        assert text.startswith("# export cancelled: incomplete")
        assert len([ln for ln in text.splitlines() if not ln.startswith("#")]) == 2
    else:
        assert not hashes.exists()


def test_single_file_export_cancelled_writes_nothing(qapp: Any, tmp_path: Path) -> None:
    from crush.ui.main_window import _ExportWorker

    src = _folder(tmp_path, 1)
    vfs = DirectoryVFS(src)
    node = vfs.root().children[0]
    dest = tmp_path / "dest"
    dest.mkdir()
    worker = _ExportWorker(vfs, node, str(dest), True)
    worker.cancel()
    seen = _run_export(worker)
    assert seen == [("cancelled", "", 0)]
    assert list(dest.iterdir()) == []


def test_filtered_export_cancelled_is_marked_incomplete(qapp: Any, tmp_path: Path) -> None:
    from crush.ui.main_window import _EXPORT_CANCELLED_FILE, _ExportMultiWorker

    vfs = _CancelAfter(_folder(tmp_path), 3)
    entries = [(c, vfs, f"/src/{c.name}") for c in vfs.root().children]
    dest = tmp_path / "dest"
    dest.mkdir()
    worker = _ExportMultiWorker(entries, str(dest), True, "name:f")
    vfs.worker = worker
    seen = _run_export(worker)
    assert seen[0][0] == "cancelled" and seen[0][2] == 3
    root = Path(seen[0][1])
    assert (root / _EXPORT_CANCELLED_FILE).exists()
    hashes = (root / "crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "# export cancelled: incomplete, 3 of 5 files exported" in hashes


def test_logarchive_build_stops(tmp_path: Path) -> None:
    from crush.parsers.unified_log_parser import build_logarchive_from_acquisition

    vfs = DirectoryVFS(_folder(tmp_path))
    with pytest.raises(CopyCancelledError):
        build_logarchive_from_acquisition(
            vfs.root(), vfs, tmp_path / "build", cancelled=lambda: True
        )


def test_logarchive_export_cancelled_saves_nothing(qapp: Any, tmp_path: Path) -> None:
    from crush.ui.main_window import _ExportLogarchiveWorker

    vfs = DirectoryVFS(_folder(tmp_path))
    dest = tmp_path / "out.logarchive"
    worker = _ExportLogarchiveWorker(vfs, vfs.root(), str(dest))
    worker.cancel()
    seen = _run_export(worker)
    assert seen == [("cancelled", str(dest), False)]
    assert not dest.exists()


# -- the type indexing -----------------------------------------------------------

def test_indexing_stop_and_resume(qapp: Any, widgets: Any, tmp_path: Path) -> None:
    from crush.ui.fs_panel import FilesystemPanel

    panel = widgets(FilesystemPanel(Session()))
    shown: list[str] = []
    states: list[str] = []
    panel.background_status.connect(shown.append)
    panel.type_indexing_state.connect(states.append)
    panel._vfs_list = [DirectoryVFS(_folder(tmp_path))]
    panel._on_prescan_activity("Indexing types", True)
    panel._on_prescan_count(1_500, 40_000)
    gen = panel._prescan_gen
    assert states[-1] == "running"

    panel.stop_type_indexing()
    assert panel._prescan_gen != gen  # the running scan ends
    assert states[-1] == "stopped"
    assert shown[-1] == "Type indexing stopped: 1,500 of 40,000 files"
    assert not panel.has_running_activity()

    started: list[int] = []
    panel._start_prescan = lambda _l, g: started.append(g)  # type: ignore[method-assign]
    panel.resume_type_indexing()
    assert started == [panel._prescan_gen]
    assert shown[-1] == ""
    assert states[-1] == "idle"  # until the scan reports its start


def test_pending_labels_are_read_once_indexing_is_stopped(
    qapp: Any, widgets: Any, tmp_path: Path
) -> None:
    """Rows that waited for the scan don't stay "…" for good."""
    from crush.ui.fs_panel import FilesystemPanel

    class _NotCached(DirectoryVFS):
        def peek_if_cached(self, node: VFSNode, n: int) -> bytes | None:
            return None

    panel = widgets(FilesystemPanel(Session()))
    vfs = _NotCached(_folder(tmp_path, 1))
    node = vfs.root().children[0]
    panel._vfs_list = [vfs]
    panel._on_prescan_activity("Indexing types", True)
    panel.stop_type_indexing()

    from PySide6.QtGui import QStandardItem

    item = QStandardItem("")
    panel._type_queue.append((item, node, vfs))
    panel._process_type_queue()
    assert item.text() == "…"
    deadline = time.monotonic() + 5
    while item.text() == "…" and time.monotonic() < deadline:
        panel._retry_pending_types()
        panel._process_type_queue()
        time.sleep(0.05)
    assert item.text() not in ("…", "")
