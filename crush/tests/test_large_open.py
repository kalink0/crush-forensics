# SPDX-License-Identifier: Apache-2.0
"""Size guard before loading a file into memory, the wait-dialog helper that
keeps the window responsive, and "Open as Hex" showing the whole file.

"Open as Hex" used to cut every file at 256 KB while the status line
reported the cut size as the file's total -- a silent truncation. It now
loads the whole file; only genuinely memory-endangering sizes are put to the
user first, and nothing is ever shortened.
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from crush.core import sysmem
from crush.core.vfs import DirectoryVFS, VFSNode
from crush.ui import large_open
from crush.ui.busy_dialog import busy_call
from crush.ui.large_open import Decision, Level, assess
from crush.viewers.hex_viewer import HexViewer

GIB = 1024**3


# ---------------------------------------------------------------------------
# assessment
# ---------------------------------------------------------------------------


def test_assess_levels_scale_with_free_memory() -> None:
    avail = 40 * GIB
    assert assess(1 * GIB, avail).level is Level.OK
    assert assess(10 * GIB, avail).level is Level.OK  # exactly 25 %
    assert assess(11 * GIB, avail).level is Level.WARN
    assert assess(32 * GIB, avail).level is Level.WARN  # exactly 80 %
    assert assess(33 * GIB, avail).level is Level.BLOCK


def test_same_file_is_riskier_on_a_smaller_machine() -> None:
    assert assess(3 * GIB, 40 * GIB).level is Level.OK
    assert assess(3 * GIB, 6 * GIB).level is Level.WARN
    assert assess(3 * GIB, 3 * GIB).level is Level.BLOCK


def test_unknown_memory_uses_a_conservative_fallback() -> None:
    assert assess(100 * 1024**2, None).level is Level.OK
    assert assess(2 * GIB, None).level is Level.WARN
    assert assess(8 * GIB, None).level is Level.BLOCK


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/meminfo")
def test_available_memory_is_reported_on_linux() -> None:
    value = sysmem.available_memory()
    assert value is not None and value > 0


# ---------------------------------------------------------------------------
# dialog decisions
# ---------------------------------------------------------------------------


def _stub_dialog(monkeypatch: pytest.MonkeyPatch, *, available: int | None, click: str | None) -> dict:
    seen: dict = {"shown": False, "buttons": []}
    monkeypatch.setattr(large_open, "available_memory", lambda: available)

    def fake_exec(self: QMessageBox) -> int:
        seen["shown"] = True
        seen["text"] = self.text()
        seen["buttons"] = [b.text().replace("&", "") for b in self.buttons()]
        seen["choice"] = next((b for b in self.buttons() if b.text().replace("&", "") == click), None)
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: seen["choice"])
    return seen


def test_small_file_opens_without_asking(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _stub_dialog(monkeypatch, available=40 * GIB, click=None)
    decision = large_open.confirm_large_open(QWidget(), "a.bin", 5 * GIB, can_open_as_source=False)
    assert decision is Decision.PROCEED
    assert not seen["shown"]


def test_risky_file_offers_open_anyway_and_alternatives(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _stub_dialog(monkeypatch, available=40 * GIB, click="Open anyway")
    decision = large_open.confirm_large_open(QWidget(), "a.zip", 15 * GIB, can_open_as_source=True)
    assert decision is Decision.PROCEED
    assert set(seen["buttons"]) == {"Open anyway", "Open in New Window", "Export…", "Cancel"}
    assert "15.0 GB" in seen["text"]


def test_hopeless_file_does_not_offer_open_anyway(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _stub_dialog(monkeypatch, available=8 * GIB, click="Export…")
    decision = large_open.confirm_large_open(QWidget(), "a.img", 20 * GIB, can_open_as_source=False)
    assert decision is Decision.EXPORT
    assert "Open anyway" not in seen["buttons"]
    assert "Open in New Window" not in seen["buttons"]


def test_new_window_and_cancel_decisions(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_dialog(monkeypatch, available=8 * GIB, click="Open in New Window")
    assert (
        large_open.confirm_large_open(QWidget(), "a.zip", 20 * GIB, can_open_as_source=True)
        is Decision.NEW_WINDOW
    )
    _stub_dialog(monkeypatch, available=8 * GIB, click=None)
    assert (
        large_open.confirm_large_open(QWidget(), "a.zip", 20 * GIB, can_open_as_source=True)
        is Decision.CANCEL
    )


# ---------------------------------------------------------------------------
# busy_call keeps the event loop running
# ---------------------------------------------------------------------------


def test_busy_call_returns_result_and_keeps_ui_alive(qapp: QApplication) -> None:
    ticks = {"n": 0}
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.__setitem__("n", ticks["n"] + 1))
    timer.start(20)

    def slow() -> str:
        time.sleep(0.4)
        return "done"

    try:
        assert busy_call(QWidget(), "Working…", slow) == "done"
    finally:
        timer.stop()
    assert ticks["n"] >= 3  # the UI thread kept processing events while waiting


def test_busy_call_raises_on_failure(qapp: QApplication) -> None:
    def boom() -> None:
        raise OSError("disk gone")

    with pytest.raises(RuntimeError, match="disk gone"):
        busy_call(QWidget(), "Working…", boom)


# ---------------------------------------------------------------------------
# main window integration
# ---------------------------------------------------------------------------


def _source(tmp_path: Path, size: int) -> tuple[DirectoryVFS, VFSNode, bytes]:
    data = bytes((i * 7 + i // 251) % 256 for i in range(size))
    (tmp_path / "blob.bin").write_bytes(data)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "blob.bin")
    return vfs, node, data


@pytest.mark.parametrize("size", [1024 * 1024, 9 * 1024 * 1024])
def test_open_as_hex_shows_the_whole_file(qapp: QApplication, tmp_path: Path, size: int) -> None:
    """1 MiB is the regression (was cut to 256 KB); 9 MiB also takes the
    worker-thread path used above the busy-dialog cut-off."""
    from crush.ui.main_window import MainWindow

    vfs, node, data = _source(tmp_path, size)
    win = MainWindow()
    try:
        win._open_node_mode(node, vfs, "hex")
        viewer = win.findChildren(HexViewer)[-1]
        assert len(viewer._data) == size
        assert hashlib.sha256(viewer._data).digest() == hashlib.sha256(data).digest()
        assert f"({size:,} B total)" in viewer._status.text()
    finally:
        win.close()


def test_double_click_on_unknown_big_file_uses_worker_thread_and_shows_all(
    qapp: QApplication, tmp_path: Path
) -> None:
    from crush.ui.main_window import MainWindow

    vfs, node, data = _source(tmp_path, 9 * 1024 * 1024)
    win = MainWindow()
    try:
        win._open_node(node, vfs)
        viewer = win.findChildren(HexViewer)[-1]
        assert viewer._data == data
    finally:
        win.close()


@pytest.mark.parametrize(
    "decision,expected",
    [
        (Decision.CANCEL, "none"),
        (Decision.NEW_WINDOW, "new_window"),
        (Decision.EXPORT, "export"),
        (Decision.PROCEED, "opened"),
    ],
)
def test_guard_routes_the_users_choice(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision: Decision, expected: str
) -> None:
    from crush.ui.main_window import MainWindow

    vfs, node, _ = _source(tmp_path, 4096)
    win = MainWindow()
    calls: list[str] = []
    monkeypatch.setattr(large_open, "confirm_large_open", lambda *a, **k: decision)
    monkeypatch.setattr(win, "_open_in_new_window", lambda n, v: calls.append("new_window"))
    monkeypatch.setattr(win, "_export_node", lambda n, v: calls.append("export"))
    monkeypatch.setattr(win, "_open_node_impl", lambda n, v: calls.append("opened"))
    try:
        win._open_node(node, vfs)
    finally:
        win.close()
    assert calls == ([] if expected == "none" else [expected])


def test_guard_covers_open_as_modes_but_not_default_twice(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crush.ui.main_window import MainWindow

    vfs, node, _ = _source(tmp_path, 4096)
    win = MainWindow()
    asked: list[str] = []

    def fake_confirm(*a: object, **k: object) -> Decision:
        asked.append("ask")
        return Decision.CANCEL

    monkeypatch.setattr(large_open, "confirm_large_open", fake_confirm)
    try:
        for mode in ("text", "hex", "protobuf", "mmkv", "sqlcipher", "realm_encrypted", "pdf_encrypted"):
            asked.clear()
            win._open_node_mode(node, vfs, mode)
            assert asked == ["ask"], mode
        asked.clear()
        win._open_node_mode(node, vfs, "default")  # ends in _open_node(): one question, not two
        assert asked == ["ask"]
    finally:
        win.close()


# ---------------------------------------------------------------------------
# hex search: same answers, also on the worker-thread path
# ---------------------------------------------------------------------------


def _search(viewer: HexViewer, mode: str, query: str) -> list[int]:
    viewer._search_mode.setCurrentText(mode)
    viewer._search_input.setText(query)
    viewer._collect_hits()
    return list(viewer._search_hits)


@pytest.mark.parametrize("force_worker", [False, True])
def test_hex_search_finds_all_hits(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, force_worker: bool
) -> None:
    if force_worker:
        monkeypatch.setattr("crush.viewers.hex_viewer._BUSY_SCAN_BYTES", 0)
    data = b"abc DEAD abc \xde\xad\xbe\xef abc \xff end"
    viewer = HexViewer(data)
    assert _search(viewer, "ASCII", "abc") == [0, 9, 18]
    assert _search(viewer, "ASCII", "ABC") == []  # case-sensitive, as before
    assert _search(viewer, "Hex", "de ad be ef") == [13]
    assert _search(viewer, "ASCII", "\xff") == [22]  # latin-1: byte 0xFF
    assert _search(viewer, "ASCII", "€") == []  # cannot occur in the bytes
    assert _search(viewer, "Hex", "zz") == []


def test_scan_finds_every_match_across_slice_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    import random

    monkeypatch.setattr("crush.viewers.hex_viewer._SCAN_SLICE", 7)
    rng = random.Random(5)
    data = bytes(rng.choice(b"ab") for _ in range(500)) + b"aaaa" * 10
    for pattern in (b"a", b"ab", b"aba", b"aaaa", b"bbbbb", b"x", data[:3], data[-4:], data):
        expected = [i for i in range(len(data) - len(pattern) + 1) if data.startswith(pattern, i)]
        assert HexViewer._scan_hits(data, pattern) == expected, pattern
    assert HexViewer._scan_hits(b"", b"a") == []
    assert HexViewer._scan_hits(b"ab", b"abc") == []


def test_highlights_cover_exactly_the_hits_on_the_current_page(qapp: QApplication) -> None:
    page = 256 * 1024
    data = bytearray(b"\x00" * (3 * page))
    marks = [5, page - 2, page + 7, 2 * page + 100]  # page - 2 straddles a page edge
    for m in marks:
        data[m : m + 4] = b"\xde\xad\xbe\xef"
    viewer = HexViewer(bytes(data))
    assert _search(viewer, "Hex", "de ad be ef") == marks

    def selections_on(p: int) -> int:
        viewer._page = p
        viewer._load_page()
        viewer._update_highlights()
        return len(viewer._text.extraSelections())

    per_page = [selections_on(p) for p in range(3)]
    expected = [
        sum(1 for m in marks if m < (p + 1) * page and m + 4 > p * page) for p in range(3)
    ]
    # a hit spanning bytes across rows may add one selection per row; never fewer than one per hit
    assert all(got >= want > 0 for got, want in zip(per_page, expected))
    assert per_page[2] >= 1


def test_guard_offers_new_window_for_any_file(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large .bin may be a disk image -- open_vfs() recognises one by its
    content -- so opening it as a source is offered whatever its name."""
    from crush.ui.main_window import MainWindow

    vfs, node, _ = _source(tmp_path, 4096)
    assert not node.name.endswith((".zip", ".img", ".e01"))
    win = MainWindow()
    seen: list[object] = []

    def fake_confirm(*a: object, **k: object) -> Decision:
        seen.append(k.get("can_open_as_source"))
        return Decision.CANCEL

    monkeypatch.setattr(large_open, "confirm_large_open", fake_confirm)
    try:
        win._open_node(node, vfs)
    finally:
        win.close()
    assert seen == [True]
