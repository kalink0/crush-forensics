# SPDX-License-Identifier: Apache-2.0
"""The hint on how the opened file opens otherwise (Open Disk Image…, Open
in New Window) is shown as a banner above it, with a button for each way
offered -- not only in the status bar. A note about a whole source stays in
the status bar.

The facts behind the buttons on a file opened as a single file are set by
open_vfs(): disk_image_path when the content says it is a disk image,
embedded_zip_path when a ZIP follows leading bytes.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from crush.core.vfs import DirectoryVFS, FileVFS, VFS, VFSNode, open_vfs
from crush.third_party import qnxprobe

_EWF_HEAD = qnxprobe.EWF_SIGNATURE + bytes(4096)
_L01_HEAD = qnxprobe.L01_SIGNATURE + bytes(4096)


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner", b"x")
    return buf.getvalue()


# -- the facts open_vfs() sets ---------------------------------------------------

def test_file_whose_content_is_a_disk_image_offers_it(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    path.write_bytes(_EWF_HEAD)
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert vfs.disk_image_path == path
    assert vfs.embedded_zip_path is None


def test_logical_evidence_is_not_offered_as_a_disk_image(tmp_path: Path) -> None:
    path = tmp_path / "evidence.L01"
    path.write_bytes(_L01_HEAD)
    vfs = open_vfs(path)
    assert "logical evidence" in str(vfs.fallback_note)
    assert vfs.disk_image_path is None


def test_no_offer_after_open_disk_image_failed_on_it(tmp_path: Path) -> None:
    path = tmp_path / "disk.img"
    path.write_bytes(bytes(8192))
    vfs = open_vfs(path, as_disk_image=True)
    assert isinstance(vfs, FileVFS)
    assert vfs.fallback_note
    assert vfs.disk_image_path is None


def test_zip_after_leading_bytes_offers_the_zip(tmp_path: Path) -> None:
    path = tmp_path / "setup.exe"
    path.write_bytes(b"MZ" + bytes(98) + _zip_bytes())
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert vfs.embedded_zip_path == path
    assert vfs.disk_image_path is None


def test_plain_file_offers_nothing(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_bytes(b"hello\n")
    vfs = open_vfs(path)
    assert not vfs.fallback_note
    assert vfs.disk_image_path is None and vfs.embedded_zip_path is None


# -- the banner ------------------------------------------------------------------

def _banner(win: QWidget) -> QWidget | None:
    bars = win.findChildren(QWidget, "source_hint_banner")
    return bars[-1] if bars else None


def _open(win: Any, node: VFSNode, vfs: VFS) -> QWidget | None:
    win._open_node(node, vfs)
    return _banner(win)


def test_member_disk_image_gets_banner_with_button(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crush.ui.main_window import MainWindow

    (tmp_path / "evidence").write_bytes(_EWF_HEAD)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence")
    win = MainWindow()
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        win, "_open_in_new_window",
        lambda n, v, as_disk_image=False: calls.append((n.name, as_disk_image)),
    )
    try:
        bar = _open(win, node, vfs)
        assert bar is not None
        assert "looks like a disk image" in bar.findChild(QLabel).text()
        buttons = bar.findChildren(QPushButton)
        assert [b.text() for b in buttons] == ["Open Disk Image in New Window"]
        buttons[0].click()
        assert calls == [("evidence", True)]
        assert "looks like a disk image" in win._status.currentMessage()
    finally:
        win.close()


def test_single_file_source_gets_banner_that_opens_it_as_disk_image(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crush.ui.main_window import MainWindow

    path = tmp_path / "evidence"
    path.write_bytes(_EWF_HEAD)
    vfs = open_vfs(path)
    win = MainWindow()
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(win, "_load_source", lambda p, **kw: calls.append((p, kw)))
    try:
        bar = _open(win, vfs.root(), vfs)
        assert bar is not None
        assert "EWF container" in bar.findChild(QLabel).text()
        buttons = bar.findChildren(QPushButton)
        assert [b.text() for b in buttons] == ["Open as Disk Image"]
        buttons[0].click()
        assert calls == [(str(path), {
            "open_after_load": True, "append_to_tree": True, "as_disk_image": True,
        })]
    finally:
        win.close()


def test_logical_evidence_member_gets_banner_without_button(
    qapp: QApplication, tmp_path: Path
) -> None:
    from crush.ui.main_window import MainWindow

    (tmp_path / "evidence.L01").write_bytes(_L01_HEAD)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.L01")
    win = MainWindow()
    try:
        bar = _open(win, node, vfs)
        assert bar is not None
        assert "logical evidence" in bar.findChild(QLabel).text()
        assert bar.findChildren(QPushButton) == []
    finally:
        win.close()


def test_note_about_a_whole_source_stays_in_the_status_bar(
    qapp: QApplication, tmp_path: Path
) -> None:
    """An AFF4 shown as its ZIP says so for every file opened from it:
    in the status bar, not as a banner repeated over each file."""
    from crush.core.vfs import ZipVFS
    from crush.ui.main_window import MainWindow

    path = tmp_path / "container.aff4"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("information.turtle", "@prefix aff4: <http://aff4.org/Schema#> .\n")
        zf.comment = b"aff4://10cf2ea2-beab-4162-9f38-f0dd44251b52"
    vfs = open_vfs(path)
    assert isinstance(vfs, ZipVFS)
    node = next(c for c in vfs.root().children if c.name == "information.turtle")
    win = MainWindow()
    try:
        assert _open(win, node, vfs) is None
        assert "AFF4 container shown as the ZIP archive" in win._status.currentMessage()
    finally:
        win.close()
        vfs.close()


def test_plain_file_gets_no_banner(qapp: QApplication, tmp_path: Path) -> None:
    from crush.ui.main_window import MainWindow

    (tmp_path / "notes.txt").write_bytes(b"hello\n")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "notes.txt")
    win = MainWindow()
    try:
        assert _open(win, node, vfs) is None
    finally:
        win.close()
