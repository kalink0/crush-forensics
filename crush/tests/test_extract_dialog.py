# SPDX-License-Identifier: Apache-2.0
"""Copy-with-progress dialog and temp-space confirmation used when an archive
member is opened in a new window or an external app."""
from __future__ import annotations

import hashlib
import io
import random
import time
import zipfile
from pathlib import Path
from typing import IO

from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox, QProgressDialog, QPushButton, QWidget

from crush.core import tempdir
from crush.core.vfs import VFS, VFSNode, ZipVFS
from crush.ui import extract_dialog


def _zip_with_member(tmp_path: Path, size: int) -> tuple[ZipVFS, VFSNode, bytes]:
    data = random.Random(21).randbytes(size)
    path = tmp_path / "src.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner/member.bin", data)
    vfs = ZipVFS(path)
    node = vfs.root().children[0].children[0]
    return vfs, node, data


def test_copy_node_with_progress_copies_and_hashes(qapp: QApplication, tmp_path: Path) -> None:
    vfs, node, data = _zip_with_member(tmp_path, 3 * 1024 * 1024 + 17)
    dest = tmp_path / "out.bin"
    parent = QWidget()
    outcome = extract_dialog.copy_node_with_progress(
        parent, vfs, node, dest, title="Test", want_hash=True
    )
    assert outcome.status == "ok"
    assert dest.read_bytes() == data
    assert outcome.bytes_copied == len(data)
    assert outcome.sha256 == hashlib.sha256(data).hexdigest()
    vfs.close()


def test_copy_node_with_progress_reports_failure_and_leaves_no_file(
    qapp: QApplication, tmp_path: Path
) -> None:
    class _Broken(VFS):
        def root(self) -> VFSNode:
            return VFSNode(name="r", path="/", is_dir=True)

        def read(self, node: VFSNode) -> bytes:
            raise OSError("boom")

        def open(self, node: VFSNode) -> IO[bytes]:
            raise OSError("boom")

        def file_count(self, node: VFSNode) -> int:
            return 1

        def total_size(self, node: VFSNode) -> int:
            return 0

    node = VFSNode(name="x.bin", path="/x.bin", is_dir=False, size=10)
    dest = tmp_path / "x.bin"
    outcome = extract_dialog.copy_node_with_progress(
        QWidget(), _Broken(), node, dest, title="Test"
    )
    assert outcome.status == "failed"
    assert "boom" in outcome.message
    assert not dest.exists()


def test_copy_node_with_progress_can_be_cancelled(qapp: QApplication, tmp_path: Path) -> None:
    """A finite but slow source (about 2 s in total): Cancel arrives mid-copy."""

    class _Slow(io.RawIOBase):
        def __init__(self) -> None:
            super().__init__()
            self._left = 20 * 1024 * 1024

        def readable(self) -> bool:
            return True

        def readinto(self, b: object) -> int:
            time.sleep(0.005)
            n = min(len(b), 64 * 1024, self._left)  # type: ignore[arg-type]
            b[:n] = b"\x00" * n  # type: ignore[index]
            self._left -= n
            return n

    class _SlowVFS(VFS):
        def root(self) -> VFSNode:
            return VFSNode(name="r", path="/", is_dir=True)

        def read(self, node: VFSNode) -> bytes:
            raise AssertionError("streaming copy must not call read()")

        def open(self, node: VFSNode) -> IO[bytes]:
            return io.BufferedReader(_Slow(), buffer_size=64 * 1024)  # type: ignore[return-value]

        def file_count(self, node: VFSNode) -> int:
            return 1

        def total_size(self, node: VFSNode) -> int:
            return 0

    node = VFSNode(name="slow.bin", path="/slow.bin", is_dir=False, size=20 * 1024 * 1024)
    dest = tmp_path / "slow.bin"
    parent = QWidget()

    def press_cancel() -> None:
        dialog = parent.findChild(QProgressDialog)
        if dialog is None:
            QTimer.singleShot(50, press_cancel)
            return
        dialog.findChild(QPushButton).click()  # what the user's Cancel click does

    QTimer.singleShot(200, press_cancel)
    outcome = extract_dialog.copy_node_with_progress(parent, _SlowVFS(), node, dest, title="Test")
    assert outcome.status == "cancelled"
    assert not dest.exists()


def _settings(tmp_path: Path) -> QSettings:
    return QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)


def test_confirm_temp_space_passes_when_there_is_room(
    qapp: QApplication, tmp_path: Path, monkeypatch: object
) -> None:
    tempdir.configure(tmp_path)
    try:
        assert extract_dialog.confirm_temp_space(QWidget(), _settings(tmp_path), 1024, "'x'")
    finally:
        tempdir.configure(None)


def test_confirm_temp_space_refuses_when_too_small(
    qapp: QApplication, tmp_path: Path, monkeypatch
) -> None:
    check = tempdir.SpaceCheck(
        location=tmp_path, needed=17 << 30, free=1 << 30, ram_backed=False, ram_available=None
    )
    monkeypatch.setattr(tempdir, "check_space", lambda _n: check)
    monkeypatch.setattr(QMessageBox, "exec", lambda self: 0)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: None)
    assert not extract_dialog.confirm_temp_space(QWidget(), _settings(tmp_path), 17 << 30, "'x'")


def test_confirm_temp_space_lets_user_continue_on_ram_backed_root(
    qapp: QApplication, tmp_path: Path, monkeypatch
) -> None:
    check = tempdir.SpaceCheck(
        location=tmp_path, needed=17 << 30, free=29 << 30, ram_backed=True, ram_available=40 << 30
    )
    monkeypatch.setattr(tempdir, "check_space", lambda _n: check)
    seen: dict[str, object] = {}

    def fake_exec(self: QMessageBox) -> int:
        seen["text"] = self.text()
        seen["buttons"] = [b.text() for b in self.buttons()]
        seen["choice"] = next(b for b in self.buttons() if b.text() == "Continue anyway")
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: seen["choice"])
    assert extract_dialog.confirm_temp_space(QWidget(), _settings(tmp_path), 17 << 30, "'x'")
    assert "RAM-backed" in str(seen["text"])
    assert "Choose directory…" in seen["buttons"]  # type: ignore[operator]


def test_choose_temp_directory_persists_and_configures(
    qapp: QApplication, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QFileDialog

    target = tmp_path / "bigdisk"
    target.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(target))
    settings = _settings(tmp_path)
    try:
        assert extract_dialog.choose_temp_directory(QWidget(), settings)
        assert tempdir.root() == target
        assert settings.value(extract_dialog.TEMP_DIR_SETTING, "", type=str) == str(target)
    finally:
        tempdir.configure(None)
