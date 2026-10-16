# SPDX-License-Identifier: Apache-2.0
"""Unlock Volume… on a locked volume inside a disk image: the image is read
again with the secret (and every one given before), the source is replaced
in the tree and the session, and the tabs open on it are opened again from
the new source. The wait dialog names each phase of a disk image load."""
from __future__ import annotations

import gzip
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from crush.core.load_phase import PHASE_SEARCH_VOLUMES
from crush.core.vfs import RawImageVFS
from crush.tests.conftest import FIXTURES_DIR

_LUKS_PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def window(qapp: QApplication) -> Iterator[Any]:
    from crush.ui.main_window import MainWindow

    win = MainWindow()
    try:
        yield win
    finally:
        win.close()


def _luks_image(tmp_path: Path) -> Path:
    img = tmp_path / "raw_luks1.img"
    img.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_luks1.img.gz").read_bytes()))
    return img


def _show(win: Any, vfs: RawImageVFS) -> None:
    win.session.add_source_vfs(vfs)
    win._fs_panel.load_vfs(vfs)


def _answer(monkeypatch: pytest.MonkeyPatch, password: str) -> None:
    from crush.ui.unlock_volume_dialog import UnlockVolumeDialog

    monkeypatch.setattr(UnlockVolumeDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(UnlockVolumeDialog, "password", lambda self: password)


def test_unlocking_replaces_the_source_and_reopens_its_tabs(
    window: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = RawImageVFS(_luks_image(tmp_path))
    _show(window, old)
    container = next(c for c in old.root().children if c.name == "lba0")
    window._open_node_mode(container, old, "hex")
    assert window._viewer_tabs.count() == 1
    _answer(monkeypatch, _LUKS_PASSPHRASE)

    window._unlock_volume(container, old)

    new = window._fs_panel._vfs_list[0]
    assert new is not old and isinstance(new, RawImageVFS)
    assert window.session.sources == [new]
    assert any(c.name.startswith("luks_") and c.is_dir for c in new.root().children)
    assert window._viewer_tabs.count() == 1
    tab = window._viewer_tabs.widget(0)
    assert tab.property("crush_vfs") is new
    assert tab.property("crush_path") == "/lba0"
    assert tab.property("crush_viewer") == "hex"
    assert "lba0" in window._status.currentMessage()
    new.close()


def test_a_secret_that_opens_nothing_keeps_the_volume_locked_and_says_why(
    window: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = RawImageVFS(_luks_image(tmp_path))
    _show(window, old)
    container = next(c for c in old.root().children if c.name == "lba0")
    _answer(monkeypatch, "not it")
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "information", lambda _p, _t, text: shown.append(text))

    window._unlock_volume(container, old)

    new = window._fs_panel._vfs_list[0]
    assert new.is_locked_volume(next(c for c in new.root().children if c.name == "lba0"))
    assert len(shown) == 1 and "no passphrase given opens a keyslot" in shown[0]
    new.close()


def test_the_wait_dialog_names_the_volume_search(qapp: QApplication) -> None:
    from crush.ui.loading_dialog import LoadingDialog

    dialog = LoadingDialog("Loading source…")
    dialog.set_phase(PHASE_SEARCH_VOLUMES)
    assert dialog._label.text() == "Searching volumes…"
    dialog.set_phase("not a phase")
    assert dialog._label.text() == "Searching volumes…"
    dialog.close()
