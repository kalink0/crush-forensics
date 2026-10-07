# SPDX-License-Identifier: Apache-2.0
"""Drag & drop opens through two zones over the window: Open (what Open
File… and Open Folder… open) and Open as Disk Image (one file, what Open
Disk Image… opens). Several files or a folder dropped on the image zone are
refused with the reason, never opened in part."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl
from PySide6.QtGui import QDragEnterEvent, QDragMoveEvent, QDropEvent
from PySide6.QtWidgets import QApplication, QWidget

from crush.ui.drop_overlay import disk_image_drop_refusal, local_paths, zone_at


# A drag event only points at its QMimeData: it has to outlive the event.
_MIME_KEPT: list[QMimeData] = []


def _mime(*paths: Path) -> QMimeData:
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(p)) for p in paths])
    _MIME_KEPT.append(mime)
    return mime


def _drop(mime: QMimeData, x: float) -> QDropEvent:
    return QDropEvent(
        QPointF(x, 100), Qt.DropAction.CopyAction, mime,
        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
    )


def _move(mime: QMimeData, x: float) -> QDragMoveEvent:
    return QDragMoveEvent(
        QPointF(x, 100).toPoint(), Qt.DropAction.CopyAction, mime,
        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
    )


# -- the rules ---------------------------------------------------------------------

def test_left_half_opens_right_half_opens_as_disk_image() -> None:
    assert zone_at(1000, 10) == "open"
    assert zone_at(1000, 499) == "open"
    assert zone_at(1000, 500) == "disk_image"
    assert zone_at(1000, 990) == "disk_image"


def test_one_file_is_taken_as_disk_image(tmp_path: Path) -> None:
    path = tmp_path / "disk.E01"
    path.write_bytes(b"x")
    assert disk_image_drop_refusal([str(path)]) == ""


def test_several_files_are_refused_as_disk_image(tmp_path: Path) -> None:
    paths = [tmp_path / "disk.E01", tmp_path / "disk.E02"]
    for p in paths:
        p.write_bytes(b"x")
    assert "One file at a time" in disk_image_drop_refusal([str(p) for p in paths])


def test_folder_is_refused_as_disk_image(tmp_path: Path) -> None:
    assert "not a folder" in disk_image_drop_refusal([str(tmp_path)])


def test_only_local_files_count(qapp: QApplication, tmp_path: Path) -> None:
    mime = QMimeData()
    mime.setUrls([QUrl("https://example.org/x.E01"), QUrl.fromLocalFile(str(tmp_path / "a"))])
    assert local_paths(mime) == [str(tmp_path / "a")]


# -- the window ----------------------------------------------------------------------

@pytest.fixture
def window(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> Any:
    from crush.ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1000, 600)
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(win, "_load_source", lambda p, **kw: calls.append((p, kw)))
    win.calls = calls
    try:
        yield win
    finally:
        win.close()


def test_drag_shows_both_zones_over_the_window(window: Any, tmp_path: Path) -> None:
    path = tmp_path / "evidence.zip"
    path.write_bytes(b"x")
    overlay = window._drop_overlay
    assert not overlay.isVisible()
    window.show()
    event = QDragEnterEvent(
        QPointF(10, 10).toPoint(), Qt.DropAction.CopyAction, _mime(path),
        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
    )
    window.dragEnterEvent(event)
    assert overlay.isVisible()
    assert overlay.geometry() == window.rect()


class _TakesDrops(QWidget):
    """Stands in for a viewer that takes drops itself (a text field)."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.entered = 0

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        self.entered += 1
        event.acceptProposedAction()


def test_drag_entering_the_window_reaches_the_zones_first(
    window: Any, tmp_path: Path
) -> None:
    """Seen on the window itself, before Qt hands the drag to the widget
    under the cursor, so the zones show even over a viewer that takes
    drops itself, and the drop lands on them."""
    path = tmp_path / "disk.E01"
    path.write_bytes(b"x")
    window.show()
    viewer = _TakesDrops(window)
    viewer.setGeometry(800, 200, 200, 200)
    viewer.show()
    viewer.raise_()
    mime = _mime(path)
    event = QDragEnterEvent(
        QPointF(900, 300).toPoint(), Qt.DropAction.CopyAction, mime,
        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
    )
    QApplication.sendEvent(window.windowHandle(), event)
    assert window._drop_overlay.isVisible()
    assert viewer.entered == 0
    QApplication.sendEvent(window.windowHandle(), _drop(mime, 900))
    assert window.calls == [
        (str(path), {"open_after_load": True, "append_to_tree": True, "as_disk_image": True})
    ]


def test_drop_on_open_zone_opens_every_item_as_before(window: Any, tmp_path: Path) -> None:
    files = [tmp_path / "a.db", tmp_path / "b.E01"]
    for f in files:
        f.write_bytes(b"x")
    overlay = window._drop_overlay
    overlay.activate([str(f) for f in files])
    overlay.dropEvent(_drop(_mime(*files), 100))
    batches = {id(kw.pop("batch")) for _, kw in window.calls}
    assert len(batches) == 1  # one drop, opened in one go
    assert window.calls == [
        (str(f), {"open_after_load": True, "append_to_tree": True}) for f in files
    ]
    assert not overlay.isVisible()


def test_drop_on_disk_image_zone_opens_it_as_disk_image(window: Any, tmp_path: Path) -> None:
    path = tmp_path / "disk.E02"
    path.write_bytes(b"x")
    overlay = window._drop_overlay
    overlay.activate([str(path)])
    overlay.dropEvent(_drop(_mime(path), 900))
    assert window.calls == [
        (str(path), {"open_after_load": True, "append_to_tree": True, "as_disk_image": True})
    ]


def test_several_files_on_disk_image_zone_open_nothing_and_say_why(
    window: Any, tmp_path: Path
) -> None:
    files = [tmp_path / "disk.001", tmp_path / "disk.002"]
    for f in files:
        f.write_bytes(b"x")
    overlay = window._drop_overlay
    overlay.activate([str(f) for f in files])
    move = _move(_mime(*files), 900)
    overlay.dragMoveEvent(move)
    assert not move.isAccepted()
    overlay.dropEvent(_drop(_mime(*files), 900))
    assert window.calls == []
    assert "One file at a time" in window._status.currentMessage()


def test_folder_on_disk_image_zone_opens_nothing_and_says_why(
    window: Any, tmp_path: Path
) -> None:
    overlay = window._drop_overlay
    overlay.activate([str(tmp_path)])
    overlay.dropEvent(_drop(_mime(tmp_path), 900))
    assert window.calls == []
    assert "not a folder" in window._status.currentMessage()


def test_refused_disk_image_zone_still_lets_open_zone_take_the_drop(
    window: Any, tmp_path: Path
) -> None:
    overlay = window._drop_overlay
    overlay.activate([str(tmp_path)])
    move = _move(_mime(tmp_path), 100)
    overlay.dragMoveEvent(move)
    assert move.isAccepted()


def test_leaving_the_window_hides_the_zones(window: Any, tmp_path: Path) -> None:
    from PySide6.QtGui import QDragLeaveEvent

    overlay = window._drop_overlay
    window.show()
    overlay.activate([str(tmp_path)])
    assert overlay.isVisible()
    overlay.dragLeaveEvent(QDragLeaveEvent())
    assert not overlay.isVisible()


def test_open_disk_image_picks_one_file(
    window: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QFileDialog

    path = tmp_path / "disk.E01"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(path), ""))
    window._open_disk_image()
    assert window.calls == [
        (str(path), {"open_after_load": True, "append_to_tree": True, "as_disk_image": True})
    ]
