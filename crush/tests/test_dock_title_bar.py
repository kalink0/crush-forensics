# SPDX-License-Identifier: Apache-2.0
"""Floating panels: our title bar on every platform, the move handed to
the window system (Wayland allows no client-side move or mouse grab)."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QPointF, Qt
from PySide6.QtGui import QMouseEvent, QWindow
from PySide6.QtWidgets import QApplication, QDockWidget, QLabel, QMainWindow

from crush.ui.main_window import MainWindow, _DockTitleBar


def _dock(widgets) -> QDockWidget:  # noqa: ANN001
    window = widgets(QMainWindow())
    dock = QDockWidget("Panel", window)
    dock.setWidget(QLabel("content"))
    window.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
    return dock


def test_floating_panel_gets_the_title_bar_on_any_platform(qapp, widgets, monkeypatch) -> None:  # noqa: ANN001
    # Wayland used to skip the title bar, leaving the move to Qt's own drag.
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("XDG_SESSION_TYPE", "wayland")
    dock = _dock(widgets)
    MainWindow._sync_dock_titlebar(None, dock, True)  # type: ignore[arg-type]
    assert isinstance(dock.titleBarWidget(), _DockTitleBar)
    MainWindow._sync_dock_titlebar(None, dock, False)  # type: ignore[arg-type]
    assert dock.titleBarWidget() is None


def test_press_on_a_floating_panel_starts_a_system_move(qapp, widgets, monkeypatch) -> None:  # noqa: ANN001
    dock = _dock(widgets)
    dock.setFloating(True)
    dock.show()
    QApplication.processEvents()
    bar = _DockTitleBar("Panel", dock)
    assert dock.windowHandle() is not None
    calls: list[bool] = []
    # On the class: the window itself is deleted before monkeypatch undoes.
    monkeypatch.setattr(QWindow, "startSystemMove", lambda self: calls.append(True) or True)
    press = QMouseEvent(
        QEvent.Type.MouseButtonPress, QPointF(5, 5), QPointF(5, 5),
        Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
    )
    bar.mousePressEvent(press)
    assert calls == [True]
    assert bar._drag_pos is None  # no manual move when the system moves it


def test_title_bar_buttons_dock_and_close_the_panel(qapp, widgets) -> None:  # noqa: ANN001
    dock = _dock(widgets)
    dock.setFloating(True)
    dock.show()
    bar = _DockTitleBar("Panel", dock)
    assert not bar.dock_button.icon().isNull()
    assert not bar.close_button.icon().isNull()
    # QMainWindow has no _dock_to_default: docking back is MainWindow's job.
    docked: list[QDockWidget] = []
    dock.parent()._dock_to_default = docked.append  # type: ignore[attr-defined]
    bar.dock_button.click()
    assert docked == [dock]
    bar.close_button.click()
    assert dock.isHidden()


def test_close_button_only_for_a_closable_panel(qapp, widgets) -> None:  # noqa: ANN001
    dock = _dock(widgets)
    dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetFloatable)
    bar = _DockTitleBar("Panel", dock)
    assert bar.close_button.isHidden()
