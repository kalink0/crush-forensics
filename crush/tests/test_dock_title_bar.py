# SPDX-License-Identifier: Apache-2.0
"""Floating panels: our title bar on every platform, the move handed to
the window system (Wayland allows no client-side move or mouse grab)."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent, QWindow
from PySide6.QtWidgets import QApplication, QDockWidget, QLabel, QMainWindow

from crush.ui.main_window import MainWindow, _DockTitleBar, _FloatingDockResizer


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


def _mouse(etype, global_pos, button=Qt.MouseButton.LeftButton, buttons=None) -> QMouseEvent:  # noqa: ANN001
    pos = QPointF(global_pos)
    return QMouseEvent(
        etype, pos, pos, button,
        button if buttons is None else buttons, Qt.KeyboardModifier.NoModifier,
    )


def _floating(widgets) -> QDockWidget:  # noqa: ANN001
    dock = _dock(widgets)
    dock.setFloating(True)
    dock.show()
    dock.setGeometry(200, 200, 300, 400)
    QApplication.processEvents()
    MainWindow._sync_dock_titlebar(None, dock, True)  # type: ignore[arg-type]
    return dock


def test_floating_panel_resizer_follows_floating_state(qapp, widgets) -> None:  # noqa: ANN001
    dock = _floating(widgets)
    resizer = _FloatingDockResizer.for_dock(dock)
    assert resizer._active
    assert _FloatingDockResizer.for_dock(dock) is resizer  # one per panel
    MainWindow._sync_dock_titlebar(None, dock, False)  # type: ignore[arg-type]
    assert not resizer._active


def test_resizer_finds_edges_and_corners(qapp, widgets) -> None:  # noqa: ANN001
    dock = _floating(widgets)
    resizer = _FloatingDockResizer.for_dock(dock)
    g = lambda x, y: dock.mapToGlobal(QPoint(x, y))  # noqa: E731
    w, h = dock.width(), dock.height()
    assert resizer.edges_at(g(w // 2, h // 2)) == Qt.Edge(0)
    assert resizer.edges_at(g(1, h // 2)) == Qt.Edge.LeftEdge
    assert resizer.edges_at(g(w - 2, h // 2)) == Qt.Edge.RightEdge
    assert resizer.edges_at(g(w // 2, h - 1)) == Qt.Edge.BottomEdge
    assert resizer.edges_at(g(w - 1, h - 1)) == Qt.Edge.BottomEdge | Qt.Edge.RightEdge
    assert resizer.edges_at(g(0, 0)) == Qt.Edge.TopEdge | Qt.Edge.LeftEdge
    assert resizer.edges_at(g(w + 5, h // 2)) == Qt.Edge(0)


def test_edge_hover_sets_the_resize_cursor(qapp, widgets) -> None:  # noqa: ANN001
    dock = _floating(widgets)
    resizer = _FloatingDockResizer.for_dock(dock)
    handle = dock.windowHandle()
    edge = dock.mapToGlobal(QPoint(dock.width() - 1, dock.height() // 2))
    move = _mouse(QEvent.Type.MouseMove, edge, Qt.MouseButton.NoButton, Qt.MouseButton.NoButton)
    assert resizer.eventFilter(handle, move) is False
    assert dock.cursor().shape() == Qt.CursorShape.SizeHorCursor
    resizer.eventFilter(handle, QEvent(QEvent.Type.Leave))
    assert dock.cursor().shape() == Qt.CursorShape.ArrowCursor


def test_press_on_an_edge_starts_a_system_resize(qapp, widgets, monkeypatch) -> None:  # noqa: ANN001
    dock = _floating(widgets)
    resizer = _FloatingDockResizer.for_dock(dock)
    calls: list[Qt.Edge] = []
    monkeypatch.setattr(QWindow, "startSystemResize", lambda self, e: calls.append(e) or True)
    middle = dock.mapToGlobal(QPoint(dock.width() // 2, dock.height() // 2))
    assert resizer.eventFilter(dock.windowHandle(), _mouse(QEvent.Type.MouseButtonPress, middle)) is False
    corner = dock.mapToGlobal(QPoint(dock.width() - 1, dock.height() - 1))
    assert resizer.eventFilter(dock.windowHandle(), _mouse(QEvent.Type.MouseButtonPress, corner)) is True
    assert calls == [Qt.Edge.RightEdge | Qt.Edge.BottomEdge]
    assert resizer._drag is None


def test_resize_falls_back_to_the_mouse_delta(qapp, widgets, monkeypatch) -> None:  # noqa: ANN001
    dock = _floating(widgets)
    resizer = _FloatingDockResizer.for_dock(dock)
    handle = dock.windowHandle()
    monkeypatch.setattr(QWindow, "startSystemResize", lambda self, e: False)
    before = dock.geometry()
    start = dock.mapToGlobal(QPoint(dock.width() - 1, dock.height() // 2))
    assert resizer.eventFilter(handle, _mouse(QEvent.Type.MouseButtonPress, start)) is True
    resizer.eventFilter(handle, _mouse(QEvent.Type.MouseMove, start + QPoint(50, 30)))
    assert dock.geometry().width() == before.width() + 50
    assert dock.geometry().height() == before.height()  # right edge only
    assert dock.geometry().left() == before.left()
    resizer.eventFilter(handle, _mouse(QEvent.Type.MouseButtonRelease, start + QPoint(50, 30)))
    assert resizer._drag is None
