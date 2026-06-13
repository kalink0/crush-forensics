# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Crush main window — QMainWindow with dockable panels."""
from __future__ import annotations

from datetime import datetime, timezone
import time
import os
import subprocess
import sys
from pathlib import Path
import logging
import shutil
import tempfile

from PySide6.QtCore import QObject, QThread, Qt, Signal, QUrl, QSettings, QTimer
from PySide6.QtGui import QCloseEvent, QPalette, QColor, QAction, QGuiApplication
from shiboken6 import isValid
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDockWidget,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QInputDialog,
    QProgressDialog,
    QStatusBar,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
)

import crush
from crush.core.vfs import VFS, VFSNode, DirectoryVFS
from crush.parsers.base import ParseResult
from crush.core.session import Session
from crush.ui.fs_panel import FilesystemPanel
from crush.ui.props_panel import PropertiesPanel
from crush.ui.loading_dialog import LoadingDialog


class _LoadSourceWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, session: Session, path: str, integrity: bool) -> None:
        super().__init__()
        self._session = session
        self._path = path
        self._integrity = integrity

    def run(self) -> None:
        try:
            vfs = self._session.add_source(self._path)
            if self._integrity:
                self._log_source_hash()
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(vfs)

    def _log_source_hash(self) -> None:
        path = Path(self._path)
        if not path.is_file():
            return
        import hashlib

        hasher = hashlib.sha256()
        total = 0
        with path.open("rb") as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                total += len(chunk)
        digest = hasher.hexdigest()
        logging.getLogger("crush").info(
            "INTEGRITY source sha256=%s  size=%d  path=%s", digest, total, path
        )


class _ClosableTabBar(QTabBar):
    def mouseReleaseEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "button") and event.button() == Qt.MouseButton.MiddleButton:
            index = self.tabAt(event.position().toPoint())
            if index >= 0:
                self.tabCloseRequested.emit(index)
                return
        super().mouseReleaseEvent(event)  # type: ignore[arg-type]


class _LogSignalHandler(QObject, logging.Handler):
    log_line = Signal(str)

    def __init__(self) -> None:
        QObject.__init__(self)
        logging.Handler.__init__(self)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        self.log_line.emit(msg)


class _DockTitleBar(QWidget):
    def __init__(self, title: str, dock: QDockWidget) -> None:
        super().__init__(dock)
        self._dock = dock
        self._drag_pos: object = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(6)
        label = QLabel(title)
        layout.addWidget(label)
        layout.addStretch()
        dock_btn = QPushButton("Dock")
        dock_btn.setFixedHeight(20)
        dock_btn.clicked.connect(self._dock_back)
        layout.addWidget(dock_btn)

    def mousePressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "button") and event.button() == Qt.MouseButton.LeftButton:
            if self._dock.isFloating():
                self._drag_pos = event.globalPosition().toPoint()  # type: ignore[union-attr]
                return
        super().mousePressEvent(event)  # type: ignore[arg-type]

    def mouseMoveEvent(self, event: object) -> None:  # type: ignore[override]
        if self._drag_pos is not None and hasattr(event, "globalPosition"):
            new_pos = event.globalPosition().toPoint()  # type: ignore[union-attr]
            delta = new_pos - self._drag_pos  # type: ignore[operator]
            self._dock.move(self._dock.pos() + delta)
            self._drag_pos = new_pos
            return
        super().mouseMoveEvent(event)  # type: ignore[arg-type]

    def mouseReleaseEvent(self, event: object) -> None:  # type: ignore[override]
        self._drag_pos = None
        super().mouseReleaseEvent(event)  # type: ignore[arg-type]

    def _dock_back(self) -> None:
        mw = self._dock.parent()
        if hasattr(mw, "_dock_to_default"):
            mw._dock_to_default(self._dock)  # type: ignore[attr-defined]


class _ClickableStatusLabel(QLabel):
    clicked = Signal()

    def mousePressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "button") and event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
            return
        super().mousePressEvent(event)  # type: ignore[arg-type]


class _ExportWorker(QObject):
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, vfs: VFS, node: VFSNode, dest_dir: str, integrity: bool) -> None:
        super().__init__()
        self._vfs = vfs
        self._node = node
        self._dest_dir = Path(dest_dir)
        self._integrity = integrity
        self._hash_lines: list[str] = []
        self._hash_base: Path | None = None
        self._logger = logging.getLogger(__name__)

    def run(self) -> None:
        try:
            target_root = self._dest_dir / _safe_name(self._node.name or "export")
            self._hash_base = target_root if self._node.is_dir else target_root.parent
            if self._node.is_dir:
                self._export_dir(self._node, target_root)
            else:
                target_root.parent.mkdir(parents=True, exist_ok=True)
                self._export_file(self._node, target_root)
            self._write_hashes_file(target_root)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(str(target_root))

    def _export_dir(self, node: VFSNode, target: Path) -> None:
        target.mkdir(parents=True, exist_ok=True)
        for child in node.children:
            child_target = target / _safe_name(child.name)
            if child.is_dir:
                self._export_dir(child, child_target)
            else:
                child_target.parent.mkdir(parents=True, exist_ok=True)
                self._export_file(child, child_target)

    def _export_file(self, node: VFSNode, target: Path) -> None:
        if not self._integrity:
            with self._vfs.open(node) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            return

        import hashlib

        hasher = hashlib.sha256()
        total = 0
        with self._vfs.open(node) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                hasher.update(chunk)
                total += len(chunk)
        digest = hasher.hexdigest()
        rel_path = target.name
        if self._hash_base is not None:
            try:
                rel_path = str(target.relative_to(self._hash_base))
            except Exception:
                rel_path = target.name
        self._hash_lines.append(f"{digest}  {total}  {rel_path}")
        self._logger.info("INTEGRITY export sha256=%s  size=%d  path=%s", digest, total, target)

    def _write_hashes_file(self, target_root: Path) -> None:
        if not self._integrity or not self._hash_lines:
            return
        base = self._hash_base if self._hash_base is not None else target_root.parent
        hash_path = base / "crush-export-hashes.txt"
        hash_path.write_text("\n".join(self._hash_lines) + "\n", encoding="utf-8")


class _ExportLogarchiveWorker(QObject):
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, vfs: VFS, node: VFSNode, dest_path: str) -> None:
        super().__init__()
        self._vfs = vfs
        self._node = node
        self._dest_path = Path(dest_path)
        self._logger = logging.getLogger(__name__)

    def run(self) -> None:
        try:
            from crush.parsers.unified_log_parser import build_logarchive_from_acquisition
            with tempfile.TemporaryDirectory(prefix="crush_logarchive_") as tmp:
                tmp_path = Path(tmp) / "build"
                tmp_path.mkdir()
                build_logarchive_from_acquisition(self._node, self._vfs, tmp_path)
                if self._dest_path.exists():
                    shutil.rmtree(self._dest_path)
                shutil.copytree(str(tmp_path), str(self._dest_path))
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(str(self._dest_path))


class _ExportMultiWorker(QObject):
    finished = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        entries: list,  # list of (VFSNode, VFS, str) — (node, vfs, virtual_path)
        dest_dir: str,
        integrity: bool,
        filter_text: str,
    ) -> None:
        super().__init__()
        self._entries = entries
        self._dest_dir = Path(dest_dir)
        self._integrity = integrity
        self._filter_text = filter_text
        self._hash_lines: list[str] = []
        self._logger = logging.getLogger(__name__)

    def run(self) -> None:
        try:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            export_root = self._dest_dir / f"crush-export-{stamp}"
            export_root.mkdir(parents=True, exist_ok=True)
            for node, vfs, virtual_path in self._entries:
                rel = virtual_path.lstrip("/\\")
                target = export_root / Path(rel)
                target.parent.mkdir(parents=True, exist_ok=True)
                self._export_file(node, vfs, target, rel)
            self._write_hashes_file(export_root, stamp)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(str(export_root))

    def _export_file(self, node: VFSNode, vfs: VFS, target: Path, rel_path: str) -> None:
        if not self._integrity:
            with vfs.open(node) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            return
        import hashlib
        hasher = hashlib.sha256()
        total = 0
        with vfs.open(node) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                hasher.update(chunk)
                total += len(chunk)
        digest = hasher.hexdigest()
        self._hash_lines.append(f"{digest}  {total}  {rel_path}")
        self._logger.info("INTEGRITY export sha256=%s  size=%d  path=%s", digest, total, target)

    def _write_hashes_file(self, export_root: Path, stamp: str) -> None:
        if not self._integrity or not self._hash_lines:
            return
        header = [
            "# crush filtered export",
            f"# filter: {self._filter_text}",
            f"# exported: {stamp}",
            f"# files: {len(self._hash_lines)}",
            "",
        ]
        (export_root / "crush-export-hashes.txt").write_text(
            "\n".join(header + self._hash_lines) + "\n", encoding="utf-8"
        )


def _safe_name(name: str) -> str:
    cleaned = name.replace("/", "_").replace("\\", "_").strip()
    if cleaned in {"", ".", ".."}:
        return "_"
    return cleaned


class MainWindow(QMainWindow):
    _open_windows: list[MainWindow] = []

    def __init__(self) -> None:
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._open_windows.append(self)
        self.destroyed.connect(self._remove_window_reference)
        self.session = Session()
        self._always_hex = False
        self._pending_open: tuple[VFSNode, VFS] | None = None
        self._load_queue: list[tuple[str, bool, bool]] = []
        self._settings = QSettings("Crush DFIR", "Crush")
        self._multi_log_windows: list[QWidget] = []
        self.setWindowTitle(f"Crush {crush.display_version()}")
        self.resize(1280, 800)
        self._build_ui()
        self._setup_logging()
        self._apply_saved_theme()
        self._apply_saved_integrity_mode()
        self._apply_saved_prescan_workers()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.setDockOptions(
            QMainWindow.DockOption.AllowTabbedDocks
            | QMainWindow.DockOption.AllowNestedDocks
            | QMainWindow.DockOption.AnimatedDocks
        )
        self._dock_defaults: dict[QDockWidget, Qt.DockWidgetArea] = {}
        # Center: tabbed viewer area
        self._viewer_tabs = QTabWidget()
        self._viewer_tabs.setTabBar(_ClosableTabBar())
        self._viewer_tabs.setTabsClosable(True)
        self._viewer_tabs.setDocumentMode(True)
        self._viewer_tabs.tabCloseRequested.connect(self._close_tab)

        self._empty_view = QWidget()
        empty_layout = QVBoxLayout(self._empty_view)
        empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.setSpacing(12)

        empty_title = QLabel("Open something to begin")
        empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = empty_title.font()
        title_font.setPointSize(title_font.pointSize() + 6)
        title_font.setBold(True)
        empty_title.setFont(title_font)
        empty_layout.addWidget(empty_title)

        empty_subtitle = QLabel("Choose a file, archive, or folder.")
        empty_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(empty_subtitle)

        button_row = QHBoxLayout()
        open_file_button = QPushButton("Open File…")
        open_file_button.clicked.connect(self._open_file)
        button_row.addWidget(open_file_button)
        open_folder_button = QPushButton("Open Folder…")
        open_folder_button.clicked.connect(self._open_folder)
        button_row.addWidget(open_folder_button)
        empty_layout.addLayout(button_row)

        self._central_stack = QStackedWidget()
        self._central_stack.addWidget(self._empty_view)
        self._central_stack.addWidget(self._viewer_tabs)
        self.setCentralWidget(self._central_stack)
        self._show_empty_view()

        # Left dock: filesystem panel
        self._fs_panel = FilesystemPanel(self.session, self)
        self._fs_panel.node_activated.connect(self._open_node)
        self._fs_panel.node_selected.connect(self._on_node_selected)
        self._fs_panel.open_requested.connect(self._open_node_mode)
        self._fs_panel.open_external_requested.connect(self._open_external_mode)
        self._fs_panel.export_requested.connect(self._export_node)
        self._fs_panel.export_multi_requested.connect(self._export_multi_nodes)
        self._fs_panel.export_logarchive_requested.connect(self._export_logarchive_node)
        self._fs_panel.close_source_requested.connect(self._close_source)
        self._fs_panel.close_source_requested.connect(self._show_empty_view_if_no_sources)
        self._fs_panel.load_finished.connect(self._show_viewer_tabs)
        self._fs_panel.background_status.connect(self._on_background_status)
        self._fs_panel.format_info_requested.connect(self._show_format_info)
        self._fs_panel.open_in_new_window_requested.connect(self._open_in_new_window)
        self._fs_dock = QDockWidget("Filesystem", self)
        self._fs_dock.setAllowedAreas(Qt.DockWidgetArea.AllDockWidgetAreas)
        self._fs_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self._fs_dock.setWidget(self._fs_panel)
        self._fs_dock.setMinimumWidth(220)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._fs_dock)
        self._dock_defaults[self._fs_dock] = Qt.DockWidgetArea.LeftDockWidgetArea
        self._fs_dock.topLevelChanged.connect(
            lambda floating, dock=self._fs_dock: self._sync_dock_titlebar(dock, floating)
        )

        # Right dock: properties panel
        self._props_panel = PropertiesPanel(self)
        self._props_dock = QDockWidget("Properties", self)
        self._props_dock.setAllowedAreas(Qt.DockWidgetArea.AllDockWidgetAreas)
        self._props_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self._props_dock.setWidget(self._props_panel)
        self._props_dock.setMinimumWidth(200)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._props_dock)
        self._dock_defaults[self._props_dock] = Qt.DockWidgetArea.RightDockWidgetArea
        self._props_dock.topLevelChanged.connect(
            lambda floating, dock=self._props_dock: self._sync_dock_titlebar(dock, floating)
        )

        # Bottom dock: log panel
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_dock = QDockWidget("Log", self)
        self._log_dock.setAllowedAreas(Qt.DockWidgetArea.AllDockWidgetAreas)
        self._log_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self._log_dock.setWidget(self._log_view)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._log_dock)
        self._dock_defaults[self._log_dock] = Qt.DockWidgetArea.BottomDockWidgetArea
        self._log_dock.hide()
        self._log_dock.topLevelChanged.connect(
            lambda floating, dock=self._log_dock: self._sync_dock_titlebar(dock, floating)
        )

        # Status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage(f"Crush {crush.display_version()} — ready")
        self._spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._spinner_idx = 0
        self._spinner_label = QLabel("")
        self._spinner_label.setVisible(False)
        self._status.addPermanentWidget(self._spinner_label)
        self._bg_status = QLabel("")
        self._bg_status.setVisible(False)
        self._status.addPermanentWidget(self._bg_status)
        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(100)
        self._spinner_timer.timeout.connect(self._on_spinner_tick)

        self._integrity_label = _ClickableStatusLabel(" \u2696 INTEGRITY ")
        self._integrity_label.setStyleSheet(
            "color: white; background-color: #c87000; font-weight: bold;"
            " padding: 1px 4px; border-radius: 3px;"
        )
        self._integrity_label.setToolTip("Integrity mode active \u2014 files are hashed on open")
        self._integrity_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self._integrity_label.clicked.connect(self._toggle_integrity_mode)
        self._integrity_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._integrity_label.customContextMenuRequested.connect(self._show_integrity_menu)
        self._integrity_label.setVisible(False)
        self._status.addPermanentWidget(self._integrity_label)
        self._no_integrity_label = _ClickableStatusLabel(" NO INTEGRITY ")
        self._no_integrity_label.setStyleSheet(
            "color: white; background-color: #6b6b6b; font-weight: bold;"
            " padding: 1px 4px; border-radius: 3px;"
        )
        self._no_integrity_label.setToolTip("Integrity mode is off")
        self._no_integrity_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self._no_integrity_label.clicked.connect(self._toggle_integrity_mode)
        self._no_integrity_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._no_integrity_label.customContextMenuRequested.connect(self._show_integrity_menu)
        self._no_integrity_label.setVisible(True)
        self._status.addPermanentWidget(self._no_integrity_label)

        self._rainbow_snapshot_btn = QPushButton("⏸  Snapshot")
        self._rainbow_snapshot_btn.setToolTip("Pause rainbow and save this colour as a custom theme")
        self._rainbow_snapshot_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._rainbow_snapshot_btn.setVisible(False)
        self._rainbow_snapshot_btn.clicked.connect(self._snapshot_rainbow)
        self._status.addPermanentWidget(self._rainbow_snapshot_btn)

        self._build_menus()

    def _build_menus(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("File")
        new_window_action = file_menu.addAction("New Window", self._new_window)
        new_window_action.setShortcut("Ctrl+N")
        file_menu.addSeparator()
        file_menu.addAction("Open file…", self._open_file)
        file_menu.addAction("Open folder…", self._open_folder)
        file_menu.addSeparator()
        self._recent_menu = file_menu.addMenu("Open Recent")
        self._rebuild_recent_menu()
        file_menu.addSeparator()
        self._close_window_action = file_menu.addAction("Close Window", self.close)
        self._close_window_action.setShortcut("Ctrl+W")
        exit_action = file_menu.addAction("Exit", QApplication.quit)
        exit_action.setShortcut("Ctrl+Q")

        view_menu = menu.addMenu("View")
        view_menu.addAction(self._fs_dock.toggleViewAction())
        view_menu.addAction(self._props_dock.toggleViewAction())
        view_menu.addAction(self._log_dock.toggleViewAction())
        view_menu.addSeparator()
        view_menu.addAction("Dock Filesystem Panel", lambda: self._dock_to_default(self._fs_dock))
        view_menu.addAction("Dock Properties Panel", lambda: self._dock_to_default(self._props_dock))
        view_menu.addAction("Dock Log Panel", lambda: self._dock_to_default(self._log_dock))
        view_menu.addAction("Reset Panel Layout", self._reset_panel_layout)
        self._always_hex_action = QAction("Always show Hex tab", self, checkable=True)
        self._always_hex_action.toggled.connect(self._set_always_hex)
        view_menu.addAction(self._always_hex_action)
        view_menu.addAction("Close all tabs", self._close_all_tabs)
        view_menu.addSeparator()
        theme_menu = view_menu.addMenu("Theme")
        theme_menu.addAction("System default", self._set_theme_system)
        theme_menu.addAction("Light", self._set_theme_light)
        theme_menu.addAction("Dark", self._set_theme_dark)
        theme_menu.addAction("Geek", self._set_theme_geek)
        theme_menu.addAction("Purple", self._set_theme_purple)
        theme_menu.addAction("Ocean", self._set_theme_ocean)
        theme_menu.addAction("Rainbow", self._set_theme_rainbow)
        theme_menu.addSeparator()
        self._custom_theme_action = theme_menu.addAction("", self._set_theme_custom)
        self._custom_theme_action.setVisible(False)

        tools_menu = menu.addMenu("Tools")
        tools_menu.addAction("Paste & Decode…", self._paste_decode)
        tools_menu.addSeparator()
        tools_menu.addAction("Export log…", self._export_log)
        tools_menu.addSeparator()
        self._integrity_mode_action = QAction("Integrity Mode", self, checkable=True)
        self._integrity_mode_action.setToolTip("Hash every file on open and write hash to log")
        self._integrity_mode_action.toggled.connect(self._set_integrity_mode)
        tools_menu.addAction(self._integrity_mode_action)
        tools_menu.addAction("Indexing Threads…", self._set_prescan_workers)

        help_menu = menu.addMenu("Help")
        help_menu.addAction("Format Reference…", self._show_format_reference)
        help_menu.addSeparator()
        help_menu.addAction("About Crush", self._about)

    def _new_window(self) -> None:
        window = MainWindow()
        window.resize(self.size())
        offset = 32
        target = self.frameGeometry().topLeft()
        target.setX(target.x() + offset)
        target.setY(target.y() + offset)

        available = self.screen().availableGeometry()
        max_x = max(available.left(), available.right() - window.width() + 1)
        max_y = max(available.top(), available.bottom() - window.height() + 1)
        target.setX(min(max(target.x(), available.left()), max_x))
        target.setY(min(max(target.y(), available.top()), max_y))
        window.move(target)
        window.show()

    def _open_in_new_window(self, path: str) -> None:
        window = MainWindow()
        window.resize(self.size())
        window.show()
        window._load_source(path)

    @classmethod
    def _remove_window_reference(cls, destroyed: QObject | None = None) -> None:
        cls._open_windows = [window for window in cls._open_windows if isValid(window)]

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _open_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Open folder")
        if path:
            self._load_source(path)

    def _open_file(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Open file", "", "All files (*)")
        for path in paths:
            self._load_source(path, open_after_load=True, append_to_tree=True)

    def _load_source(self, path: str, open_after_load: bool = False, append_to_tree: bool = False) -> None:
        if self._thread_is_running(getattr(self, "_load_thread", None)):
            self._load_queue.append((path, open_after_load, append_to_tree))
            self._status.showMessage("Queued source for loading…")
            self._logger.debug("Load queued: %s (open_after_load=%s append=%s)", path, open_after_load, append_to_tree)
            return

        self._logger.info("Loading source: %s", path)
        self._logger.debug("Load start: %s (open_after_load=%s append=%s)", path, open_after_load, append_to_tree)
        self._loading_path = path
        self._open_after_load = open_after_load
        self._append_to_tree = append_to_tree
        self._tree_build_started = time.monotonic()
        self._status.showMessage(f"Loading: {path}")
        self._progress = LoadingDialog("Loading source…", self)
        self._progress.show()

        self._load_thread = QThread(self)
        self._load_worker = _LoadSourceWorker(self.session, path, self.session.integrity_mode)
        self._load_worker.moveToThread(self._load_thread)
        self._load_thread.started.connect(self._load_worker.run)
        self._load_worker.finished.connect(self._on_load_finished)
        self._load_worker.failed.connect(self._on_load_failed)
        self._load_worker.finished.connect(self._load_thread.quit)
        self._load_worker.failed.connect(self._load_thread.quit)
        self._load_thread.finished.connect(self._load_worker.deleteLater)
        self._load_thread.finished.connect(self._on_load_thread_finished)
        self._load_thread.start()

    def _on_load_finished(self, vfs: VFS) -> None:
        self._logger.debug("Load worker finished; preparing tree build")
        if hasattr(self, "_progress"):
            self._progress.set_text("Building tree…")
        if getattr(self, "_open_after_load", False) and not vfs.root().is_dir:
            self._pending_open = (vfs.root(), vfs)
        if getattr(self, "_tree_loaded_connected", False):
            try:
                self._fs_panel.load_finished.disconnect(self._on_tree_loaded)
            except Exception:
                pass
            self._tree_loaded_connected = False
        self._fs_panel.load_finished.connect(self._on_tree_loaded)
        self._tree_loaded_connected = True
        self._loading_vfs = vfs
        self._tree_loaded = False
        self._logger.debug("Dispatching to FilesystemPanel (%s)", "append" if getattr(self, "_append_to_tree", False) else "load")
        if getattr(self, "_append_to_tree", False):
            self._fs_panel.append_vfs(vfs)
        else:
            self._fs_panel.load_vfs(vfs)
        self._update_window_title()
        QTimer.singleShot(0, self._ensure_tree_loaded)

    def _on_load_failed(self, message: str) -> None:
        self._logger.debug("Load worker failed: %s", message)
        if hasattr(self, "_progress"):
            self._progress.close()
        self._status.showMessage(f"Error loading source: {message}")
        self._logger.error("Load error: %s", message)
        QMessageBox.critical(self, "Load error", message)

    def _on_tree_loaded(self) -> None:
        self._logger.debug("Tree load finished")
        self._tree_loaded = True
        if getattr(self, "_tree_loaded_connected", False):
            try:
                self._fs_panel.load_finished.disconnect(self._on_tree_loaded)
            except Exception:
                pass
            self._tree_loaded_connected = False
        if hasattr(self, "_progress"):
            self._progress.close()
        self._status.showMessage(f"Loaded: {self._loading_path}")
        self._logger.info("Loaded: %s", self._loading_path)
        self._add_to_recent_files(self._loading_path)
        if hasattr(self, "_tree_build_started"):
            elapsed = time.monotonic() - self._tree_build_started
            if hasattr(self, "_loading_vfs"):
                root = self._loading_vfs.root()
                try:
                    file_count = self._loading_vfs.file_count(root)
                    total_size = self._loading_vfs.total_size(root)
                    self._logger.info(
                        "Load + initial tree render: %.3f s (files: %s, size: %s)",
                        elapsed,
                        f"{file_count:,}",
                        _format_size(total_size),
                    )
                except Exception:
                    self._logger.info("Load + initial tree render: %.3f s", elapsed)
            else:
                self._logger.info("Load + initial tree render: %.3f s", elapsed)
        if self._pending_open:
            node, vfs = self._pending_open
            self._pending_open = None
            self._open_node(node, vfs)

    def _ensure_tree_loaded(self) -> None:
        if not getattr(self, "_tree_loaded", False):
            self._logger.warning("Tree load signal not received; closing progress dialog.")
            self._on_tree_loaded()

    def _export_node(self, node: VFSNode, vfs: VFS) -> None:
        dest_dir = QFileDialog.getExistingDirectory(self, "Export to folder")
        if not dest_dir:
            return

        if self._thread_is_running(getattr(self, "_export_thread", None)):
            QMessageBox.information(self, "Export", "An export is already running.")
            return

        self._status.showMessage("Exporting…")
        self._logger.info("Export requested: %s -> %s", node.path, dest_dir)
        self._export_progress = QProgressDialog("Exporting…", None, 0, 0, self)
        self._export_progress.setWindowTitle("Export")
        self._export_progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        self._export_progress.setCancelButton(None)
        self._export_progress.setMinimumDuration(0)
        self._export_progress.show()

        self._export_thread = QThread(self)
        self._export_worker = _ExportWorker(vfs, node, dest_dir, self.session.integrity_mode)
        self._export_worker.moveToThread(self._export_thread)
        self._export_thread.started.connect(self._export_worker.run)
        self._export_worker.finished.connect(self._on_export_finished)
        self._export_worker.failed.connect(self._on_export_failed)
        self._export_worker.finished.connect(self._export_thread.quit)
        self._export_worker.failed.connect(self._export_thread.quit)
        self._export_thread.finished.connect(self._export_worker.deleteLater)
        self._export_thread.finished.connect(self._on_export_thread_finished)
        self._export_thread.start()

    def _export_multi_nodes(self, entries: list, filter_text: str) -> None:
        if not entries:
            return
        dest_dir = QFileDialog.getExistingDirectory(self, "Export filtered results to folder")
        if not dest_dir:
            return
        if self._thread_is_running(getattr(self, "_export_thread", None)):
            QMessageBox.information(self, "Export", "An export is already running.")
            return
        n = len(entries)
        self._status.showMessage(f"Exporting {n} file{'s' if n != 1 else ''}…")
        self._logger.info("Multi-export: %d files, filter=%r -> %s", n, filter_text, dest_dir)
        self._export_progress = QProgressDialog(
            f"Exporting {n} file{'s' if n != 1 else ''}…", None, 0, 0, self
        )
        self._export_progress.setWindowTitle("Export filtered results")
        self._export_progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        self._export_progress.setCancelButton(None)
        self._export_progress.setMinimumDuration(0)
        self._export_progress.show()
        self._export_thread = QThread(self)
        self._export_worker = _ExportMultiWorker(
            entries, dest_dir, self.session.integrity_mode, filter_text
        )
        self._export_worker.moveToThread(self._export_thread)
        self._export_thread.started.connect(self._export_worker.run)
        self._export_worker.finished.connect(self._on_export_finished)
        self._export_worker.failed.connect(self._on_export_failed)
        self._export_worker.finished.connect(self._export_thread.quit)
        self._export_worker.failed.connect(self._export_thread.quit)
        self._export_thread.finished.connect(self._export_worker.deleteLater)
        self._export_thread.finished.connect(self._on_export_thread_finished)
        self._export_thread.start()

    def _on_export_finished(self, dest: str) -> None:
        if hasattr(self, "_export_progress"):
            self._export_progress.close()
        self._status.showMessage(f"Exported to: {dest}")
        self._logger.info("Exported to: %s", dest)
        choice = QMessageBox.question(
            self,
            "Export complete",
            f"Export finished:\n{dest}\n\nOpen location?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if choice == QMessageBox.StandardButton.Yes:
            target = Path(dest)
            open_path = target.parent if target.is_file() else target
            self._open_local_file(open_path)

    def _on_export_failed(self, message: str) -> None:
        if hasattr(self, "_export_progress"):
            self._export_progress.close()
        self._status.showMessage(f"Export failed: {message}")
        self._logger.error("Export failed: %s", message)
        QMessageBox.critical(self, "Export failed", message)

    def _export_logarchive_node(self, node: VFSNode, vfs: VFS) -> None:
        dest_dir = QFileDialog.getExistingDirectory(self, "Save .logarchive to folder")
        if not dest_dir:
            return

        if self._thread_is_running(getattr(self, "_logarchive_thread", None)):
            QMessageBox.information(self, "Export", "An export is already running.")
            return

        archive_name = node.name if node.name.endswith(".logarchive") else f"{node.name}.logarchive"
        dest_path = Path(dest_dir) / archive_name
        if dest_path.exists():
            reply = QMessageBox.question(
                self,
                "Overwrite?",
                f"{dest_path} already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._status.showMessage("Building .logarchive…")
        self._logger.info("Export logarchive: %s -> %s", node.path, dest_path)
        self._logarchive_progress = QProgressDialog("Building .logarchive…", None, 0, 0, self)
        self._logarchive_progress.setWindowTitle("Export .logarchive")
        self._logarchive_progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        self._logarchive_progress.setCancelButton(None)
        self._logarchive_progress.setMinimumDuration(0)
        self._logarchive_progress.show()

        self._logarchive_thread = QThread(self)
        self._logarchive_worker = _ExportLogarchiveWorker(vfs, node, str(dest_path))
        self._logarchive_worker.moveToThread(self._logarchive_thread)
        self._logarchive_thread.started.connect(self._logarchive_worker.run)
        self._logarchive_worker.finished.connect(self._on_logarchive_finished)
        self._logarchive_worker.failed.connect(self._on_logarchive_failed)
        self._logarchive_worker.finished.connect(self._logarchive_thread.quit)
        self._logarchive_worker.failed.connect(self._logarchive_thread.quit)
        self._logarchive_thread.finished.connect(self._logarchive_worker.deleteLater)
        self._logarchive_thread.start()

    def _on_logarchive_finished(self, dest: str) -> None:
        if hasattr(self, "_logarchive_progress"):
            self._logarchive_progress.close()
        self._status.showMessage(f"Saved: {dest}")
        self._logger.info("Logarchive exported to: %s", dest)
        choice = QMessageBox.question(
            self,
            "Export complete",
            f".logarchive saved:\n{dest}\n\nOpen location?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if choice == QMessageBox.StandardButton.Yes:
            self._open_local_file(Path(dest).parent)

    def _on_logarchive_failed(self, message: str) -> None:
        if hasattr(self, "_logarchive_progress"):
            self._logarchive_progress.close()
        self._status.showMessage(f"Export failed: {message}")
        self._logger.error("Logarchive export failed: %s", message)
        QMessageBox.critical(self, "Export failed", message)

    def _open_node(self, node: VFSNode, vfs: VFS) -> None:
        """Called when the user double-clicks a file in the FS panel."""
        self._hash_node_if_integrity(node, vfs)
        import crush.parsers  # noqa: F401 — triggers parser registration
        from crush.core.registry import ParserRegistry

        parser = ParserRegistry.best(node, vfs)
        if parser is None:
            self._status.showMessage(f"No parser found for {node.name}")
            return

        try:
            result = parser.parse(node, vfs)
            result = self._enrich_with_format_info(parser, node, vfs, result)
            self._show_result(node, result, vfs)
            self._props_panel.update_properties(node, result.metadata)
            self._status.showMessage(
                f"{node.path}  [{parser.DISPLAY_NAME}]"
            )
        except Exception as exc:
            self._status.showMessage(f"Parse error: {exc}")
            QMessageBox.warning(self, "Parse error", str(exc))

    def _open_node_mode(self, node: VFSNode, vfs: VFS, mode: str) -> None:
        if mode == "hex":
            self._hash_node_if_integrity(node, vfs)
            from crush.parsers.base import ParseResult
            hex_bytes = self._read_hex_bytes(vfs, node)
            if hex_bytes is None:
                QMessageBox.warning(self, "Hex view", "Unable to load hex view.")
                return
            result = ParseResult(viewer_type="hex", data=hex_bytes)
            result = self._enrich_with_format_info(None, node, vfs, result)
            self._show_result(node, result, vfs)
            self._props_panel.update_properties(node, result.metadata)
            return
        if mode == "text":
            self._hash_node_if_integrity(node, vfs)
            from crush.parsers.base import ParseResult
            raw = vfs.read(node)
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            result = ParseResult(viewer_type="text", data=text)
            result = self._enrich_with_format_info(None, node, vfs, result)
            self._show_result(node, result, vfs)
            self._props_panel.update_properties(node, result.metadata)
            return
        if mode == "multi_log":
            self._hash_node_if_integrity(node, vfs)
            self._open_multi_log_window(node, vfs)
            self._status.showMessage(f"{node.path}  [Multi-Log Studio — loading…]")
            return
        if mode == "multi_log_add":
            self._hash_node_if_integrity(node, vfs)
            viewer = self._find_multi_log_viewer()
            if viewer is not None:
                viewer.add_source(node, vfs)
                self._status.showMessage(f"Added to Multi-Log Studio: {node.path}")
            else:
                self._open_multi_log_window(node, vfs)
                self._status.showMessage(f"{node.path}  [Multi-Log Studio — loading…]")
            return
        if mode == "multi_log_folder":
            from crush.viewers.multi_log_viewer import (
                _discover_log_nodes,
                FolderDiscoveryDialog,
            )
            found = _discover_log_nodes(node, vfs)
            if not found:
                QMessageBox.information(
                    self,
                    "Multi-Log Studio",
                    f"No log files found in '{node.name}'.",
                )
                return
            dlg = FolderDiscoveryDialog(node.name, found, self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            selected = dlg.selected_nodes()
            if not selected:
                return
            viewer = self._find_multi_log_viewer()
            if viewer is None:
                viewer = self._open_multi_log_window(selected[0], vfs)
                remaining = selected[1:]
            else:
                remaining = selected
            for n in remaining:
                viewer.add_source(n, vfs)
            self._status.showMessage(
                f"{node.path}  [Multi-Log Studio — loading {len(selected)} file(s)…]"
            )
            return
        if mode == "protobuf":
            self._hash_node_if_integrity(node, vfs)
            from crush.parsers.protobuf_parser import ProtobufParser
            parser = ProtobufParser()
            try:
                result = parser.parse(node, vfs)
                result = self._enrich_with_format_info(parser, node, vfs, result)
                self._show_result(node, result, vfs)
                self._props_panel.update_properties(node, result.metadata)
                self._status.showMessage(
                    f"{node.path}  [{parser.DISPLAY_NAME}]"
                )
            except Exception as exc:
                self._status.showMessage(f"Protobuf parse error: {exc}")
                QMessageBox.warning(self, "Protobuf parse error", str(exc))
            return
        self._open_node(node, vfs)

    def _open_multi_log_window(self, node: VFSNode, vfs: VFS) -> QWidget:
        """Open *node* in a new, standalone Multi-Log Studio window.

        The window is parented to the main window so Qt destroys it when the
        application exits, but the ``Qt.Window`` flag makes it appear as an
        independent top-level window in the OS task bar.
        """
        from crush.viewers.multi_log_viewer import MultiLogViewer
        viewer = MultiLogViewer(node, vfs, parent=None)
        viewer.setWindowFlags(Qt.WindowType.Window)
        viewer.setWindowTitle(f"Multi-Log Studio — {node.name}")
        viewer.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._log_dock.show()
        # Size to 80 % of the available screen area, capped at 1400 × 850.
        avail = self.screen().availableGeometry()
        w = min(1400, int(avail.width()  * 0.80))
        h = min(850,  int(avail.height() * 0.80))
        viewer.resize(w, h)
        viewer.show()
        self._multi_log_windows.append(viewer)
        return viewer

    def _find_multi_log_viewer(self) -> QWidget | None:
        """Return the most recently opened Multi-Log Studio window, if any.

        Removes stale entries (closed / destroyed windows) from the tracking
        list before searching.
        """
        from crush.viewers.multi_log_viewer import MultiLogViewer
        self._multi_log_windows = [
            w for w in self._multi_log_windows if isValid(w)
        ]
        for w in reversed(self._multi_log_windows):
            if isinstance(w, MultiLogViewer):
                w.raise_()
                w.activateWindow()
                return w
        return None

    def _open_external_mode(self, node: VFSNode, vfs: VFS, mode: str) -> None:
        if node.is_dir:
            if isinstance(vfs, DirectoryVFS) and Path(node.path).exists():
                self._open_local_file(Path(node.path))
            else:
                QMessageBox.information(
                    self,
                    "Open External",
                    "Opening directories from archives is not supported yet.",
                )
            return
        path = self._materialize_node_for_external(node, vfs)
        if path is None:
            QMessageBox.warning(self, "Open External", "Unable to materialize file.")
            return
        if mode == "choose":
            self._open_external_with_app(path)
        else:
            self._open_local_file(path)

    def _paste_decode(self) -> None:
        from crush.ui.paste_decode_dialog import PasteDecodeDialog
        PasteDecodeDialog(self).show()

    def _open_bytes_with_format(self, data: bytes, filename_hint: str, parser_display_name: object) -> None:
        """Open *data* in the appropriate viewer, honouring an explicit format choice."""
        import crush.parsers  # noqa: F401 — ensures all parsers are registered
        from crush.core.registry import ParserRegistry
        from crush.core.vfs import BytesVFS

        if parser_display_name == "__hex__":
            from crush.viewers.hex_viewer import HexViewer
            viewer = HexViewer(data, self)
            self._viewer_tabs.addTab(viewer, "hex")
            self._viewer_tabs.setCurrentIndex(self._viewer_tabs.count() - 1)
            return

        vfs = BytesVFS(data, name=filename_hint)
        node = vfs.root()

        if parser_display_name is None:
            parser = ParserRegistry.best(node, vfs)
        else:
            parser = next(
                (p for p in ParserRegistry._parsers if p.DISPLAY_NAME == parser_display_name),
                None,
            ) or ParserRegistry.best(node, vfs)

        if parser is None:
            QMessageBox.warning(self, "No parser found", f"No parser could handle this data as {filename_hint!r}.")
            return
        try:
            result = parser.parse(node, vfs)
            self._show_result(node, result, vfs)
            self._props_panel.update_properties(node, result.metadata)
            self._status.showMessage(f"Opened pasted data  [{parser.DISPLAY_NAME}]")
        except Exception as exc:
            self._status.showMessage(f"Parse error: {exc}")
            QMessageBox.warning(self, "Parse error", str(exc))

    def _open_bytes_as_artifact(self, data: bytes, name: str) -> None:
        """Open in-memory bytes (e.g. a BLOB cell) as a new tab using the best parser."""
        import crush.parsers  # noqa: F401 — triggers parser registration
        from crush.core.registry import ParserRegistry
        from crush.core.vfs import BytesVFS

        vfs = BytesVFS(data, name=name)
        node = vfs.root()
        parser = ParserRegistry.best(node, vfs)
        if parser is None:
            return
        try:
            result = parser.parse(node, vfs)
            self._show_result(node, result, vfs)
            self._props_panel.update_properties(node, result.metadata)
            self._status.showMessage(f"Opened artifact: {name}  [{parser.DISPLAY_NAME}]")
        except Exception as exc:
            self._status.showMessage(f"Artifact parse error: {exc}")
            QMessageBox.warning(self, "Parse error", str(exc))

    def _materialize_node_for_external(self, node: VFSNode, vfs: VFS) -> Path | None:
        try:
            if isinstance(vfs, DirectoryVFS) and Path(node.path).exists():
                return Path(node.path)
            if not hasattr(self, "_external_temp_paths"):
                self._external_temp_paths: list[Path] = []
            tmp_dir = Path(tempfile.mkdtemp(prefix="crush-open-"))
            suffix = node.extension or ""
            tmp_path = tmp_dir / (node.name or f"file{suffix}")
            with vfs.open(node) as src, open(tmp_path, "wb") as dst:
                dst.write(src.read())
            self._external_temp_paths.append(tmp_path)
            return tmp_path
        except Exception as exc:
            if hasattr(self, "_logger"):
                self._logger.error("Open external failed: %s", exc)
            return None

    def _open_local_file(self, path: str | Path) -> None:
        from crush.ui import open_url
        open_url(QUrl.fromLocalFile(str(path)).toString())

    def _open_external_with_app(self, path: Path) -> None:
        title = "Choose application"
        app_path, _ = QFileDialog.getOpenFileName(self, title, "", "Applications (*)")
        if not app_path:
            return
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen([app_path, str(path)], close_fds=True)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-a", app_path, str(path)])
            else:
                subprocess.Popen([app_path, str(path)])
        except Exception as exc:
            QMessageBox.warning(self, "Open External", str(exc))

    def _on_node_selected(self, node: VFSNode, vfs: VFS) -> None:
        metadata: dict[str, str] = {
            "Type": "Directory" if node.is_dir else "File",
        }
        if node.is_dir:
            metadata["Files"] = f"{vfs.file_count(node):,}"
            metadata["Total size"] = _format_size(vfs.total_size(node))
        else:
            metadata["Size"] = _format_size(node.size)
        self._props_panel.update_properties(node, metadata)

    def _show_result(self, node: VFSNode, result: ParseResult, vfs: VFS) -> None:
        from crush.ui.viewer_factory import make_viewer
        base_view = make_viewer(result, node, vfs, self)
        if hasattr(base_view, "open_bytes_requested"):
            base_view.open_bytes_requested.connect(self._open_bytes_as_artifact)
        widget: QWidget = base_view
        if self._always_hex:
            hex_bytes = self._read_hex_bytes(vfs, node)
            if hex_bytes is not None:
                from crush.viewers.hex_viewer import HexViewer
                tabbed = QTabWidget()
                tabbed.addTab(base_view, "View")
                tabbed.addTab(HexViewer(hex_bytes, tabbed), "Hex")
                widget = tabbed
            else:
                tabbed = QTabWidget()
                tabbed.addTab(base_view, "View")
                tabbed.addTab(QLabel("Unable to load hex view."), "Hex")
                widget = tabbed

        label = node.path
        existing_idx = -1
        for i in range(self._viewer_tabs.count()):
            w = self._viewer_tabs.widget(i)
            if w is None:
                continue
            if w.property("crush_path") == node.path and w.property("crush_viewer") == result.viewer_type:
                existing_idx = i
                break
        if existing_idx >= 0:
            self._viewer_tabs.setCurrentIndex(existing_idx)
            return
        if result.viewer_type == "hex":
            label = f"{node.path} [Hex]"
        elif result.viewer_type == "multi_log":
            label = f"{node.path} [Multi-Log]"
        widget.setProperty("crush_path", node.path)
        widget.setProperty("crush_viewer", result.viewer_type)
        widget.setProperty("crush_vfs", vfs)
        idx = self._viewer_tabs.addTab(widget, label)
        self._viewer_tabs.setTabToolTip(idx, node.path)
        self._viewer_tabs.setCurrentIndex(idx)

    def _close_tab(self, index: int) -> None:
        self._viewer_tabs.removeTab(index)

    def _close_all_tabs(self) -> None:
        self._viewer_tabs.clear()

    def _close_tabs_for_vfs(self, vfs: VFS) -> int:
        closed = 0
        for i in range(self._viewer_tabs.count() - 1, -1, -1):
            w = self._viewer_tabs.widget(i)
            if w is None:
                continue
            if w.property("crush_vfs") is vfs:
                self._viewer_tabs.removeTab(i)
                closed += 1
        return closed

    def _close_source(self, vfs: VFS) -> None:
        closed_tabs = self._close_tabs_for_vfs(vfs)
        self._fs_panel.close_vfs(vfs)
        self.session.remove_source(vfs)
        self._update_window_title()
        name = vfs.root().name
        self._status.showMessage(f"Closed source: {name} ({closed_tabs} tabs closed)")

    def _show_empty_view(self) -> None:
        self._central_stack.setCurrentWidget(self._empty_view)

    def _show_empty_view_if_no_sources(self, _vfs: VFS) -> None:
        if not self._fs_panel._vfs_list:
            self._show_empty_view()

    def _show_viewer_tabs(self) -> None:
        self._central_stack.setCurrentWidget(self._viewer_tabs)
    def _update_window_title(self) -> None:
        sources = self._fs_panel._vfs_list
        app_title = f"Crush {crush.display_version()}"
        if not sources:
            self.setWindowTitle(app_title)
            return

        source_name = sources[-1].root().name
        if len(sources) == 1:
            self.setWindowTitle(f"{source_name} — {app_title}")
        else:
            self.setWindowTitle(f"{source_name} (+{len(sources) - 1}) — {app_title}")

    def _enrich_with_format_info(self, parser: object, node: VFSNode, vfs: VFS, result: object) -> object:
        """Prepend format knowledge-base metadata to a ParseResult without overriding parser data."""
        try:
            from crush.core.format_db import FormatDatabase
            from crush.parsers.base import ParseResult
            fmt = FormatDatabase.get().by_parser_class(type(parser).__name__) if parser else None
            if fmt is None:
                peek = vfs.peek(node)
                fmt = FormatDatabase.get().identify(peek, node.name)
            if fmt is None:
                return result
            fmt_meta: dict = {"Format": fmt.name}
            if fmt.platforms:
                fmt_meta["Platforms"] = fmt.platforms.replace(",", ", ")
            if fmt.forensic_relevance:
                fmt_meta["Forensic relevance"] = fmt.forensic_relevance
            if fmt.links:
                fmt_meta["Reference"] = fmt.links[0][1]
            # Parser metadata takes precedence over format defaults
            merged = {**fmt_meta, **result.metadata}  # type: ignore[union-attr]
            return ParseResult(
                result.viewer_type,  # type: ignore[union-attr]
                result.data,  # type: ignore[union-attr]
                result.sub_nodes,  # type: ignore[union-attr]
                merged,
                result.text_index,  # type: ignore[union-attr]
                result.viewer_hints,  # type: ignore[union-attr]
            )
        except Exception:
            return result

    def _show_format_info(self, node: VFSNode, vfs: VFS) -> None:
        """Show a format info popup and also update the Properties panel."""
        try:
            from crush.core.format_db import FormatDatabase
            from crush.ui.format_info_dialog import FormatInfoDialog
            peek = vfs.peek(node, 2048)
            fmt = FormatDatabase.get().identify(peek, node.name)
            if fmt is None:
                from crush.core.magic import detect_fast_label
                label = detect_fast_label(peek, node.path or node.name)
                if label:
                    fmt = FormatDatabase.get().by_short_name(label)
            dlg = FormatInfoDialog(node, fmt, self)
            dlg.exec()
            # Also update the Properties panel
            if fmt:
                meta: dict = {"Format": fmt.name}
                if fmt.category:
                    meta["Category"] = fmt.category
                if fmt.platforms:
                    meta["Platforms"] = fmt.platforms.replace(",", ", ")
                if fmt.forensic_relevance:
                    meta["Forensic relevance"] = fmt.forensic_relevance
                meta["Parser support"] = "Supported" if fmt.parser_class else "Not yet supported"
                if fmt.links:
                    meta["Reference"] = fmt.links[0][1]
                self._props_panel.update_properties(node, meta)
                self._props_dock.show()
                self._props_dock.raise_()
        except Exception as exc:
            self._status.showMessage(f"Format info error: {exc}")

    def _show_format_reference(self) -> None:
        from crush.ui.format_reference import FormatReferenceDialog
        dlg = FormatReferenceDialog(self)
        dlg.exec()

    def _about(self) -> None:
        from crush.ui.about_dialog import AboutDialog
        AboutDialog(self).exec()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._status.showMessage("Closing…")
        if hasattr(self, "_logger"):
            self._logger.info("Closing application")

        if self._thread_is_running(getattr(self, "_load_thread", None)):
            self._load_thread.quit()
            self._load_thread.wait(2000)
        if self._thread_is_running(getattr(self, "_export_thread", None)):
            self._export_thread.quit()
            self._export_thread.wait(2000)

        try:
            self.session.close()
        except Exception as exc:
            if hasattr(self, "_logger"):
                self._logger.error("Error during shutdown: %s", exc)

        # Best-effort cleanup for temp files created for external open.
        for tmp_path in getattr(self, "_external_temp_paths", []):
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
                if tmp_path.parent.exists():
                    tmp_path.parent.rmdir()
            except Exception:
                pass

        event.accept()

    def _reset_panel_layout(self) -> None:
        for dock, area in (
            (self._fs_dock, Qt.DockWidgetArea.LeftDockWidgetArea),
            (self._props_dock, Qt.DockWidgetArea.RightDockWidgetArea),
            (self._log_dock, Qt.DockWidgetArea.BottomDockWidgetArea),
        ):
            try:
                self._dock_to_default(dock)
                dock.show()
            except Exception:
                continue

    def _on_spinner_tick(self) -> None:
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_chars)
        self._spinner_label.setText(self._spinner_chars[self._spinner_idx])

    def _on_background_status(self, text: str) -> None:
        if not text:
            self._spinner_timer.stop()
            self._spinner_label.setVisible(False)
            self._bg_status.setVisible(False)
            self._bg_status.setText("")
            self._bg_status.setToolTip("")
            return
        self._bg_status.setText(text)
        self._bg_status.setToolTip(text)
        self._bg_status.setVisible(True)
        self._spinner_label.setVisible(True)
        if not self._spinner_timer.isActive():
            self._spinner_timer.start()

    def _sync_dock_titlebar(self, dock: QDockWidget, floating: bool) -> None:
        # On Wayland (native or XWayland) the compositor owns window decorations
        # including resize handles. A custom title bar strips them entirely.
        _on_wayland = (
            QGuiApplication.platformName() == "wayland"
            or os.environ.get("XDG_SESSION_TYPE") == "wayland"
            or bool(os.environ.get("WAYLAND_DISPLAY"))
        )
        if _on_wayland:
            if floating:
                dock.setWindowFlag(Qt.WindowType.Window, True)
                dock.show()
            else:
                dock.setWindowFlag(Qt.WindowType.Window, False)
            return
        if floating:
            dock.setTitleBarWidget(_DockTitleBar(dock.windowTitle(), dock))
        else:
            dock.setTitleBarWidget(None)

    def _dock_to_default(self, dock: QDockWidget) -> None:
        area = self._dock_defaults.get(dock, Qt.DockWidgetArea.LeftDockWidgetArea)
        if dock.isFloating():
            dock.setFloating(False)
        self.addDockWidget(area, dock)

    def _thread_is_running(self, thread: QThread | None) -> bool:
        if thread is None:
            return False
        if not isValid(thread):
            return False
        try:
            return thread.isRunning()
        except RuntimeError:
            return False

    def _on_load_thread_finished(self) -> None:
        self._load_thread = None
        if self._load_queue:
            path, open_after_load, append_to_tree = self._load_queue.pop(0)
            self._load_source(path, open_after_load=open_after_load, append_to_tree=append_to_tree)

    def _on_export_thread_finished(self) -> None:
        self._export_thread = None

    def _setup_logging(self) -> None:
        self._logger = logging.getLogger("crush")
        level_name = os.getenv("CRUSH_LOG_LEVEL", "INFO").upper()
        level = logging.getLevelName(level_name)
        if not isinstance(level, int):
            level = logging.INFO
        self._logger.setLevel(level)
        self._log_level = level
        self._logger.propagate = False

        self._log_signal_handler = _LogSignalHandler()
        self._log_signal_handler.setLevel(level)
        self._log_signal_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        self._log_signal_handler.log_line.connect(self._append_log_line)
        self._logger.addHandler(self._log_signal_handler)

        self._file_handler: logging.FileHandler | None = None
        self._set_log_path(self._default_log_path())
        self._logger.info("Logging started: %s", self._log_path)

    def _default_log_path(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return Path(tempfile.gettempdir()) / f"crush-{ts}.log"

    def _set_log_path(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if self._file_handler:
            self._logger.removeHandler(self._file_handler)
            self._file_handler.close()
        self._file_handler = logging.FileHandler(path, encoding="utf-8")
        self._file_handler.setLevel(getattr(self, "_log_level", logging.INFO))
        self._file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        self._logger.addHandler(self._file_handler)
        self._log_path = path
        self._status.showMessage(f"Logging to: {path}")

    def _export_log(self) -> None:
        if not hasattr(self, "_log_path"):
            QMessageBox.information(self, "Export log", "No log file yet.")
            return
        suggested = self._log_path.name
        dest_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export log",
            suggested,
            "Log files (*.log);;All files (*)",
        )
        if not dest_path:
            return
        try:
            shutil.copy2(self._log_path, dest_path)
            self._status.showMessage(f"Log exported to: {dest_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export log failed", str(exc))

    _LOG_COLORS = {
        "ERROR":    "#e74c3c",
        "CRITICAL": "#c0392b",
        "WARNING":  "#e67e22",
        "DEBUG":    "#7f8c8d",
    }

    def _append_log_line(self, line: str) -> None:
        import html as _html
        from PySide6.QtGui import QTextCursor
        color = None
        for level, clr in self._LOG_COLORS.items():
            if f" {level} " in line:
                color = clr
                break
        escaped = _html.escape(line)
        html_line = (
            f"<span style='color:{color};font-family:monospace;'>{escaped}</span>"
            if color else
            f"<span style='font-family:monospace;'>{escaped}</span>"
        )
        cursor = self._log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not self._log_view.document().isEmpty():
            cursor.insertBlock()
        cursor.insertHtml(html_line)
        self._log_view.setTextCursor(cursor)
        self._log_view.ensureCursorVisible()

    def _set_theme_system(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self.style().standardPalette())
        self._settings.setValue("theme", "system")
        self._logger.info("Theme set to system default")

    def _set_always_hex(self, enabled: bool) -> None:
        self._always_hex = enabled
        if hasattr(self, "_logger"):
            self._logger.info("Always show hex tab: %s", enabled)

    def _integrity_mode_description(self) -> str:
        return (
            "Integrity mode does the following:\n"
            "- Records SHA-256 hashes when files are opened or exported.\n"
            "- Hashes ZIP/TAR/file sources on open (folders are not hashed).\n"
            "- Writes those hashes to the log.\n"
            "- Creates a crush-export-hashes.txt file next to exported data.\n"
            "- You can turn it off for faster opening of large ZIP/TAR sources and faster browsing."
        )

    def _show_integrity_menu(self, pos: object) -> None:
        sender = self.sender()
        if sender is None or not hasattr(sender, "mapToGlobal"):
            return
        menu = QMenu(self)
        toggle_action = menu.addAction("Toggle Integrity Mode")
        info_action = menu.addAction("What is Integrity Mode?")
        action = menu.exec(sender.mapToGlobal(pos))  # type: ignore[arg-type]
        if action == toggle_action:
            self._toggle_integrity_mode()
        elif action == info_action:
            QMessageBox.information(self, "Integrity Mode", self._integrity_mode_description())

    def _toggle_integrity_mode(self) -> None:
        self._integrity_mode_action.setChecked(not self._integrity_mode_action.isChecked())

    def _set_integrity_mode(self, enabled: bool) -> None:
        self.session.integrity_mode = enabled
        self._integrity_label.setVisible(enabled)
        self._no_integrity_label.setVisible(not enabled)
        self._settings.setValue("integrity_mode", enabled)
        state = "enabled" if enabled else "disabled"
        if hasattr(self, "_logger"):
            self._logger.info("Integrity mode %s", state)

    def _hash_node_if_integrity(self, node: VFSNode, vfs: VFS) -> None:
        if not self.session.integrity_mode or node.is_dir:
            return
        import hashlib
        try:
            data = vfs.read(node)
            digest = hashlib.sha256(data).hexdigest()
            self._logger.info(
                "INTEGRITY sha256=%s  size=%d  path=%s", digest, len(data), node.path
            )
        except Exception as exc:
            self._logger.warning("INTEGRITY hash failed for %s: %s", node.path, exc)

    def _read_hex_bytes(self, vfs: VFS, node: VFSNode) -> bytes | None:
        max_bytes = 1024 * 256
        try:
            with vfs.open(node) as src:
                return src.read(max_bytes)
        except Exception as exc:
            if hasattr(self, "_logger"):
                self._logger.warning("Failed to read hex bytes for %s: %s", node.path, exc)
            return None

    def _stop_rainbow_timer(self) -> None:
        if hasattr(self, "_rainbow_timer"):
            self._rainbow_timer.stop()
        if hasattr(self, "_rainbow_snapshot_btn"):
            self._rainbow_snapshot_btn.setVisible(False)

    def _set_theme_light(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self._light_palette())
        self._settings.setValue("theme", "light")
        self._logger.info("Theme set to light")

    def _set_theme_dark(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self._dark_palette())
        self._settings.setValue("theme", "dark")
        self._logger.info("Theme set to dark")

    def _light_palette(self) -> QPalette:
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(248, 249, 251))
        pal.setColor(QPalette.ColorRole.WindowText, QColor(25, 25, 25))
        pal.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(242, 244, 247))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
        pal.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
        pal.setColor(QPalette.ColorRole.Text, QColor(25, 25, 25))
        pal.setColor(QPalette.ColorRole.Button, QColor(240, 242, 245))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor(25, 25, 25))
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(248, 249, 251))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, QColor(25, 25, 25))
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(248, 249, 251))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, QColor(25, 25, 25))
        pal.setColor(QPalette.ColorRole.Mid, QColor(160, 164, 170))
        pal.setColor(QPalette.ColorRole.Dark, QColor(190, 194, 200))
        pal.setColor(QPalette.ColorRole.Shadow, QColor(120, 124, 130))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(56, 120, 255))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        return pal

    def _apply_saved_theme(self) -> None:
        saved_name = self._settings.value("custom_theme_name", "", type=str)
        if saved_name:
            self._custom_theme_action.setText(saved_name)
            self._custom_theme_action.setVisible(True)
        theme = self._settings.value("theme", "light")
        if theme == "dark":
            self._set_theme_dark()
        elif theme == "geek":
            self._set_theme_geek()
        elif theme == "purple":
            self._set_theme_purple()
        elif theme == "ocean":
            self._set_theme_ocean()
        elif theme == "rainbow":
            self._set_theme_rainbow()
        elif theme == "custom":
            self._set_theme_custom()
        elif theme == "system":
            self._set_theme_system()
        else:
            self._set_theme_light()

    def _apply_saved_integrity_mode(self) -> None:
        enabled = self._settings.value("integrity_mode", False, type=bool)
        # setChecked triggers the toggled signal which calls _set_integrity_mode
        self._integrity_mode_action.setChecked(enabled)

    def _apply_saved_prescan_workers(self) -> None:
        import os as _os
        default = min(8, _os.cpu_count() or 4)
        workers = self._settings.value("prescan_workers", default, type=int)
        self._fs_panel._prescan_workers = max(1, workers)

    def _add_to_recent_files(self, path: str) -> None:
        recent: list[str] = self._settings.value("recent_files", [], type=list)
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        recent = recent[:10]
        self._settings.setValue("recent_files", recent)
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self) -> None:
        self._recent_menu.clear()
        recent: list[str] = self._settings.value("recent_files", [], type=list)
        if not recent:
            empty = self._recent_menu.addAction("(empty)")
            empty.setEnabled(False)
        else:
            for path in recent:
                action = self._recent_menu.addAction(path)
                action.setToolTip(path)
                action.triggered.connect(lambda checked=False, p=path: self._load_source(p))
            self._recent_menu.addSeparator()
            self._recent_menu.addAction("Clear Recent", self._clear_recent_files)

    def _clear_recent_files(self) -> None:
        self._settings.setValue("recent_files", [])
        self._rebuild_recent_menu()

    def _set_prescan_workers(self) -> None:
        import os as _os
        default = min(8, _os.cpu_count() or 4)
        current = self._settings.value("prescan_workers", default, type=int)
        value, ok = QInputDialog.getInt(
            self,
            "Indexing Threads",
            f"Number of parallel threads for file type indexing\n(CPU cores: {_os.cpu_count() or '?'}):",
            current,
            1,
            64,
            1,
        )
        if ok:
            self._settings.setValue("prescan_workers", value)
            self._fs_panel._prescan_workers = value

    def _dark_palette(self) -> QPalette:
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(32, 34, 37))
        pal.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Base, QColor(24, 26, 29))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(32, 34, 37))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
        pal.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
        pal.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Button, QColor(45, 48, 52))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(32, 34, 37))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, QColor(220, 220, 220))
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(32, 34, 37))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Mid, QColor(65, 68, 74))
        pal.setColor(QPalette.ColorRole.Dark, QColor(20, 22, 25))
        pal.setColor(QPalette.ColorRole.Shadow, QColor(10, 10, 12))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(64, 128, 255))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        return pal

    def _set_theme_geek(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self._geek_palette())
        self._settings.setValue("theme", "geek")
        self._logger.info("Theme set to geek")

    def _geek_palette(self) -> QPalette:
        green = QColor(0, 204, 68)       # phosphor green
        green_dim = QColor(0, 140, 46)   # dimmed green for secondary elements
        green_dark = QColor(0, 60, 20)   # very dark green for backgrounds
        black = QColor(4, 10, 4)         # near-black with a green tint
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(8, 16, 8))
        pal.setColor(QPalette.ColorRole.WindowText, green)
        pal.setColor(QPalette.ColorRole.Base, black)
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(10, 22, 10))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 30, 10))
        pal.setColor(QPalette.ColorRole.ToolTipText, green)
        pal.setColor(QPalette.ColorRole.Text, green)
        pal.setColor(QPalette.ColorRole.Button, QColor(10, 22, 10))
        pal.setColor(QPalette.ColorRole.ButtonText, green)
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(8, 16, 8))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, green)
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(8, 16, 8))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, green)
        pal.setColor(QPalette.ColorRole.Mid, green_dim)
        pal.setColor(QPalette.ColorRole.Dark, green_dark)
        pal.setColor(QPalette.ColorRole.Shadow, QColor(0, 30, 10))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(0, 255, 100))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(0, 180, 60))
        pal.setColor(QPalette.ColorRole.HighlightedText, black)
        return pal

    def _set_theme_purple(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self._purple_palette())
        self._settings.setValue("theme", "purple")
        self._logger.info("Theme set to purple")

    def _purple_palette(self) -> QPalette:
        lavender = QColor(190, 130, 255)    # bright lavender for primary text
        violet = QColor(130, 80, 200)       # dimmed violet for secondary elements
        deep = QColor(40, 10, 70)           # deep purple for backgrounds
        black = QColor(12, 6, 20)           # near-black with purple tint
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(20, 10, 36))
        pal.setColor(QPalette.ColorRole.WindowText, lavender)
        pal.setColor(QPalette.ColorRole.Base, black)
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(22, 12, 38))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(30, 15, 50))
        pal.setColor(QPalette.ColorRole.ToolTipText, lavender)
        pal.setColor(QPalette.ColorRole.Text, lavender)
        pal.setColor(QPalette.ColorRole.Button, QColor(28, 14, 48))
        pal.setColor(QPalette.ColorRole.ButtonText, lavender)
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(20, 10, 36))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, lavender)
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(20, 10, 36))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, lavender)
        pal.setColor(QPalette.ColorRole.Mid, violet)
        pal.setColor(QPalette.ColorRole.Dark, deep)
        pal.setColor(QPalette.ColorRole.Shadow, QColor(8, 4, 16))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(220, 160, 255))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(150, 80, 230))
        pal.setColor(QPalette.ColorRole.HighlightedText, black)
        return pal

    def _set_theme_ocean(self) -> None:
        self._stop_rainbow_timer()
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(self._ocean_palette())
        self._settings.setValue("theme", "ocean")
        self._logger.info("Theme set to ocean")

    def _ocean_palette(self) -> QPalette:
        cyan = QColor(0, 210, 200)          # sunlit ocean surface — primary text
        cyan_dim = QColor(0, 140, 140)      # deeper water — secondary elements
        navy = QColor(0, 30, 60)            # deep ocean — backgrounds
        black = QColor(2, 10, 20)           # abyss — near-black with ocean tint
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(4, 18, 38))
        pal.setColor(QPalette.ColorRole.WindowText, cyan)
        pal.setColor(QPalette.ColorRole.Base, black)
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(6, 22, 44))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 24, 48))
        pal.setColor(QPalette.ColorRole.ToolTipText, cyan)
        pal.setColor(QPalette.ColorRole.Text, cyan)
        pal.setColor(QPalette.ColorRole.Button, QColor(6, 24, 48))
        pal.setColor(QPalette.ColorRole.ButtonText, cyan)
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(4, 18, 38))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, cyan)
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(4, 18, 38))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, cyan)
        pal.setColor(QPalette.ColorRole.Mid, cyan_dim)
        pal.setColor(QPalette.ColorRole.Dark, navy)
        pal.setColor(QPalette.ColorRole.Shadow, QColor(0, 10, 24))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(100, 240, 255))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(0, 160, 180))
        pal.setColor(QPalette.ColorRole.HighlightedText, black)
        return pal

    def _set_theme_rainbow(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        self._settings.setValue("theme", "rainbow")
        self._logger.info("Theme set to rainbow")
        if not hasattr(self, "_rainbow_timer"):
            self._rainbow_timer = QTimer(self)
            self._rainbow_timer.timeout.connect(self._step_rainbow)
            self._rainbow_hue = 0.0
        self._rainbow_timer.start(50)
        self._rainbow_snapshot_btn.setVisible(True)

    def _step_rainbow(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        self._rainbow_hue = (self._rainbow_hue + 0.004) % 1.0
        app.setPalette(self._rainbow_palette(self._rainbow_hue))

    def _rainbow_palette(self, hue: float) -> QPalette:
        text = QColor.fromHsvF(hue, 0.85, 1.0)
        dim = QColor.fromHsvF((hue + 0.05) % 1.0, 0.6, 0.55)
        bg = QColor.fromHsvF(hue, 0.25, 0.09)
        base = QColor.fromHsvF(hue, 0.18, 0.06)
        highlight = QColor.fromHsvF((hue + 0.5) % 1.0, 0.9, 0.95)
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, bg)
        pal.setColor(QPalette.ColorRole.WindowText, text)
        pal.setColor(QPalette.ColorRole.Base, base)
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor.fromHsvF(hue, 0.2, 0.10))
        pal.setColor(QPalette.ColorRole.ToolTipBase, bg)
        pal.setColor(QPalette.ColorRole.ToolTipText, text)
        pal.setColor(QPalette.ColorRole.Text, text)
        pal.setColor(QPalette.ColorRole.Button, QColor.fromHsvF(hue, 0.20, 0.11))
        pal.setColor(QPalette.ColorRole.ButtonText, text)
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, bg)
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, text)
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, bg)
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, text)
        pal.setColor(QPalette.ColorRole.Mid, dim)
        pal.setColor(QPalette.ColorRole.Dark, QColor.fromHsvF(hue, 0.30, 0.07))
        pal.setColor(QPalette.ColorRole.Shadow, QColor.fromHsvF(hue, 0.20, 0.04))
        pal.setColor(QPalette.ColorRole.BrightText, QColor.fromHsvF((hue + 0.08) % 1.0, 1.0, 1.0))
        pal.setColor(QPalette.ColorRole.Highlight, highlight)
        pal.setColor(QPalette.ColorRole.HighlightedText, base)
        return pal

    def _snapshot_rainbow(self) -> None:
        self._stop_rainbow_timer()
        hue = getattr(self, "_rainbow_hue", 0.0)
        name, ok = QInputDialog.getText(
            self, "Save Custom Theme", "Name for your theme:", text="My Theme"
        )
        if ok and name.strip():
            name = name.strip()
            self._settings.setValue("custom_theme_hue", hue)
            self._settings.setValue("custom_theme_name", name)
            self._custom_theme_action.setText(name)
            self._custom_theme_action.setVisible(True)
            app = QApplication.instance()
            if app:
                app.setPalette(self._rainbow_palette(hue))
            self._settings.setValue("theme", "custom")
            self._logger.info("Custom theme '%s' saved (hue=%.3f)", name, hue)
        else:
            self._rainbow_timer.start(50)
            self._rainbow_snapshot_btn.setVisible(True)

    def _set_theme_custom(self) -> None:
        self._stop_rainbow_timer()
        hue = self._settings.value("custom_theme_hue", 0.0, type=float)
        app = QApplication.instance()
        if app:
            app.setPalette(self._rainbow_palette(hue))
        self._settings.setValue("theme", "custom")
        self._logger.info("Theme set to custom")


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.1f} {units[unit_index]}"
