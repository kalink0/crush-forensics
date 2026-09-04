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
from PySide6.QtGui import (
    QCloseEvent,
    QDragEnterEvent,
    QDropEvent,
    QPalette,
    QColor,
    QAction,
    QFontMetrics,
    QGuiApplication,
)
from shiboken6 import isValid
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDockWidget,
    QFileDialog,
    QLabel,
    QLineEdit,
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
    QToolButton,
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
    password_required = Signal(bool)  # True = a previously supplied password was wrong

    def __init__(
        self,
        session: Session,
        path: str,
        integrity: bool,
        itunes_zip_prefix: str | None = None,
        password: str = "",
    ) -> None:
        super().__init__()
        self._session = session
        self._path = path
        self._integrity = integrity
        self._itunes_zip_prefix = itunes_zip_prefix
        self._password = password

    def run(self) -> None:
        from crush.core.passwords import PasswordRequiredError, WrongPasswordError

        try:
            if self._itunes_zip_prefix is not None:
                from crush.core.vfs import open_itunes_backup_from_zip

                vfs = self._session.add_source_vfs(
                    open_itunes_backup_from_zip(
                        self._path, self._itunes_zip_prefix, password=self._password
                    )
                )
            else:
                vfs = self._session.add_source(self._path, password=self._password)
            if self._integrity:
                self._log_source_hash()
        except WrongPasswordError:
            self.password_required.emit(True)
            return
        except PasswordRequiredError:
            self.password_required.emit(False)
            return
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


class _RecentFileButton(QWidget):
    opened = Signal(str)

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        self.setToolTip(path)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        p = Path(path)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(12)
        name = QLabel(f"<b>{p.name}</b>")
        directory = QLabel(f"<span style='color:gray'>{p.parent}</span>")
        directory.setSizePolicy(directory.sizePolicy().horizontalPolicy(), directory.sizePolicy().verticalPolicy())
        layout.addWidget(name)
        layout.addWidget(directory, stretch=1)

    def mousePressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "button") and event.button() == Qt.MouseButton.LeftButton:
            self.opened.emit(self._path)
        else:
            super().mousePressEvent(event)  # type: ignore[arg-type]

    def enterEvent(self, event: object) -> None:  # type: ignore[override]
        self.setStyleSheet("background-color: palette(highlight); border-radius: 4px;")

    def leaveEvent(self, event: object) -> None:  # type: ignore[override]
        self.setStyleSheet("")


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
    _AMERICA_INTRO_MS = 650
    _AMERICA_FINALE_MS = 1000
    _AMERICA_CHILL_TICK_MS = 50
    _AMERICA_HOLD_MS = 1800
    _AMERICA_FADE_MS = 450

    def __init__(self) -> None:
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setAcceptDrops(True)
        self._open_windows.append(self)
        self.destroyed.connect(self._remove_window_reference)
        self.session = Session()
        self._always_hex = False
        self._pending_open: tuple[VFSNode, VFS] | None = None
        self._load_queue: list[tuple[str, bool, bool, str | None]] = []
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
        self._viewer_tabs.currentChanged.connect(self._on_viewer_tab_changed)
        # Long VFS paths (issue #47) would otherwise grow the tab past the
        # viewport and push the native close button off-screen; cap the
        # width and elide in the middle so the close button always fits.
        self._viewer_tabs.tabBar().setElideMode(Qt.TextElideMode.ElideMiddle)
        self._viewer_tabs.setStyleSheet("QTabBar::tab { max-width: 240px; }")
        self._viewer_tabs.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._viewer_tabs.tabBar().customContextMenuRequested.connect(self._show_tab_context_menu)

        self._tab_list_menu = QMenu(self)
        self._tab_list_menu.aboutToShow.connect(self._populate_tab_list_menu)
        self._tab_list_menu.triggered.connect(self._on_tab_list_menu_triggered)
        self._tab_list_button = QToolButton()
        self._tab_list_button.setText("▾")
        self._tab_list_button.setToolTip("Show open tabs")
        self._tab_list_button.setAutoRaise(True)
        self._tab_list_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._tab_list_button.setMenu(self._tab_list_menu)
        self._viewer_tabs.setCornerWidget(self._tab_list_button, Qt.Corner.TopRightCorner)

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

        self._recent_on_welcome = QVBoxLayout()
        self._recent_on_welcome.setSpacing(4)
        empty_layout.addSpacing(16)
        empty_layout.addLayout(self._recent_on_welcome)

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
        self._fs_panel.send_to_peach_batch_requested.connect(self._send_to_peach_batch)
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
        self._props_panel.format_info_requested.connect(self._show_format_info)
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

        self._america_show_btn = QPushButton("")
        self._america_show_btn.setMinimumWidth(150)
        self._america_show_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._america_show_btn.setToolTip("Replay the U-S-A theme show")
        self._america_show_btn.setVisible(False)
        self._america_show_btn.clicked.connect(self._replay_america_show)
        self._status.addPermanentWidget(self._america_show_btn)

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
        theme_menu.addAction("'Merica", self._set_theme_america)
        theme_menu.addSeparator()
        self._custom_theme_action = theme_menu.addAction("", self._set_theme_custom)
        self._custom_theme_action.setVisible(False)

        tools_menu = menu.addMenu("Tools")
        tools_menu.addAction("Paste & Decode…", self._paste_decode)
        tools_menu.addAction("Value Inspector…", self._open_value_inspector)
        tools_menu.addSeparator()
        tools_menu.addAction("Export log…", self._export_log)
        tools_menu.addSeparator()
        self._integrity_mode_action = QAction("Integrity Mode", self, checkable=True)
        self._integrity_mode_action.setToolTip("Hash every file on open and write hash to log")
        self._integrity_mode_action.toggled.connect(self._set_integrity_mode)
        tools_menu.addAction(self._integrity_mode_action)
        tools_menu.addAction("Indexing Threads…", self._set_prescan_workers)
        tools_menu.addAction("Log Temp Directory…", self._set_log_temp_dir)
        peach_menu = tools_menu.addMenu("Peach")
        peach_menu.addAction("Open Peach", self._open_peach_standalone)
        peach_menu.addAction("Binary Path…", self._set_peach_binary_path)

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

    def _open_in_new_window(self, node: VFSNode, vfs: VFS) -> None:
        self._hash_node_if_integrity(node, vfs)
        path = self._materialize_node_for_external(node, vfs)
        if path is None:
            QMessageBox.warning(
                self, "Open in New Window", f"Unable to materialize {node.name!r} for a new window."
            )
            return
        window = MainWindow()
        window.resize(self.size())
        window.show()
        if not isinstance(vfs, DirectoryVFS):
            # The temp file was materialized in this (source) window's
            # tracking list; transfer ownership to the new window so its
            # cleanup runs when that window closes, not this one.
            self._external_temp_paths.remove(path)
            window._external_temp_paths = [path]
        window._load_source(str(path))

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

    def _load_source(
        self,
        path: str,
        open_after_load: bool = False,
        append_to_tree: bool = False,
        itunes_zip_prefix: str | None = None,
        password: str = "",
    ) -> None:
        if itunes_zip_prefix is None and Path(path).suffix.lower() == ".zip":
            itunes_zip_prefix = self._maybe_confirm_itunes_backup_zip(path)

        if self._thread_is_running(getattr(self, "_load_thread", None)):
            self._load_queue.append(
                (path, open_after_load, append_to_tree, itunes_zip_prefix, password)
            )
            self._status.showMessage("Queued source for loading…")
            self._logger.debug("Load queued: %s (open_after_load=%s append=%s)", path, open_after_load, append_to_tree)
            return

        self._logger.info("Loading source: %s", path)
        self._logger.debug("Load start: %s (open_after_load=%s append=%s)", path, open_after_load, append_to_tree)
        self._loading_path = path
        self._loading_itunes_zip_prefix = itunes_zip_prefix
        self._open_after_load = open_after_load
        self._append_to_tree = append_to_tree
        self._tree_build_started = time.monotonic()
        self._status.showMessage(f"Loading: {path}")
        self._progress = LoadingDialog("Loading source…", self)
        self._progress.show()

        self._load_thread = QThread(self)
        self._load_worker = _LoadSourceWorker(
            self.session, path, self.session.integrity_mode, itunes_zip_prefix, password
        )
        self._load_worker.moveToThread(self._load_thread)
        self._load_thread.started.connect(self._load_worker.run)
        self._load_worker.finished.connect(self._on_load_finished)
        self._load_worker.failed.connect(self._on_load_failed)
        self._load_worker.password_required.connect(self._on_password_required)
        self._load_worker.finished.connect(self._load_thread.quit)
        self._load_worker.failed.connect(self._load_thread.quit)
        self._load_worker.password_required.connect(self._load_thread.quit)
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
        append = getattr(self, "_append_to_tree", False) and not vfs.root().is_dir
        self._logger.debug("Dispatching to FilesystemPanel (%s)", "append" if append else "load")
        if append:
            self._fs_panel.append_vfs(vfs)
        else:
            self._close_all_tabs()
            self._fs_panel.load_vfs(vfs)
        self._update_window_title()
        QTimer.singleShot(0, self._ensure_tree_loaded)

    def _on_load_failed(self, message: str) -> None:
        self._logger.debug("Load worker failed: %s", message)
        if hasattr(self, "_progress"):
            self._progress.close()
        self._status.showMessage(f"Error loading source: {message}")
        self._logger.error("Load error: %s", message)

        path = getattr(self, "_loading_path", None)
        offer_hex = bool(path) and Path(path).is_file()

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("Load error")
        box.setText(message)
        box.addButton(QMessageBox.StandardButton.Ok)
        hex_button = (
            box.addButton("Open as Hex", QMessageBox.ButtonRole.ActionRole) if offer_hex else None
        )
        box.exec()
        if hex_button is not None and box.clickedButton() is hex_button:
            self._open_failed_source_as_hex(path)

    def _open_failed_source_as_hex(self, path: str) -> None:
        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            QMessageBox.warning(self, "Open as Hex", f"Could not read {path!r}: {exc}")
            return
        from crush.viewers.hex_viewer import HexViewer
        viewer = HexViewer(data, self)
        idx = self._viewer_tabs.addTab(viewer, f"{Path(path).name} [Hex]")
        self._viewer_tabs.setCurrentIndex(idx)
        self._show_viewer_tabs()

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
            self._props_panel.update_properties(node, result.metadata, vfs)
            possibly_encrypted = result.metadata.get("Possibly Encrypted")
            if possibly_encrypted:
                # A normal double-click never auto-prompts for a password (see
                # pdf_parser.py / realm_parser.py), but that shouldn't mean the
                # hint is invisible unless the user happens to be looking at
                # the Properties panel -- surface it in the status bar too.
                self._status.showMessage(
                    f"{node.path}  [{parser.DISPLAY_NAME} — {possibly_encrypted}]"
                )
            else:
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
            self._props_panel.update_properties(node, result.metadata, vfs)
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
            self._props_panel.update_properties(node, result.metadata, vfs)
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
        if mode == "send_to_peach_folder":
            from crush.viewers.multi_log_viewer import (
                _discover_log_nodes,
                FolderDiscoveryDialog,
            )
            found = _discover_log_nodes(node, vfs)
            if not found:
                QMessageBox.information(
                    self, "Send to Peach", f"No log files found in '{node.name}'."
                )
                return
            dlg = FolderDiscoveryDialog(node.name, found, self, title="Send Logs to Peach")
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            selected = dlg.selected_nodes()
            if not selected:
                return
            self._send_to_peach_batch([(n, vfs) for n in selected])
            return
        if mode == "send_to_peach":
            self._hash_node_if_integrity(node, vfs)
            self._send_to_peach(node, vfs)
            return
        if mode == "protobuf":
            self._hash_node_if_integrity(node, vfs)
            from crush.parsers.protobuf_parser import ProtobufParser
            parser = ProtobufParser()
            try:
                result = parser.parse(node, vfs)
                result = self._enrich_with_format_info(parser, node, vfs, result)
                self._show_result(node, result, vfs)
                self._props_panel.update_properties(node, result.metadata, vfs)
                self._status.showMessage(
                    f"{node.path}  [{parser.DISPLAY_NAME}]"
                )
            except Exception as exc:
                self._status.showMessage(f"Protobuf parse error: {exc}")
                QMessageBox.warning(self, "Protobuf parse error", str(exc))
            return
        if mode == "mmkv":
            self._hash_node_if_integrity(node, vfs)
            from crush.parsers.mmkv_parser import MMKVParser
            parser = MMKVParser()
            try:
                result = parser.parse(node, vfs)
                result = self._enrich_with_format_info(parser, node, vfs, result)
                self._show_result(node, result, vfs)
                self._props_panel.update_properties(node, result.metadata, vfs)
                self._status.showMessage(f"{node.path}  [{parser.DISPLAY_NAME}]")
            except Exception as exc:
                self._status.showMessage(f"MMKV parse error: {exc}")
                QMessageBox.warning(self, "MMKV parse error", str(exc))
            return
        if mode == "mmkv_encrypted":
            self._hash_node_if_integrity(node, vfs)
            self._open_encrypted_mmkv(node, vfs)
            return
        if mode == "realm_encrypted":
            self._hash_node_if_integrity(node, vfs)
            self._open_encrypted_realm(node, vfs)
            return
        if mode == "sqlcipher":
            self._hash_node_if_integrity(node, vfs)
            self._open_encrypted_sqlite(node, vfs)
            return
        if mode == "pdf_encrypted":
            self._hash_node_if_integrity(node, vfs)
            self._open_encrypted_pdf(node, vfs)
            return
        self._open_node(node, vfs)

    def _open_encrypted_sqlite(self, node: VFSNode, vfs: VFS, was_wrong: bool = False) -> None:
        from crush.core.passwords import WrongPasswordError
        from crush.parsers.sqlite_parser import SQLiteParser
        from crush.ui.sqlcipher_dialog import SQLCipherCredentialsDialog

        dialog = SQLCipherCredentialsDialog(self, was_wrong=was_wrong)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self._status.showMessage("Load cancelled: password required")
            return
        key_text = dialog.key_text()
        if not key_text:
            self._status.showMessage("Load cancelled: password required")
            return
        raw_key = dialog.is_raw_key()
        cipher_params = dialog.cipher_params()

        parser = SQLiteParser()
        try:
            result = parser.parse(
                node, vfs, password=key_text, raw_key=raw_key, cipher_params=cipher_params
            )
        except WrongPasswordError:
            self._open_encrypted_sqlite(node, vfs, was_wrong=True)
            return
        except Exception as exc:
            self._status.showMessage(f"SQLCipher decrypt error: {exc}")
            QMessageBox.warning(self, "SQLCipher decrypt error", str(exc))
            return

        result = self._enrich_with_format_info(parser, node, vfs, result)
        self._show_result(node, result, vfs)
        self._props_panel.update_properties(node, result.metadata, vfs)
        self._status.showMessage(f"{node.path}  [{parser.DISPLAY_NAME} — decrypted]")

    def _open_encrypted_realm(self, node: VFSNode, vfs: VFS, was_wrong: bool = False) -> None:
        from crush.core.passwords import WrongPasswordError
        from crush.parsers.realm_parser import RealmParser

        title = "Incorrect Key" if was_wrong else "Realm Encryption Key"
        prompt = (
            "Incorrect key. Please try again (64-byte key as a hex string):"
            if was_wrong
            else "Enter the 64-byte Realm encryption key as a hex string:"
        )
        key_text, ok = QInputDialog.getText(self, title, prompt, QLineEdit.EchoMode.Normal)
        if not ok or not key_text:
            self._status.showMessage("Load cancelled: encryption key required")
            return

        parser = RealmParser()
        try:
            result = parser.parse(node, vfs, password=key_text)
        except WrongPasswordError:
            self._open_encrypted_realm(node, vfs, was_wrong=True)
            return
        except Exception as exc:
            self._status.showMessage(f"Realm decrypt error: {exc}")
            QMessageBox.warning(self, "Realm decrypt error", str(exc))
            return

        result = self._enrich_with_format_info(parser, node, vfs, result)
        self._show_result(node, result, vfs)
        self._props_panel.update_properties(node, result.metadata, vfs)
        self._status.showMessage(f"{node.path}  [{parser.DISPLAY_NAME} — decrypted]")

    def _open_encrypted_mmkv(self, node: VFSNode, vfs: VFS, was_wrong: bool = False) -> None:
        from crush.core.passwords import WrongPasswordError
        from crush.parsers.mmkv_parser import MMKVParser
        from crush.ui.mmkv_key_dialog import MMKVKeyDialog

        dialog = MMKVKeyDialog(self, was_wrong=was_wrong)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self._status.showMessage("Load cancelled: encryption key required")
            return
        key_bytes = dialog.key_bytes()
        if key_bytes is None:
            self._status.showMessage("Load cancelled: encryption key required")
            if dialog.is_hex():
                QMessageBox.warning(self, "MMKV decrypt error", "Not a valid hex string.")
            return

        parser = MMKVParser()
        try:
            result = parser.parse(node, vfs, password=key_bytes, aes256=dialog.is_aes256())
        except WrongPasswordError:
            self._open_encrypted_mmkv(node, vfs, was_wrong=True)
            return
        except Exception as exc:
            self._status.showMessage(f"MMKV decrypt error: {exc}")
            QMessageBox.warning(self, "MMKV decrypt error", str(exc))
            return

        result = self._enrich_with_format_info(parser, node, vfs, result)
        self._show_result(node, result, vfs)
        self._props_panel.update_properties(node, result.metadata, vfs)
        self._status.showMessage(f"{node.path}  [{parser.DISPLAY_NAME} — decrypted]")

    def _open_encrypted_pdf(self, node: VFSNode, vfs: VFS, was_wrong: bool = False) -> None:
        from crush.core.passwords import WrongPasswordError
        from crush.parsers.pdf_parser import PDFParser

        title = "Incorrect Password" if was_wrong else "PDF Password"
        prompt = (
            "Incorrect password. Please try again:"
            if was_wrong
            else "Enter the PDF's password:"
        )
        password, ok = QInputDialog.getText(self, title, prompt, QLineEdit.EchoMode.Password)
        if not ok or not password:
            self._status.showMessage("Load cancelled: password required")
            return

        parser = PDFParser()
        try:
            result = parser.parse(node, vfs, password=password)
        except WrongPasswordError:
            self._open_encrypted_pdf(node, vfs, was_wrong=True)
            return
        except Exception as exc:
            self._status.showMessage(f"PDF decrypt error: {exc}")
            QMessageBox.warning(self, "PDF decrypt error", str(exc))
            return

        result = self._enrich_with_format_info(parser, node, vfs, result)
        self._show_result(node, result, vfs)
        self._props_panel.update_properties(node, result.metadata, vfs)
        self._status.showMessage(f"{node.path}  [{parser.DISPLAY_NAME} — decrypted]")

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

    def _open_value_inspector(self) -> None:
        from crush.viewers.value_inspector import ValueInspector
        ValueInspector.inspect("", self)

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
            self._props_panel.update_properties(node, result.metadata, vfs)
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
            self._props_panel.update_properties(node, result.metadata, vfs)
            self._status.showMessage(f"Opened artifact: {name}  [{parser.DISPLAY_NAME}]")
        except Exception as exc:
            self._status.showMessage(f"Artifact parse error: {exc}")
            QMessageBox.warning(self, "Parse error", str(exc))

    def _open_table_as_tab(self, title: str, viewer_data: dict) -> None:
        """Open an already-resolved table (e.g. from the Realm Views tab) as
        a new top-level tab — same tab machinery as _open_bytes_as_artifact,
        just skipping the parse step since the data is already final."""
        from crush.core.vfs import BytesVFS
        from crush.parsers.base import ParseResult

        vfs = BytesVFS(b"", name=title)
        node = vfs.root()
        # __db_path (if the caller backed this table with a temp SQLite
        # file, e.g. the Realm Views tab does) has to sit at the top level
        # of `data`, alongside the table entry, not nested inside it --
        # TableViewer only ever reads data.get("__db_path").
        data: dict = {title: viewer_data}
        db_path = viewer_data.pop("__db_path", None)
        if db_path:
            data["__db_path"] = db_path
        result = ParseResult(
            viewer_type="table", data=data, viewer_hints={"show_db_tabs": False}
        )
        self._show_result(node, result, vfs)
        self._status.showMessage(f"Opened view: {title}")

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

    def _export_vfs_tree(self, node: VFSNode, vfs: VFS, dest: Path) -> None:
        """Recursively copy a VFS node's tree onto the real filesystem at *dest*."""
        if node.is_dir:
            dest.mkdir(parents=True, exist_ok=True)
            for child in node.children:
                self._export_vfs_tree(child, vfs, dest / child.name)
        else:
            with vfs.open(node) as src, open(dest, "wb") as out:
                out.write(src.read())

    def _materialize_directory_node_for_external(
        self, node: VFSNode, vfs: VFS
    ) -> tuple[Path, Path | None] | None:
        """Resolve a VFS node (file or directory) to a real filesystem path,
        extracting it to a temp dir first if needed.

        Sibling to _materialize_node_for_external, not a modification of it —
        that one has its own single-file-specific extraction path and other
        callers (Open External). This one is generic over files and
        directories via _export_vfs_tree, needed since AUL sources (a
        .logarchive bundle, or a diagnostics+uuidtext pair) are always
        directories, and archive/backup-backed VFSs can't expose those as a
        real filesystem path directly — and reused as-is for plain log files
        handed to peach, so callers don't need to branch on node.is_dir.

        Returns (source_path, cleanup_dir). cleanup_dir is None when the node
        already lives on a real DirectoryVFS (no extraction happened, nothing
        to clean up); otherwise it's the temp directory the caller should ask
        the external tool to delete once it's done with source_path.
        """
        try:
            if isinstance(vfs, DirectoryVFS) and Path(node.path).exists():
                return Path(node.path), None

            tmp_dir = Path(tempfile.mkdtemp(prefix="crush-open-"))
            source_path = tmp_dir / node.name
            self._export_vfs_tree(node, vfs, source_path)
            return source_path, tmp_dir
        except Exception as exc:
            if hasattr(self, "_logger"):
                self._logger.error("Materialize directory for external failed: %s", exc)
            return None

    def _resolve_peach_source(
        self, node: VFSNode, vfs: VFS
    ) -> tuple[Path, Path | None] | None:
        """Resolve a single VFS node to a real filesystem path for peach,
        plus an optional temp dir to ask peach to clean up. None on failure
        — callers decide how to surface that (single vs. batch report it
        differently).

        A raw full-FS acquisition's diagnostics/ folder is useless to peach
        on its own — peach needs uuidtext/ sitting right next to it (its own
        docs: "Selecting diagnostics alone, with no uuidtext anywhere nearby,
        fails fast"). uuidtext/ is a *sibling* of diagnostics/ in the VFS
        tree, not a descendant of the right-clicked node, so the generic
        materializer below can't see it on its own.

        Deliberately NOT reusing build_logarchive_from_acquisition() here —
        that flattens diagnostics/'s own children (Persist/Special/...) up a
        level and keeps uuidtext/ as its own folder alongside them, which is
        neither of the two layouts peach's docs say it recognizes ("the
        diagnostics folder itself, with uuidtext next to it as a sibling" or
        "their common parent folder") — it's built for crush's own bundled
        unifiedlog_iterator instead, a different consumer with different
        structural tolerances. Recreate the raw layout peach actually
        documents instead: diagnostics/ and uuidtext/ untouched, as direct
        children of one temp parent folder, and hand peach that parent.
        """
        from crush.parsers.unified_log_parser import (
            _find_uuidtext_sibling,
            is_ios_diagnostics_node,
        )

        if is_ios_diagnostics_node(node):
            try:
                tmp_dir = Path(tempfile.mkdtemp(prefix="crush-open-"))
                self._export_vfs_tree(node, vfs, tmp_dir / "diagnostics")
                uuidtext_node = _find_uuidtext_sibling(node, vfs)
                if uuidtext_node is not None:
                    self._export_vfs_tree(uuidtext_node, vfs, tmp_dir / "uuidtext")
                elif hasattr(self, "_logger"):
                    self._logger.warning(
                        "Send to Peach: no uuidtext sibling found for %s — "
                        "message strings will not resolve", node.path
                    )
                return tmp_dir, tmp_dir
            except Exception as exc:
                if hasattr(self, "_logger"):
                    self._logger.error(
                        "Send to Peach: materialize failed for %s: %s", node.path, exc
                    )
                return None

        return self._materialize_directory_node_for_external(node, vfs)

    def _send_to_peach(self, node: VFSNode, vfs: VFS) -> None:
        """Hand off a single log source to peach-forensics via a one-shot CLI spawn.

        Offered for AUL sources (a .logarchive bundle or a raw diagnostics
        folder) and, more broadly, any plain file — mirrors "Open in
        Multi-Log Studio"'s own long-standing lack of pre-filtering (any
        file, no extension/content check) rather than trying to guess
        whether a given file matches one of peach's own TOML text-log
        configs, which live in peach's per-user data dir and aren't visible
        to Crush at all. Peach's own manual sourcetype-confirm-before-Load
        step is the real gate, same as it always is.

        No IPC after launch — peach runs completely independently once
        started, matching its own design. Directory-backed sources already
        living on a real filesystem are passed straight through; archive/
        backup-backed sources are extracted to a temp dir first, with
        --cleanup-dir telling peach to remove it once peach closes.

        Extracted sources also get --ephemeral-session: a source that
        needed materializing from an archive/backup wasn't already sitting
        on disk in the clear, so peach must not leave a durable, unencrypted
        session copy of it behind once it closes. A source that was already
        a real filesystem path doesn't need this — it was already at rest,
        unencrypted, wherever it lives.
        """
        resolved = self._resolve_peach_source(node, vfs)
        if resolved is None:
            QMessageBox.warning(self, "Send to Peach", "Unable to materialize source for Peach.")
            return
        source_path, cleanup_dir = resolved

        from crush.core.peach_launcher import launch_peach

        override = self._settings.value("peach_binary_path", "", type=str)
        try:
            launch_peach(
                [source_path],
                cleanup_dirs=[cleanup_dir] if cleanup_dir else [],
                override_path=override,
                ephemeral_session=cleanup_dir is not None,
            )
            self._status.showMessage(f"Sent to Peach: {node.path}")
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            QMessageBox.warning(self, "Send to Peach", str(exc))

    def _send_to_peach_batch(self, items: list[tuple[VFSNode, VFS]]) -> None:
        """Hand off multiple log sources to peach in a single spawn (multiple
        --add-source flags), so they land in the same session for
        correlation — used for both a multi-selection in the tree and the
        recursive-folder discovery flow.

        Failures on individual items are collected and reported together at
        the end rather than one dialog per failure; sources that resolved
        fine are still sent even if others in the batch failed.
        """
        from crush.core.peach_launcher import launch_peach

        sources: list[Path] = []
        cleanup_dirs: list[Path] = []
        failed: list[str] = []

        for node, vfs in items:
            resolved = self._resolve_peach_source(node, vfs)
            if resolved is None:
                failed.append(node.path)
                continue
            source_path, cleanup_dir = resolved
            sources.append(source_path)
            if cleanup_dir is not None:
                cleanup_dirs.append(cleanup_dir)

        if not sources:
            QMessageBox.warning(
                self, "Send to Peach",
                "Unable to materialize any of the selected sources for Peach.",
            )
            return

        override = self._settings.value("peach_binary_path", "", type=str)
        try:
            launch_peach(
                sources,
                cleanup_dirs=cleanup_dirs,
                override_path=override,
                ephemeral_session=bool(cleanup_dirs),
            )
            msg = f"Sent {len(sources)} source(s) to Peach"
            if failed:
                msg += f"  ({len(failed)} skipped)"
            self._status.showMessage(msg)
            if failed:
                QMessageBox.warning(
                    self, "Send to Peach",
                    "Some sources could not be materialized and were skipped:\n"
                    + "\n".join(failed),
                )
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            QMessageBox.warning(self, "Send to Peach", str(exc))

    def _set_log_temp_dir(self) -> None:
        current = self._settings.value("log_temp_dir", "", type=str)
        text, ok = QInputDialog.getText(
            self,
            "Log Temp Directory",
            "Directory to use for intermediate files during log conversion "
            "(e.g. Apple Unified Log .tracev3 / .logarchive processing) — "
            "leave blank to use the OS default temp location:",
            QLineEdit.EchoMode.Normal,
            current,
        )
        if ok:
            self._settings.setValue("log_temp_dir", text.strip())

    def _set_peach_binary_path(self) -> None:
        current = self._settings.value("peach_binary_path", "", type=str)
        text, ok = QInputDialog.getText(
            self,
            "Peach Binary Path",
            "Path to a peach-forensics executable to use instead of the "
            "version bundled with Crush (leave blank to use the bundled one):",
            QLineEdit.EchoMode.Normal,
            current,
        )
        if ok:
            self._settings.setValue("peach_binary_path", text.strip())

    def _open_peach_standalone(self) -> None:
        """Launch peach with no source pre-filled — same binary/override
        resolution as Send to Peach, just without a file to hand off."""
        from crush.core.peach_launcher import launch_peach

        override = self._settings.value("peach_binary_path", "", type=str)
        try:
            launch_peach([], override_path=override)
            self._status.showMessage("Opened Peach")
        except (FileNotFoundError, RuntimeError) as exc:
            QMessageBox.warning(self, "Open Peach", str(exc))

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
        self._props_panel.update_properties(node, metadata, vfs)

    def _wrap_with_encryption_banner(self, view: QWidget, hint: str) -> QWidget:
        """Prepend a prominent banner above *view* -- used when a parser's
        metadata carries "Possibly Encrypted" (see pdf_parser.py /
        realm_parser.py). The Properties panel already lists this metadata
        too, but that's easy to miss; this puts it directly in the tab
        content, impossible to miss, without popping up an interrupting
        dialog on every double-click of an encrypted file."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        banner = QLabel(f"\U0001F512 This file appears to be encrypted. {hint}")
        banner.setWordWrap(True)
        banner.setStyleSheet(
            "color: white; background-color: #c87000; font-weight: bold;"
            " padding: 6px 10px;"
        )
        layout.addWidget(banner)
        layout.addWidget(view)
        return container

    def _show_result(self, node: VFSNode, result: ParseResult, vfs: VFS) -> None:
        from crush.ui.viewer_factory import make_viewer
        base_view = make_viewer(result, node, vfs, self)
        if hasattr(base_view, "open_bytes_requested"):
            base_view.open_bytes_requested.connect(self._open_bytes_as_artifact)
        if hasattr(base_view, "open_table_requested"):
            base_view.open_table_requested.connect(self._open_table_as_tab)
        possibly_encrypted = result.metadata.get("Possibly Encrypted")
        if possibly_encrypted:
            base_view = self._wrap_with_encryption_banner(base_view, possibly_encrypted)
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
        self._props_panel.clear()

    def _close_all_tabs(self) -> None:
        self._viewer_tabs.clear()
        self._props_panel.clear()

    def _close_other_tabs(self, keep_index: int) -> None:
        keep_widget = self._viewer_tabs.widget(keep_index)
        for i in range(self._viewer_tabs.count() - 1, -1, -1):
            if self._viewer_tabs.widget(i) is not keep_widget:
                self._viewer_tabs.removeTab(i)
        self._props_panel.clear()

    def _show_tab_context_menu(self, pos: object) -> None:
        tab_bar = self._viewer_tabs.tabBar()
        index = tab_bar.tabAt(pos)  # type: ignore[arg-type]
        if index < 0:
            return
        menu = QMenu(self)
        close_action = menu.addAction("Close")
        close_others_action = menu.addAction("Close Others")
        close_others_action.setEnabled(self._viewer_tabs.count() > 1)
        close_all_action = menu.addAction("Close All")
        action = menu.exec(tab_bar.mapToGlobal(pos))  # type: ignore[arg-type]
        if action == close_action:
            self._close_tab(index)
        elif action == close_others_action:
            self._close_other_tabs(index)
        elif action == close_all_action:
            self._close_all_tabs()

    def _populate_tab_list_menu(self) -> None:
        self._tab_list_menu.clear()
        metrics = QFontMetrics(self._tab_list_menu.font())
        current = self._viewer_tabs.currentIndex()
        for i in range(self._viewer_tabs.count()):
            full_label = self._viewer_tabs.tabText(i)
            elided = metrics.elidedText(full_label, Qt.TextElideMode.ElideMiddle, 500)
            menu_action = self._tab_list_menu.addAction(elided)
            menu_action.setToolTip(self._viewer_tabs.tabToolTip(i))
            menu_action.setData(i)
            menu_action.setCheckable(True)
            menu_action.setChecked(i == current)

    def _on_tab_list_menu_triggered(self, action: QAction) -> None:
        index = action.data()
        if isinstance(index, int) and 0 <= index < self._viewer_tabs.count():
            self._viewer_tabs.setCurrentIndex(index)

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
        self._props_panel.clear()
        self._fs_panel.close_vfs(vfs)
        self.session.remove_source(vfs)
        self._update_window_title()
        name = vfs.root().name
        self._status.showMessage(f"Closed source: {name} ({closed_tabs} tabs closed)")
        if not self.session.sources:
            self._show_empty_view()

    def _show_empty_view(self) -> None:
        self._rebuild_welcome_recent()
        self._central_stack.setCurrentWidget(self._empty_view)

    def _rebuild_welcome_recent(self) -> None:
        while self._recent_on_welcome.count():
            item = self._recent_on_welcome.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        recent: list[str] = self._settings.value("recent_files", [], type=list)
        if not recent:
            return
        header = QLabel("Recently opened: ")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._recent_on_welcome.addWidget(header)
        container = QWidget()
        container.setFixedWidth(480)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(4)
        for path in recent[:10]:
            btn = _RecentFileButton(path)
            btn.opened.connect(self._load_source)
            container_layout.addWidget(btn)
        self._recent_on_welcome.addWidget(container, alignment=Qt.AlignmentFlag.AlignHCenter)

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
                self._props_panel.update_properties(node, meta, vfs)
                self._props_dock.show()
                self._props_dock.raise_()
        except Exception as exc:
            self._status.showMessage(f"Format info error: {exc}")

    def _show_format_reference(self) -> None:
        from crush.ui.format_reference import FormatReferenceDialog
        FormatReferenceDialog(self).show()

    def _about(self) -> None:
        from crush.ui.about_dialog import AboutDialog
        AboutDialog(self).exec()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() and any(
            url.isLocalFile() for url in event.mimeData().urls()
        ):
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        # Same load path as "Open file"/"Open folder" (_load_source), so a
        # dropped item follows the exact same append-vs-replace rule already
        # in _on_load_finished: a single flat file appends to the current
        # tree, a folder or archive (anything whose VFS root is a directory)
        # replaces it — nothing drag & drop specific to decide here.
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if not paths:
            return
        event.acceptProposedAction()
        for path in paths:
            self._load_source(path, open_after_load=True, append_to_tree=True)

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
            path, open_after_load, append_to_tree, itunes_zip_prefix, password = self._load_queue.pop(0)
            self._load_source(
                path,
                open_after_load=open_after_load,
                append_to_tree=append_to_tree,
                itunes_zip_prefix=itunes_zip_prefix,
                password=password,
            )

    def _on_password_required(self, was_wrong: bool) -> None:
        if hasattr(self, "_progress"):
            self._progress.close()

        title = "Incorrect Password" if was_wrong else "Password Required"
        prompt = (
            "Incorrect password. Please try again:"
            if was_wrong
            else "This backup is password-protected. Enter the backup password:"
        )
        password, ok = QInputDialog.getText(self, title, prompt, QLineEdit.EchoMode.Password)
        if not ok or not password:
            self._status.showMessage("Load cancelled: password required")
            return

        self._load_source(
            self._loading_path,
            open_after_load=self._open_after_load,
            append_to_tree=self._append_to_tree,
            itunes_zip_prefix=getattr(self, "_loading_itunes_zip_prefix", None),
            password=password,
        )

    def _maybe_confirm_itunes_backup_zip(self, path: str) -> str | None:
        from crush.core.vfs import detect_itunes_backup_in_zip

        try:
            prefix = detect_itunes_backup_in_zip(path)
        except Exception:
            return None
        if prefix is None:
            return None

        answer = QMessageBox.question(
            self,
            "iTunes Backup Detected",
            "An iTunes backup structure was detected inside this ZIP file.\n\n"
            "Open it as an iTunes backup (reconstructed filesystem tree)?\n"
            "Choosing \"No\" opens the file as a regular ZIP archive instead.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return prefix if answer == QMessageBox.StandardButton.Yes else None

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

    @staticmethod
    def _checkbox_qss(pal: QPalette) -> str:
        """QSS override for QCheckBox/QRadioButton indicators.

        The Fusion style's built-in indicator painting shades its border
        from palette roles (Light/Midlight/Mid/Dark/Shadow) that every
        _*_palette() method below leaves mostly unset -- measured directly
        (render to an offscreen QPixmap, sample the indicator's border vs.
        fill pixels): border-vs-fill contrast comes out just ~60/255 in the
        Light theme and ~1-8/255 in Dark/Geek, i.e. the checkbox border is
        essentially invisible against its own interior in every theme, not
        just one. Styling the indicator subcontrol directly, from the same
        palette already tuned per theme, guarantees a clearly bordered box
        (unchecked) vs. a solid Highlight-filled box (checked) regardless
        of theme -- a deliberate trade of the native tick-mark glyph (which
        QSS on this subcontract would otherwise suppress anyway without a
        bundled checkmark image asset) for guaranteed contrast everywhere.
        """
        border = pal.color(QPalette.ColorRole.WindowText).name()
        base = pal.color(QPalette.ColorRole.Base).name()
        highlight = pal.color(QPalette.ColorRole.Highlight).name()
        disabled_border = pal.color(QPalette.ColorRole.Mid).name()
        disabled_bg = pal.color(QPalette.ColorRole.Window).name()
        return f"""
            QCheckBox::indicator, QRadioButton::indicator {{
                width: 13px;
                height: 13px;
                border: 1px solid {border};
                background: {base};
            }}
            QCheckBox::indicator {{ border-radius: 2px; }}
            QRadioButton::indicator {{ border-radius: 7px; }}
            QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
                background: {highlight};
                border: 1px solid {highlight};
            }}
            QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
                border: 1px solid {highlight};
            }}
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{
                border: 1px solid {disabled_border};
                background: {disabled_bg};
            }}
        """

    def _set_palette_everywhere(self, pal: QPalette) -> None:
        """Apply *pal* app-wide and directly to the dock widgets, filesystem
        tree, and properties panel (and their viewports) of every open
        window.

        QApplication.setPalette() alone doesn't reliably reach these once
        any app-wide stylesheet has been active, so they're updated
        explicitly instead of relying on propagation.
        """
        app = QApplication.instance()
        if app is None:
            return
        app.setPalette(pal)
        for window in self._open_windows:
            if not isValid(window):
                continue
            if hasattr(window, "_fs_dock"):
                window._fs_dock.setPalette(pal)
            if hasattr(window, "_props_dock"):
                window._props_dock.setPalette(pal)
            if hasattr(window, "_log_dock"):
                window._log_dock.setPalette(pal)
            if hasattr(window, "_fs_panel"):
                fs_panel = window._fs_panel
                fs_panel._tree.setPalette(pal)
                fs_panel._tree.viewport().setPalette(pal)
                fs_panel._search_view.setPalette(pal)
                fs_panel._search_view.viewport().setPalette(pal)
            if hasattr(window, "_props_panel"):
                props_panel = window._props_panel
                props_panel.setPalette(pal)
                props_panel.viewport().setPalette(pal)
                props_panel._container.setPalette(pal)
            if hasattr(window, "_viewer_tabs"):
                viewer_tabs = window._viewer_tabs
                viewer_tabs.setPalette(pal)
                viewer_tabs.tabBar().setPalette(pal)
                # Individual viewer widgets (hex/text/table/image/... — see
                # crush/viewers/) frequently set their own explicit palette
                # or stylesheet at creation time; once a widget has an
                # explicit (non-inherited) palette, QWidget.setPalette() on
                # an ancestor no longer cascades down to it. Only walking
                # the *currently visible* tab keeps this affordable at
                # animation frequency (every 50ms) -- other tabs catch up
                # via _on_viewer_tab_changed() when they're actually shown.
                current = viewer_tabs.currentWidget()
                if current is not None:
                    self._propagate_palette_recursive(current, pal)
            if hasattr(window, "_empty_view"):
                window._empty_view.setPalette(pal)

    @staticmethod
    def _propagate_palette_recursive(widget: QWidget, pal: QPalette) -> None:
        """Force *pal* onto *widget* and every descendant (plus scroll-area
        viewports), overriding any explicit palette/stylesheet a viewer set
        on itself when it was created under a different theme.
        """
        widget.setPalette(pal)
        viewport = getattr(widget, "viewport", None)
        if callable(viewport):
            vp = viewport()
            if vp is not None:
                vp.setPalette(pal)
        for child in widget.findChildren(QWidget):
            child.setPalette(pal)
            child_viewport = getattr(child, "viewport", None)
            if callable(child_viewport):
                vp = child_viewport()
                if vp is not None:
                    vp.setPalette(pal)

    def _on_viewer_tab_changed(self, index: int) -> None:
        """Re-apply the live app palette to a viewer tab when it becomes
        visible, catching it up if it wasn't the current tab during a
        Rainbow/'Merica tick (see _set_palette_everywhere)."""
        if index < 0:
            return
        widget = self._viewer_tabs.widget(index)
        if widget is None:
            return
        app = QApplication.instance()
        if app is None:
            return
        self._propagate_palette_recursive(widget, app.palette())

    def _apply_palette(self, pal: QPalette) -> None:
        """Set the application palette and a matching checkbox/radio-button
        stylesheet (see _checkbox_qss) -- the two must change together or a
        theme switch leaves stale indicator colors.

        Only used by the static themes. Rainbow and 'Merica update the
        palette directly via _set_palette_everywhere() and never touch the
        stylesheet, since re-applying an app-wide stylesheet at animation
        frequency (up to every 50ms) causes flicker and swallows clicks.

        Clears any existing stylesheet before reapplying it, rather than
        just replacing its content in place: once QStyleSheetStyle has
        polished a widget against a stylesheet, later setPalette() calls on
        that widget (including the explicit ones in
        _set_palette_everywhere()) stop taking effect until the stylesheet
        is actually removed and reapplied -- confirmed by probing
        QTreeView.palette() after a setStyleSheet() -> setPalette() ->
        setStyleSheet() sequence, which still reports the *first*
        stylesheet's colors. Without the clear, switching between two
        static themes leaves the filesystem tree and properties panel
        stuck on whichever theme was active when a stylesheet was first
        applied; only entering Rainbow/'Merica (which clears the
        stylesheet via _clear_checkbox_qss()) breaks the staleness.

        Skips the stylesheet update while a popup or modal dialog is open:
        QApplication-wide setStyleSheet() forces a full re-polish of every
        top-level widget, which splits an in-flight mouse press/release on
        a dialog button into two unrelated events. The palette itself still
        updates; the checkbox QSS catches up on the next static-theme switch.
        """
        app = QApplication.instance()
        if app is None:
            return
        if app.activePopupWidget() is None and app.activeModalWidget() is None:
            app.setStyleSheet("")
        self._set_palette_everywhere(pal)
        if app.activePopupWidget() is None and app.activeModalWidget() is None:
            app.setStyleSheet(self._checkbox_qss(pal))

    @staticmethod
    def _clear_checkbox_qss() -> None:
        """Drop any checkbox stylesheet left over from a static theme.

        Called once when entering Rainbow or 'Merica, since they never set
        a stylesheet themselves (see _apply_palette).
        """
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet("")

    def _set_theme_system(self) -> None:
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self.style().standardPalette())
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

    def _stop_animated_themes(self) -> None:
        for window in self._open_windows:
            if not isValid(window):
                continue
            if hasattr(window, "_rainbow_timer"):
                window._rainbow_timer.stop()
            if hasattr(window, "_america_timer"):
                window._america_timer.stop()
            if hasattr(window, "_rainbow_snapshot_btn"):
                window._rainbow_snapshot_btn.setVisible(False)
            if hasattr(window, "_america_show_btn"):
                window._america_show_btn.setVisible(False)

    def _set_theme_light(self) -> None:
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self._light_palette())
        self._settings.setValue("theme", "light")
        self._logger.info("Theme set to light")

    def _set_theme_dark(self) -> None:
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self._dark_palette())
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
        elif theme == "america":
            self._set_theme_america()
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
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self._geek_palette())
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
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self._purple_palette())
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
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._apply_palette(self._ocean_palette())
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
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._settings.setValue("theme", "rainbow")
        self._logger.info("Theme set to rainbow")
        self._clear_checkbox_qss()
        if not hasattr(self, "_rainbow_timer"):
            self._rainbow_timer = QTimer(self)
            self._rainbow_timer.timeout.connect(self._step_rainbow)
            self._rainbow_hue = 0.0
        self._rainbow_timer.start(50)
        self._rainbow_snapshot_btn.setVisible(True)

    def _step_rainbow(self) -> None:
        self._rainbow_hue = (self._rainbow_hue + 0.004) % 1.0
        self._set_palette_everywhere(self._rainbow_palette(self._rainbow_hue))

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

    def _set_theme_america(self) -> None:
        self._stop_animated_themes()
        app = QApplication.instance()
        if app is None:
            return
        self._settings.setValue("theme", "america")
        self._logger.info("Theme set to 'Merica")
        if not hasattr(self, "_america_timer"):
            self._america_timer = QTimer(self)
            self._america_timer.timeout.connect(self._step_america)
        self._start_america_show()

    def _replay_america_show(self) -> None:
        self._start_america_show()

    def _start_america_show(self) -> None:
        self._clear_checkbox_qss()
        self._america_intro_step = 0
        self._america_chill_elapsed_ms = 0
        self._america_timer.setInterval(self._AMERICA_INTRO_MS)
        self._america_show_btn.setVisible(True)
        self._step_america()
        self._america_timer.start()

    def _step_america(self) -> None:
        chant = (
            ("U", QColor(178, 34, 52), "white"),
            ("S", QColor(245, 245, 240), "#172554"),
            ("A", QColor(35, 71, 143), "white"),
        )
        if self._america_intro_step < 9:
            letter, color, text_color = chant[self._america_intro_step % len(chant)]
            self._set_palette_everywhere(self._america_show_palette(letter))
            self._america_show_btn.setText(f" ★ ★ ★   {letter}   ★ ★ ★ ")
            self._america_show_btn.setStyleSheet(
                f"color: {text_color}; background-color: {color.name()};"
                " font-weight: bold; padding: 2px 8px; border-radius: 3px;"
            )
            self._america_intro_step += 1
            return

        if self._america_intro_step == 9:
            self._america_show_btn.setText(" ★  'MERICA  ★ ")
            self._america_show_btn.setStyleSheet(
                "color: white; background-color: #233f88;"
                " font-weight: bold; padding: 2px 8px; border-radius: 3px;"
            )
            self._america_intro_step += 1
            self._america_timer.setInterval(self._AMERICA_FINALE_MS)
            self._set_palette_everywhere(self._america_palette(0.0))
            return
        elif self._america_intro_step == 10:
            self._america_show_btn.setText(" ★  Replay Show  ★ ")
            self._america_show_btn.setStyleSheet(
                "color: white; background-color: #233f88;"
                " font-weight: bold; padding: 2px 8px; border-radius: 3px;"
            )
            self._america_intro_step += 1
            self._america_timer.setInterval(self._AMERICA_CHILL_TICK_MS)

        self._america_chill_elapsed_ms += self._america_timer.interval()
        phase = self._america_chill_phase(self._america_chill_elapsed_ms)
        self._set_palette_everywhere(self._america_palette(phase))

    @classmethod
    def _america_chill_phase(cls, elapsed_ms: int) -> float:
        segment_ms = cls._AMERICA_HOLD_MS + cls._AMERICA_FADE_MS
        color_index = (elapsed_ms // segment_ms) % 3
        segment_elapsed = elapsed_ms % segment_ms
        if segment_elapsed < cls._AMERICA_HOLD_MS:
            return float(color_index)
        fade_progress = (
            segment_elapsed - cls._AMERICA_HOLD_MS
        ) / cls._AMERICA_FADE_MS
        return color_index + fade_progress

    def _america_show_palette(self, letter: str) -> QPalette:
        if letter == "U":
            pal = self._america_palette(0.0)
            pal.setColor(QPalette.ColorRole.Window, QColor(72, 8, 20))
            pal.setColor(QPalette.ColorRole.Button, QColor(92, 12, 28))
            return pal
        if letter == "S":
            pal = self._light_palette()
            pal.setColor(QPalette.ColorRole.Highlight, QColor(178, 34, 52))
            pal.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.BrightText, QColor(35, 71, 143))
            return pal
        pal = self._america_palette(2.0)
        pal.setColor(QPalette.ColorRole.Window, QColor(8, 22, 62))
        pal.setColor(QPalette.ColorRole.Button, QColor(12, 32, 82))
        return pal

    def _america_palette(self, phase: float) -> QPalette:
        colors = (
            QColor(224, 55, 70),
            QColor(245, 245, 240),
            QColor(72, 112, 210),
        )
        index = int(phase) % len(colors)
        progress = phase - int(phase)
        accent = self._blend_color(colors[index], colors[(index + 1) % len(colors)], progress)
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(16, 22, 42))
        pal.setColor(QPalette.ColorRole.WindowText, accent)
        pal.setColor(QPalette.ColorRole.Base, QColor(9, 13, 28))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(21, 28, 52))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(245, 245, 240))
        pal.setColor(QPalette.ColorRole.ToolTipText, QColor(16, 22, 42))
        pal.setColor(QPalette.ColorRole.Text, accent)
        pal.setColor(QPalette.ColorRole.Button, QColor(25, 34, 64))
        pal.setColor(QPalette.ColorRole.ButtonText, accent)
        if hasattr(QPalette.ColorRole, "Menu"):
            pal.setColor(QPalette.ColorRole.Menu, QColor(16, 22, 42))
        if hasattr(QPalette.ColorRole, "MenuText"):
            pal.setColor(QPalette.ColorRole.MenuText, accent)
        if hasattr(QPalette.ColorRole, "MenuBar"):
            pal.setColor(QPalette.ColorRole.MenuBar, QColor(16, 22, 42))
        if hasattr(QPalette.ColorRole, "MenuBarText"):
            pal.setColor(QPalette.ColorRole.MenuBarText, accent)
        pal.setColor(QPalette.ColorRole.Mid, QColor(130, 138, 160))
        pal.setColor(QPalette.ColorRole.Dark, QColor(7, 10, 22))
        pal.setColor(QPalette.ColorRole.Shadow, QColor(3, 5, 12))
        pal.setColor(QPalette.ColorRole.BrightText, QColor(224, 55, 70))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(72, 112, 210))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor(245, 245, 240))
        return pal

    @staticmethod
    def _blend_color(start: QColor, end: QColor, progress: float) -> QColor:
        progress = max(0.0, min(1.0, progress))
        return QColor(
            round(start.red() + (end.red() - start.red()) * progress),
            round(start.green() + (end.green() - start.green()) * progress),
            round(start.blue() + (end.blue() - start.blue()) * progress),
        )

    def _snapshot_rainbow(self) -> None:
        self._stop_animated_themes()
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
                self._apply_palette(self._rainbow_palette(hue))
            self._settings.setValue("theme", "custom")
            self._logger.info("Custom theme '%s' saved (hue=%.3f)", name, hue)
        else:
            self._rainbow_timer.start(50)
            self._rainbow_snapshot_btn.setVisible(True)

    def _set_theme_custom(self) -> None:
        self._stop_animated_themes()
        hue = self._settings.value("custom_theme_hue", 0.0, type=float)
        app = QApplication.instance()
        if app:
            self._apply_palette(self._rainbow_palette(hue))
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
