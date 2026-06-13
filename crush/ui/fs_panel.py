# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Filesystem panel — left dock, shows the VFS tree."""
from __future__ import annotations

import concurrent.futures
from collections import deque
import logging
import os
import threading
import time

from PySide6.QtCore import QModelIndex, QSettings, QStringListModel, Qt, Signal, QSortFilterProxyModel, QTimer
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCompleter,
    QLineEdit,
    QMenu,
    QStackedWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
)


from crush.core.session import Session
from crush.core.vfs import VFS, VFSNode, DirectoryVFS
from crush.core.magic import detect_fast_label

_IMAGE_TYPE_LABELS: frozenset[str] = frozenset({
    "image", "heic", "heif", "avif", "jxl",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif",
})
_MEDIA_TYPE_LABELS: frozenset[str] = frozenset({
    "media", "mp4", "mov", "avi", "mkv", "mp3", "m4a", "aac", "wav", "flac",
    "ogg", "opus",
})


def _type_matches(type_filter: str, type_label: str) -> bool:
    label_lower = type_label.lower()
    if type_filter == "image":
        return label_lower in _IMAGE_TYPE_LABELS
    if type_filter == "media":
        return label_lower in _MEDIA_TYPE_LABELS
    return type_filter in label_lower

_ROLE_NODE = Qt.ItemDataRole.UserRole + 1
_ROLE_VFS  = Qt.ItemDataRole.UserRole + 2
_ROLE_LOADED = Qt.ItemDataRole.UserRole + 3
_ROLE_PLACEHOLDER = Qt.ItemDataRole.UserRole + 4
_ROLE_PATH = Qt.ItemDataRole.UserRole + 5
_ROLE_SORT = Qt.ItemDataRole.UserRole + 6

_SIZE_UNITS: list[str] = ["B", "KB", "MB", "GB", "TB", "PB"]
_logger = logging.getLogger(__name__)


def _format_size(size: int) -> str:
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(_SIZE_UNITS) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {_SIZE_UNITS[unit_index]}"
    return f"{value:.1f} {_SIZE_UNITS[unit_index]}"


class _FilterLineEdit(QLineEdit):
    """QLineEdit that shows the completer dropdown on click/focus."""

    def mousePressEvent(self, event):  # noqa: N802
        super().mousePressEvent(event)
        if self.completer():
            self.completer().complete()


class FilesystemPanel(QWidget):
    """Left-dock panel that displays the VFS as a tree."""

    node_activated = Signal(object, object)  # (VFSNode, VFS)
    node_selected = Signal(object, object)  # (VFSNode, VFS)
    open_requested = Signal(object, object, str)  # (VFSNode, VFS, mode)
    open_external_requested = Signal(object, object, str)  # (VFSNode, VFS, mode)
    export_requested = Signal(object, object)  # (VFSNode, VFS)
    export_multi_requested = Signal(object, str)  # (list[(VFSNode, VFS, str)], filter_text)
    export_logarchive_requested = Signal(object, object)  # (VFSNode, VFS)
    format_info_requested = Signal(object, object)  # (VFSNode, VFS)
    close_source_requested = Signal(object)  # (VFS)
    open_in_new_window_requested = Signal(str)  # (path)
    load_finished = Signal()
    background_status = Signal(str)
    _search_results_ready = Signal(object)  # internal: list of result dicts
    _prescan_activity = Signal(str, bool)   # internal: (activity_name, is_start)

    def __init__(self, session: Session, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._session = session
        self._vfs_list: list[VFS] = []
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Name", "Size", "Files", "Total Size", "Type"])
        self._proxy = _VfsFilterProxy(self)
        self._proxy.setSourceModel(self._model)
        self._search_model = QStandardItemModel()
        self._search_model.setHorizontalHeaderLabels(["Name", "Path", "Size", "Type"])
        self._search_model.setSortRole(_ROLE_SORT)
        self._navigate_after_filter: tuple[VFSNode, VFS] | None = None
        self._search_gen: int = 0
        self._prescan_gen: int = 0
        self._search_results_ready.connect(self._on_search_results_ready)
        self._prescan_activity.connect(self._on_prescan_activity)
        self._type_cache: dict[tuple[int, str], str] = {}
        self._prescan_workers: int = min(8, os.cpu_count() or 4)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(150)
        self._filter_timer.timeout.connect(self._apply_filter_now)
        self._pending_filter = ""
        self._build_timer = QTimer(self)
        self._build_timer.setInterval(0)
        self._build_timer.timeout.connect(self._process_build_queue)
        self._build_queue: deque[tuple[QStandardItem, VFSNode, VFS]] = deque()
        self._build_batch = 200
        self._type_queue: deque[tuple[QStandardItem, VFSNode, VFS]] = deque()
        self._type_timer = QTimer(self)
        self._type_timer.setInterval(0)
        self._type_timer.timeout.connect(self._process_type_queue)
        self._activities: set[str] = set()
        self.background_status.emit("")
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._filter = _FilterLineEdit()
        self._filter.setPlaceholderText("Filter… (name:x  type:x)")
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._on_filter_text_changed)
        self._filter.returnPressed.connect(self._on_filter_return)
        self._filter_history_settings = QSettings("Crush DFIR", "Crush")
        self._filter_history_model = QStringListModel(
            self._filter_history_settings.value("filter_history", [], type=list)
        )
        _completer = QCompleter(self._filter_history_model, self._filter)
        _completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        _completer.setFilterMode(Qt.MatchFlag.MatchContains)
        _completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        _completer.activated.connect(self._on_filter_return)
        self._filter.setCompleter(_completer)
        layout.addWidget(self._filter)

        self._stack = QStackedWidget()

        # Page 0: normal tree view
        self._tree = QTreeView()
        self._tree.setModel(self._proxy)
        self._tree.setAnimated(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSortingEnabled(False)
        self._tree.setColumnWidth(0, 160)
        self._tree.setColumnWidth(1, 65)
        self._tree.setColumnWidth(2, 60)
        self._tree.setColumnWidth(3, 90)
        self._tree.doubleClicked.connect(self._on_double_click)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)
        self._tree.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._tree.expanded.connect(self._on_expanded)
        self._stack.addWidget(self._tree)

        # Page 1: flat search results view
        self._search_view = QTreeView()
        self._search_view.setModel(self._search_model)
        self._search_view.setRootIsDecorated(False)
        self._search_view.setUniformRowHeights(True)
        self._search_view.setAlternatingRowColors(True)
        self._search_view.setSortingEnabled(True)
        self._search_view.setColumnWidth(0, 160)
        self._search_view.setColumnWidth(1, 200)
        self._search_view.setColumnWidth(2, 65)
        self._search_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._search_view.doubleClicked.connect(self._on_search_double_click)
        self._search_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._search_view.customContextMenuRequested.connect(self._on_search_context_menu)
        self._search_view.selectionModel().selectionChanged.connect(self._on_search_selection_changed)
        self._stack.addWidget(self._search_view)

        layout.addWidget(self._stack)

    def load_vfs(self, vfs: VFS) -> None:
        """Replace the tree with a new VFS source."""
        _logger.debug("FilesystemPanel.load_vfs: start")
        self._vfs_list = [vfs]
        self._vfs = vfs
        self._build_timer.stop()
        self._build_queue.clear()
        self._type_timer.stop()
        self._type_queue.clear()
        self._type_cache.clear()
        self._activities.clear()
        self.background_status.emit("")
        self._prescan_gen += 1

        # Recreate model to avoid slow row-by-row clears on large trees.
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Name", "Size", "Files", "Total Size", "Type"])
        self._proxy.setSourceModel(self._model)

        root_node = vfs.root()
        row = self._node_to_row_shallow(root_node, vfs)
        self._model.appendRow(row)
        self._tree.expand(self._proxy.mapFromSource(self._model.indexFromItem(row[0])))
        if root_node.children:
            self._add_placeholder(row[0])
        self._start_prescan([vfs], self._prescan_gen)
        self.load_finished.emit()
        _logger.debug("FilesystemPanel.load_vfs: emitted load_finished")

    def append_vfs(self, vfs: VFS) -> None:
        """Append a new VFS source to the existing tree."""
        _logger.debug("FilesystemPanel.append_vfs: start")
        self._vfs_list.append(vfs)
        self._vfs = vfs
        root_node = vfs.root()
        row = self._node_to_row_shallow(root_node, vfs)
        self._model.appendRow(row)
        self._proxy.invalidateFilter()
        self._tree.expand(self._proxy.mapFromSource(self._model.indexFromItem(row[0])))
        if root_node.children:
            self._add_placeholder(row[0])
        self._prescan_gen += 1
        self._start_prescan([vfs], self._prescan_gen)
        self.load_finished.emit()
        _logger.debug("FilesystemPanel.append_vfs: emitted load_finished")

    def close_vfs(self, vfs: VFS) -> None:
        """Remove a VFS source from the tree."""
        if vfs not in self._vfs_list:
            return
        _logger.debug("FilesystemPanel.close_vfs: start")
        self._vfs_list = [item for item in self._vfs_list if item is not vfs]
        self._vfs = self._vfs_list[-1] if self._vfs_list else None
        self._build_timer.stop()
        self._build_queue.clear()
        self._type_timer.stop()
        self._type_queue.clear()
        self._type_cache.clear()
        self._activities.clear()
        self.background_status.emit("")
        self._prescan_gen += 1

        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Name", "Size", "Files", "Total Size", "Type"])
        self._proxy.setSourceModel(self._model)

        for source in self._vfs_list:
            root_node = source.root()
            row = self._node_to_row_shallow(root_node, source)
            self._model.appendRow(row)
            self._tree.expand(self._proxy.mapFromSource(self._model.indexFromItem(row[0])))
            if root_node.children:
                self._add_placeholder(row[0])

        self._search_gen += 1
        self._search_model.setRowCount(0)
        self._filter.clear()

        if self._vfs_list:
            self._start_prescan(list(self._vfs_list), self._prescan_gen)
        _logger.debug("FilesystemPanel.close_vfs: done")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _node_to_row_shallow(self, node: VFSNode, vfs: VFS) -> list[QStandardItem]:
        name_item = QStandardItem(node.name)
        name_item.setData(node, _ROLE_NODE)
        name_item.setData(vfs, _ROLE_VFS)
        name_item.setData(False, _ROLE_LOADED)
        name_item.setEditable(False)

        size_item = QStandardItem(_format_size(node.size) if not node.is_dir else "")
        size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        size_item.setEditable(False)

        files_item = QStandardItem(
            f"{vfs.file_count(node):,}" if node.is_dir else ""
        )
        files_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        files_item.setEditable(False)

        total_item = QStandardItem(
            _format_size(vfs.total_size(node)) if node.is_dir else _format_size(node.size)
        )
        total_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        total_item.setEditable(False)

        type_item = QStandardItem("DIR" if node.is_dir else "")
        type_item.setEditable(False)

        if node.is_dir and node.children:
            self._add_placeholder(name_item)
        if not node.is_dir:
            self._type_queue.append((type_item, node, vfs))
            if not self._type_timer.isActive():
                self._activity_start("Type detection")
                self._type_timer.start()

        return [name_item, size_item, files_item, total_item, type_item]

    def _on_double_click(self, index: QModelIndex) -> None:
        proxy_index = index.siblingAtColumn(0)
        source_index = self._proxy.mapToSource(proxy_index)
        item = self._model.itemFromIndex(source_index)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs and not node.is_dir:
            self.node_activated.emit(node, vfs)

    def _on_selection_changed(self, *_: object) -> None:
        selection = self._tree.selectionModel().selectedIndexes()
        if not selection:
            return
        index = next((i for i in selection if i.column() == 0), selection[0])
        proxy_index = index.siblingAtColumn(0)
        source_index = self._proxy.mapToSource(proxy_index)
        item = self._model.itemFromIndex(source_index)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs:
            self.node_selected.emit(node, vfs)

    def _on_expanded(self, index: QModelIndex) -> None:
        proxy_index = index.siblingAtColumn(0)
        source_index = self._proxy.mapToSource(proxy_index)
        item = self._model.itemFromIndex(source_index)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs:
            self._ensure_children_loaded(item, node, vfs)

    def _on_context_menu(self, pos: object) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return
        proxy_index = index.siblingAtColumn(0)
        source_index = self._proxy.mapToSource(proxy_index)
        item = self._model.itemFromIndex(source_index)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if not node or not vfs:
            return
        self._show_context_menu(node, vfs, self._tree.viewport().mapToGlobal(pos))

    def _collect_result_entries(self, rows: object) -> list[tuple[VFSNode, VFS, str]]:
        """Return (node, vfs, virtual_path) for each file row in rows (skips dirs)."""
        entries: list[tuple[VFSNode, VFS, str]] = []
        for row in rows:
            name_item = self._search_model.item(row, 0)
            path_item = self._search_model.item(row, 1)
            if name_item is None:
                continue
            node: VFSNode | None = name_item.data(_ROLE_NODE)
            vfs: VFS | None = name_item.data(_ROLE_VFS)
            if not node or not vfs or node.is_dir:
                continue
            virtual_path = path_item.text() if path_item else node.name
            entries.append((node, vfs, virtual_path))
        return entries

    def _on_search_context_menu(self, pos: object) -> None:
        index = self._search_view.indexAt(pos)
        global_pos = self._search_view.viewport().mapToGlobal(pos)

        selected_rows = sorted({idx.row() for idx in self._search_view.selectedIndexes()})
        selected_entries = self._collect_result_entries(selected_rows)

        if len(selected_entries) > 1:
            all_entries = self._collect_result_entries(range(self._search_model.rowCount()))
            menu = QMenu(self)
            export_sel = menu.addAction(f"Export {len(selected_entries)} selected files…")
            export_all = None
            if len(all_entries) > len(selected_entries):
                menu.addSeparator()
                export_all = menu.addAction(f"Export all {len(all_entries)} results…")
            action = menu.exec(global_pos)
            filter_text = self._filter.text().strip()
            if action == export_sel:
                self.export_multi_requested.emit(selected_entries, filter_text)
            elif export_all is not None and action == export_all:
                self.export_multi_requested.emit(all_entries, filter_text)
            return

        if not index.isValid():
            return
        item = self._search_model.itemFromIndex(index.siblingAtColumn(0))
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if not node or not vfs:
            return
        self._show_context_menu(node, vfs, global_pos, from_search=True)

    def _show_context_menu(
        self,
        node: VFSNode,
        vfs: VFS,
        global_pos: object,
        from_search: bool = False,
    ) -> None:
        menu = QMenu(self)
        open_action = menu.addAction("Open")
        open_in_new_window_action = None
        if not node.is_dir and isinstance(vfs, DirectoryVFS):
            open_in_new_window_action = menu.addAction("Open in New Window")
        open_hex_action = menu.addAction("Open in Hex")
        open_text_action = menu.addAction("Open as Plain Text")
        open_logs_folder_action = None
        open_multi_log_action   = None
        add_multi_log_action    = None
        open_ios_diag_action    = None
        add_ios_diag_action     = None
        export_logarchive_action = None
        _is_logarchive = node.name.lower().endswith(".logarchive")
        _is_ios_diag = False
        if node.is_dir:
            from crush.parsers.unified_log_parser import is_ios_diagnostics_node
            _is_ios_diag = is_ios_diagnostics_node(node)
        if _is_ios_diag:
            open_ios_diag_action = menu.addAction("Open as Unified Log Archive")
            add_ios_diag_action  = menu.addAction("Add to Multi-Log Studio as Unified Log Archive")
            menu.addSeparator()
            export_logarchive_action = menu.addAction("Export as .logarchive…")
        elif node.is_dir and not _is_logarchive:
            open_logs_folder_action = menu.addAction("Open Logs in Multi-Log Studio")
        else:
            open_multi_log_action = menu.addAction("Open in Multi-Log Studio")
            add_multi_log_action  = menu.addAction("Add to Multi-Log Studio")
        open_proto_action = menu.addAction("Open as Protobuf Viewer")
        open_external_default = None
        open_external_choose = None
        if not node.is_dir:
            menu.addSeparator()
            open_external_default = menu.addAction("Open External (Default)")
            open_external_choose = menu.addAction("Open External (Choose App…)")
        reveal_action = None
        if from_search:
            menu.addSeparator()
            reveal_action = menu.addAction("Open Containing Folder")
        menu.addSeparator()
        format_info_action = menu.addAction("Show Format Info")
        menu.addSeparator()
        export_action = menu.addAction("Export…")
        close_source_action = None
        if node is vfs.root():
            menu.addSeparator()
            close_source_action = menu.addAction("Close Source")
        action = menu.exec(global_pos)
        if action is None:
            return
        if action == open_in_new_window_action:
            self.open_in_new_window_requested.emit(node.path)
        elif action == open_action:
            self.open_requested.emit(node, vfs, "default")
        elif action == open_hex_action:
            self.open_requested.emit(node, vfs, "hex")
        elif action == open_text_action:
            self.open_requested.emit(node, vfs, "text")
        elif action == open_logs_folder_action:
            self.open_requested.emit(node, vfs, "multi_log_folder")
        elif action == open_ios_diag_action:
            self.open_requested.emit(node, vfs, "multi_log")
        elif action == add_ios_diag_action:
            self.open_requested.emit(node, vfs, "multi_log_add")
        elif action == open_multi_log_action:
            self.open_requested.emit(node, vfs, "multi_log")
        elif action == add_multi_log_action:
            self.open_requested.emit(node, vfs, "multi_log_add")
        elif action == open_proto_action:
            self.open_requested.emit(node, vfs, "protobuf")
        elif action == open_external_default:
            self.open_external_requested.emit(node, vfs, "default")
        elif action == open_external_choose:
            self.open_external_requested.emit(node, vfs, "choose")
        elif action == reveal_action:
            self._open_containing_folder(node, vfs)
        elif action == format_info_action:
            self.format_info_requested.emit(node, vfs)
        elif action == export_action:
            self.export_requested.emit(node, vfs)
        elif action == export_logarchive_action:
            self.export_logarchive_requested.emit(node, vfs)
        elif action == close_source_action:
            self.close_source_requested.emit(vfs)

    def _open_containing_folder(self, node: VFSNode, vfs: VFS) -> None:
        if node.is_dir:
            target = node
        else:
            path_nodes = self._build_node_path(node, vfs)
            if len(path_nodes) >= 2:
                target = path_nodes[-2]
            else:
                target = path_nodes[0] if path_nodes else node
        self._navigate_after_filter = (target, vfs)
        self._filter.clear()

    def _save_filter_to_history(self, text: str = "") -> None:
        value = (text or self._filter.text()).strip()
        if not value:
            return
        history: list[str] = self._filter_history_settings.value("filter_history", [], type=list)
        if value in history:
            history.remove(value)
        history.insert(0, value)
        history = history[:30]
        self._filter_history_settings.setValue("filter_history", history)
        self._filter_history_model.setStringList(history)

    def _on_filter_text_changed(self, text: str) -> None:
        if not text:
            self._pending_filter = ""
            self._filter_timer.start()

    def _on_filter_return(self) -> None:
        self._pending_filter = self._filter.text()
        self._filter_timer.start()
        self._save_filter_to_history()

    def _apply_filter(self, text: str) -> None:
        self._pending_filter = text
        self._filter_timer.start()

    def _apply_filter_now(self) -> None:
        text = self._pending_filter.strip()
        if not text:
            self._stack.setCurrentIndex(0)
            self._proxy.setFilterFixedString("")
            if self._navigate_after_filter:
                node, vfs = self._navigate_after_filter
                self._navigate_after_filter = None
                self._navigate_to_node(node, vfs)
        else:
            self._populate_search_results(text)
            self._stack.setCurrentIndex(1)

    def _parse_filter_text(self, text: str) -> dict[str, str]:
        """Parse filter tokens into a dict.  A leading '-' marks negation.
        'type:sqlite -type:segb name:foo' → {'type': 'sqlite', '-type': 'segb', 'name': 'foo'}.
        Plain text without tokens is treated as a name filter."""
        import re
        tokens: dict[str, str] = {}
        for neg, key, value in re.findall(r'(-?)(\w+):(\S+)', text):
            token_key = f"-{key.lower()}" if neg else key.lower()
            tokens[token_key] = value.lower()
        remainder = re.sub(r'-?\w+:\S+', '', text).strip()
        if remainder and 'name' not in tokens:
            tokens['name'] = remainder.lower()
        return tokens

    def _populate_search_results(self, text: str) -> None:
        self._type_queue.clear()
        self._search_model.setRowCount(0)
        tokens = self._parse_filter_text(text)
        if not tokens:
            return
        self._search_gen += 1
        gen = self._search_gen
        vfs_list = list(self._vfs_list)
        threading.Thread(
            target=self._search_worker,
            args=(vfs_list, tokens, gen),
            daemon=True,
        ).start()

    def _search_worker(self, vfs_list: list[VFS], tokens: dict[str, str], gen: int) -> None:
        results: list[dict] = []
        for vfs in vfs_list:
            self._collect_matches(vfs.root(), vfs, tokens, "", results, gen)
            if self._search_gen != gen:
                return
        if self._search_gen == gen:
            self._search_results_ready.emit(results)

    def _collect_matches(
        self, node: VFSNode, vfs: VFS, tokens: dict[str, str],
        parent_path: str, results: list[dict], gen: int,
    ) -> None:
        if self._search_gen != gen:
            return
        path = f"{parent_path}/{node.name}" if parent_path else node.name

        name_filter = tokens.get('name')
        name_exclude = tokens.get('-name')
        type_filter = tokens.get('type')
        type_exclude = tokens.get('-type')

        name_match = (
            (name_filter is None or name_filter in node.name.lower())
            and (name_exclude is None or name_exclude not in node.name.lower())
        )

        if type_filter is not None or type_exclude is not None:
            if node.is_dir:
                type_label: str | None = "DIR"
                dir_words = ("dir", "folder", "directory")
                pos_ok = type_filter is None or any(type_filter in w for w in dir_words)
                neg_ok = type_exclude is None or not any(type_exclude in w for w in dir_words)
                type_match = pos_ok and neg_ok
            else:
                type_label = self._detect_type_label(node, vfs)
                pos_ok = type_filter is None or _type_matches(type_filter, type_label)
                neg_ok = type_exclude is None or not _type_matches(type_exclude, type_label)
                type_match = pos_ok and neg_ok
        else:
            type_label = None
            type_match = True

        if name_match and type_match:
            results.append({
                'node': node, 'vfs': vfs,
                'path': path, 'type_label': type_label,
            })

        for child in node.children:
            self._collect_matches(child, vfs, tokens, path, results, gen)

    def _on_search_results_ready(self, results: list[dict]) -> None:
        self._type_queue.clear()
        self._search_model.setRowCount(0)
        for r in results:
            node: VFSNode = r['node']
            vfs: VFS = r['vfs']
            type_label: str | None = r['type_label']

            name_item = QStandardItem(node.name)
            name_item.setData(node, _ROLE_NODE)
            name_item.setData(vfs, _ROLE_VFS)
            name_item.setData(node.name.lower(), _ROLE_SORT)
            name_item.setEditable(False)

            path_item = QStandardItem(r['path'])
            path_item.setData(r['path'].lower(), _ROLE_SORT)
            path_item.setEditable(False)

            size_item = QStandardItem(_format_size(node.size) if not node.is_dir else "")
            size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            size_item.setData(node.size if not node.is_dir else 0, _ROLE_SORT)
            size_item.setEditable(False)

            resolved = type_label if type_label is not None else ("DIR" if node.is_dir else "-")
            type_item = QStandardItem(resolved)
            type_item.setData(resolved.lower(), _ROLE_SORT)
            type_item.setEditable(False)

            self._search_model.appendRow([name_item, path_item, size_item, type_item])

            if not node.is_dir and type_label is None:
                self._type_queue.append((type_item, node, vfs))
                if not self._type_timer.isActive():
                    self._activity_start("Type detection")
                    self._type_timer.start()

    def _on_search_double_click(self, index: QModelIndex) -> None:
        item = self._search_model.itemFromIndex(index.siblingAtColumn(0))
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if not node or not vfs:
            return
        if node.is_dir:
            self._navigate_after_filter = (node, vfs)
            self._filter.clear()
        else:
            self.node_activated.emit(node, vfs)

    def _on_search_selection_changed(self, *_: object) -> None:
        selection = self._search_view.selectionModel().selectedIndexes()
        if not selection:
            return
        index = next((i for i in selection if i.column() == 0), selection[0])
        item = self._search_model.itemFromIndex(index.siblingAtColumn(0))
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs:
            self.node_selected.emit(node, vfs)

    def _navigate_to_node(self, node: VFSNode, vfs: VFS) -> None:
        """Expand the tree to the given node and select it."""
        path_nodes = self._build_node_path(node, vfs)
        if not path_nodes:
            return
        # Find the root model item for this vfs
        current_item: QStandardItem | None = None
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 0)
            if item and item.data(_ROLE_VFS) is vfs and item.data(_ROLE_NODE) is path_nodes[0]:
                current_item = item
                break
        if current_item is None:
            return
        # Walk down through path, force-loading each level
        for path_node in path_nodes[1:]:
            self._load_children_sync(current_item, current_item.data(_ROLE_NODE), vfs)
            found: QStandardItem | None = None
            for r in range(current_item.rowCount()):
                child = current_item.child(r, 0)
                if child and child.data(_ROLE_NODE) is path_node:
                    found = child
                    break
            if found is None:
                break
            current_item = found
        # Expand and select
        idx = self._proxy.mapFromSource(self._model.indexFromItem(current_item))
        self._tree.scrollTo(idx)
        self._tree.setCurrentIndex(idx)
        self._tree.expand(idx)

    def _build_node_path(self, target: VFSNode, vfs: VFS) -> list[VFSNode]:
        """Return nodes from root to target (inclusive), or [] if not found."""
        def walk(current: VFSNode, path: list[VFSNode]) -> bool:
            path.append(current)
            if current is target:
                return True
            for child in current.children:
                if walk(child, path):
                    return True
            path.pop()
            return False
        result: list[VFSNode] = []
        walk(vfs.root(), result)
        return result

    def _load_children_sync(self, parent_item: QStandardItem, node: VFSNode, vfs: VFS) -> None:
        """Synchronously load children of parent_item if not yet loaded."""
        if parent_item.data(_ROLE_LOADED):
            return
        parent_item.setData(True, _ROLE_LOADED)
        if parent_item.rowCount() == 1:
            first = parent_item.child(0, 0)
            if first is not None and first.data(_ROLE_PLACEHOLDER):
                parent_item.removeRows(0, parent_item.rowCount())
        for child in node.children:
            row = self._node_to_row_shallow(child, vfs)
            parent_item.appendRow(row)

    def _process_build_queue(self) -> None:
        if not self._build_queue:
            self._build_timer.stop()
            self._activity_end("Loading folders")
            return

        processed = 0
        while self._build_queue and processed < self._build_batch:
            parent_item, node, vfs = self._build_queue.popleft()
            for child in node.children:
                row = self._node_to_row_shallow(child, vfs)
                parent_item.appendRow(row)
                if child.is_dir and child.children:
                    self._add_placeholder(row[0])
            processed += 1

        if not self._build_queue:
            self._build_timer.stop()
            self._activity_end("Loading folders")

    def _process_type_queue(self) -> None:
        if not self._type_queue:
            self._type_timer.stop()
            self._activity_end("Type detection")
            return
        processed = 0
        while self._type_queue and processed < 300:
            type_item, node, vfs = self._type_queue.popleft()
            label = self._detect_type_label(node, vfs)
            try:
                type_item.setText(label)
            except RuntimeError:
                pass  # item was deleted (e.g. search results refreshed mid-detection)
            processed += 1
        if not self._type_queue:
            self._type_timer.stop()
            self._activity_end("Type detection")

    def _detect_type_label(self, node: VFSNode, vfs: VFS) -> str:
        if node.is_dir:
            return "DIR"
        cache_key = (id(vfs), node.path)
        if cache_key in self._type_cache:
            return self._type_cache[cache_key]
        label = ""
        try:
            peek = vfs.peek(node, 2048)
            label = detect_fast_label(peek, node.path)
            if not label:
                try:
                    from crush.core.format_db import FormatDatabase
                    fmt = FormatDatabase.get().identify(peek, node.name)
                    if fmt:
                        label = fmt.short_name or fmt.name
                except Exception:
                    pass
        except Exception:
            label = ""
        if not label:
            label = "-"
        self._type_cache[cache_key] = label
        return label

    def _start_prescan(self, vfs_list: list[VFS], gen: int) -> None:
        threading.Thread(
            target=self._prescan_worker,
            args=(vfs_list, gen),
            daemon=True,
        ).start()

    def _on_prescan_activity(self, name: str, is_start: bool) -> None:
        if is_start:
            self._activity_start(name)
        else:
            self._activity_end(name)

    def _prescan_worker(self, vfs_list: list[VFS], gen: int) -> None:
        """Walk all VFS nodes in background to warm the type cache.

        File nodes are collected first, then dispatched to a ThreadPoolExecutor
        whose size is controlled by self._prescan_workers.  VFS implementations
        are thread-safe (DirectoryVFS opens independent handles; ZipVFS uses
        thread-local ZipFile handles; TarVFS serialises via a per-instance lock).
        """
        from crush.core.vfs import DirectoryVFS, FileVFS, ZipVFS
        # Archive VFS types (ZIP, tar) serialize on a lock anyway — extra threads
        # only add overhead.  Use parallel workers only when every source is a
        # plain directory or single-file VFS.
        if all(isinstance(vfs, (DirectoryVFS, FileVFS)) for vfs in vfs_list):
            n_workers = self._prescan_workers
        else:
            n_workers = 1
        _logger.info("Type pre-scan started (workers=%d)", n_workers)
        self._prescan_activity.emit("Indexing types", True)
        t0 = time.monotonic()

        # Collect all file nodes up-front so we can split them evenly.
        # For ZIP sources use storage order so reads are sequential (no random seeks).
        all_nodes: list[tuple[VFSNode, VFS]] = []
        for vfs in vfs_list:
            if isinstance(vfs, ZipVFS):
                all_nodes.extend((node, vfs) for node in vfs.storage_ordered_files())
            else:
                stack: deque[VFSNode] = deque([vfs.root()])
                while stack:
                    node = stack.popleft()
                    if not node.is_dir:
                        all_nodes.append((node, vfs))
                    stack.extend(node.children)

        total = len(all_nodes)
        _logger.info("Type pre-scan: %d files to index", total)

        chunk_size = max(1, (total + n_workers - 1) // n_workers)
        chunks = [all_nodes[i : i + chunk_size] for i in range(0, total, chunk_size)]

        def _process_chunk(chunk: list[tuple[VFSNode, VFS]]) -> int:
            processed = 0
            for node, vfs in chunk:
                if self._prescan_gen != gen:
                    return processed
                self._detect_type_label(node, vfs)
                processed += 1
            return processed

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as executor:
                futures = [executor.submit(_process_chunk, chunk) for chunk in chunks]
                for future in concurrent.futures.as_completed(futures):
                    if self._prescan_gen != gen:
                        for f in futures:
                            f.cancel()
                        _logger.info("Type pre-scan cancelled")
                        return
                    try:
                        future.result()
                    except Exception as exc:
                        _logger.debug("Pre-scan chunk error: %s", exc)
        finally:
            if self._prescan_gen == gen:
                elapsed = time.monotonic() - t0
                _logger.info(
                    "Type pre-scan complete: %d files indexed in %.1f s", total, elapsed
                )
                self._prescan_activity.emit("Indexing types", False)

    def _ensure_children_loaded(self, parent_item: QStandardItem, node: VFSNode, vfs: VFS) -> None:
        if parent_item.data(_ROLE_LOADED):
            return
        parent_item.setData(True, _ROLE_LOADED)
        if parent_item.rowCount() == 1:
            first = parent_item.child(0, 0)
            if first is not None and first.data(_ROLE_PLACEHOLDER):
                parent_item.removeRows(0, parent_item.rowCount())
        if node.children:
            self._build_queue.append((parent_item, node, vfs))
            if not self._build_timer.isActive():
                self._activity_start("Loading folders")
                self._build_timer.start()

    def _activity_start(self, name: str) -> None:
        if name not in self._activities:
            self._activities.add(name)
            if hasattr(self, "_emit_background_status"):
                self._emit_background_status()
            _logger.debug("FilesystemPanel activity start: %s", name)

    def _activity_end(self, name: str) -> None:
        if name in self._activities:
            self._activities.discard(name)
            if hasattr(self, "_emit_background_status"):
                self._emit_background_status()
            _logger.debug("FilesystemPanel activity end: %s", name)

    def _emit_background_status(self) -> None:
        if not self._activities:
            self.background_status.emit("")
            return
        items = ", ".join(sorted(self._activities))
        self.background_status.emit(f"Background: {items}")

    def _add_placeholder(self, parent_item: QStandardItem) -> None:
        if parent_item.rowCount() > 0:
            return
        placeholder = QStandardItem("")
        placeholder.setData(True, _ROLE_PLACEHOLDER)
        placeholder.setEditable(False)
        parent_item.appendRow(
            [placeholder, QStandardItem(""), QStandardItem(""), QStandardItem(""), QStandardItem("")]
        )

    def _label_from_registry(self, node: VFSNode, vfs: VFS) -> str:
        try:
            import crush.parsers  # noqa: F401
            from crush.core.registry import ParserRegistry
            parser = ParserRegistry.best(node, vfs)
            if parser is None:
                return ""
            return parser.DISPLAY_NAME
        except Exception:
            return ""


class _VfsFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setFilterKeyColumn(0)
        self.setRecursiveFilteringEnabled(True)
