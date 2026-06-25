# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Search panel — flat file-finder across a selected VFS folder."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
    QTimer,
)
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from crush.core.vfs import VFS, VFSNode
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

_ROLE_NODE = Qt.ItemDataRole.UserRole + 1
_ROLE_VFS = Qt.ItemDataRole.UserRole + 2
_ROLE_SORT = Qt.ItemDataRole.UserRole + 3  # numeric sort value
_ROLE_TYPE = Qt.ItemDataRole.UserRole + 4  # detected type key (from magic bytes)

_SIZE_UNITS = ["B", "KB", "MB", "GB", "TB"]


def _fmt_size(n: int) -> str:
    v = float(n)
    for unit in _SIZE_UNITS:
        if v < 1024 or unit == _SIZE_UNITS[-1]:
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024
    return str(n)


def _fmt_ts(ts: float) -> str:
    if ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


_ISOBMFF_IMAGE_BRANDS: frozenset[bytes] = frozenset({
    b"heic", b"heix", b"hevc", b"hevx",
    b"heim", b"heis", b"hevm", b"hevs",
    b"mif1", b"msf1",
    b"avif", b"avis",
})


def _detect_type(peek: bytes, ext: str) -> str:
    """Return type key from magic bytes; fall back to extension."""
    if len(peek) >= 4:
        # JPEG / JPEG XL bare codestream
        if peek[:3] == b"\xFF\xD8\xFF" or peek[:2] == b"\xFF\x0A":
            return "image"
        # PNG
        if peek[:8] == b"\x89PNG\r\n\x1a\n":
            return "image"
        # GIF
        if peek[:6] in (b"GIF87a", b"GIF89a"):
            return "image"
        # BMP
        if peek[:2] == b"BM":
            return "image"
        # TIFF
        if peek[:4] in (b"II*\x00", b"MM\x00*"):
            return "image"
        # WebP
        if len(peek) >= 12 and peek[:4] == b"RIFF" and peek[8:12] == b"WEBP":
            return "image"
        # HEIC / HEIF / AVIF (ISOBMFF ftyp box)
        if len(peek) >= 12 and peek[4:8] == b"ftyp" and peek[8:12] in _ISOBMFF_IMAGE_BRANDS:
            return "image"
        # JPEG XL ISOBMFF container
        if len(peek) >= 12 and peek[:12] == b"\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A":
            return "image"
        # SQLite
        if len(peek) >= 16 and peek[:16] == b"SQLite format 3\x00":
            return "sqlite"
        # Binary plist
        if peek[:6] == b"bplist":
            return "plist"
        # PDF
        if peek[:4] == b"%PDF":
            return "pdf"
    # Fall back to extension
    ext_clean = ext.lstrip(".").lower()
    for type_key, exts in _TYPE_EXTENSIONS.items():
        if ext_clean in exts:
            return type_key
    return ""


class SearchPanel(QWidget):
    """Flat-table search panel. Scope is set by right-clicking a folder in the FS panel."""

    node_activated = Signal(object, object)  # (VFSNode, VFS)
    node_selected = Signal(object, object)   # (VFSNode, VFS)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vfs: VFS | None = None
        self._root: VFSNode | None = None
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(200)
        self._debounce.timeout.connect(self._run_search)
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_scope(self, node: VFSNode, vfs: VFS) -> None:
        """Set the folder to search in and run the initial search."""
        self._root = node
        self._vfs = vfs
        label = node.path if node.path != "/" else vfs.root().name
        self._scope_label.setText(label)
        self._scope_label.setToolTip(label)
        self._run_search()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Scope bar
        scope_bar = QWidget()
        sb = QHBoxLayout(scope_bar)
        sb.setContentsMargins(6, 4, 6, 4)
        sb.setSpacing(6)
        sb.addWidget(QLabel("Scope:"))
        self._scope_label = QLabel("(none — right-click a folder in the tree)")
        self._scope_label.setWordWrap(False)
        sb.addWidget(self._scope_label, 1)
        layout.addWidget(scope_bar)

        # Filter bar
        filter_bar = QWidget()
        fb = QHBoxLayout(filter_bar)
        fb.setContentsMargins(6, 4, 6, 4)
        fb.setSpacing(6)

        fb.addWidget(QLabel("Name:"))
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("* wildcard or regex")
        self._name_input.setClearButtonEnabled(True)
        self._name_input.textChanged.connect(self._debounce.start)
        fb.addWidget(self._name_input, 2)

        fb.addWidget(QLabel("Ext:"))
        self._ext_input = QLineEdit()
        self._ext_input.setPlaceholderText(".pdf")
        self._ext_input.setClearButtonEnabled(True)
        self._ext_input.setFixedWidth(60)
        self._ext_input.textChanged.connect(self._debounce.start)
        fb.addWidget(self._ext_input)

        fb.addWidget(QLabel("Type:"))
        self._type_combo = QComboBox()
        self._type_combo.addItems([
            "All", "SQLite", "Image", "Media", "plist", "JSON", "XML",
            "ABX", "SEGB", "LevelDB", "PDF", "Text",
        ])
        self._type_combo.currentTextChanged.connect(self._debounce.start)
        fb.addWidget(self._type_combo)

        self._recurse_check = QCheckBox("Recursive")
        self._recurse_check.setChecked(True)
        self._recurse_check.toggled.connect(self._debounce.start)
        fb.addWidget(self._recurse_check)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._run_search)
        fb.addWidget(self._refresh_btn)

        layout.addWidget(filter_bar)

        # Status
        self._status = QLabel("")
        self._status.setContentsMargins(6, 0, 6, 2)
        layout.addWidget(self._status)

        # Table
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(
            ["Name", "Path", "Extension", "Size", "Modified"]
        )
        self._proxy = _SearchProxy(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        install_horizontal_wheel_scroll(self._table)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.setColumnWidth(0, 200)
        self._table.setColumnWidth(1, 280)
        self._table.setColumnWidth(2, 70)
        self._table.setColumnWidth(3, 80)
        self._table.setColumnWidth(4, 140)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table)

    # ------------------------------------------------------------------
    # Search logic
    # ------------------------------------------------------------------

    def _run_search(self) -> None:
        if self._root is None or self._vfs is None:
            return
        name_pat = self._name_input.text().strip()
        ext_filter = self._ext_input.text().strip().lower()
        type_filter = self._type_combo.currentText()
        recursive = self._recurse_check.isChecked()

        # Build name regex
        name_re: re.Pattern[str] | None = None
        if name_pat:
            try:
                escaped = re.escape(name_pat).replace(r"\*", ".*")
                name_re = re.compile(escaped, re.IGNORECASE)
            except re.error:
                name_re = None

        if ext_filter and not ext_filter.startswith("."):
            ext_filter = "." + ext_filter

        files: list[VFSNode] = []
        self._collect(self._root, files, recursive, depth=0)

        # Filter
        matched: list[VFSNode] = []
        for node in files:
            if name_re and not name_re.search(node.name):
                continue
            if ext_filter and not node.name.lower().endswith(ext_filter):
                continue
            matched.append(node)

        self._populate(matched)

        # Type filter applied via proxy after population
        self._proxy.set_type_filter("" if type_filter == "All" else type_filter.lower())
        self._proxy.invalidateFilter()

    def _collect(
        self, node: VFSNode, out: list[VFSNode], recursive: bool, depth: int
    ) -> None:
        for child in node.children:
            if child.is_dir:
                if recursive:
                    self._collect(child, out, recursive, depth + 1)
            else:
                out.append(child)

    def _populate(self, nodes: list[VFSNode]) -> None:
        self._model.removeRows(0, self._model.rowCount())
        for node in nodes:
            ext = Path(node.name).suffix.lower()
            peek = self._vfs.peek(node, 20) if self._vfs else b""
            detected_type = _detect_type(peek, ext)
            size_str = _fmt_size(node.size)
            ts_str = _fmt_ts(node.modified)

            name_item = QStandardItem(node.name)
            name_item.setData(node, _ROLE_NODE)
            name_item.setData(self._vfs, _ROLE_VFS)
            name_item.setData(detected_type, _ROLE_TYPE)
            name_item.setEditable(False)

            path_item = QStandardItem(node.path)
            path_item.setEditable(False)

            ext_item = QStandardItem(ext)
            ext_item.setEditable(False)

            size_item = QStandardItem(size_str)
            size_item.setData(node.size, _ROLE_SORT)
            size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            size_item.setEditable(False)

            ts_item = QStandardItem(ts_str)
            ts_item.setData(node.modified, _ROLE_SORT)
            ts_item.setEditable(False)

            self._model.appendRow([name_item, path_item, ext_item, size_item, ts_item])

        count = self._model.rowCount()
        self._status.setText(f"{count:,} file{'s' if count != 1 else ''} found")

    # ------------------------------------------------------------------
    # Interaction
    # ------------------------------------------------------------------

    def _on_double_click(self, index: QModelIndex) -> None:
        source = self._proxy.mapToSource(index.siblingAtColumn(0))
        item = self._model.itemFromIndex(source)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs:
            self.node_activated.emit(node, vfs)

    def _on_selection_changed(self) -> None:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            return
        source = self._proxy.mapToSource(indexes[0].siblingAtColumn(0))
        item = self._model.itemFromIndex(source)
        if item is None:
            return
        node: VFSNode | None = item.data(_ROLE_NODE)
        vfs: VFS | None = item.data(_ROLE_VFS)
        if node and vfs:
            self.node_selected.emit(node, vfs)


class _SearchProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._type_filter = ""

    def set_type_filter(self, text: str) -> None:
        self._type_filter = text.lower()

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        left_sort = self.sourceModel().data(left, _ROLE_SORT)
        right_sort = self.sourceModel().data(right, _ROLE_SORT)
        if left_sort is not None and right_sort is not None:
            try:
                return float(left_sort) < float(right_sort)
            except (TypeError, ValueError):
                pass
        return super().lessThan(left, right)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._type_filter:
            return True
        name_idx = self.sourceModel().index(source_row, 0, source_parent)
        detected_type = self.sourceModel().data(name_idx, _ROLE_TYPE) or ""
        return detected_type == self._type_filter


# Map type-filter key → set of matching extensions
_TYPE_EXTENSIONS: dict[str, set[str]] = {
    "sqlite":  {"db", "sqlite", "sqlite3", "db3"},
    "image":   {"jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif", "heic", "heif", "avif", "jxl"},
    "media":   {"mp4", "mov", "avi", "mkv", "mp3", "m4a", "aac", "wav", "flac", "ogg"},
    "plist":   {"plist"},
    "json":    {"json"},
    "xml":     {"xml"},
    "abx":     {"abx"},
    "segb":    {"segb"},
    "leveldb": set(),
    "pdf":     {"pdf"},
    "text":    {"txt", "log", "md", "csv", "tsv", "ini", "cfg", "conf", "py", "js", "ts",
                "html", "htm", "css", "sh", "bat", "yaml", "yml", "toml"},
}
