# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Reusable split tree + hex view synchronization for byte-mapped decoders."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QSplitter, QTreeView, QVBoxLayout, QWidget

from crush.viewers.hex_viewer import HexViewer

ByteRange = tuple[int, int]
ByteRangeGetter = Callable[[QStandardItem], ByteRange | None]
ByteRangesGetter = Callable[[QStandardItem], list[ByteRange]]
TreeSelectionCallback = Callable[[], None]


class ByteMappedTreeHex(QWidget):
    """Pair an existing decoded tree with a raw hex view.

    The caller owns the tree model and row contents. This widget only handles
    byte-range highlighting and bidirectional selection, so protobuf, ABX,
    plist, Realm, and later SQLite can reuse the same interaction layer.
    Ranges are half-open absolute byte offsets into *raw*.
    """

    def __init__(
        self,
        *,
        raw: bytes,
        tree: QTreeView,
        model: QStandardItemModel,
        range_for_item: ByteRangeGetter,
        highlight_ranges_for_item: ByteRangesGetter | None = None,
        selection_changed: TreeSelectionCallback | None = None,
        footer: QWidget | None = None,
        hex_visible: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._tree = tree
        self._model = model
        self._range_for_item = range_for_item
        self._highlight_ranges_for_item = highlight_ranges_for_item
        self._selection_changed = selection_changed
        self._syncing_selection = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        tree_panel = QWidget()
        tree_layout = QVBoxLayout(tree_panel)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        tree_layout.setSpacing(0)
        tree_layout.addWidget(tree)
        if footer is not None:
            tree_layout.addWidget(footer)

        self._hex = HexViewer(raw, self)
        self._hex.setVisible(hex_visible)
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.addWidget(tree_panel)
        self._splitter.addWidget(self._hex)
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 1)
        self._splitter.setSizes([520, 520])
        layout.addWidget(self._splitter, 1)

        tree.selectionModel().selectionChanged.connect(self._on_tree_selection_changed)
        self._hex.byteOffsetFocused.connect(self._select_deepest_item_for_offset)

    @property
    def hex_viewer(self) -> HexViewer:
        return self._hex

    def set_hex_visible(self, visible: bool) -> None:
        self._hex.setVisible(visible)

    def is_hex_visible(self) -> bool:
        return not self._hex.isHidden()

    def _on_tree_selection_changed(self) -> None:
        if self._selection_changed is not None:
            self._selection_changed()
        if self._syncing_selection:
            return
        item = self._current_key_item()
        if item is None:
            self._hex.clear_byte_range_highlight()
            return
        rng = self._range_for_item(item)
        if rng is None:
            self._hex.clear_byte_range_highlight()
            return
        self._highlight_item_ranges(item, scroll=True)

    def _current_key_item(self) -> QStandardItem | None:
        index = self._tree.currentIndex()
        if not index.isValid():
            return None
        return self._model.itemFromIndex(self._model.index(index.row(), 0, index.parent()))

    def _select_deepest_item_for_offset(self, offset: int) -> None:
        if self._syncing_selection:
            return
        item = self._find_deepest_item_for_offset(
            self._model.invisibleRootItem(),
            offset,
        )
        if item is None:
            return
        index = self._model.indexFromItem(item)
        if not index.isValid():
            return
        self._syncing_selection = True
        self._tree.setCurrentIndex(index)
        self._tree.scrollTo(index)
        self._syncing_selection = False
        if self._selection_changed is not None:
            self._selection_changed()
        self._highlight_item_ranges(item, scroll=False)

    def _highlight_item_ranges(self, item: QStandardItem, *, scroll: bool) -> None:
        ranges = (
            self._highlight_ranges_for_item(item)
            if self._highlight_ranges_for_item is not None
            else []
        )
        if not ranges:
            rng = self._range_for_item(item)
            ranges = [rng] if rng is not None else []
        self._hex.highlight_byte_ranges(ranges, scroll=scroll)

    def _find_deepest_item_for_offset(
        self,
        parent: QStandardItem,
        offset: int,
    ) -> QStandardItem | None:
        match: QStandardItem | None = None
        for row in range(parent.rowCount()):
            item = parent.child(row, 0)
            if item is None:
                continue
            rng = self._range_for_item(item)
            if rng is None or not (rng[0] <= offset < rng[1]):
                continue
            child_match = self._find_deepest_item_for_offset(item, offset)
            match = child_match or item
        return match
