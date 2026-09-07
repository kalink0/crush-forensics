# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the reusable byte-mapped tree/hex synchronization widget."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QTreeView

from crush.viewers.byte_mapped_tree_hex import ByteMappedTreeHex

_RANGE_ROLE = Qt.ItemDataRole.UserRole


def _make_tree() -> tuple[QTreeView, QStandardItemModel, QStandardItem, QStandardItem]:
    model = QStandardItemModel()
    model.setHorizontalHeaderLabels(["Name", "Value", "Type"])
    tree = QTreeView()
    tree.setModel(model)

    parent = QStandardItem("container")
    parent.setData((2, 8), _RANGE_ROLE)
    child = QStandardItem("child")
    child.setData((4, 6), _RANGE_ROLE)
    child_value = QStandardItem("value")
    child_type = QStandardItem("bytes")
    parent.appendRow([child, child_value, child_type])
    model.invisibleRootItem().appendRow([parent, QStandardItem("(1 item)"), QStandardItem("dict")])
    return tree, model, parent, child


def _range_for_item(item: QStandardItem) -> tuple[int, int] | None:
    value = item.data(_RANGE_ROLE)
    return value if isinstance(value, tuple) else None


def test_tree_selection_highlights_hex_range(qapp) -> None:
    tree, model, _parent, child = _make_tree()
    widget = ByteMappedTreeHex(
        raw=bytes(range(16)),
        tree=tree,
        model=model,
        range_for_item=_range_for_item,
    )

    tree.setCurrentIndex(model.indexFromItem(child))
    widget._on_tree_selection_changed()

    assert widget.hex_viewer._focus_range == (4, 6)


def test_hex_offset_selects_deepest_tree_row(qapp) -> None:
    tree, model, _parent, child = _make_tree()
    widget = ByteMappedTreeHex(
        raw=bytes(range(16)),
        tree=tree,
        model=model,
        range_for_item=_range_for_item,
    )

    widget._select_deepest_item_for_offset(5)

    assert tree.currentIndex() == model.indexFromItem(child)
    assert widget.hex_viewer._focus_range == (4, 6)


def test_highlight_ranges_callback_can_supply_multiple_ranges(qapp) -> None:
    tree, model, parent, _child = _make_tree()
    widget = ByteMappedTreeHex(
        raw=bytes(range(16)),
        tree=tree,
        model=model,
        range_for_item=_range_for_item,
        highlight_ranges_for_item=lambda _item: [(2, 3), (3, 4), (4, 6)],
    )

    tree.setCurrentIndex(model.indexFromItem(parent))
    widget._on_tree_selection_changed()

    assert widget.hex_viewer._focus_ranges == [(2, 3), (3, 4), (4, 6)]


def test_hex_viewer_caps_focus_ranges_at_five(qapp) -> None:
    tree, model, parent, _child = _make_tree()
    widget = ByteMappedTreeHex(
        raw=bytes(range(16)),
        tree=tree,
        model=model,
        range_for_item=_range_for_item,
        highlight_ranges_for_item=lambda _item: [(i, i + 1) for i in range(8)],
    )

    tree.setCurrentIndex(model.indexFromItem(parent))
    widget._on_tree_selection_changed()

    assert widget.hex_viewer._focus_ranges == [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]
