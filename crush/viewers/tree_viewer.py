# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tree viewer — displays plist, XML, and other hierarchical data."""
from __future__ import annotations

import plistlib
from collections.abc import Callable, Mapping
from typing import Any

from PySide6.QtCore import QT_TRANSLATE_NOOP, QModelIndex, QPersistentModelIndex, Qt, QTimer
from PySide6.QtGui import QKeySequence, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.byte_mapped_tree_hex import ByteMappedTreeHex
from crush.core.issues import ParseIssue, render
from crush.ui.i18n import translate
from crush.viewers.generated_text import EXPORT_TEXT_ROLE, Gen

_USER_ROLE = Qt.ItemDataRole.UserRole
_BYTE_RANGE_ROLE = Qt.ItemDataRole.UserRole + 1
_BYTE_HIGHLIGHT_RANGES_ROLE = Qt.ItemDataRole.UserRole + 2
# Set on a container row whose child rows aren't built yet (see _LazyTreeModel).
_PENDING_ROLE = Qt.ItemDataRole.UserRole + 3

# NSKeyedArchiver class metadata: not shown as rows, the classname goes to
# the Type column instead.
_CLASS_META_KEYS = ("$class", "$classes", "$classname")


class _ObjRef:
    """Keep the node's original decoded value opaque to Qt's QVariant
    conversion — a bare dict/list/int stored via setData() gets walked by
    shiboken looking for a native Qt type, and a value in the uint64 range
    (e.g. an NSKeyedArchiver UID) raises OverflowError partway through.
    *path* is the node's key path, for building its child rows later."""

    def __init__(self, obj: Any, path: tuple[str, ...] = ()) -> None:
        self.obj = obj
        self.path = path


def _child_entries(obj: Any) -> list[tuple[str, Any]]:
    """(key, value) of each child row of *obj*; empty for a leaf."""
    if isinstance(obj, dict):
        return [(str(k), v) for k, v in obj.items() if k not in _CLASS_META_KEYS]
    if isinstance(obj, (list, tuple)):
        return [(str(i), v) for i, v in enumerate(obj)]
    return []


def _has_child_rows(obj: Any) -> bool:
    if isinstance(obj, dict):
        return any(k not in _CLASS_META_KEYS for k in obj)
    return isinstance(obj, (list, tuple)) and bool(obj)


def _value_texts(obj: Any) -> tuple[str, str]:
    """(English original, display text) of *obj*'s Value cell."""
    if isinstance(obj, dict):
        return Gen(
            QT_TRANSLATE_NOOP("GeneratedView", "({count} keys)"), count=len(_child_entries(obj))
        ).pair()
    if isinstance(obj, (list, tuple)):
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "({count} items)"), count=len(obj)).pair()
    if isinstance(obj, bytes):
        return Gen(QT_TRANSLATE_NOOP("GeneratedView", "<BLOB {size:,} B>"), size=len(obj)).pair()
    if isinstance(obj, ParseIssue):
        # A parser's note (e.g. in the Realm File Structure tree): shown in
        # the UI language, copied in English.
        return str(obj), render(obj, localized=True)
    return str(obj), str(obj)


def _subtree_matches(obj: Any, text: str) -> bool:
    """Whether a row below *obj* would show *text* (lowercase) in its Key or
    Value cell -- the filter's test, run on the data of rows not built yet."""
    for key, value in _child_entries(obj):
        if text in key.lower() or text in _value_texts(value)[1].lower():
            return True
        if _subtree_matches(value, text):
            return True
    return False


class _LazyTreeModel(QStandardItemModel):
    """Builds a container's child rows the first time they're needed
    (expanding it, the filter, a hex click) instead of all up front:
    a large file (issue #127: a 15 MB XML is ~500k rows) otherwise froze the
    UI for tens of seconds before showing anything. Nothing is left out --
    every row is built as soon as its parent is opened."""

    def __init__(self, populate: Callable[[QStandardItem], None]) -> None:
        super().__init__()
        self._populate = populate

    def _pending_item(self, parent: QModelIndex | QPersistentModelIndex) -> QStandardItem | None:
        if not parent.isValid():
            return None
        item = self.itemFromIndex(parent.siblingAtColumn(0))
        return item if item is not None and item.data(_PENDING_ROLE) else None

    def hasChildren(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> bool:  # noqa: B008
        if self._pending_item(parent) is not None:
            return True
        return super().hasChildren(parent)

    def canFetchMore(self, parent: QModelIndex | QPersistentModelIndex) -> bool:
        return self._pending_item(parent) is not None

    def fetchMore(self, parent: QModelIndex | QPersistentModelIndex) -> None:
        item = self._pending_item(parent)
        if item is not None:
            self._populate(item)


def _valid_byte_range(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], int)
        and isinstance(value[1], int)
        and value[0] <= value[1]
    )


def _byte_range_from_item(item: QStandardItem) -> tuple[int, int] | None:
    value = item.data(_BYTE_RANGE_ROLE)
    if _valid_byte_range(value):
        return value
    return None


def _byte_highlight_ranges_from_item(item: QStandardItem) -> list[tuple[int, int]]:
    value = item.data(_BYTE_HIGHLIGHT_RANGES_ROLE)
    if isinstance(value, list):
        return [rng for rng in value if _valid_byte_range(rng)]
    rng = _byte_range_from_item(item)
    return [rng] if rng is not None else []


class TreeViewer(QWidget):
    """Viewer for plist / XML / any nested dict/list structure."""

    def __init__(
        self,
        data: Any,
        parent: QWidget | None = None,
        *,
        raw: bytes | None = None,
        byte_ranges_by_path: Mapping[
            tuple[str, ...],
            Mapping[str, tuple[int, int] | list[tuple[int, int]]],
        ] | None = None,
        hex_visible: bool = False,
    ) -> None:
        super().__init__(parent)
        self._raw = raw
        self._initial_hex_visible = hex_visible
        self._byte_ranges_by_path = byte_ranges_by_path or {}
        self._build_ui()
        self._load(data)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setFixedHeight(36)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)
        self._expand_all_btn = QPushButton(translate("TreeViewer", "Expand All"))
        self._expand_all_btn.clicked.connect(self._expand_all)
        tb_layout.addWidget(self._expand_all_btn)
        self._collapse_all_btn = QPushButton(translate("TreeViewer", "Collapse All"))
        self._collapse_all_btn.clicked.connect(self._collapse_all)
        tb_layout.addWidget(self._collapse_all_btn)
        tb_layout.addStretch()
        tb_layout.addWidget(QLabel(translate("TreeViewer", "Search:")))

        self._search = QLineEdit()
        self._search.setPlaceholderText(translate("TreeViewer", "Filter keys / values…"))
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(200)
        # Each filter pass walks the whole tree: wait for a pause in typing.
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(lambda: self._apply_filter(self._search.text()))
        self._search.textChanged.connect(lambda _text: self._filter_timer.start())
        tb_layout.addWidget(self._search)
        self._hex_toggle_btn: QPushButton | None = None
        if self._raw is not None:
            self._hex_toggle_btn = QPushButton(translate("TreeViewer", "Show Hex"))
            self._hex_toggle_btn.clicked.connect(self._toggle_hex_view)
            tb_layout.addWidget(self._hex_toggle_btn)
            if self._initial_hex_visible:
                self._hex_toggle_btn.setText(translate("TreeViewer", "Hide Hex"))
        layout.addWidget(toolbar)

        # Tree view
        self._filter_text = ""
        self._model = _LazyTreeModel(self._populate_children)
        self._model.setHorizontalHeaderLabels(
            [
                translate("TreeViewer", "Key / Index"),
                translate("TreeViewer", "Value"),
                translate("TreeViewer", "Type"),
            ]
        )

        self._tree = QTreeView()
        self._tree.setModel(self._model)
        # Read-only for the whole view rather than per item (three calls per
        # row add up on a large tree).
        self._tree.setEditTriggers(QTreeView.EditTrigger.NoEditTriggers)
        self._tree.setAlternatingRowColors(True)
        self._tree.setAnimated(True)
        install_horizontal_wheel_scroll(self._tree)
        self._tree.header().setStretchLastSection(False)
        self._tree.setColumnWidth(0, 220)
        self._tree.setColumnWidth(1, 300)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)
        self._tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)

        value_bar = QWidget()
        vb_layout = QHBoxLayout(value_bar)
        vb_layout.setContentsMargins(8, 4, 8, 4)
        vb_layout.setSpacing(8)
        vb_layout.addWidget(QLabel(translate("TreeViewer", "Value:")))
        self._value_field = QLineEdit()
        self._value_field.setReadOnly(True)
        vb_layout.addWidget(self._value_field, 1)

        self._mapped_view: ByteMappedTreeHex | None = None
        if self._raw is not None:
            self._mapped_view = ByteMappedTreeHex(
                raw=self._raw,
                tree=self._tree,
                model=self._model,
                range_for_item=_byte_range_from_item,
                highlight_ranges_for_item=_byte_highlight_ranges_from_item,
                selection_changed=self._update_value_field,
                footer=value_bar,
                hex_visible=self._initial_hex_visible,
                parent=self,
            )
            layout.addWidget(self._mapped_view, 1)
        else:
            layout.addWidget(self._tree, 1)
            layout.addWidget(value_bar)
            self._tree.selectionModel().selectionChanged.connect(self._update_value_field)

    def _toggle_hex_view(self) -> None:
        if self._mapped_view is None or self._hex_toggle_btn is None:
            return
        visible = not self._mapped_view.is_hex_visible()
        self._mapped_view.set_hex_visible(visible)
        self._hex_toggle_btn.setText(
            translate("TreeViewer", "Hide Hex") if visible else translate("TreeViewer", "Show Hex")
        )

    def _expand_all(self) -> None:
        # Builds every row not built yet -- on the UI thread (Qt items can't
        # be made elsewhere), so a large tree takes a while: say so.
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            # All rows first, then one expand pass: letting expandAll() fetch
            # them level by level lays out the view again for each level, and
            # adding rows under an expanded row costs the view per row too --
            # so build them with everything collapsed.
            self._tree.collapseAll()
            self._populate_all(self._model.invisibleRootItem())
            self._tree.expandAll()
        finally:
            QApplication.restoreOverrideCursor()

    def _populate_all(self, parent: QStandardItem) -> None:
        for row in range(parent.rowCount()):
            item = parent.child(row, 0)
            if item is not None:
                self._populate_children(item)
                self._populate_all(item)

    def _collapse_all(self) -> None:
        self._tree.collapseAll()

    def _load(self, data: Any) -> None:
        self._value_field.clear()
        self._model.removeRows(0, self._model.rowCount())
        root = self._model.invisibleRootItem()
        if isinstance(data, dict):
            for key, value in data.items():
                self._build_items(root, value, str(key), ())
        elif isinstance(data, (list, tuple)):
            for i, value in enumerate(data):
                self._build_items(root, value, str(i), ())
        else:
            self._build_items(root, data, "value", ())
        # Top-level rows only: each deeper level would be built up front, and
        # one level down can already be ~500k rows (issue #127).
        self._tree.expandToDepth(0)

    def _build_items(
        self,
        parent: QStandardItem,
        obj: Any,
        key: str,
        parent_path: tuple[str, ...],
    ) -> None:
        """Append the row for *obj*. A container's own child rows are built
        later, when first needed (_populate_children)."""
        node_path = parent_path + (key,)
        if isinstance(obj, dict):
            # Surface the NSKeyedArchiver classname in the Type column
            class_meta = obj.get("$class")
            classname = (
                class_meta.get("$classname", "") if isinstance(class_meta, dict) else ""
            )
            type_name = classname if classname else "dict"
        else:
            type_name = type(obj).__name__

        english, display = _value_texts(obj)
        key_item = QStandardItem(str(key))
        val_item = QStandardItem(display)
        if display != english:
            val_item.setData(english, EXPORT_TEXT_ROLE)
        type_item = QStandardItem(type_name)
        key_item.setData(_ObjRef(obj, node_path), _USER_ROLE)
        self._apply_byte_range_metadata(key_item, node_path)
        if _has_child_rows(obj):
            key_item.setData(True, _PENDING_ROLE)
        parent.appendRow([key_item, val_item, type_item])

    def _populate_children(self, item: QStandardItem, *, apply_filter: bool = True) -> None:
        """Build the child rows of container row *item* if not built yet.
        With a filter active they're filtered like the rest of the tree."""
        if not item.data(_PENDING_ROLE):
            return
        item.setData(None, _PENDING_ROLE)
        ref = item.data(_USER_ROLE)
        if not isinstance(ref, _ObjRef):
            return
        for key, value in _child_entries(ref.obj):
            self._build_items(item, value, key, ref.path)
        if apply_filter and self._filter_text:
            self._filter_items(item, self._filter_text)

    def _apply_byte_range_metadata(
        self,
        item: QStandardItem,
        path: tuple[str, ...],
    ) -> None:
        meta = self._byte_ranges_by_path.get(path)
        if meta is None:
            return
        byte_range = meta.get("byte_range")
        if _valid_byte_range(byte_range):
            item.setData(byte_range, _BYTE_RANGE_ROLE)
        highlight_ranges = meta.get("highlight_ranges")
        if isinstance(highlight_ranges, list):
            item.setData(highlight_ranges, _BYTE_HIGHLIGHT_RANGES_ROLE)

    @staticmethod
    def _make_blob(obj: Any) -> bytes:
        if isinstance(obj, bytes):
            return obj
        if isinstance(obj, str):
            return obj.encode("utf-8", errors="replace")
        try:
            return plistlib.dumps(obj, fmt=plistlib.FMT_XML)
        except Exception:
            if isinstance(obj, (list, tuple)):
                return "\n".join(str(item) for item in obj).encode("utf-8", errors="replace")
            return str(obj).encode("utf-8", errors="replace")

    def _apply_filter(self, text: str) -> None:
        """Show/hide rows whose key or value contains the search text."""
        self._filter_timer.stop()
        self._filter_text = text.lower()
        self._filter_items(self._model.invisibleRootItem(), self._filter_text)

    def _filter_items(self, parent: QStandardItem, text: str) -> bool:
        any_visible = False
        for row in range(parent.rowCount()):
            key_item = parent.child(row, 0)
            val_item = parent.child(row, 1)
            if key_item is None:
                continue
            if text and key_item.data(_PENDING_ROLE):
                # Rows not built yet: build them only where there's a hit.
                ref = key_item.data(_USER_ROLE)
                if isinstance(ref, _ObjRef) and _subtree_matches(ref.obj, text):
                    self._populate_children(key_item, apply_filter=False)
            child_visible = self._filter_items(key_item, text)
            key_match = not text or text in key_item.text().lower()
            val_match = val_item and text in val_item.text().lower()
            visible = key_match or bool(val_match) or child_visible
            self._tree.setRowHidden(
                row,
                self._model.indexFromItem(parent),
                not visible,
            )
            any_visible = any_visible or visible
        return any_visible

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "matches"):
            if event.matches(QKeySequence.StandardKey.Copy):
                key, val = self._current_key_value(for_copy=True)
                if key == "" and val == "":
                    return
                if val:
                    QApplication.clipboard().setText(val)
                else:
                    QApplication.clipboard().setText(key)
                return
        super().keyPressEvent(event)  # type: ignore[arg-type]

    def _current_key_value(self, for_copy: bool = False) -> tuple[str, str]:
        """Key and value text of the current row. *for_copy*: the English
        original of Crush's own words (e.g. "(3 keys)"), as copy writes it."""
        index = self._tree.currentIndex()
        if not index.isValid():
            return "", ""
        row = index.row()
        parent_index = index.parent()
        key_item = self._model.itemFromIndex(self._model.index(row, 0, parent_index))
        val_item = self._model.itemFromIndex(self._model.index(row, 1, parent_index))
        if key_item is None:
            return "", ""
        key = key_item.text()
        val = val_item.text() if val_item is not None else ""
        if for_copy and val_item is not None:
            val = val_item.data(EXPORT_TEXT_ROLE) or val
        return key, val

    def _update_value_field(self) -> None:
        _, val = self._current_key_value()
        self._value_field.setText(val)
        self._value_field.setCursorPosition(0)

    def _current_obj_and_key(self) -> tuple[Any, str]:
        index = self._tree.currentIndex()
        if not index.isValid():
            return None, ""
        row = index.row()
        parent_index = index.parent()
        key_item = self._model.itemFromIndex(self._model.index(row, 0, parent_index))
        if key_item is None:
            return None, ""
        ref = key_item.data(_USER_ROLE)
        obj = ref.obj if isinstance(ref, _ObjRef) else None
        return obj, key_item.text()

    def _on_context_menu(self, pos: object) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return
        self._tree.setCurrentIndex(index)
        key, val = self._current_key_value(for_copy=True)
        if not key and not val:
            return
        obj, _ = self._current_obj_and_key()
        menu = QMenu(self)
        inspect_action = menu.addAction(translate("TreeViewer", "Inspect BLOB…"))
        menu.addSeparator()
        copy_key = menu.addAction(translate("TreeViewer", "Copy key"))
        copy_value = menu.addAction(translate("TreeViewer", "Copy value"))
        copy_pair = menu.addAction(translate("TreeViewer", "Copy key = value"))
        action = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if action == inspect_action:
            from crush.viewers.table_viewer import BlobInspector
            BlobInspector(self._make_blob(obj), self).show()
        elif action == copy_key:
            QApplication.clipboard().setText(key)
        elif action == copy_value:
            QApplication.clipboard().setText(val)
        elif action == copy_pair:
            QApplication.clipboard().setText(f"{key} = {val}")
