# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tree viewer — displays plist, XML, and other hierarchical data."""
from __future__ import annotations

import plistlib
from collections.abc import Callable, Mapping
from typing import Any

from PySide6.QtCore import QT_TRANSLATE_NOOP, QModelIndex, QPersistentModelIndex, Qt, QTimer, Signal
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
from crush.viewers.generated_text import EXPORT_TEXT_ROLE, Gen, gen_text
from crush.viewers.value_field import show_value, value_text

_USER_ROLE = Qt.ItemDataRole.UserRole
_BYTE_RANGE_ROLE = Qt.ItemDataRole.UserRole + 1
_BYTE_HIGHLIGHT_RANGES_ROLE = Qt.ItemDataRole.UserRole + 2
# Set on a container row whose child rows aren't built yet (see _LazyTreeModel).
_PENDING_ROLE = Qt.ItemDataRole.UserRole + 3

# NSKeyedArchiver class metadata: in a tree resolved from an archive not
# shown as rows, the classname goes to the Type column instead
# (TreeViewer(fold_class_meta=True)). Every other tree shows these keys like
# any other: in JSON, XML or a plain plist they're ordinary data.
_CLASS_META_KEYS: tuple[str, ...] = ("$class", "$classes", "$classname")

# Rows the initial expansion may build (see TreeViewer._expand_initially):
# a few screens' worth, so opening stays instant whatever the file's size.
_INITIAL_EXPAND_ROWS = 1000


class _ObjRef:
    """Keep the node's original decoded value opaque to Qt's QVariant
    conversion — a bare dict/list/int stored via setData() gets walked by
    shiboken looking for a native Qt type, and a value in the uint64 range
    (e.g. an NSKeyedArchiver UID) raises OverflowError partway through.
    *path* is the node's key path, for building its child rows later."""

    def __init__(self, obj: Any, path: tuple[str, ...] = ()) -> None:
        self.obj = obj
        self.path = path


# Every helper below takes *hidden*, the dict keys not shown as rows, so the
# rows, their count, the Value text and the filter always agree. No default
# on purpose: a call that leaves it out is a type error, not a silent
# fallback to hiding.


def _child_entries(obj: Any, hidden: tuple[str, ...]) -> list[tuple[str, Any]]:
    """(key, value) of each child row of *obj*; empty for a leaf."""
    if isinstance(obj, dict):
        return [(str(k), v) for k, v in obj.items() if k not in hidden]
    if isinstance(obj, (list, tuple)):
        return [(str(i), v) for i, v in enumerate(obj)]
    return []


def _has_child_rows(obj: Any, hidden: tuple[str, ...]) -> bool:
    if isinstance(obj, dict):
        return any(k not in hidden for k in obj)
    return isinstance(obj, (list, tuple)) and bool(obj)


def _child_row_count(item: QStandardItem, hidden: tuple[str, ...]) -> int:
    """Rows under *item*, built or not."""
    ref = item.data(_USER_ROLE)
    if not item.data(_PENDING_ROLE) or not isinstance(ref, _ObjRef):
        return item.rowCount()
    obj = ref.obj
    if isinstance(obj, dict):
        return sum(1 for k in obj if k not in hidden)
    return len(obj)


_KEYS_TEXT = QT_TRANSLATE_NOOP("GeneratedView", "({count} keys)")
_ITEMS_TEXT = QT_TRANSLATE_NOOP("GeneratedView", "({count} items)")
_BLOB_TEXT = QT_TRANSLATE_NOOP("GeneratedView", "<BLOB {size:,} B>")


def _generated_value(obj: Any, hidden: tuple[str, ...]) -> tuple[str, dict[str, int]] | None:
    """(template, params) of a Value cell in Crush's own words; None for file data."""
    if isinstance(obj, dict):
        return _KEYS_TEXT, {"count": sum(1 for k in obj if k not in hidden)}
    if isinstance(obj, (list, tuple)):
        return _ITEMS_TEXT, {"count": len(obj)}
    if isinstance(obj, bytes):
        return _BLOB_TEXT, {"size": len(obj)}
    return None


def _value_texts(obj: Any, hidden: tuple[str, ...]) -> tuple[str, str]:
    """(English original, display text) of *obj*'s Value cell."""
    generated = _generated_value(obj, hidden)
    if generated is not None:
        template, params = generated
        return Gen(template, **params).pair()
    if isinstance(obj, ParseIssue):
        # A parser's note (e.g. in the Realm File Structure tree): shown in
        # the UI language, copied in English.
        return str(obj), render(obj, localized=True)
    return str(obj), str(obj)


def _display_value_text(obj: Any, translated: dict[str, str], hidden: tuple[str, ...]) -> str:
    """_value_texts(obj)[1], with each template translated once per filter
    pass (kept in *translated*) instead of once per row: the filter asks for
    every row's text, built or not."""
    generated = _generated_value(obj, hidden)
    if generated is None:
        return _value_texts(obj, hidden)[1]
    template, params = generated
    display = translated.get(template)
    if display is None:
        display = translated[template] = gen_text(template)
    try:
        return display.format(**params)
    except (KeyError, IndexError, ValueError):
        # As Gen.pair(): a translation whose placeholders don't fit falls back to English.
        return template.format(**params)


class _FilterPass:
    """What one filter pass remembers: each container's answer (the filter
    asks again at every level it builds on the way down to a hit) and each
    translated template."""

    def __init__(self, text: str, hidden: tuple[str, ...]) -> None:
        self.text = text
        self.hidden = hidden
        self.seen: dict[int, bool] = {}
        self.translated: dict[str, str] = {}


def _subtree_matches(obj: Any, fp: _FilterPass) -> bool:
    """Whether a row below *obj* would show the filter text (lowercase) in
    its Key or Value cell -- the filter's test, run on the data of rows not
    built yet."""
    known = fp.seen.get(id(obj))
    if known is not None:
        return known
    found = False
    for key, value in _child_entries(obj, fp.hidden):
        if (
            fp.text in key.lower()
            or fp.text in _display_value_text(value, fp.translated, fp.hidden).lower()
            or _subtree_matches(value, fp)
        ):
            found = True
            break
    fp.seen[id(obj)] = found
    return found


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

    # Bytes from a widget inside this viewer (a nested table, the BLOB
    # Inspector, ...) to open as a new tab -- see crush/viewers/open_bytes.py.
    open_bytes_with_format_requested = Signal(bytes, str, object, dict)

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
        fold_class_meta: bool = False,
    ) -> None:
        """*fold_class_meta*: *data* was resolved from an NSKeyedArchiver
        archive -- its $class / $classes / $classname keys are class metadata
        of the resolved objects: not listed as rows, the classname shown in
        the Type column. Only for such a tree; anywhere else they're data."""
        super().__init__(parent)
        self._raw = raw
        self._initial_hex_visible = hex_visible
        self._byte_ranges_by_path = byte_ranges_by_path or {}
        self._fold_class_meta = fold_class_meta
        self._hidden_keys: tuple[str, ...] = _CLASS_META_KEYS if fold_class_meta else ()
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
        if isinstance(data, (dict, list, tuple)):
            # The top level follows the same rows rule as every level below
            # (a resolved NSKeyedArchiver root would otherwise show "$class").
            for key, value in _child_entries(data, self._hidden_keys):
                self._build_items(root, value, key, ())
        else:
            self._build_items(root, data, "value", ())
        self._expand_initially()

    def _expand_initially(self) -> None:
        """Expand the first levels (up to depth 1) as long as that builds at
        most _INITIAL_EXPAND_ROWS rows in total, a whole level at a time: a
        small tree opens as before, a large one (e.g. a JSON export's
        top-level list of 500k records) opens collapsed instead of building
        and expanding every record (issue #127). Nothing is left out: every
        row stays one click away."""
        budget = _INITIAL_EXPAND_ROWS
        root = self._model.invisibleRootItem()
        level = [root.child(row, 0) for row in range(root.rowCount())]
        for _depth in range(2):
            cost = sum(_child_row_count(item, self._hidden_keys) for item in level)
            if cost == 0 or cost > budget:
                return
            budget -= cost
            # Build first, then expand: rows added under an expanded row
            # cost the view per row.
            for item in level:
                self._populate_children(item)
            for item in level:
                if item.rowCount():
                    self._tree.expand(self._model.indexFromItem(item))
            level = [item.child(row, 0) for item in level for row in range(item.rowCount())]

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
        if isinstance(obj, dict) and self._fold_class_meta:
            # Surface the NSKeyedArchiver classname in the Type column
            class_meta = obj.get("$class")
            classname = (
                class_meta.get("$classname", "") if isinstance(class_meta, dict) else ""
            )
            type_name = classname if classname else "dict"
        else:
            type_name = type(obj).__name__

        english, display = _value_texts(obj, self._hidden_keys)
        key_item = QStandardItem(str(key))
        val_item = QStandardItem(display)
        if display != english:
            val_item.setData(english, EXPORT_TEXT_ROLE)
        type_item = QStandardItem(type_name)
        key_item.setData(_ObjRef(obj, node_path), _USER_ROLE)
        self._apply_byte_range_metadata(key_item, node_path)
        if _has_child_rows(obj, self._hidden_keys):
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
        for key, value in _child_entries(ref.obj, self._hidden_keys):
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

    @staticmethod
    def _blob_origin(obj: Any) -> str:
        """What _make_blob hands the BLOB Inspector for *obj*: its own bytes,
        or a form Crush made from it -- said so, as those aren't stored bytes."""
        if isinstance(obj, bytes):
            return translate("TreeViewer", "the value's bytes")
        if isinstance(obj, str):
            return translate("TreeViewer", "the value's text, UTF-8 encoded")
        return translate(
            "TreeViewer",
            "the value written out by Crush as an XML plist (or as text) -- not bytes "
            "stored in the file",
        )

    def _apply_filter(self, text: str) -> None:
        """Show/hide rows whose key or value contains the search text."""
        self._filter_timer.stop()
        self._filter_text = text.lower()
        # Builds the rows of every hit not built yet -- on the UI thread, so a
        # short search text on a large tree takes a while: say so.
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._filter_items(self._model.invisibleRootItem(), self._filter_text)
        finally:
            QApplication.restoreOverrideCursor()

    def _filter_items(
        self, parent: QStandardItem, text: str, fp: _FilterPass | None = None
    ) -> bool:
        if fp is None:
            fp = _FilterPass(text, self._hidden_keys)
        any_visible = False
        for row in range(parent.rowCount()):
            key_item = parent.child(row, 0)
            val_item = parent.child(row, 1)
            if key_item is None:
                continue
            if text and key_item.data(_PENDING_ROLE):
                # Rows not built yet: build them only where there's a hit.
                ref = key_item.data(_USER_ROLE)
                if isinstance(ref, _ObjRef) and _subtree_matches(ref.obj, fp):
                    self._populate_children(key_item, apply_filter=False)
            child_visible = self._filter_items(key_item, text, fp)
            key_match = not text or text in key_item.text().lower()
            val_match = val_item and text in val_item.text().lower()
            visible = key_match or bool(val_match) or child_visible
            # Taken after the rows below were built: a model index isn't
            # guaranteed to survive a structural change.
            self._tree.setRowHidden(row, self._model.indexFromItem(parent), not visible)
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
        """Key and value text of the current row. *for_copy*: as copy writes
        it -- a blob's bytes as hex (the cell only says "<BLOB n B>"), and
        the English original of Crush's own words (e.g. "(3 keys)")."""
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
        if for_copy:
            ref = key_item.data(_USER_ROLE)
            if isinstance(ref, _ObjRef) and isinstance(ref.obj, bytes):
                val = value_text(ref.obj)
            elif val_item is not None:
                val = val_item.data(EXPORT_TEXT_ROLE) or val
        return key, val

    def _update_value_field(self) -> None:
        # A blob's cell says only "<BLOB n B>"; the field below shows its
        # bytes (as the Protobuf viewer does), whole -- as Copy value takes it.
        obj, _ = self._current_obj_and_key()
        _, val = self._current_key_value()
        show_value(self._value_field, obj if isinstance(obj, bytes) else val)

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
            keys: list[str] = []
            walk = index
            while walk.isValid():
                keys.append(str(walk.siblingAtColumn(0).data() or ""))
                walk = walk.parent()
            keys.reverse()
            BlobInspector(
                self._make_blob(obj), self,
                artifact_path="/virtual/tree/" + "/".join(keys),
                provenance={
                    "Source key": " / ".join(keys),
                    "Inspected bytes": self._blob_origin(obj),
                },
            ).show()
        elif action == copy_key:
            QApplication.clipboard().setText(key)
        elif action == copy_value:
            QApplication.clipboard().setText(val)
        elif action == copy_pair:
            QApplication.clipboard().setText(f"{key} = {val}")
