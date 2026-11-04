# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The Core Data views inside the table viewer: the Entities view's entity
tree and record detail, the models its grid and the History view show, and
the rows of the Store, Model, Keys and External Data views.

Everything shown comes from the store object the SQLite parser built
(crush.parsers.coredata_store.CoreDataStore) -- these widgets read its
results and never decide anything about the layout themselves.
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import (
    QT_TRANSLATE_NOOP,
    QAbstractTableModel,
    QModelIndex,
    QObject,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from crush.core.issues import ParseIssue, render_value
from crush.ui.i18n import translate
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.generated_text import (
    EXPORT_TEXT_ROLE,
    Gen,
    gen_item,
    gen_text,
    gens,
    set_headers,
)

ROWID_ROLE = Qt.ItemDataRole.UserRole + 1  # same role as the table viewer's rows
TARGET_ROLE = Qt.ItemDataRole.UserRole + 40
BYTES_ROLE = Qt.ItemDataRole.UserRole + 41
ENTITY_ROLE = Qt.ItemDataRole.UserRole + 42
_STATUS_COLOR = QColor("#cc8800")

# Values a Core Data view gets from the store at runtime (its English
# words): marked here, translated by their English text.
GENERATED_VALUES = (
    QT_TRANSLATE_NOOP("GeneratedView", "name match"),
    QT_TRANSLATE_NOOP("GeneratedView", "ambiguous"),
    QT_TRANSLATE_NOOP("GeneratedView", "no column found"),
    QT_TRANSLATE_NOOP("GeneratedView", "resolved"),
    QT_TRANSLATE_NOOP("GeneratedView", "unresolved"),
    QT_TRANSLATE_NOOP("GeneratedView", "to-one column"),
    QT_TRANSLATE_NOOP("GeneratedView", "inverse column"),
    QT_TRANSLATE_NOOP("GeneratedView", "join table"),
    QT_TRANSLATE_NOOP("GeneratedView", "destination column"),
    QT_TRANSLATE_NOOP("GeneratedView", "attribute"),
    QT_TRANSLATE_NOOP("GeneratedView", "derived attribute"),
    QT_TRANSLATE_NOOP("GeneratedView", "composite attribute"),
    QT_TRANSLATE_NOOP("GeneratedView", "relationship"),
    QT_TRANSLATE_NOOP("GeneratedView", "fetched property"),
    QT_TRANSLATE_NOOP("GeneratedView", "expression"),
    QT_TRANSLATE_NOOP("GeneratedView", "column"),
    QT_TRANSLATE_NOOP("GeneratedView", "insert"),
    QT_TRANSLATE_NOOP("GeneratedView", "update"),
    QT_TRANSLATE_NOOP("GeneratedView", "delete"),
    QT_TRANSLATE_NOOP("GeneratedView", "reference"),
    QT_TRANSLATE_NOOP("GeneratedView", "unrecognised"),
    QT_TRANSLATE_NOOP("GeneratedView", "file"),
    QT_TRANSLATE_NOOP("GeneratedView", "entity"),
    QT_TRANSLATE_NOOP("GeneratedView", "exists"),
    QT_TRANSLATE_NOOP("GeneratedView", "no such row"),
    QT_TRANSLATE_NOOP("GeneratedView", "true"),
    QT_TRANSLATE_NOOP("GeneratedView", "false"),
)
_GENERATED_SET = frozenset(GENERATED_VALUES)


def word(english: str | None) -> Gen | str:
    """A store word (status, kind) as a translatable Gen when it's one of
    GENERATED_VALUES, else as it is."""
    if english is None:
        return ""
    return Gen(english) if english in _GENERATED_SET else english


class Cell:
    """One precomputed cell: what's shown, its raw value (sorting, copy,
    BLOB actions), a tooltip, a colour and the English text for export."""

    __slots__ = ("display", "raw", "tooltip", "color", "export")

    def __init__(
        self,
        display: Any = "",
        raw: Any = None,
        tooltip: Any = None,
        color: QColor | None = None,
    ) -> None:
        self.export: str | None = None
        if isinstance(display, Gen):
            english, shown = display.pair()
            self.display = shown
            self.export = english if english != shown else None
        else:
            self.display = "" if display is None else str(display)
        self.raw = raw
        self.tooltip = render_value(tooltip, localized=True) if tooltip is not None else None
        self.color = color


def stored_cell(value: Any, tooltip: Any = None) -> Cell:
    """A value as stored, the way the table grid shows it."""
    if value is None:
        return Cell("", None, tooltip, QColor(Qt.GlobalColor.gray))
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        return Cell(f"<BLOB {len(data):,} B>", data, tooltip, QColor(Qt.GlobalColor.blue))
    return Cell(str(value), value if isinstance(value, (int, float)) else None, tooltip)


class Header:
    __slots__ = ("label", "tooltip")

    def __init__(self, label: str | Gen, tooltip: Any = None) -> None:
        self.label = label
        self.tooltip = tooltip

    def pair(self) -> tuple[str, str]:
        return self.label.pair() if isinstance(self.label, Gen) else (self.label, self.label)


class _SelfSortingModel(QAbstractTableModel):
    """A Core Data view's model that sorts and filters itself, like the
    Strings view's: tens of thousands of rows through the proxy's per-cell
    Python calls would freeze the UI. *_order* is the shown order of the
    rows (indexes into the data), *_shown* the rows the filter keeps.
    Column 0 is "Row": the row's place in the order it was read."""

    sorts_itself = True

    def _init_rows(self, total: int) -> None:
        self._total = total
        self._order: list[int] = list(range(total))
        self._shown: list[int] = self._order
        self._filter = ""
        self._haystack: list[str] | None = None

    def total_rows(self) -> int:
        return self._total

    def record_index(self, row: int) -> int:
        """The data index of shown row *row*."""
        return self._shown[row]

    def shown_row(self, index: int) -> int | None:
        """The shown row of data index *index* (None if filtered out)."""
        try:
            return self._shown.index(index)
        except ValueError:
            return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._shown)

    # Subclasses: the text a row is searched in, and a column's sort key.
    def _row_text(self, index: int) -> str:
        raise NotImplementedError

    def _sort_key(self, index: int, col: int) -> Any:
        raise NotImplementedError

    def needs_haystack(self) -> bool:
        return self._haystack is None

    def build_haystack(self) -> list[str]:
        """Every row's searched text (casefolded); safe off the UI thread."""
        return [self._row_text(i).casefold() for i in range(self._total)]

    def set_haystack(self, haystack: list[str]) -> None:
        self._haystack = haystack

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        if column < 0 or column >= self.columnCount():
            return
        self.layoutAboutToBeChanged.emit()
        if column == 0:
            self._order = list(range(self._total))
        else:
            self._order = sorted(range(self._total), key=lambda i: _key(self._sort_key(i, column)))
        if order == Qt.SortOrder.DescendingOrder:
            self._order.reverse()
        self._apply_filter_rows()
        self.layoutChanged.emit()

    def set_filter(self, text: str) -> None:
        """Keep rows where any cell's shown text contains *text*,
        case-insensitively -- what the proxy's fixed-string filter does
        for the other views."""
        self.beginResetModel()
        self._filter = text.casefold()
        self._apply_filter_rows()
        self.endResetModel()

    def _apply_filter_rows(self) -> None:
        if not self._filter:
            self._shown = self._order
            return
        if self._haystack is None:
            self._haystack = self.build_haystack()
        hay = self._haystack
        needle = self._filter
        self._shown = [i for i in self._order if needle in hay[i]]


def _key(value: Any) -> tuple[int, Any]:
    """Sort key over mixed stored types: NULL first, then numbers by value,
    then text, then BLOBs by their bytes."""
    if value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (1, value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return (3, bytes(value))
    return (2, str(value).casefold())


class RowsModel(_SelfSortingModel):
    """A generated view with many rows (History): cells built once (off the
    UI thread), shown without creating an item per cell."""

    def __init__(
        self,
        headers: list[Header],
        rows: list[list[Cell]],
        parent: QObject | None = None,
        row_data: list[Any] | None = None,
        haystack: list[str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._headers = [Header(Gen(QT_TRANSLATE_NOOP("GeneratedView", "Row")))] + headers
        self._rows = rows
        self.row_data = row_data or []
        self._init_rows(len(rows))
        self._haystack = haystack

    def row_record(self, row: int) -> Any:
        index = self.record_index(row)
        return self.row_data[index] if 0 <= index < len(self.row_data) else None

    def _row_text(self, index: int) -> str:
        return "\x00".join([str(index + 1)] + [c.display for c in self._rows[index]])

    def _sort_key(self, index: int, col: int) -> Any:
        cell = self._rows[index][col - 1] if col - 1 < len(self._rows[index]) else Cell()
        return cell.raw if isinstance(cell.raw, (int, float)) else (cell.display or None)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._headers)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation != Qt.Orientation.Horizontal or not 0 <= section < len(self._headers):
            return None
        header = self._headers[section]
        english, display = header.pair()
        if role == Qt.ItemDataRole.DisplayRole:
            return display
        if role == EXPORT_TEXT_ROLE:
            return english if english != display else None
        if role == Qt.ItemDataRole.ToolTipRole and header.tooltip is not None:
            return render_value(header.tooltip, localized=True)
        return None

    def cell(self, row: int, col: int) -> Cell:
        index = self.record_index(row)
        if col == 0:
            return Cell(str(index + 1), index + 1)
        cells = self._rows[index]
        return cells[col - 1] if col - 1 < len(cells) else Cell()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        cell = self.cell(index.row(), index.column())
        if role == Qt.ItemDataRole.DisplayRole:
            return cell.display
        if role == Qt.ItemDataRole.UserRole:
            return cell.raw
        if role == Qt.ItemDataRole.ToolTipRole:
            return cell.tooltip
        if role == Qt.ItemDataRole.ForegroundRole:
            return cell.color
        if role == EXPORT_TEXT_ROLE:
            return cell.export
        return None


class RecordModel(_SelfSortingModel):
    """The Entities view's records: every row of the selected entity, read
    from *records* (a RecordSet) cell by cell when shown. Column 0 is
    "Row"; the others follow the store's grid columns. Row arguments are
    shown rows; record_index() maps one to its row in *records*."""

    def __init__(self, store: Any, records: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.store = store
        self.records = records
        self._grid = records.grid
        self._cache: dict[int, list[tuple[str, Any]]] = {}
        self._init_rows(len(records.rows))

    def record_values(self, row: int) -> tuple[Any, ...]:
        return self.records.rows[self.record_index(row)]

    def _row_text(self, index: int) -> str:
        return "\x00".join([str(index + 1)] + [text for text, _s in self._cells(index)])

    def _sort_key(self, index: int, col: int) -> Any:
        grid = self.grid_column(col)
        if grid is None:
            return None
        if grid.source is None or grid.is_entity_name:
            return self._cells(index)[col - 1][0]
        return self.records.rows[index][grid.source]

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._grid) + 1

    def grid_column(self, col: int) -> Any:
        return self._grid[col - 1] if 1 <= col <= len(self._grid) else None

    def source_column(self, col: int) -> int | None:
        """Index of the table column a grid column shows (for hex provenance)."""
        grid = self.grid_column(col)
        return grid.source if grid is not None else None

    def column_name(self, col: int) -> str | None:
        source = self.source_column(col)
        return self.records.columns[source][0] if source is not None else None

    def rowid(self, row: int) -> Any:
        if not 0 <= row < len(self._shown):
            return None
        index = self.record_index(row)
        return self.records.rowids[index] if 0 <= index < len(self.records.rowids) else None

    def row_of_rowid(self, rowid: Any) -> int | None:
        try:
            return self.shown_row(self.records.rowids.index(rowid))
        except ValueError:
            return None

    def row_of_pk(self, pk: Any) -> int | None:
        """The shown row of the record with *pk* (None: no such record, or
        filtered out)."""
        col = next((i for i, (c, _t) in enumerate(self.records.columns) if c.upper() == "Z_PK"), None)
        if col is None:
            return None
        index = next((r for r, row in enumerate(self.records.rows) if row[col] == pk), None)
        return self.shown_row(index) if index is not None else None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation != Qt.Orientation.Horizontal:
            return None
        if section == 0:
            english, display = Gen(QT_TRANSLATE_NOOP("GeneratedView", "Row")).pair()
            tooltip = None
        else:
            grid = self.grid_column(section)
            if grid is None:
                return None
            if grid.is_entity_name:
                english, display = Gen(QT_TRANSLATE_NOOP("GeneratedView", "entity [derived]")).pair()
            elif grid.derived:
                english = f"{grid.header} [derived]"
                display = Gen(
                    QT_TRANSLATE_NOOP("GeneratedView", "{name} [derived]"), name=grid.header
                ).pair()[1]
            else:
                english = display = grid.header
            tooltip = grid.tooltip
        if role == Qt.ItemDataRole.DisplayRole:
            return display
        if role == EXPORT_TEXT_ROLE:
            return english if english != display else None
        if role == Qt.ItemDataRole.ToolTipRole and tooltip is not None:
            return render_value(tooltip, localized=True)
        return None

    def _cells(self, index: int) -> list[tuple[str, Any]]:
        cached = self._cache.get(index)
        if cached is None:
            values = self.records.rows[index]
            cached = [self.store.cell_text(self.records, values, g) for g in self._grid]
            self._cache[index] = cached
        return cached

    def raw_value(self, row: int, col: int) -> Any:
        grid = self.grid_column(col)
        if grid is None or grid.source is None:
            return None
        return self.records.rows[self.record_index(row)][grid.source]

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        record = self.record_index(row)
        if col == 0:
            if role == Qt.ItemDataRole.DisplayRole:
                return str(record + 1)
            if role == Qt.ItemDataRole.UserRole:
                return record + 1
            if role == ROWID_ROLE:
                return self.rowid(row)
            return None
        text, status = self._cells(record)[col - 1]
        raw = self.raw_value(row, col)
        grid = self.grid_column(col)
        if role == Qt.ItemDataRole.DisplayRole:
            return text
        is_name = grid is not None and grid.is_entity_name
        is_decoded = grid is not None and grid.is_decoded
        if role == Qt.ItemDataRole.UserRole:
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)
            return None if is_name else raw
        if role == Qt.ItemDataRole.ToolTipRole:
            return render_value(status, localized=True) if status is not None else None
        if role == Qt.ItemDataRole.ForegroundRole:
            if status is not None and (is_decoded or is_name):
                return _STATUS_COLOR
            if raw is None and not is_name:
                return Qt.GlobalColor.gray
            if isinstance(raw, (bytes, bytearray, memoryview)) and not is_decoded:
                return Qt.GlobalColor.blue
        return None


class EntityTreePanel(QWidget):
    """The entities in Z_PRIMARYKEY, subentities nested under their parent,
    each with the rows it shows. Emits entitySelected(name)."""

    entitySelected = Signal(str)
    backRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        top = QHBoxLayout()
        top.setContentsMargins(4, 2, 4, 0)
        self.back_button = QPushButton(translate("CoreDataView", "Back"))
        self.back_button.setToolTip(
            translate("CoreDataView", "Return to the record shown before following a relationship")
        )
        self.back_button.setEnabled(False)
        self.back_button.clicked.connect(self.backRequested.emit)
        top.addWidget(QLabel(translate("CoreDataView", "Entities (rows)")))
        top.addStretch()
        top.addWidget(self.back_button)
        layout.addLayout(top)
        self.model = QStandardItemModel(self)
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self.tree.selectionModel().currentChanged.connect(self._on_current)
        install_horizontal_wheel_scroll(self.tree)
        layout.addWidget(self.tree, stretch=1)
        self._items: dict[str, QStandardItem] = {}
        self._loading = False

    def populate(self, store: Any, counts: dict[str, dict[Any, int]]) -> None:
        self._loading = True
        self.model.clear()
        self._items.clear()
        set_headers(self.model, gens(
            QT_TRANSLATE_NOOP("GeneratedView", "Entity"),
            QT_TRANSLATE_NOOP("GeneratedView", "Rows"),
            QT_TRANSLATE_NOOP("GeneratedView", "Z_ENT"),
            QT_TRANSLATE_NOOP("GeneratedView", "Status"),
        ))

        def add(parent: QStandardItem, info: Any, seen: set[int]) -> None:
            status = store.entity_status(info.name)
            name_item = QStandardItem(info.name)
            name_item.setEditable(False)
            name_item.setData(info.name, ENTITY_ROLE)
            status_text = render_value(status, localized=True) if status is not None else ""
            status_item = QStandardItem(status_text)
            status_item.setEditable(False)
            if status is not None:
                name_item.setToolTip(status_text)
                status_item.setToolTip(status_text)
                name_item.setForeground(_STATUS_COLOR)
                status_item.setForeground(_STATUS_COLOR)
            count = store.entity_row_count(info.name, counts)
            count_item = QStandardItem("" if count is None else f"{count:,}")
            count_item.setEditable(False)
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if count is not None:
                count_item.setData(count, Qt.ItemDataRole.UserRole)
            ent_item = QStandardItem(str(info.ent))
            ent_item.setEditable(False)
            parent.appendRow([name_item, count_item, ent_item, status_item])
            self._items[info.name] = name_item
            for child in sorted(store.children(info.ent), key=lambda e: e.name.lower()):
                if child.ent not in seen:
                    add(name_item, child, seen | {child.ent})

        roots = [e for e in store.entities if e.super_ent in (0, None) or store.entity_by_ent(e.super_ent) is None]
        for info in sorted(roots, key=lambda e: e.name.lower()):
            add(self.model.invisibleRootItem(), info, {info.ent})
        self.tree.expandToDepth(0)
        self.tree.resizeColumnToContents(0)
        self._loading = False

    def select(self, name: str) -> None:
        item = self._items.get(name)
        if item is None:
            return
        index = self.model.indexFromItem(item)
        self.tree.setCurrentIndex(index)
        self.tree.scrollTo(index)

    def current(self) -> str | None:
        index = self.tree.currentIndex()
        if not index.isValid():
            return None
        item = self.model.itemFromIndex(index.siblingAtColumn(0))
        return item.data(ENTITY_ROLE) if item is not None else None

    def _on_current(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if self._loading or not current.isValid():
            return
        item = self.model.itemFromIndex(current.siblingAtColumn(0))
        if item is not None and item.data(ENTITY_ROLE):
            self.entitySelected.emit(item.data(ENTITY_ROLE))


class RecordDetailPanel(QWidget):
    """The selected record: every property by model type with its raw
    value and column, the columns no property names, and its relationships
    with their targets. Emits navigateRequested(entity, pk) for a target and
    openBytesRequested(bytes, label) for a binary value."""

    navigateRequested = Signal(str, object)
    openBytesRequested = Signal(bytes, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.label = QLabel(translate("CoreDataView", "Select a record to show its properties and relationships."))
        self.label.setWordWrap(True)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label.setStyleSheet("padding: 2px 8px; color: palette(mid);")
        layout.addWidget(self.label)
        self.model = QStandardItemModel(self)
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self.tree.doubleClicked.connect(self._on_double_clicked)
        install_horizontal_wheel_scroll(self.tree)
        layout.addWidget(self.tree, stretch=1)

    def clear(self) -> None:
        self.model.clear()
        self.label.setText(translate("CoreDataView", "Select a record to show its properties and relationships."))

    def show_record(
        self, entity: str, pk: Any, table: str, values: list[Any], relationships: list[Any] | None,
        note: Any = None,
    ) -> None:
        self.model.clear()
        set_headers(self.model, gens(
            QT_TRANSLATE_NOOP("GeneratedView", "Property"),
            QT_TRANSLATE_NOOP("GeneratedView", "Kind"),
            QT_TRANSLATE_NOOP("GeneratedView", "Type"),
            QT_TRANSLATE_NOOP("GeneratedView", "Value"),
            QT_TRANSLATE_NOOP("GeneratedView", "Raw"),
            QT_TRANSLATE_NOOP("GeneratedView", "Column"),
            QT_TRANSLATE_NOOP("GeneratedView", "Status"),
        ))
        head = translate("CoreDataView", "Record {entity} · table {table} · Z_PK {pk}").format(
            entity=entity, table=table, pk=pk,
        )
        if note is not None:
            head += "\n" + render_value(note, localized=True)
        self.label.setText(head)
        root = self.model.invisibleRootItem()
        attrs = gen_item(Gen(QT_TRANSLATE_NOOP("GeneratedView", "Properties")))
        attrs.setEditable(False)
        root.appendRow([attrs] + [QStandardItem("") for _ in range(6)])
        for value in values:
            raw = value.raw
            raw_text = (
                "; ".join(_raw_text(v) for v in raw) if isinstance(raw, tuple) else _raw_text(raw)
            )
            items = [
                QStandardItem(value.name),
                _item(word(value.kind)),
                QStandardItem(value.type_text),
                QStandardItem(value.value),
                QStandardItem(raw_text),
                QStandardItem(", ".join(value.columns)),
                QStandardItem(render_value(value.status, localized=True) if value.status is not None else ""),
            ]
            if isinstance(raw, (bytes, bytearray, memoryview)):
                items[0].setData(bytes(raw), BYTES_ROLE)
                items[4].setToolTip(translate("CoreDataView", "Double-click to inspect the bytes"))
            if value.status is not None:
                items[6].setForeground(_STATUS_COLOR)
            for it in items:
                it.setEditable(False)
            attrs.appendRow(items)
        if relationships is not None:
            rels = gen_item(Gen(QT_TRANSLATE_NOOP("GeneratedView", "Relationships")))
            rels.setEditable(False)
            root.appendRow([rels] + [QStandardItem("") for _ in range(6)])
            for rel in relationships:
                self._add_relationship(rels, rel)
        self.tree.expandToDepth(0)
        for col in range(self.model.columnCount()):
            self.tree.resizeColumnToContents(col)

    def _add_relationship(self, parent: QStandardItem, rel: Any) -> None:
        rule = rel.rule
        if rule.resolved:
            count = len(rel.targets)
            summary = (
                f"→ {rel.destination} #{rel.targets[0].pk}" if not rel.to_many and rel.targets
                else (f"→ {count:,} " + translate("CoreDataView", "objects") if rel.to_many else "—")
            )
        else:
            summary = "; ".join(f"{c} = {_raw_text(v)}" for c, v in (rel.stored or ())) or "—"
        where = rule.table or ""
        if rule.kind == "join table" and rule.table:
            where = translate("CoreDataView", "join {table}").format(table=rule.table)
        columns = ", ".join(c for c in (rule.key_column, rule.source_column, rule.ent_column, rule.order_column) if c)
        status = rel.status if rel.status is not None else rule.reason
        items = [
            QStandardItem(rel.name),
            _item(word("relationship")),
            QStandardItem(("→ " if not rel.to_many else "↠ ") + (rel.destination or "?")),
            QStandardItem(summary),
            QStandardItem(_raw_text(rel.stored) if not isinstance(rel.stored, tuple) else ""),
            QStandardItem(f"{where} {columns}".strip() if rule.resolved else ", ".join(rule.candidates)),
            _item(word(rule.status)) if status is None else QStandardItem(
                f"{gen_text(rule.status)}: {render_value(status, localized=True)}"  # i18n: keep -- layout
            ),
        ]
        if status is not None:
            items[6].setForeground(_STATUS_COLOR)
        for it in items:
            it.setEditable(False)
        if rule.resolved and not rel.to_many and rel.targets:
            items[0].setData((rel.targets[0].entity, rel.targets[0].pk), TARGET_ROLE)
        parent.appendRow(items)
        if rel.to_many:
            for target in rel.targets:
                child = [
                    QStandardItem(f"#{target.pk}"),
                    QStandardItem(""),
                    QStandardItem(target.entity or ""),
                    QStandardItem(
                        "" if target.order is None else translate("CoreDataView", "order {n}").format(n=target.order)
                    ),
                    QStandardItem(_raw_text(target.pk)),
                    QStandardItem(""),
                    _item(word("exists" if target.exists else "no such row")),
                ]
                if not target.exists:
                    child[6].setForeground(_STATUS_COLOR)
                child[0].setData((target.entity, target.pk), TARGET_ROLE)
                for it in child:
                    it.setEditable(False)
                items[0].appendRow(child)
        elif rel.targets and not rel.targets[0].exists:
            items[6].setText(render_value(rel.status, localized=True) if rel.status else items[6].text())

    def _on_double_clicked(self, index: QModelIndex) -> None:
        item = self.model.itemFromIndex(index.siblingAtColumn(0))
        if item is None:
            return
        target = item.data(TARGET_ROLE)
        if target is not None:
            self.navigateRequested.emit(target[0] or "", target[1])
            return
        data = item.data(BYTES_ROLE)
        if isinstance(data, bytes):
            self.openBytesRequested.emit(data, item.text())


class ObjectDetailPanel(QWidget):
    """Every stored key of a model object (DetailNode trees), for the
    Core Data Model view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.label = QLabel(translate("CoreDataView", "Select a row to show every key its objects store."))
        self.label.setWordWrap(True)
        self.label.setStyleSheet("padding: 2px 8px; color: palette(mid);")
        layout.addWidget(self.label)
        self.model = QStandardItemModel(self)
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setAlternatingRowColors(True)
        install_horizontal_wheel_scroll(self.tree)
        layout.addWidget(self.tree, stretch=1)

    def show_sections(self, sections: list[tuple[str, list[Any]]]) -> None:
        self.model.clear()
        set_headers(self.model, gens(
            QT_TRANSLATE_NOOP("GeneratedView", "Key"),
            QT_TRANSLATE_NOOP("GeneratedView", "Value"),
            QT_TRANSLATE_NOOP("GeneratedView", "Class"),
        ))
        root = self.model.invisibleRootItem()
        for title, nodes in sections:
            head = QStandardItem(title)
            head.setEditable(False)
            root.appendRow([head, QStandardItem(""), QStandardItem("")])
            for node in nodes:
                _append_detail(head, node)
        self.tree.expandToDepth(1)
        self.tree.resizeColumnToContents(0)
        self.tree.setColumnWidth(1, 420)
        self.label.setText("")


def model_detail_sections(source: Any, mrow: Any) -> list[tuple[str, list[Any]]]:
    """Every stored key of the row's property (and the property a proxy
    stands for), of its entity and of the model -- for the detail pane."""
    prop = mrow.prop
    title = translate("CoreDataView", "{class_name} {name} (#{index})")
    sections: list[tuple[str, list[Any]]] = []
    if prop.kind != "entity":
        sections.append((title.format(class_name=prop.via_class or prop.class_name, name=prop.name,
                                      index=prop.index), source.describe(prop.index)))
        if prop.underlying_index is not None:
            sections.append((title.format(class_name=prop.class_name, name=prop.name,
                                          index=prop.underlying_index), source.describe(prop.underlying_index)))
    if mrow.entity_index is not None:
        sections.append((title.format(class_name="NSEntityDescription", name=mrow.entity,
                                      index=mrow.entity_index), source.describe(mrow.entity_index)))
    if mrow.model_index is not None:
        sections.append((translate("CoreDataView", "{class_name} (#{index})").format(
            class_name="NSManagedObjectModel", index=mrow.model_index,
        ), source.describe(mrow.model_index)))
    return sections


class ModelView(QWidget):
    """The Core Data Model view of a model on its own (a .mom file): one
    row per property as each entity lists it, without column candidates (no
    store to match against), every stored key of the selected row below."""

    def __init__(self, source: Any, parent: QWidget | None = None) -> None:
        from PySide6.QtCore import QSortFilterProxyModel
        from PySide6.QtWidgets import QLineEdit, QSplitter, QTableView

        super().__init__(parent)
        self._source = source
        self._rows = source.model_rows()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        if source.model_issues:
            status = QLabel("\n".join(render_value(i, localized=True) for i in source.model_issues))
            status.setWordWrap(True)
            status.setStyleSheet("padding: 2px 8px; color: #cc8800;")
            layout.addWidget(status)
        self.search = QLineEdit()
        self.search.setPlaceholderText(translate("CoreDataView", "Filter rows…"))
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self.model = QStandardItemModel(self)
        headers, cells = model_rows_cells(self._rows, with_columns=False)
        fill_standard_model(self.model, headers, cells)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.resizeColumnsToContents()
        self.table.selectionModel().currentChanged.connect(self._on_current)
        self.detail = ObjectDetailPanel()
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        layout.addWidget(splitter, stretch=1)

    def _on_current(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            return
        row = self.proxy.mapToSource(current).row()
        if 0 <= row < len(self._rows):
            self.detail.show_sections(model_detail_sections(self._source, self._rows[row]))


def _append_detail(parent: QStandardItem, node: Any) -> None:
    items = [QStandardItem(node.key), QStandardItem(node.value), QStandardItem(node.class_name)]
    for it in items:
        it.setEditable(False)
    items[1].setToolTip(node.value)
    parent.appendRow(items)
    for child in node.children:
        _append_detail(items[0], child)


def _item(text: Gen | str) -> QStandardItem:
    if isinstance(text, Gen):
        return gen_item(text)
    return QStandardItem(text)


def _raw_text(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        head = data[:16].hex(" ")
        return f"<BLOB {len(data):,} B> {head}" + (" …" if len(data) > 16 else "")
    return repr(value) if isinstance(value, str) else str(value)


def status_lines(*issues: Any) -> list[Any]:
    return [i for i in issues if i is not None]


class HistoryTable:
    """The History view's cells and search text, built off the UI thread
    (history_table) and shown by a RowsModel (model)."""

    def __init__(self, headers: list[Header], rows: list[list[Cell]], result: Any) -> None:
        self.headers = headers
        self.rows = rows
        self.result = result
        self.haystack = [
            "\x00".join([str(i + 1)] + [c.display for c in cells]).casefold()
            for i, cells in enumerate(rows)
        ]

    def model(self, parent: QObject | None = None) -> RowsModel:
        return RowsModel(self.headers, self.rows, parent, row_data=self.result.rows, haystack=self.haystack)


def history_table(result: Any) -> HistoryTable:
    """The Core Data History view: one row per ACHANGE row, the stored
    references next to what they resolve to, tombstones as attribute =
    value (interpreted) and every raw slot. Plain Python: safe off the UI
    thread."""
    g = QT_TRANSLATE_NOOP
    headers = [
        Header("Z_PK"),
        Header("ZTRANSACTIONID"),
        Header(Gen(g("GeneratedView", "Time (UTC) [derived]"))),
        Header("ZTIMESTAMP"),
        Header(Gen(g("GeneratedView", "Author"))), Header("ZAUTHORTS"), Header("ZAUTHOR"),
        Header(Gen(g("GeneratedView", "Bundle ID"))), Header("ZBUNDLEIDTS"), Header("ZBUNDLEID"),
        Header(Gen(g("GeneratedView", "Process"))), Header("ZPROCESSIDTS"), Header("ZPROCESSID"),
        Header(Gen(g("GeneratedView", "Context"))), Header("ZCONTEXTNAMETS"), Header("ZCONTEXTNAME"),
        Header(Gen(g("GeneratedView", "Change type [derived]"))),
        Header("ZCHANGETYPE"),
        Header("ZENTITY"),
        Header(Gen(g("GeneratedView", "Entity [derived]"))),
        Header("ZENTITYPK"),
        Header(Gen(g("GeneratedView", "Object now [derived]"))),
        Header("ZCOLUMNS"),
        Header(Gen(g("GeneratedView", "ZCOLUMNS set bits [derived]")), ParseIssue("coredata.zcolumns_undetermined")),
        Header(Gen(g("GeneratedView", "Tombstones [interpreted]")), ParseIssue("coredata.tombstones_interpreted")),
    ] + [Header(c) for c in result.tombstone_columns]
    rows: list[list[Cell]] = []
    for r in result.rows:
        cells = [stored_cell(r.change_pk), stored_cell(r.transaction)]
        cells.append(Cell(r.timestamp or "", r.timestamp_raw if isinstance(r.timestamp_raw, (int, float)) else None,
                          r.timestamp_status, _STATUS_COLOR if r.timestamp_status is not None else None))
        cells.append(stored_cell(r.timestamp_raw))
        for key in ("author", "bundle", "process", "context"):
            ref, name, text = r.strings[key]
            cells.append(Cell(name if name is not None else "", None))
            cells.append(stored_cell(ref))
            cells.append(stored_cell(text))
        cells.append(Cell(word(r.change_type)))
        cells.append(stored_cell(r.change_type_raw))
        cells.append(stored_cell(r.entity_raw))
        cells.append(Cell(r.entity_name or ""))
        cells.append(stored_cell(r.entity_pk))
        if r.target_exists is None:
            cells.append(Cell(""))
        else:
            cells.append(Cell(word("exists" if r.target_exists else "no such row")))
        columns_raw = r.columns_raw
        if isinstance(columns_raw, (bytes, bytearray, memoryview)):
            cells.append(Cell(bytes(columns_raw).hex(" "), bytes(columns_raw)))
        else:
            cells.append(stored_cell(columns_raw))
        bits = r.columns_bits
        cells.append(Cell(", ".join(str(b) for b in bits) if bits else "", None,
                          ParseIssue("coredata.zcolumns_undetermined") if bits else None))
        tomb_parts = []
        tomb_tip = []
        for slot in r.tombstones:
            if slot.attribute is not None:
                tomb_parts.append(f"{slot.attribute}={_tomb_text(slot.raw)}")
            else:
                tomb_parts.append(f"[{slot.slot}]={_tomb_text(slot.raw)} ⚠")  # i18n: keep -- layout
                tomb_tip.append(
                    render_value(slot.status, localized=True) + " — "
                    + translate("CoreDataView", "candidates: {names}").format(names=", ".join(slot.candidates) or "—")
                )
        cells.append(Cell("; ".join(tomb_parts), None,
                          "\n".join(tomb_tip) if tomb_tip else None,
                          _STATUS_COLOR if tomb_tip else None))
        for column in result.tombstone_columns:
            cells.append(stored_cell(r.raw.get(column.upper())))
        rows.append(cells)
    return HistoryTable(headers, rows, result)


def _tomb_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        if len(data) == 16:
            import uuid

            return str(uuid.UUID(bytes=data)).upper()
        return f"<BLOB {len(data):,} B>"
    return str(value)


def model_rows_cells(rows: list[Any], with_columns: bool) -> tuple[list[Header], list[list[Cell]]]:
    """The Core Data Model view: one row per property as each entity lists it."""
    g = QT_TRANSLATE_NOOP
    headers = [
        Header(Gen(g("GeneratedView", "Entity"))), Header("Z_ENT"),
        Header(Gen(g("GeneratedView", "Superentity"))),
    ]
    if with_columns:
        headers.append(Header(Gen(g("GeneratedView", "Root table"))))
    headers += [
        Header(Gen(g("GeneratedView", "Property"))),
        Header(Gen(g("GeneratedView", "Declared in"))),
        Header(Gen(g("GeneratedView", "Kind"))),
        Header(Gen(g("GeneratedView", "Class"))),
        Header(Gen(g("GeneratedView", "Type"))),
        Header(Gen(g("GeneratedView", "Value class"))),
        Header(Gen(g("GeneratedView", "Transformer"))),
        Header("NSFlagsKey"),
        Header("NSIsOptional"),
        Header("_P"),
    ]
    if with_columns:
        headers += [
            Header(Gen(g("GeneratedView", "Column candidates")), ParseIssue("coredata.mapping_heuristic")),
            Header(Gen(g("GeneratedView", "Declared SQL type"))),
            Header(Gen(g("GeneratedView", "Mapping status")), ParseIssue("coredata.mapping_heuristic")),
        ]
    headers += [
        Header(Gen(g("GeneratedView", "Destination"))),
        Header(Gen(g("GeneratedView", "Inverse"))),
        Header("NSMinCount"), Header("NSMaxCount"),
        Header(Gen(g("GeneratedView", "Delete rule"))),
        Header("NSIsOrdered"),
    ]
    if with_columns:
        headers += [
            Header(Gen(g("GeneratedView", "Relationship rule")), ParseIssue("coredata.rel_rules")),
            Header(Gen(g("GeneratedView", "Rule status"))),
        ]
    out: list[list[Cell]] = []
    for row in rows:
        prop = row.prop
        type_text = ""
        if prop.attribute_type is not None:
            type_text = f"{prop.type_name() or 'unknown'} ({prop.attribute_type})"
        cells = [Cell(row.entity), stored_cell(row.ent), Cell(row.superentity or "")]
        if with_columns:
            cells.append(Cell(row.table or ""))
        cls = prop.class_name + (f" (via {prop.via_class})" if prop.via_class else "")
        unknown_class = None if prop.known_class else ParseIssue("coredata.model_unknown_class", {
            "entity": row.entity, "property": prop.name, "class_name": prop.class_name,
        })
        unknown_type = None
        if prop.attribute_type is not None and prop.type_name() is None:
            unknown_type = ParseIssue("coredata.unknown_attribute_type", {
                "entity": row.entity, "property": prop.name, "type": prop.attribute_type,
            })
        cells += [
            Cell(prop.name), Cell(row.declared_in), Cell(word(prop.kind)),
            Cell(cls, None, unknown_class, _STATUS_COLOR if unknown_class else None),
            Cell(type_text, prop.attribute_type, unknown_type, _STATUS_COLOR if unknown_type else None),
            Cell(prop.value_class or ""), Cell(prop.transformer or ""),
            stored_cell(prop.flags), stored_cell(prop.optional), stored_cell(prop.p_value),
        ]
        if with_columns:
            cells += [
                Cell(", ".join(c for c, _t in row.candidates)),
                Cell(", ".join(t or "—" for _c, t in row.candidates)),
                Cell(word(row.mapping)),
            ]
            if row.mapping and row.mapping != "name match":
                cells[-1].color = _STATUS_COLOR
        delete_rule = prop.delete_rule_text()
        cells += [
            Cell(prop.destination or ""), Cell(prop.inverse or ""),
            stored_cell(prop.min_count), stored_cell(prop.max_count), Cell(delete_rule),
            stored_cell(prop.ordered),
        ]
        if with_columns:
            rule = row.rule
            if rule is None:
                cells += [Cell(""), Cell("")]
            else:
                where = ", ".join(c for c in (rule.table, rule.key_column, rule.source_column,
                                              rule.ent_column, rule.order_column) if c)
                cells += [
                    Cell(word(rule.kind), None, where or None),
                    Cell(word(rule.status), None, rule.reason,
                         _STATUS_COLOR if not rule.resolved else None),
                ]
        out.append(cells)
    return headers, out


def fill_standard_model(model: QStandardItemModel, headers: list[Header], rows: list[list[Cell]]) -> None:
    """Small generated views (Store, Model, Keys, External Data) as
    QStandardItem rows, column 0 "Row" like the grid's."""
    labels: list[str | Gen] = [Gen(QT_TRANSLATE_NOOP("GeneratedView", "Row"))]
    labels += [h.label for h in headers]
    set_headers(model, labels)
    for col, header in enumerate(headers, start=1):
        if header.tooltip is not None:
            item = model.horizontalHeaderItem(col)
            if item is not None:
                item.setToolTip(render_value(header.tooltip, localized=True))
    for n, cells in enumerate(rows, start=1):
        row_item = QStandardItem(str(n))
        row_item.setData(n, Qt.ItemDataRole.UserRole)
        row_item.setEditable(False)
        items = [row_item]
        for cell in cells:
            item = QStandardItem(cell.display)
            item.setEditable(False)
            if cell.raw is not None:
                item.setData(cell.raw, Qt.ItemDataRole.UserRole)
            if cell.tooltip:
                item.setToolTip(cell.tooltip)
            if cell.color is not None:
                item.setForeground(cell.color)
            if cell.export is not None:
                item.setData(cell.export, EXPORT_TEXT_ROLE)
            items.append(item)
        model.appendRow(items)
