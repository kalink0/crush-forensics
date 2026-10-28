# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Chromium Disk Cache viewer — Overview, Entries, Orphans / Recovered, and
a detail pane per entry: summary, structure (tree + hex of each file the
entry is stored in), headers, certificates, body and streams.

The parser hands over plain rows and a store (data["__store"]) that reads
an entry's details when it is selected; bodies and streams open in a new
tab in whichever viewer their content calls for."""
from __future__ import annotations

import csv
from collections import Counter
from typing import Any

from PySide6.QtCore import (
    QT_TRANSLATE_NOOP,
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from crush.core.issues import CatalogText, ParseIssue, render_value
from crush.ui.busy_dialog import busy_call
from crush.ui.i18n import translate
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.generated_text import EXPORT_TEXT_ROLE, gen_text
from crush.viewers.hex_viewer import HexViewer
from crush.viewers.open_bytes import request_open_bytes, source_path_of
from crush.viewers.tree_viewer import TreeViewer

_SORT_ROLE = Qt.ItemDataRole.UserRole + 1
# An entry whose files are bigger than this is read behind a wait dialog
# (the main window's threshold for parsing in the background).
_BUSY_BYTES = 8 * 1024 * 1024

# Row fields whose values are Crush's own words (marked GeneratedView where
# the parser writes them): shown translated, exported in English.
_GENERATED_FIELDS = frozenset({"state", "kind", "kind_basis", "source", "reached_via"})

# (header, field shown, field sorted by)
_ENTRY_COLUMNS: list[tuple[str, str, str]] = [
    (QT_TRANSLATE_NOOP("GeneratedView", "#"), "id", "id"),
    (QT_TRANSLATE_NOOP("GeneratedView", "State"), "state", "state"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Kind"), "kind", "kind"),
    (QT_TRANSLATE_NOOP("GeneratedView", "URL"), "url", "url"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Top-frame site"), "top_frame_site", "top_frame_site"),
    (QT_TRANSLATE_NOOP("GeneratedView", "HTTP status"), "http_status", "http_status"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Content type"), "content_type", "content_type"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Content encoding"), "content_encoding", "content_encoding"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Body size (B)"), "body_size", "body_size"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Request time (UTC)"), "request_time_text", "request_time"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Response time (UTC)"), "response_time_text", "response_time"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Last used (UTC)"), "last_used_text", "last_used"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Entry created (UTC)"), "created_text", "created"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Server"), "server", "server"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Protocol"), "protocol", "protocol"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Key"), "key", "key"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Hash"), "hash", "hash"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Stored in"), "files", "files"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Note"), "note", "note"),
]
_ORPHAN_COLUMNS: list[tuple[str, str, str]] = [
    (QT_TRANSLATE_NOOP("GeneratedView", "#"), "id", "id"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Source"), "source", "source"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Hash"), "hash", "hash"),
    (QT_TRANSLATE_NOOP("GeneratedView", "URL"), "url", "url"),
    (QT_TRANSLATE_NOOP("GeneratedView", "State"), "state", "state"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Last used (UTC)"), "last_used_text", "last_used"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Trailer prefetch size"), "prefetch", "prefetch"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Entry created (UTC)"), "created_text", "created"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Size (B)"), "size", "size"),
    (QT_TRANSLATE_NOOP("GeneratedView", "File"), "file", "file"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Offset"), "offset", "offset"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Key"), "key", "key"),
    (QT_TRANSLATE_NOOP("GeneratedView", "Reason / note"), "note", "note"),
]


def _english(field: str, value: Any) -> str:
    """A cell's English text (CSV export, copy)."""
    if value is None:
        return ""
    if isinstance(value, (ParseIssue, CatalogText)) or isinstance(value, list):
        return render_value(value)
    if isinstance(value, int) and field not in ("id", "offset"):
        return str(value)
    return str(value)


def _display(field: str, value: Any) -> str:
    """A cell's text in the UI language."""
    if value is None:
        return ""
    if isinstance(value, (ParseIssue, CatalogText)) or isinstance(value, list):
        return render_value(value, localized=True)
    if field in _GENERATED_FIELDS and isinstance(value, str):
        return gen_text(value)
    if field == "offset" and isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, int) and field != "id":
        return f"{value:,}"
    return str(value)


class _RowsModel(QAbstractTableModel):
    """The parser's row dicts as a table; nothing is copied into Qt items,
    so 40,000+ rows open at once."""

    def __init__(self, rows: list[dict[str, Any]], columns: list[tuple[str, str, str]]) -> None:
        super().__init__()
        self.rows = rows
        self.columns = columns
        self._search: list[str | None] = [None] * len(rows)

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        _header, shown, sort_field = self.columns[index.column()]
        value = row.get(shown)
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return _display(shown, value)
        if role == EXPORT_TEXT_ROLE:
            return _english(shown, value)
        if role == _SORT_ROLE:
            key = row.get(sort_field)
            if key is None:
                return ""
            if isinstance(key, int):
                return key
            return _display(sort_field, key).lower()
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation != Qt.Orientation.Horizontal:
            return None
        header = self.columns[section][0]
        if role == Qt.ItemDataRole.DisplayRole:
            return gen_text(header)
        if role == EXPORT_TEXT_ROLE:
            return header
        return None

    def sort_rows(self, column: int, order: Qt.SortOrder) -> None:
        """Reorder the rows by *column*: keys computed once per row and
        sorted in Python -- a proxy sort asks for two keys per comparison,
        about a second on 40,000 rows."""
        _header, _shown, sort_field = self.columns[column]

        def key(i: int) -> tuple[int, Any]:
            value = self.rows[i].get(sort_field)
            if value is None or value == "":
                return (0, 0)
            if isinstance(value, int):
                return (1, value)
            return (2, _display(sort_field, value).lower())

        order_idx = sorted(
            range(len(self.rows)), key=key, reverse=order == Qt.SortOrder.DescendingOrder
        )
        self.layoutAboutToBeChanged.emit()
        new_pos = {old: new for new, old in enumerate(order_idx)}
        self.rows = [self.rows[i] for i in order_idx]
        self._search = [self._search[i] for i in order_idx]
        changed_from = self.persistentIndexList()
        changed_to = [self.index(new_pos[i.row()], i.column()) for i in changed_from]
        self.changePersistentIndexList(changed_from, changed_to)
        self.layoutChanged.emit()

    def search_text(self, row: int) -> str:
        text = self._search[row]
        if text is None:
            values = self.rows[row]
            text = "\n".join(_display(shown, values.get(shown)) for _h, shown, _s in self.columns).lower()
            self._search[row] = text
        return text


class _Filter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self._state: str | None = None
        self._text = ""
        self.setSortRole(_SORT_ROLE)

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        # The rows model sorts itself (_RowsModel.sort_rows); this proxy
        # only filters and keeps the model's order.
        model = self.sourceModel()
        if isinstance(model, _RowsModel) and 0 <= column < model.columnCount():
            model.sort_rows(column, order)

    def set_state(self, state: str | None) -> None:
        self._state = state
        self.invalidateFilter()

    def set_text(self, text: str) -> None:
        self._text = text.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex) -> bool:
        model = self.sourceModel()
        assert isinstance(model, _RowsModel)
        if self._state is not None and model.rows[source_row].get("state") != self._state:
            return False
        return not self._text or self._text in model.search_text(source_row)


def _label(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class _DetailPane(QTabWidget):
    """What the store reads for one selected entry. A tab's widget is built
    when the tab is first shown (a structure tab holds a whole data file in
    its hex view)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._title = ""
        self._pending: dict[QWidget, Any] = {}
        self.currentChanged.connect(self._build_current)
        self.show_message(translate("ChromiumCacheViewer", "Select an entry."))

    def show_message(self, text: str) -> None:
        self._pending.clear()
        self.clear()
        self.addTab(_label(text), translate("ChromiumCacheViewer", "Details"))

    def _add_lazy(self, build: Any, title: str) -> None:
        placeholder = QWidget()
        self._pending[placeholder] = build
        self.addTab(placeholder, title)

    def _build_current(self, index: int) -> None:
        placeholder = self.widget(index)
        build = self._pending.pop(placeholder, None)
        if build is None:
            return
        title = self.tabText(index)
        self.blockSignals(True)
        self.removeTab(index)
        self.insertTab(index, build(), title)
        self.setCurrentIndex(index)
        self.blockSignals(False)
        placeholder.deleteLater()

    def show_detail(self, detail: dict[str, Any], title: str) -> None:
        current = self.currentIndex()
        self._pending.clear()
        self.blockSignals(True)
        self.clear()
        self._title = title
        summary: dict[str, Any] = {}
        if detail.get("kind"):
            summary["Kind"] = detail["kind"]
        if detail.get("kind_basis"):
            summary["Kind determined by"] = detail["kind_basis"]
        if detail.get("key"):
            summary["Key"] = detail["key"]
        notes = [n for n in detail.get("notes", []) if n]
        if notes:
            summary["Notes"] = notes
        self._add_lazy(lambda: TreeViewer(summary, self), translate("ChromiumCacheViewer", "Summary"))
        for part in detail.get("structure", []):
            self._add_lazy(
                lambda p=part: TreeViewer(
                    p["tree"], self, raw=p["raw"], byte_ranges_by_path=p["ranges"], hex_visible=True,
                ),
                translate("ChromiumCacheViewer", "Structure: {file}").format(file=part["title"]),
            )
        if detail.get("headers") or detail.get("status_line") or detail.get("request_headers"):
            self._add_lazy(lambda: self._headers_tab(detail), translate("ChromiumCacheViewer", "Headers"))
        if detail.get("certificates"):
            self._add_lazy(
                lambda: self._certificates_tab(detail["certificates"]),
                translate("ChromiumCacheViewer", "Certificates ({count})").format(
                    count=len(detail["certificates"])),
            )
        body = detail.get("body")
        if body is not None:
            self._add_lazy(lambda: self._body_tab(body), translate("ChromiumCacheViewer", "Body"))
        if detail.get("streams"):
            self._add_lazy(lambda: self._streams_tab(detail["streams"]), translate("ChromiumCacheViewer", "Streams"))
        self.blockSignals(False)
        # The tab the analyst was on stays selected from entry to entry.
        target = current if 0 <= current < self.count() else 0
        self.setCurrentIndex(target)
        self._build_current(target)

    def _open(self, data: bytes, what: str, where: str) -> None:
        request_open_bytes(
            self, data, f"/virtual/chromium-cache/{self._title}/{what}", None,
            {
                "Source entry": f"{self._title} ({source_path_of(self)})",
                "Inspected bytes": f"{what} — {where}",  # i18n: keep -- provenance values stay English
            },
        )

    def _headers_tab(self, detail: dict[str, Any]) -> QWidget:
        rows: list[tuple[str, str]] = []
        if detail.get("status_line"):
            rows.append((translate("ChromiumCacheViewer", "(status line)"), detail["status_line"]))
        rows.extend(detail.get("headers", []))
        request = detail.get("request_headers") or []
        if request:
            rows.append((translate("ChromiumCacheViewer", "(request headers)"), ""))
            rows.extend(request)
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels([
            translate("ChromiumCacheViewer", "Name"), translate("ChromiumCacheViewer", "Value"),
        ])
        for i, (name, value) in enumerate(rows):
            for col, text in enumerate((name, value)):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(i, col, item)
        table.horizontalHeader().setStretchLastSection(True)
        table.resizeColumnToContents(0)
        install_horizontal_wheel_scroll(table)
        return table

    def _certificates_tab(self, certificates: list[dict[str, Any]]) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        tree = {
            translate("ChromiumCacheViewer", "Certificate {n}").format(n=i): cert["fields"]
            for i, cert in enumerate(certificates)
        }
        layout.addWidget(TreeViewer(tree, widget), 1)
        buttons = QHBoxLayout()
        for i, cert in enumerate(certificates):
            button = QPushButton(translate("ChromiumCacheViewer", "Open certificate {n} (DER)").format(n=i))
            button.clicked.connect(
                lambda _c=False, der=cert["der"], n=i, rng=cert.get("range"): self._open(
                    der, f"certificate-{n}.der", f"0x{rng[0]:x}–0x{rng[1]:x}" if rng else "",
                )
            )
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        return widget

    def _body_tab(self, body: dict[str, Any]) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(4, 4, 4, 0)
        raw: bytes | None = body.get("raw")
        derived: bytes | None = body.get("derived")
        lines = []
        if raw is not None:
            lines.append(translate("ChromiumCacheViewer", "RAW: {size:,} B as stored ({where}).").format(
                size=len(raw), where=body.get("where", "")))
        if derived is not None:
            lines.append(translate(
                "ChromiumCacheViewer", "Derived: {size:,} B, the RAW body with {codings} removed."
            ).format(size=len(derived), codings=body.get("derived_label", "")))
        if body.get("note"):
            lines.append(render_value(body["note"], localized=True))
        layout.addWidget(_label("\n".join(lines)))
        buttons = QHBoxLayout()
        if raw is not None:
            open_raw = QPushButton(translate("ChromiumCacheViewer", "Open RAW body in new tab"))
            open_raw.clicked.connect(lambda: self._open(raw, "body", body.get("where", "")))
            buttons.addWidget(open_raw)
        if derived is not None:
            open_derived = QPushButton(translate("ChromiumCacheViewer", "Open decompressed body in new tab"))
            open_derived.clicked.connect(lambda: self._open(
                derived, "body-decompressed", f"{body.get('derived_label', '')} of {body.get('where', '')}"
            ))
            buttons.addWidget(open_derived)
        buttons.addStretch()
        layout.addLayout(buttons)
        views = QTabWidget()
        if raw is not None:
            views.addTab(HexViewer(raw, views), translate("ChromiumCacheViewer", "RAW"))
        if derived is not None:
            views.addTab(HexViewer(derived, views), translate("ChromiumCacheViewer", "Decompressed (derived)"))
        sparse = body.get("sparse") or []
        if sparse:
            views.addTab(self._sparse_table(sparse, body.get("gaps") or []),
                         translate("ChromiumCacheViewer", "Sparse ranges ({count})").format(count=len(sparse)))
        layout.addWidget(views, 1)
        return widget

    def _sparse_table(self, ranges: list[dict[str, Any]], gaps: list[tuple[int, int]]) -> QWidget:
        rows: list[tuple[int, int, str, bytes | None]] = [
            (r["offset"], r["length"], r["where"], r["data"]) for r in ranges
        ] + [(s, e - s, "", None) for s, e in gaps]
        rows.sort(key=lambda r: r[0])
        table = QTableWidget(len(rows), 4)
        table.setHorizontalHeaderLabels([
            translate("ChromiumCacheViewer", "Offset in the entry"),
            translate("ChromiumCacheViewer", "Length (B)"),
            translate("ChromiumCacheViewer", "Stored"),
            translate("ChromiumCacheViewer", "Where"),
        ])
        for i, (offset, length, where, data) in enumerate(rows):
            stored = (translate("ChromiumCacheViewer", "yes") if data is not None
                      else translate("ChromiumCacheViewer", "gap — not stored"))
            for col, text in enumerate((f"{offset:,}", f"{length:,}", stored, where)):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(i, col, item)
        table.horizontalHeader().setStretchLastSection(True)
        table.cellDoubleClicked.connect(
            lambda row, _col: rows[row][3] is not None and self._open(
                rows[row][3] or b"", f"range-{rows[row][0]}", rows[row][2]
            )
        )
        return table

    def _streams_tab(self, streams: list[dict[str, Any]]) -> QWidget:
        tabs = QTabWidget()
        for s in streams:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(4, 4, 4, 0)
            row = QHBoxLayout()
            row.addWidget(_label(translate("ChromiumCacheViewer", "Stream {index}: {size:,} B ({where})").format(
                index=s["index"], size=s["size"], where=s["where"])), 1)
            button = QPushButton(translate("ChromiumCacheViewer", "Open in new tab"))
            button.clicked.connect(
                lambda _c=False, d=s["data"], i=s["index"], w=s["where"]: self._open(d, f"stream-{i}", w)
            )
            row.addWidget(button)
            layout.addLayout(row)
            layout.addWidget(HexViewer(s["data"], page), 1)
            tabs.addTab(page, translate("ChromiumCacheViewer", "Stream {index}").format(index=s["index"]))
        return tabs


class _RowsWidget(QWidget):
    """Toolbar (state filter, search, CSV export), the table, and the
    detail pane for the selected row."""

    def __init__(
        self, rows: list[dict[str, Any]], columns: list[tuple[str, str, str]],
        detail: Any, title_prefix: str, parent: QWidget | None = None, read_size: Any = None,
    ) -> None:
        super().__init__(parent)
        self._detail = detail
        self._read_size = read_size
        self._title_prefix = title_prefix
        self._model = _RowsModel(rows, columns)
        self._proxy = _Filter()
        self._proxy.setSourceModel(self._model)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        toolbar = QToolBar()
        toolbar.setMovable(False)
        states = Counter(r.get("state") for r in rows if r.get("state"))
        self._state_buttons: dict[str | None, QPushButton] = {}
        if states:
            toolbar.addWidget(QLabel(translate("ChromiumCacheViewer", "  Show: ")))
            for state, count in [(None, len(rows)), *states.most_common()]:
                text = (translate("ChromiumCacheViewer", "All ({count:,})").format(count=count) if state is None
                        else f"{gen_text(state)} ({count:,})")  # i18n: keep -- layout, state marked where written
                button = QPushButton(text)
                button.setCheckable(True)
                button.setFlat(True)
                button.clicked.connect(lambda _c=False, s=state: self._set_state(s))
                toolbar.addWidget(button)
                self._state_buttons[state] = button
            self._state_buttons[None].setChecked(True)
            toolbar.addSeparator()
        toolbar.addWidget(QLabel(translate("ChromiumCacheViewer", "  Search: ")))
        search = QLineEdit()
        search.setPlaceholderText(translate("ChromiumCacheViewer", "Filter rows…"))
        search.setClearButtonEnabled(True)
        search.setFixedWidth(240)
        search.textChanged.connect(self._proxy.set_text)
        toolbar.addWidget(search)
        toolbar.addSeparator()
        export = QPushButton(translate("ChromiumCacheViewer", "Export CSV…"))
        export.clicked.connect(self._export_csv)
        toolbar.addWidget(export)
        layout.addWidget(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        install_horizontal_wheel_scroll(self._table)
        self._table.selectionModel().currentRowChanged.connect(self._on_row)
        splitter.addWidget(self._table)
        self._pane = _DetailPane(splitter)
        splitter.addWidget(self._pane)
        splitter.setSizes([380, 320])
        layout.addWidget(splitter, 1)

    def _set_state(self, state: str | None) -> None:
        self._proxy.set_state(state)
        for s, button in self._state_buttons.items():
            button.setChecked(s == state)

    def _on_row(self, current: QModelIndex, _previous: QModelIndex) -> None:
        source = self._proxy.mapToSource(current)
        if not source.isValid():
            return
        row = self._model.rows[source.row()]
        title = f"{self._title_prefix}{row['id']}"
        try:
            size = self._read_size(row["id"]) if self._read_size is not None else 0
            if size > _BUSY_BYTES:
                detail = busy_call(
                    self,
                    translate("ChromiumCacheViewer", "Reading entry {id} ({size:,} B)…").format(
                        id=row["id"], size=size),
                    lambda: self._detail(row["id"]),
                )
            else:
                detail = self._detail(row["id"])
        except Exception as exc:  # noqa: BLE001 -- shown, not swallowed
            self._pane.show_message(translate(
                "ChromiumCacheViewer", "The entry's details couldn't be read: {error}"
            ).format(error=str(exc)))
            return
        self._pane.show_detail(detail, title)

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, translate("ChromiumCacheViewer", "Export CSV"), "", "CSV (*.csv)"  # i18n: keep -- file filter
        )
        if not path:
            return
        # The visible rows in their order, taken here; written in the
        # background (40,000 rows take about a second).
        rows = [
            self._model.rows[self._proxy.mapToSource(self._proxy.index(r, 0)).row()]
            for r in range(self._proxy.rowCount())
        ]
        columns = list(self._model.columns)

        def write() -> None:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow([header for header, _s, _k in columns])
                for row in rows:
                    writer.writerow([_english(shown, row.get(shown)) for _h, shown, _k in columns])

        try:
            busy_call(self, translate("ChromiumCacheViewer", "Exporting {count:,} rows…").format(
                count=len(rows)), write)
        except RuntimeError as exc:
            QMessageBox.warning(
                self, translate("ChromiumCacheViewer", "Export CSV"),
                translate("ChromiumCacheViewer", "The CSV file couldn't be written: {error}").format(
                    error=str(exc)),
            )


class ChromiumCacheViewer(QWidget):
    """Tabs: Overview | Entries | Orphans / Recovered."""

    open_bytes_with_format_requested = Signal(bytes, str, object, dict)

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        store = data.get("__store")
        entries: list[dict[str, Any]] = data.get("entries", [])
        orphans: list[dict[str, Any]] = data.get("orphans", [])
        tabs.addTab(TreeViewer(data.get("overview", {}), tabs), translate("ChromiumCacheViewer", "Overview"))
        if entries:
            tabs.addTab(
                _RowsWidget(
                    entries, _ENTRY_COLUMNS, store.detail if store else None, "entry-", tabs,
                    read_size=store.read_size if store else None,
                ),
                translate("ChromiumCacheViewer", "Entries ({count:,})").format(count=len(entries)),
            )
        else:
            tabs.addTab(
                _label(render_value(data.get("entries_note", ""), localized=True)),
                translate("ChromiumCacheViewer", "Entries (0)"),
            )
        if orphans:
            tabs.addTab(
                _RowsWidget(orphans, _ORPHAN_COLUMNS, store.orphan_detail if store else None, "orphan-", tabs),
                translate("ChromiumCacheViewer", "Orphans / Recovered ({count:,})").format(count=len(orphans)),
            )
        else:
            tabs.addTab(
                _label(render_value(data.get("orphans_note", ""), localized=True)),
                translate("ChromiumCacheViewer", "Orphans / Recovered (0)"),
            )
        layout.addWidget(tabs)
