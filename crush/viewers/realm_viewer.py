# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Realm viewer — header, schema, top-ref comparison, hex preview."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.tree_viewer import TreeViewer
from crush.viewers.hex_viewer import HexViewer
from crush.viewers.table_viewer import BlobInspector, TableViewer, _cap_columns


class FreeDataViewer(QWidget):
    """Splitter widget: freed-block table (top) + HexViewer of selected block (bottom)."""

    _SOURCE_COLORS = {
        "inactive": QColor("#cc8800"),   # orange — freed before this transaction
        "active":   QColor("#cc3333"),   # red    — freed in this transaction
        "both":     QColor("#888888"),   # gray   — present in both free lists
    }
    _COLUMNS = ["Offset", "Size", "Source", "Type", "Strings / notes"]

    def __init__(self, blocks: list[dict], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._blocks = blocks
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # --- top: table of freed blocks ---
        self._model = QStandardItemModel(0, len(self._COLUMNS))
        self._model.setHorizontalHeaderLabels(self._COLUMNS)

        for block in self._blocks:
            offset  = block["offset"]
            size    = block["size"]
            source  = block.get("source", "?")
            arr_hdr = block.get("array_header")
            strings = block.get("strings", [])

            if arr_hdr:
                type_str = (
                    f"array  count={arr_hdr['Element count (size)']}"
                    f"  w={arr_hdr['width']}"
                    f"  has_refs={arr_hdr['has_refs']}"
                )
                notes = ""
            else:
                type_str = "raw data"
                preview = " | ".join(strings[:4])
                if len(strings) > 4:
                    preview += f"  (+{len(strings) - 4} more)"
                notes = preview or "(no printable strings)"

            color = self._SOURCE_COLORS.get(source)
            row_items = [
                self._item(f"0x{offset:08x}", color),
                self._item(f"{size:,}", color),
                self._item(source, color),
                self._item(type_str, color),
                self._item(notes, color),
            ]
            self._model.appendRow(row_items)

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        install_horizontal_wheel_scroll(self._table)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.resizeColumnsToContents()
        _cap_columns(self._table)
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        splitter.addWidget(self._table)

        # --- bottom: hex viewer ---
        self._hex = HexViewer(b"", splitter)
        splitter.addWidget(self._hex)
        splitter.setSizes([300, 250])

        layout.addWidget(splitter)

        # Select first row by default
        if self._blocks:
            self._table.selectRow(0)

    @staticmethod
    def _item(text: str, color: QColor | None) -> QStandardItem:
        it = QStandardItem(text)
        it.setEditable(False)
        if color:
            it.setForeground(color)
        return it

    def _on_row_changed(self, current, _previous) -> None:
        row = current.row()
        if 0 <= row < len(self._blocks):
            self._hex.set_data(self._blocks[row]["bytes"])

    def _on_context_menu(self, pos) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        if 0 <= row < len(self._blocks):
            raw: bytes = self._blocks[row]["bytes"]
            menu = QMenu(self)
            inspect = menu.addAction(f"Inspect Block… ({len(raw)} B)")
            if menu.exec(self._table.viewport().mapToGlobal(pos)) == inspect:
                BlobInspector(raw, self).show()


def _create_realm_sqlite(
    table_data: dict[str, Any],
    inactive_table_data: dict[str, Any] | None = None,
) -> Path | None:
    """Dump decoded Realm tables into a temporary SQLite file.

    Active-ref tables are stored under their original names.
    Inactive-ref tables are stored with a ``_prev_`` prefix so forensic queries
    can compare both snapshots:
        SELECT * FROM class_Evidence e
        JOIN _prev_class_Evidence p ON e._objkey = p._objkey

    Each table gets a leading _objkey column (Realm ObjKey) for cross-table JOINs.

    Returns the Path to the temp file, or None on failure.
    The caller is responsible for cleanup (TableViewer.closeEvent handles it).
    """
    def _q(name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def _sql_safe(value: Any) -> Any:
        # List/Set (incl. LinkList) columns decode to real Python lists, and
        # SQLite's bind layer rejects list/dict values outright ("Error
        # binding parameter ... type 'list' is not supported") -- store
        # their JSON form instead so the export doesn't fail wholesale and
        # the values remain searchable (e.g. via LIKE).
        if isinstance(value, (list, dict)):
            try:
                return json.dumps(value)
            except (TypeError, ValueError):
                return str(value)
        return value

    def _insert_tables(conn: sqlite3.Connection, data: dict[str, Any], prefix: str) -> None:
        for tbl_name, tbl in data.items():
            cols: list[str] = tbl.get("columns", [])
            rows: list[list] = tbl.get("rows", [])
            obj_keys: list = tbl.get("__obj_keys") or []
            if not cols:
                continue
            sql_name = prefix + tbl_name
            col_defs = "_objkey INTEGER, " + ", ".join(_q(c) for c in cols)
            conn.execute(f"CREATE TABLE {_q(sql_name)} ({col_defs})")  # noqa: S608
            if rows:
                ph = ", ".join("?" * (len(cols) + 1))
                conn.executemany(
                    f"INSERT INTO {_q(sql_name)} VALUES ({ph})",  # noqa: S608
                    [
                        [obj_keys[i] if i < len(obj_keys) else None]
                        + [_sql_safe(v) for v in row]
                        for i, row in enumerate(rows)
                    ],
                )

    def _display_expr(conn: sqlite3.Connection, sql_table: str, alias: str) -> str:
        # No guessing which single column is "the important one" -- that
        # varies per Realm schema (name/subject/title/... is not universal).
        # Instead, deterministically concatenate every column of the linked
        # row as "col=val, col=val, ...", so the resolution is complete and
        # schema-agnostic rather than a best-effort pick that could silently
        # show an unhelpful column on an unfamiliar schema.
        try:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(sql_table)})").fetchall()]
        except sqlite3.Error:
            return f'{alias}."_objkey"'
        cols = [c for c in cols if c != "_objkey"]
        if not cols:
            return f'{alias}."_objkey"'
        parts = []
        for c in cols:
            label = c.replace("'", "''")  # escape for the SQL string literal
            parts.append(f"'{label}=' || COALESCE(CAST({alias}.{_q(c)} AS TEXT), '')")
        return " || ', ' || ".join(parts)

    def _create_link_views(conn: sqlite3.Connection, data: dict[str, Any], prefix: str) -> None:
        # A raw Link/LinkList column only holds ObjKey numbers (e.g. "[2]"),
        # meaningless without a manual json_each()+JOIN per query. This adds
        # a "v_<table>" view per table that has any, replacing those columns
        # with the resolved target row's display value inline -- so
        # `SELECT * FROM v_<table>` shows sender/recipient names directly.
        for tbl_name, tbl in data.items():
            cols: list[str] = tbl.get("columns", [])
            col_types: list[str] = tbl.get("__column_types") or []
            col_targets: list[str | None] = tbl.get("__column_target_tables") or []
            if not cols:
                continue
            link_info: dict[str, tuple[str, str]] = {}
            for i, col in enumerate(cols):
                ctype = col_types[i] if i < len(col_types) else ""
                target = col_targets[i] if i < len(col_targets) else None
                if ctype not in ("link", "linklist") or not target:
                    continue
                target_sql = prefix + target
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (target_sql,)
                ).fetchone()
                if exists:
                    link_info[col] = (ctype, target_sql)
            if not link_info:
                continue

            sql_name = prefix + tbl_name
            select_parts = ['t."_objkey"']
            for col in cols:
                if col not in link_info:
                    select_parts.append(f"t.{_q(col)}")
                    continue
                ctype, target_sql = link_info[col]
                display_expr = _display_expr(conn, target_sql, "x")
                if ctype == "linklist":
                    sub = (
                        f"(SELECT group_concat({display_expr}, ', ') "
                        f"FROM json_each(t.{_q(col)}) je "
                        f'JOIN {_q(target_sql)} x ON x."_objkey" = je.value)'
                    )
                else:  # link (single)
                    sub = (
                        f"(SELECT {display_expr} FROM {_q(target_sql)} x "
                        f'WHERE x."_objkey" = t.{_q(col)})'
                    )
                select_parts.append(f"{sub} AS {_q(col)}")

            view_name = "v_" + sql_name
            select_sql = ", ".join(select_parts)
            try:
                conn.execute(
                    f"CREATE VIEW {_q(view_name)} AS "  # noqa: S608
                    f"SELECT {select_sql} FROM {_q(sql_name)} t"
                )
            except sqlite3.Error:
                pass  # view is a convenience; the base table remains queryable either way

    try:
        fd, path_str = tempfile.mkstemp(suffix=".db", prefix="crush_realm_")
        os.close(fd)
        conn = sqlite3.connect(path_str)
        _insert_tables(conn, table_data, "")
        if inactive_table_data:
            _insert_tables(conn, inactive_table_data, "_prev_")
        _create_link_views(conn, table_data, "")
        if inactive_table_data:
            _create_link_views(conn, inactive_table_data, "_prev_")
        conn.commit()
        conn.close()
        return Path(path_str)
    except Exception:
        return None


def _build_resolved_view(
    source_table: dict[str, Any],
    link_configs: list[tuple[str, dict[str, Any], list[str]]],
) -> dict[str, Any]:
    """Resolve one or more Link/LinkList columns to only the
    caller-selected target columns each, computed directly from the
    already-decoded parser output (no SQL round-trip). Uses the same
    "col=val, col=val" text convention as _display_expr above, just
    restricted per column to its own selected_cols and picked interactively
    (RealmViewer's Views tab) instead of showing every column.

    *link_configs* is a list of (link_col_name, target_table, selected_cols)
    — a table with several Link/LinkList columns (e.g. from/to/cc/
    attachments) is resolved in one pass, each with its own target table
    and column selection, rather than one tab per column.

    Returns a single table's {"columns", "rows", "__obj_keys"} dict, ready
    to hand to TableViewer as one entry of its data mapping.
    """
    src_names: list[str] = source_table.get("column_names") or []
    src_cols_dict: dict[int, list] = source_table.get("columns") or {}
    src_obj_keys: list = source_table.get("obj_keys") or []
    n_rows: int = source_table.get("row_count") or 0

    # Precompute one {target_objkey: "col=val, col=val"} lookup per configured
    # link column -- each may point at a different target table/selection.
    resolvers: dict[int, dict[Any, str]] = {}
    for link_col_name, target_table, selected_cols in link_configs:
        if link_col_name not in src_names:
            continue
        link_idx = src_names.index(link_col_name)

        target_names: list[str] = target_table.get("column_names") or []
        target_cols_dict: dict[int, list] = target_table.get("columns") or {}
        target_obj_keys: list = target_table.get("obj_keys") or []
        name_to_idx = {n: i for i, n in enumerate(target_names)}
        selected_idx = [(c, name_to_idx[c]) for c in selected_cols if c in name_to_idx]

        def _format_target_row(
            row_idx: int, selected_idx=selected_idx, target_cols_dict=target_cols_dict,
        ) -> str:
            parts = []
            for col_name, ci in selected_idx:
                vals = target_cols_dict.get(ci) or []
                val = vals[row_idx] if row_idx < len(vals) else None
                parts.append(f"{col_name}={'' if val is None else val}")
            return ", ".join(parts)

        target_by_key: dict[Any, str] = {}
        for r, key in enumerate(target_obj_keys):
            if key is None:
                continue
            target_by_key[key] = _format_target_row(r)
        resolvers[link_idx] = target_by_key

    rows: list[list[Any]] = []
    for r in range(n_rows):
        row: list[Any] = []
        for ci in range(len(src_names)):
            vals = src_cols_dict.get(ci) or []
            row.append(vals[r] if r < len(vals) else None)
        for link_idx, target_by_key in resolvers.items():
            raw_link_val = row[link_idx]
            if isinstance(raw_link_val, list):
                resolved = [target_by_key.get(k) for k in raw_link_val if k in target_by_key]
                row[link_idx] = "; ".join(v for v in resolved if v is not None) or None
            else:
                row[link_idx] = target_by_key.get(raw_link_val)
        rows.append(row)

    return {"columns": src_names, "rows": rows, "__obj_keys": src_obj_keys}


class RealmViewer(QWidget):
    """Realm viewer with tabs: Header | Schema | Top Refs | Tables | Views | Hex Preview."""

    # Emitted by the Views tab's "Open View" button: (title, single-table
    # {"columns", "rows", "__obj_keys"} dict) — MainWindow opens it as a
    # real new tab, the same mechanism already used for "Open as new tab"
    # on BLOB cells (TableViewer.open_bytes_requested).
    open_table_requested = Signal(str, dict)

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()

        tables: list[dict] = self._data.get("tables", [])
        inactive_tables: list[dict] = self._data.get("inactive_tables", [])
        inactive_ref_index: int | None = self._data.get("inactive_ref_index")

        # --- Header ---
        header = self._data.get("header")
        if header:
            tabs.addTab(TreeViewer({"Header": header}, tabs), "Header")
        else:
            lbl = QLabel("Header not detected (possibly encrypted or non-standard).")
            lbl.setWordWrap(True)
            tabs.addTab(lbl, "Header")

        # --- Schema ---
        schema: list[str] = self._data.get("schema", [])
        if schema:
            table_lookup: dict[str, dict] = {t.get("name", ""): t for t in tables}
            schema_tree: dict[str, Any] = {}
            for name in schema:
                t = table_lookup.get(name)
                if t:
                    col_names: list[str] = t.get("column_names") or []
                    col_types: list[str] = t.get("column_types") or []
                    col_targets: list[str | None] = t.get("column_target_tables") or []
                    n_rows = t.get("row_count")
                    if n_rows is None:
                        rows_label = "? rows"
                    elif t.get("row_count_estimated"):
                        rows_label = f"~{n_rows} rows (estimated — file corruption)"
                    else:
                        rows_label = f"{n_rows} rows"
                    label = f"{name}  ({rows_label}, {len(col_names)} cols)"
                    col_entries: dict[str, str] = {}
                    for i in range(len(col_names)):
                        type_str = col_types[i] if i < len(col_types) else "?"
                        target = col_targets[i] if i < len(col_targets) else None
                        col_entries[col_names[i]] = (
                            f"{type_str}  →  {target}" if target else type_str
                        )
                    schema_tree[label] = col_entries
                else:
                    schema_tree[name] = "(no column data decoded)"
            tabs.addTab(
                TreeViewer({f"Tables ({len(schema)})": schema_tree}, tabs), "Schema"
            )

        # --- Top Refs ---
        top_refs = self._data.get("top_refs", {})
        if top_refs:
            tabs.addTab(self._build_top_refs_tab(top_refs, tabs), "Top Refs")

        # --- Tables ---
        if tables or inactive_tables:
            tabs.addTab(
                self._build_tables_tab(tables, tabs, inactive_tables, inactive_ref_index),
                "Tables",
            )

        # --- Views ---
        if tables:
            tabs.addTab(self._build_views_tab(tables, tabs), "Views")

        # --- Freed Data ---
        freed_blocks: list[dict] = self._data.get("freed_blocks", [])
        if freed_blocks:
            tabs.addTab(
                FreeDataViewer(freed_blocks, tabs),
                f"Freed Data ({len(freed_blocks)})",
            )

        # --- Strings ---
        strings: list[str] = self._data.get("strings", [])
        if strings:
            strings_data: dict[str, Any] = {
                f"Strings ({len(strings)})": {
                    "columns": ["String"],
                    "rows": [[s] for s in strings],
                }
            }
            tabs.addTab(TableViewer(strings_data, tabs), "Strings")

        # --- Hex Preview ---
        preview = self._data.get("preview", b"")
        tabs.addTab(HexViewer(preview, tabs), "Hex Preview")

        layout.addWidget(tabs)

    def _build_tables_tab(
        self,
        tables: list[dict],
        parent: QWidget,
        inactive_tables: list[dict] | None = None,
        inactive_ref_index: int | None = None,  # noqa: ARG002  kept for future use
    ) -> QWidget:
        """Convert Realm table dicts to the TableViewer format and return the widget.

        Active-ref tables are shown by default.  When the user checks
        "Show diff to prev ref" the viewer injects deleted/modified rows
        from the inactive ref inline, colour-coded like the SQLite WAL view.
        Inactive-ref tables are stored as ``_prev_<name>`` in the temp SQLite
        DB so cross-snapshot SQL comparisons are still possible.
        """
        inactive_tables = inactive_tables or []

        table_data: dict[str, Any] = {}
        inactive_table_data: dict[str, Any] = {}
        summary_rows: list[list] = []

        def _decode(t: dict) -> tuple[list[str], list[list], list, int, list[str], list]:
            cols_dict: dict[int, list] = t.get("columns", {})
            col_indices = sorted(cols_dict.keys())
            col_names = t.get("column_names")
            col_types_all = t.get("column_types") or []
            col_targets_all = t.get("column_target_tables") or []
            if col_names:
                headers = [
                    col_names[i] if i < len(col_names) else f"col_{i}"
                    for i in col_indices
                ]
            else:
                headers = [f"col_{i}" for i in col_indices]
            types = [col_types_all[i] if i < len(col_types_all) else "" for i in col_indices]
            targets = [col_targets_all[i] if i < len(col_targets_all) else None for i in col_indices]
            n_rows = max((len(v) for v in cols_dict.values()), default=0)
            decoded_rows: list[list] = []
            for r in range(n_rows):
                decoded_rows.append(
                    [cols_dict[ci][r] if r < len(cols_dict[ci]) else None for ci in col_indices]
                )
            obj_keys = t.get("obj_keys") or []
            return headers, decoded_rows, obj_keys, n_rows, types, targets

        for t in tables:
            name: str = t.get("name") or "?"
            if not t.get("columns"):
                continue
            headers, rows, obj_keys, n_rows, col_types, col_targets = _decode(t)
            table_data[name] = {
                "columns": headers,
                "rows": rows,
                "__obj_keys": obj_keys,
                "__column_types": col_types,
                "__column_target_tables": col_targets,
            }
            notes = "row count estimated (file corruption)" if t.get("row_count_estimated") else ""
            summary_rows.append([name, len(headers), n_rows, notes])

        for t in inactive_tables:
            name = t.get("name") or "?"
            if not t.get("columns"):
                continue
            headers, rows, obj_keys, n_rows, col_types, col_targets = _decode(t)
            inactive_table_data[name] = {
                "columns": headers,
                "rows": rows,
                "__obj_keys": obj_keys,
                "__column_types": col_types,
                "__column_target_tables": col_targets,
            }

        viewer_data: dict[str, Any] = {
            "Summary": {
                "columns": ["Table", "Decoded cols", "Rows", "Notes"],
                "rows": summary_rows,
            },
            "__prev_ref_data": inactive_table_data or None,
        }
        viewer_data.update(table_data)
        tmp = _create_realm_sqlite(table_data, inactive_table_data or None)
        if tmp:
            viewer_data["__db_path"] = str(tmp)
        return TableViewer(viewer_data, parent, show_db_tabs=False, summary_nav_table="Summary")

    def _build_views_tab(self, tables: list[dict], parent: QWidget) -> QWidget:
        """Interactive Link/LinkList resolver: pick a table, configure
        *every* one of its Link/LinkList columns at once (each with its own
        target-column checklist), and open the whole table resolved in a
        single new tab -- no SQL needed. Complements the always-on,
        all-columns "v_<table>" SQL views (_create_realm_sqlite) with a
        user-configurable, Python-side alternative reached from its own tab
        rather than the Schema tab.
        """
        table_by_name: dict[str, dict] = {t.get("name", ""): t for t in tables}

        # table name -> [(link_column, target_table_name), ...]
        table_links: dict[str, list[tuple[str, str]]] = {}
        for t in tables:
            name = t.get("name") or "?"
            col_names: list[str] = t.get("column_names") or []
            col_types: list[str] = t.get("column_types") or []
            col_targets: list[str | None] = t.get("column_target_tables") or []
            links: list[tuple[str, str]] = []
            for i, col in enumerate(col_names):
                ctype = col_types[i] if i < len(col_types) else ""
                target = col_targets[i] if i < len(col_targets) else None
                if ctype in ("link", "linklist") and target and target in table_by_name:
                    links.append((col, target))
            if links:
                table_links[name] = links

        if not table_links:
            empty = QLabel("No Link/LinkList columns with a resolvable target table found.")
            empty.setWordWrap(True)
            empty.setContentsMargins(8, 8, 8, 8)
            return empty

        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Tables with Link / LinkList columns:"))
        table_list = QListWidget()
        table_list.setAlternatingRowColors(True)
        for name in table_links:
            table_list.addItem(QListWidgetItem(name))
        left_layout.addWidget(table_list)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(
            QLabel("Link columns and which target columns to include (unchecked = leave raw):")
        )
        sel_row = QHBoxLayout()
        all_btn = QPushButton("Select All")
        none_btn = QPushButton("Deselect All")
        sel_row.addWidget(all_btn)
        sel_row.addWidget(none_btn)
        sel_row.addStretch()
        right_layout.addLayout(sel_row)
        tree = QTreeWidget()
        tree.setHeaderHidden(True)
        right_layout.addWidget(tree)
        open_btn = QPushButton("Open View")
        open_btn.setEnabled(False)
        right_layout.addWidget(open_btn)
        splitter.addWidget(right)
        splitter.setSizes([260, 420])

        layout.addWidget(splitter)

        def _populate_tree() -> None:
            tree.clear()
            item = table_list.currentItem()
            if item is None:
                open_btn.setEnabled(False)
                return
            for col, target in table_links.get(item.text(), []):
                group = QTreeWidgetItem([f"{col}  →  {target}"])
                group.setFlags(
                    group.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate
                )
                group.setData(0, Qt.ItemDataRole.UserRole, (col, target))
                target_cols = (table_by_name.get(target) or {}).get("column_names") or []
                for c in target_cols:
                    child = QTreeWidgetItem([c])
                    child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    child.setCheckState(0, Qt.CheckState.Checked)
                    group.addChild(child)
                tree.addTopLevelItem(group)
                group.setCheckState(0, Qt.CheckState.Checked)
                group.setExpanded(True)
            open_btn.setEnabled(tree.topLevelItemCount() > 0)

        def _set_all(state: Qt.CheckState) -> None:
            for i in range(tree.topLevelItemCount()):
                group = tree.topLevelItem(i)
                for j in range(group.childCount()):
                    group.child(j).setCheckState(0, state)

        def _open_view() -> None:
            table_item = table_list.currentItem()
            if table_item is None:
                return
            source_table = table_by_name.get(table_item.text())
            if not source_table:
                return
            link_configs: list[tuple[str, dict, list[str]]] = []
            for i in range(tree.topLevelItemCount()):
                group = tree.topLevelItem(i)
                col, target = group.data(0, Qt.ItemDataRole.UserRole)
                selected = [
                    group.child(j).text(0)
                    for j in range(group.childCount())
                    if group.child(j).checkState(0) == Qt.CheckState.Checked
                ]
                if not selected:
                    continue  # left raw, as documented in the column header above
                target_table = table_by_name.get(target)
                if not target_table:
                    continue
                link_configs.append((col, target_table, selected))
            if not link_configs:
                return
            resolved = _build_resolved_view(source_table, link_configs)
            cols_desc = ", ".join(c for c, _t, _s in link_configs)
            self.open_table_requested.emit(f"{table_item.text()} ({cols_desc})", resolved)

        table_list.currentItemChanged.connect(lambda *_args: _populate_tree())
        all_btn.clicked.connect(lambda: _set_all(Qt.CheckState.Checked))
        none_btn.clicked.connect(lambda: _set_all(Qt.CheckState.Unchecked))
        open_btn.clicked.connect(_open_view)

        table_list.setCurrentRow(0)
        return widget

    def _build_top_refs_tab(
        self, top_refs: dict[str, Any], parent: QWidget
    ) -> QWidget:
        active_idx = top_refs.get("active_index", -1)
        tree: dict[str, Any] = {}

        for key, idx in (("top_ref_0", 0), ("top_ref_1", 1)):
            entry = top_refs.get(key, {})
            offset = entry.get("offset", 0)
            status = "ACTIVE" if idx == active_idx else "inactive"
            label = f"top_ref[{idx}] — {status}"
            hdr = entry.get("array_header")
            node_info: dict[str, Any] = {"File offset": f"0x{offset:x} ({offset})"}
            if hdr:
                node_info.update({k: str(v) for k, v in hdr.items()})
            else:
                node_info["Note"] = (
                    "Array header not readable (outside preview range or invalid)"
                )

            children = entry.get("children", [])
            if children:
                children_dict: dict[str, Any] = {}
                for child in children:
                    i = child["index"]
                    child_off = child["offset"]
                    child_hdr = child.get("array_header")
                    if child_hdr:
                        children_dict[f"[{i}] 0x{child_off:x}"] = {
                            "has_refs": str(child_hdr["has_refs"]),
                            "Element count": str(child_hdr["Element count (size)"]),
                            "width": str(child_hdr["width"]),
                            "width_scheme": str(child_hdr["width_scheme"]),
                            "Total bytes": str(child_hdr["Total array bytes"]),
                        }
                    else:
                        children_dict[f"[{i}]"] = (
                            f"0x{child_off:x} ({child_off}) — offset out of range"
                        )
                node_info["Children"] = children_dict

            tree[label] = node_info

        # Structural diff — root array header fields
        hdr0 = top_refs.get("top_ref_0", {}).get("array_header")
        hdr1 = top_refs.get("top_ref_1", {}).get("array_header")
        if hdr0 and hdr1:
            root_diff: dict[str, str] = {
                k: f"ref[0]={hdr0[k]}  vs  ref[1]={hdr1[k]}"
                for k in hdr0
                if str(hdr0[k]) != str(hdr1[k])
            }
            tree["Diff — root array header"] = (
                root_diff if root_diff else {"(none)": "Root array headers are identical"}
            )

        # Structural diff — children content (element count, flags, width; NOT offsets,
        # since offsets always change on every write and carry no forensic signal)
        _SKIP_KEYS = {"Checksum", "Payload bytes (raw)", "Payload bytes (aligned)",
                      "Total array bytes", "Flags (raw)"}
        ch0_list = top_refs.get("top_ref_0", {}).get("children", [])
        ch1_list = top_refs.get("top_ref_1", {}).get("children", [])
        ch0_by_idx = {c["index"]: c for c in ch0_list}
        ch1_by_idx = {c["index"]: c for c in ch1_list}
        all_indices = sorted(set(ch0_by_idx) | set(ch1_by_idx))
        child_diff: dict[str, Any] = {}
        for i in all_indices:
            c0 = ch0_by_idx.get(i)
            c1 = ch1_by_idx.get(i)
            if c0 is None:
                child_diff[f"[{i}]"] = "only in ref[1]"
                continue
            if c1 is None:
                child_diff[f"[{i}]"] = "only in ref[0]"
                continue
            ch0h = c0.get("array_header") or {}
            ch1h = c1.get("array_header") or {}
            diffs: dict[str, str] = {
                k: f"ref[0]={ch0h[k]}  vs  ref[1]={ch1h.get(k)}"
                for k in ch0h
                if k not in _SKIP_KEYS and str(ch0h.get(k)) != str(ch1h.get(k))
            }
            if diffs:
                child_diff[f"[{i}]"] = diffs
        tree["Diff — children"] = (
            child_diff if child_diff else {"(none)": "All children are identical"}
        )

        # Schema-level diff between the two refs
        schema_diff = top_refs.get("schema_diff")
        if schema_diff:
            sd: dict[str, Any] = {}
            only_active = schema_diff.get("only_in_active", [])
            only_inactive = schema_diff.get("only_in_inactive", [])
            changed = schema_diff.get("row_count_changed", {})
            if only_active:
                sd[f"Only in active ref[{active_idx}]"] = {t: "new" for t in only_active}
            if only_inactive:
                inactive_label = 1 - active_idx
                sd[f"Only in inactive ref[{inactive_label}]"] = {
                    t: "removed" for t in only_inactive
                }
            if changed:
                sd["Row count changed"] = {
                    t: v for t, v in changed.items()
                }
            tree["Diff — schema"] = (
                sd if sd else {"(none)": "Both refs expose identical tables"}
            )

        return TreeViewer(tree, parent)
