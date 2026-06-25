# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Realm viewer — header, schema, top-ref comparison, hex preview."""
from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QLabel,
    QMenu,
    QSplitter,
    QTabWidget,
    QTableView,
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
                        [obj_keys[i] if i < len(obj_keys) else None] + row
                        for i, row in enumerate(rows)
                    ],
                )

    try:
        fd, path_str = tempfile.mkstemp(suffix=".db", prefix="crush_realm_")
        os.close(fd)
        conn = sqlite3.connect(path_str)
        _insert_tables(conn, table_data, "")
        if inactive_table_data:
            _insert_tables(conn, inactive_table_data, "_prev_")
        conn.commit()
        conn.close()
        return Path(path_str)
    except Exception:
        return None


class RealmViewer(QWidget):
    """Realm viewer with tabs: Header | Schema | Top Refs | Hex Preview."""

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
                    n_rows = t.get("row_count")
                    rows_label = f"{n_rows} rows" if n_rows is not None else "? rows"
                    label = f"{name}  ({rows_label}, {len(col_names)} cols)"
                    schema_tree[label] = {
                        col_names[i]: col_types[i] if i < len(col_types) else "?"
                        for i in range(len(col_names))
                    }
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

        def _decode(t: dict) -> tuple[list[str], list[list], list, int]:
            cols_dict: dict[int, list] = t.get("columns", {})
            col_indices = sorted(cols_dict.keys())
            col_names = t.get("column_names")
            if col_names:
                headers = [
                    col_names[i] if i < len(col_names) else f"col_{i}"
                    for i in col_indices
                ]
            else:
                headers = [f"col_{i}" for i in col_indices]
            n_rows = max((len(v) for v in cols_dict.values()), default=0)
            decoded_rows: list[list] = []
            for r in range(n_rows):
                decoded_rows.append(
                    [cols_dict[ci][r] if r < len(cols_dict[ci]) else None for ci in col_indices]
                )
            obj_keys = t.get("obj_keys") or []
            return headers, decoded_rows, obj_keys, n_rows

        for t in tables:
            name: str = t.get("name") or "?"
            if not t.get("columns"):
                continue
            headers, rows, obj_keys, n_rows = _decode(t)
            table_data[name] = {"columns": headers, "rows": rows, "__obj_keys": obj_keys}
            summary_rows.append([name, len(headers), n_rows])

        for t in inactive_tables:
            name = t.get("name") or "?"
            if not t.get("columns"):
                continue
            headers, rows, obj_keys, n_rows = _decode(t)
            inactive_table_data[name] = {"columns": headers, "rows": rows, "__obj_keys": obj_keys}

        viewer_data: dict[str, Any] = {
            "Summary": {
                "columns": ["Table", "Decoded cols", "Rows"],
                "rows": summary_rows,
            },
            "__prev_ref_data": inactive_table_data or None,
        }
        viewer_data.update(table_data)
        tmp = _create_realm_sqlite(table_data, inactive_table_data or None)
        if tmp:
            viewer_data["__db_path"] = str(tmp)
        return TableViewer(viewer_data, parent, show_db_tabs=False, summary_nav_table="Summary")

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
