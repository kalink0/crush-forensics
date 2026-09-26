# SPDX-License-Identifier: Apache-2.0
"""Generated views in the Table Viewer: Crush's own words are shown in the
UI language, CSV export and copy always write the English original, and
file data is never translated."""
from __future__ import annotations

import ast
import csv
import sqlite3
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

import crush.viewers.generated_text as gen_module
import crush.viewers.table_viewer as tv_module
from crush.viewers.table_viewer import (
    TableViewer,
    _GENERATED_VALUES,
    _Gen,
    _export_cell_text,
    _export_header_text,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def fake_translation(monkeypatch):
    """Every generated-view text shown as «text» -- a stand-in for a real
    translation that makes translated vs. original visible."""
    real = gen_module.translate

    def fake(context: str, text: str, *args: object) -> str:
        return f"«{text}»" if context == "GeneratedView" else real(context, text, *args)

    monkeypatch.setattr(gen_module, "translate", fake)


def _headers(model) -> tuple[list[str], list[str]]:
    shown = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    exported = [_export_header_text(model, c) for c in range(model.columnCount())]
    return shown, exported


def _column(model, col: int) -> tuple[list[str], list[str]]:
    shown = [model.index(r, col).data() for r in range(model.rowCount())]
    exported = [_export_cell_text(model, model.index(r, col)) for r in range(model.rowCount())]
    return shown, exported


def _make_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    # A table whose names and values look like Crush's own words: file data,
    # never translated.
    conn.execute('CREATE TABLE "Active" ("Page" TEXT, "Status" TEXT)')
    conn.execute("INSERT INTO \"Active\" VALUES ('x', 'Superseded')")
    conn.commit()
    conn.close()


def _viewer(db_path: Path) -> TableViewer:
    data = {
        "__db_path": str(db_path),
        "Active": {"columns": ["Page", "Status"], "rows": [["x", "Superseded"]]},
    }
    return TableViewer(data, source_name=db_path.name)


def test_db_info_translated_on_screen_english_in_export(
    qapp, tmp_path: Path, fake_translation, monkeypatch
) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    tv = _viewer(db)
    tv._load_db_info()
    model = tv._source_model

    shown, exported = _headers(model)
    assert shown == ["«Setting (generated)»", "«Value»", "«Description»"]
    assert exported == ["Setting (generated)", "Value", "Description"]

    names_shown, names_exported = _column(model, 0)
    assert "«Page size (B)»" in names_shown
    assert "Page size (B)" in names_exported
    desc_shown, desc_exported = _column(model, 2)
    assert "«Application-defined schema version number»" in desc_shown
    assert "Application-defined schema version number" in desc_exported

    out = tmp_path / "out.csv"
    monkeypatch.setattr(
        tv_module.QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "")
    )
    tv._export_csv()
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0] == ["Setting (generated)", "Value", "Description"]
    assert not any("«" in cell for row in rows for cell in row)


def test_file_data_is_never_translated(qapp, tmp_path: Path, fake_translation) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    tv = _viewer(db)
    tv._load_table("Active")

    shown, exported = _headers(tv._source_model)
    assert shown == ["«Row»", "Page", "Status"]
    assert exported == ["Row", "Page", "Status"]
    values, _ = _column(tv._source_model, 2)
    assert values == ["Superseded"]


def test_copy_writes_the_english_original(qapp, tmp_path: Path, fake_translation) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    tv = _viewer(db)
    tv._load_db_info()
    tv._copy_rows([0])
    copied = QApplication.clipboard().text()
    assert "«" not in copied
    proxy = tv._proxy_model  # copy follows the view's row order
    first = proxy.index(0, 0)
    assert first.data().startswith("«")
    assert copied.split("\t")[0] == _export_cell_text(proxy, first)


def test_view_names_are_keyed_by_english(qapp, tmp_path: Path, fake_translation) -> None:
    db = tmp_path / "t.db"
    _make_db(db)
    tv = _viewer(db)
    combo = tv._table_combo
    texts = [combo.itemText(i) for i in range(combo.count())]
    assert "«DB Info (generated)»" in texts
    assert "DB Info (generated)" not in texts
    combo.setCurrentIndex(texts.index("«DB Info (generated)»"))
    assert tv._current_table() == "DB Info (generated)"
    # A real table keeps its own name as its key.
    combo.setCurrentIndex(texts.index("Active"))
    assert tv._current_table() == "Active"


def test_nested_value_and_broken_translation(qapp, monkeypatch) -> None:
    label = _Gen("WAL {status} (frame {frame})", status=_Gen("Superseded"), frame=3)
    monkeypatch.setattr(gen_module, "translate", lambda c, t, *a: f"«{t}»")
    assert label.pair() == ("WAL Superseded (frame 3)", "«WAL «Superseded» (frame 3)»")
    # A translation whose placeholders don't fit: English, never a crash.
    monkeypatch.setattr(gen_module, "translate", lambda c, t, *a: "{wrong}")
    assert _Gen("{count} rows", count=2).pair() == ("2 rows", "2 rows")


def _string_assignments(path: Path, keyword: str) -> set[str]:
    """String values the core assigns to `f["status"] = ...` / `kind=...`."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == keyword
                    and isinstance(node.value.value, str)
                ):
                    found.add(node.value.value)
        if isinstance(node, ast.keyword) and node.arg == keyword:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                found.add(node.value.value)
    return found


def test_every_core_value_shown_in_a_view_is_marked() -> None:
    """WAL frame status and journal row kind come from crush.core at
    runtime; a value missing from _GENERATED_VALUES would silently stay
    English in a translated UI."""
    statuses = _string_assignments(ROOT / "crush/core/sqlite_wal.py", "status")
    kinds = _string_assignments(ROOT / "crush/core/sqlite_journal.py", "kind")
    assert statuses and kinds
    assert statuses | kinds <= set(_GENERATED_VALUES)
