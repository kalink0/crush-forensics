# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic crush-analyze contract v1 result viewer."""
from __future__ import annotations

from crush.viewers.analyzer_result_viewer import AnalyzerResultViewer

_OK_RESULT = {
    "status": "ok",
    "warnings": [],
    "error": None,
    "run": {"dev_mode": False},
    "columns": [
        {"key": "bundle_id", "label": "Bundle ID", "type": "string"},
    ],
    "rows": [
        {"_row_status": "ok", "bundle_id": "com.example.app"},
    ],
}


def test_ok_result_shows_no_banner_and_all_rows(qapp) -> None:
    from PySide6.QtWidgets import QLabel, QTableView

    viewer = AnalyzerResultViewer(_OK_RESULT)

    assert viewer.findChild(QLabel, "analyzer_banner") is None
    table_view = viewer.findChild(QTableView)
    assert table_view is not None
    assert table_view.model().rowCount() == 1
    assert table_view.model().columnCount() == 1


def test_error_result_shows_a_banner_with_the_message(qapp) -> None:
    from PySide6.QtWidgets import QLabel

    result = {
        **_OK_RESULT,
        "status": "error",
        "error": {"message": "boom", "detail": "ValueError"},
        "rows": [],
        "columns": [],
    }

    viewer = AnalyzerResultViewer(result)

    banner = viewer.findChild(QLabel, "analyzer_banner")
    assert banner is not None
    assert "error" in banner.text().lower()
    assert "boom" in banner.text()


def test_dev_mode_result_shows_an_unvetted_module_banner(qapp) -> None:
    from PySide6.QtWidgets import QLabel

    result = {**_OK_RESULT, "run": {"dev_mode": True}}

    viewer = AnalyzerResultViewer(result)

    banner = viewer.findChild(QLabel, "analyzer_banner")
    assert banner is not None
    assert "dev mode" in banner.text().lower()


def test_warnings_are_shown_even_when_status_is_ok(qapp) -> None:
    from PySide6.QtWidgets import QLabel

    result = {**_OK_RESULT, "warnings": ["3 rows skipped: malformed date"]}

    viewer = AnalyzerResultViewer(result)

    banner = viewer.findChild(QLabel, "analyzer_banner")
    assert banner is not None
    assert "3 rows skipped" in banner.text()


def test_search_filters_rows_across_all_columns(qapp) -> None:
    result = {
        **_OK_RESULT,
        "rows": [
            {"_row_status": "ok", "bundle_id": "com.apple.mobilesafari"},
            {"_row_status": "ok", "bundle_id": "com.example.testapp"},
        ],
    }

    viewer = AnalyzerResultViewer(result)
    viewer._search.setText("testapp")

    assert viewer._proxy_model.rowCount() == 1
    assert viewer._proxy_model.index(0, 0).data() == "com.example.testapp"


def test_copy_selection_joins_selected_rows_as_tsv(qapp) -> None:
    from PySide6.QtWidgets import QApplication

    result = {
        **_OK_RESULT,
        "columns": [
            {"key": "bundle_id", "label": "Bundle ID", "type": "string"},
            {"key": "bundle_path", "label": "Bundle Path", "type": "string"},
        ],
        "rows": [
            {"_row_status": "ok", "bundle_id": "a", "bundle_path": "/A.app"},
            {"_row_status": "ok", "bundle_id": "b", "bundle_path": "/B.app"},
        ],
    }

    viewer = AnalyzerResultViewer(result)
    viewer._table.selectAll()
    viewer._copy_selection()

    assert QApplication.clipboard().text() == "a\t/A.app\nb\t/B.app"


def test_value_bar_shows_the_currently_selected_cell(qapp) -> None:
    result = {
        **_OK_RESULT,
        "columns": [
            {"key": "bundle_id", "label": "Bundle ID", "type": "string"},
            {"key": "bundle_path", "label": "Bundle Path", "type": "string"},
        ],
        "rows": [
            {"_row_status": "ok", "bundle_id": "com.example.app", "bundle_path": "/A/B/App.app"},
        ],
    }

    viewer = AnalyzerResultViewer(result)
    assert viewer._value_field.text() == ""

    index = viewer._proxy_model.index(0, 1)
    viewer._table.setCurrentIndex(index)

    assert viewer._value_field.text() == "/A/B/App.app"
    assert viewer._value_field.isReadOnly()


def test_export_csv_writes_filtered_rows_only(qapp, tmp_path, monkeypatch) -> None:
    import csv

    from PySide6.QtWidgets import QFileDialog

    result = {
        **_OK_RESULT,
        "rows": [
            {"_row_status": "ok", "bundle_id": "com.apple.mobilesafari"},
            {"_row_status": "ok", "bundle_id": "com.example.testapp"},
        ],
    }
    out_path = tmp_path / "out.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", lambda *a, **k: (str(out_path), "CSV (*.csv)")
    )

    viewer = AnalyzerResultViewer(result)
    viewer._search.setText("testapp")
    viewer._export_csv()

    with open(out_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows == [["Bundle ID"], ["com.example.testapp"]]
