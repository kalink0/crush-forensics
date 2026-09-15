# SPDX-License-Identifier: Apache-2.0
"""Tests for PropertiesPanel.show_analyzer_result and its wiring into
MainWindow's tab-switch refresh (crush/ui/props_panel.py,
crush/ui/main_window.py's _on_viewer_tab_changed)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from crush.ui.props_panel import PropertiesPanel

_RESULT = {
    "analyzer": {
        "id": "get_installed_apps",
        "name": "Application State",
        "tool": "crush-analyze",
        "tool_version": "0.1.0",
        "module_version": "2026-08-25",
    },
    "run": {
        "input_path": "/tmp/fixture",
        "started_at": "2026-09-14T12:00:00Z",
        "duration_ms": 42,
    },
    "status": "ok",
    "warnings": [],
}


def _field_texts(panel: PropertiesPanel) -> list[str]:
    return [
        panel._layout.itemAt(i).widget().text()
        for i in range(panel._layout.count())
        if isinstance(panel._layout.itemAt(i).widget(), QLabel)
    ]


def test_show_analyzer_result_displays_provenance_fields(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT)

    texts = " ".join(_field_texts(panel))
    assert "get_installed_apps" in texts
    assert "crush-analyze 0.1.0" in texts
    assert "/tmp/fixture" in texts
    assert "42 ms" in texts
    assert "ok" in texts


def test_show_analyzer_result_flags_error_status(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result({**_RESULT, "status": "error"})

    texts = " ".join(_field_texts(panel))
    assert "error" in texts


def test_show_analyzer_result_header_uses_passed_title_not_raw_contract_name(qapp) -> None:
    """The tab title and picker label go through MainWindow's own
    _ANALYZER_MODULE_DISPLAY_NAMES override (e.g. "Installed
    Applications"), not the contract's raw "Application State" -- the
    panel header must match what the tab actually says, not silently
    show a different name for the same result."""
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT, "Installed Applications")

    texts = " ".join(_field_texts(panel))
    assert "Installed Applications" in texts
    assert "Application State" not in texts


def test_show_analyzer_result_falls_back_to_contract_name_without_title(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT)

    texts = " ".join(_field_texts(panel))
    assert "Application State" in texts


def test_show_analyzer_result_shows_source_link_for_curated_module(qapp) -> None:
    """A curated module's contract v1 result carries analyzer.source (the
    upstream repo/commit/path crush-analyze's vendored copy was fetched
    from) -- the panel should show which parser file it is and a link
    pinned to that exact commit, not just the repo."""
    panel = PropertiesPanel()
    result = {
        **_RESULT,
        "analyzer": {
            **_RESULT["analyzer"],
            "source": {
                "repo": "https://github.com/abrignoni/iLEAPP",
                "commit": "b055398e485daae838ba3c55fd611cc303f0a854",
                "path": "scripts/artifacts/applicationStateDB.py",
                "url": (
                    "https://github.com/abrignoni/iLEAPP/blob/"
                    "b055398e485daae838ba3c55fd611cc303f0a854/"
                    "scripts/artifacts/applicationStateDB.py"
                ),
            },
        },
    }

    panel.show_analyzer_result(result)

    texts = " ".join(_field_texts(panel))
    assert "applicationStateDB.py" in texts
    assert "iLEAPP" in texts
    assert "b055398e" in texts
    link_labels = [
        panel._layout.itemAt(i).widget()
        for i in range(panel._layout.count())
        if isinstance(panel._layout.itemAt(i).widget(), QLabel)
        and "href=" in panel._layout.itemAt(i).widget().text()
    ]
    assert len(link_labels) == 1
    assert result["analyzer"]["source"]["url"] in link_labels[0].text()


def test_show_analyzer_result_omits_source_rows_when_nothing_to_show(qapp) -> None:
    """The stub-module case: no source dict -- nothing meaningful to
    show, so no "Parser file"/"Source" rows should be added at all."""
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT)

    field_labels = [
        panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole).widget().text()
        for i in range(panel._layout.rowCount())
        if panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole) is not None
    ]
    assert "Parser file:" not in field_labels
    assert "Source:" not in field_labels


def test_show_analyzer_result_lists_source_files(qapp) -> None:
    panel = PropertiesPanel()
    result = {
        **_RESULT,
        "run": {
            **_RESULT["run"],
            "source_files": [
                "private/var/mobile/Library/FrontBoard/applicationState.db",
                "private/var/mobile/Library/FrontBoard/applicationState.db-wal",
            ],
        },
    }

    panel.show_analyzer_result(result)

    field_widgets = [
        panel._layout.itemAt(i, panel._layout.ItemRole.FieldRole).widget()
        for i in range(panel._layout.rowCount())
        if panel._layout.itemAt(i, panel._layout.ItemRole.FieldRole) is not None
    ]
    files_lbl = next(w for w in field_widgets if "applicationState.db-wal" in w.text())
    assert "applicationState.db" in files_lbl.text()
    # Real evidence filenames must never be interpreted as HTML.
    assert files_lbl.textFormat() == Qt.TextFormat.PlainText
    label_texts = [
        panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole).widget().text()
        for i in range(panel._layout.rowCount())
        if panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole) is not None
    ]
    assert "Source files (2):" in label_texts


def test_show_analyzer_result_omits_source_files_row_when_absent(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT)

    label_texts = [
        panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole).widget().text()
        for i in range(panel._layout.rowCount())
        if panel._layout.itemAt(i, panel._layout.ItemRole.LabelRole) is not None
    ]
    assert not any(t.startswith("Source files") for t in label_texts)


def test_show_analyzer_result_shows_relevance_text_when_given(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT, "Installed Applications", "Why this matters.")

    texts = " ".join(_field_texts(panel))
    assert "Why this matters." in texts


def test_show_analyzer_result_omits_relevance_row_when_none(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result(_RESULT)

    texts = " ".join(_field_texts(panel))
    assert "Why this matters." not in texts


def test_show_analyzer_result_clears_previous_node_state(qapp) -> None:
    panel = PropertiesPanel()
    panel._current_node = object()
    panel._current_vfs = object()

    panel.show_analyzer_result(_RESULT)

    assert panel._current_node is None
    assert panel._current_vfs is None
