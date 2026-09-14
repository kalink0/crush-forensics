# SPDX-License-Identifier: Apache-2.0
"""Tests for PropertiesPanel.show_analyzer_result and its wiring into
MainWindow's tab-switch refresh (crush/ui/props_panel.py,
crush/ui/main_window.py's _on_viewer_tab_changed)."""
from __future__ import annotations

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
        "dev_mode": False,
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


def test_show_analyzer_result_flags_dev_mode(qapp) -> None:
    panel = PropertiesPanel()

    panel.show_analyzer_result({**_RESULT, "run": {**_RESULT["run"], "dev_mode": True}})

    texts = " ".join(_field_texts(panel))
    assert "unvetted external module" in texts


def test_show_analyzer_result_clears_previous_node_state(qapp) -> None:
    panel = PropertiesPanel()
    panel._current_node = object()
    panel._current_vfs = object()

    panel.show_analyzer_result(_RESULT)

    assert panel._current_node is None
    assert panel._current_vfs is None
