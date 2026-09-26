# SPDX-License-Identifier: Apache-2.0
"""Translated knowledge content: formats.db texts (forensic relevance,
magic-byte descriptions, categories) and analyzer module texts, and the
shared "Show English original" setting."""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QCheckBox, QLabel

from crush.core import issues
from crush.core.format_db import (
    CATEGORY_CONTEXT,
    FORMAT_CATEGORIES,
    KNOWLEDGE_CONTEXT,
    FormatDatabase,
    FormatMatch,
)
from crush.core.issues import CatalogText, render_value
from crush.data import build_formats_db
from crush.ui import i18n

PACKAGE = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = PACKAGE / "data" / "build_formats_db.py"


def _lupdate(tmp_path: Path, *files: Path) -> set[tuple[str, str, str]]:
    """(context, source, disambiguation) of every text lupdate extracts."""
    here = Path(sys.executable).parent
    tool = shutil.which("pyside6-lupdate") or shutil.which(
        "pyside6-lupdate", path=f"{here}{os.pathsep}{here / 'Scripts'}"
    )
    assert tool, "pyside6-lupdate not found (installed with PySide6)"
    ts = tmp_path / "out.ts"
    subprocess.run([tool, *map(str, files), "-ts", str(ts)], check=True, capture_output=True)
    return {
        (ctx.findtext("name") or "", m.findtext("source") or "", m.findtext("comment") or "")
        for ctx in ET.parse(ts).getroot().iter("context")
        for m in ctx.iter("message")
    }


@pytest.fixture
def translated(qapp, tmp_path: Path):
    """A fake translation: every catalog text becomes '<DE> text'. The
    setting lives in a scratch file, never the analyst's own settings."""
    issues.set_translator(lambda _ctx, source, _dis: f"<DE> {source}")
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    yield settings
    issues.set_translator(None)
    issues.set_knowledge_original(False)


def _sqlite() -> FormatMatch:
    fmt = FormatDatabase.get().by_parser_class("SQLiteParser")
    assert fmt is not None
    return fmt


# -- Marking in build_formats_db.py ---------------------------------------------

def _noop_problems() -> list[str]:
    """Every forensic_relevance and non-empty magic description must be
    QT_TRANSLATE_NOOP("FormatKnowledge", <literal>, <the format's name>)."""
    tree = ast.parse(BUILD_SCRIPT.read_text(encoding="utf-8"))
    formats = next(
        n.value for n in tree.body
        if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "FORMATS"
    )
    found = []
    assert isinstance(formats, ast.List)
    for entry in formats.elts:
        assert isinstance(entry, ast.Dict)
        fields = {ast.literal_eval(k): v for k, v in zip(entry.keys, entry.values) if k}
        name = ast.literal_eval(fields["name"])
        values = [("forensic_relevance", fields.get("forensic_relevance"))]
        magic = fields.get("magic")
        if isinstance(magic, ast.List):
            for m in magic.elts:
                assert isinstance(m, ast.Dict)
                mf = {ast.literal_eval(k): v for k, v in zip(m.keys, m.values) if k}
                values.append(("magic description", mf.get("description")))
        for what, value in values:
            if value is None or (isinstance(value, ast.Constant) and value.value == ""):
                continue
            ok = (
                isinstance(value, ast.Call)
                and getattr(value.func, "id", "") == "QT_TRANSLATE_NOOP"
                and len(value.args) == 3
                and all(isinstance(a, ast.Constant) for a in value.args)
                and value.args[0].value == KNOWLEDGE_CONTEXT  # type: ignore[attr-defined]
                and value.args[2].value == name  # type: ignore[attr-defined]
            )
            if not ok:
                found.append(f"{name}: {what} not marked for translation")
    return found


def test_every_knowledge_text_is_marked_with_its_format() -> None:
    assert _noop_problems() == []


def test_lupdate_extracts_every_knowledge_text(tmp_path: Path) -> None:
    extracted = _lupdate(tmp_path, BUILD_SCRIPT)
    expected = set()
    for fmt in build_formats_db.FORMATS:
        if fmt.get("status") != "reviewed":
            continue
        expected.add((KNOWLEDGE_CONTEXT, fmt["forensic_relevance"], fmt["name"]))
        for m in fmt.get("magic", []):
            if m.get("description"):
                expected.add((KNOWLEDGE_CONTEXT, m["description"], fmt["name"]))
    assert expected - extracted == set()


def test_lupdate_extracts_categories(tmp_path: Path) -> None:
    extracted = _lupdate(tmp_path, PACKAGE / "core" / "format_db.py")
    assert {(CATEGORY_CONTEXT, c, "") for c in FORMAT_CATEGORIES} <= extracted


# -- CatalogText --------------------------------------------------------------

def test_catalog_text_english_without_translation() -> None:
    fmt = _sqlite()
    text = fmt.relevance_text()
    assert str(text) == fmt.forensic_relevance
    assert text.localized() == fmt.forensic_relevance
    assert render_value(text, localized=True) == fmt.forensic_relevance


def test_catalog_text_translated_but_str_stays_english(translated) -> None:
    text = _sqlite().relevance_text()
    assert text.localized() == f"<DE> {text.text}"
    assert render_value(text, localized=True) == f"<DE> {text.text}"
    assert str(text) == text.text
    assert render_value(text) == text.text


def test_catalog_text_uses_format_name_as_disambiguation(qapp) -> None:
    seen = []
    issues.set_translator(lambda ctx, src, dis: seen.append((ctx, dis)) or src)
    try:
        fmt = _sqlite()
        fmt.relevance_text().localized()
        fmt.magic_description_text("x").localized()
        fmt.category_text().localized()
    finally:
        issues.set_translator(None)
    assert seen == [
        (KNOWLEDGE_CONTEXT, fmt.name), (KNOWLEDGE_CONTEXT, fmt.name), (CATEGORY_CONTEXT, ""),
    ]


def test_english_original_switches_knowledge_not_labels(translated) -> None:
    fmt = _sqlite()
    i18n.set_knowledge_original(translated, True)
    assert fmt.relevance_text().localized() == fmt.forensic_relevance
    assert fmt.category_text().localized() == f"<DE> {fmt.category}"
    assert translated.value(i18n.KNOWLEDGE_ORIGINAL_KEY, type=bool) is True


def test_english_original_setting_loaded(translated) -> None:
    translated.setValue(i18n.KNOWLEDGE_ORIGINAL_KEY, True)
    i18n.load_knowledge_original(translated)
    assert issues.knowledge_original() is True


def test_empty_translation_falls_back_to_english(qapp) -> None:
    issues.set_translator(lambda *_a: "")
    try:
        assert CatalogText("FormatKnowledge", "Text", "X", knowledge=True).localized() == "Text"
    finally:
        issues.set_translator(None)


# -- UI ---------------------------------------------------------------------------

def _labels(widget) -> list[str]:
    return [lbl.text() for lbl in widget.findChildren(QLabel)]


def _checkbox(widget) -> QCheckBox | None:
    boxes = widget.findChildren(QCheckBox)
    return boxes[0] if boxes else None


def _metadata(fmt: FormatMatch) -> dict:
    return {
        "Format": fmt.name,
        "Category": fmt.category_text(),
        "Forensic relevance": fmt.relevance_text(),
    }


def test_props_panel_english_shows_no_checkbox(qapp) -> None:
    from crush.core.vfs import VFSNode
    from crush.ui.props_panel import PropertiesPanel

    fmt = _sqlite()
    panel = PropertiesPanel()
    panel.update_properties(VFSNode(name="a.db", path="/a.db", is_dir=False), _metadata(fmt))
    assert fmt.forensic_relevance in _labels(panel)
    assert fmt.category in _labels(panel)
    assert _checkbox(panel) is None


def test_props_panel_translated_and_toggled(translated, monkeypatch) -> None:
    from crush.core.vfs import VFSNode
    from crush.ui import knowledge_toggle
    from crush.ui.props_panel import PropertiesPanel

    monkeypatch.setattr(knowledge_toggle, "_app_settings", lambda: translated)
    fmt = _sqlite()
    panel = PropertiesPanel()
    panel.update_properties(VFSNode(name="a.db", path="/a.db", is_dir=False), _metadata(fmt))
    assert f"<DE> {fmt.forensic_relevance}" in _labels(panel)
    box = _checkbox(panel)
    assert box is not None and not box.isChecked()

    box.setChecked(True)
    assert fmt.forensic_relevance in _labels(panel)
    assert f"<DE> {fmt.category}" in _labels(panel)  # a label, not knowledge
    box.setChecked(False)
    assert f"<DE> {fmt.forensic_relevance}" in _labels(panel)


def test_analyzer_relevance_translated(translated, monkeypatch) -> None:
    from crush.ui import knowledge_toggle
    from crush.ui.props_panel import PropertiesPanel

    monkeypatch.setattr(knowledge_toggle, "_app_settings", lambda: translated)
    relevance = CatalogText("AnalyzerKnowledge", "Why this matters.", "mod", knowledge=True)
    panel = PropertiesPanel()
    panel.show_analyzer_result({"analyzer": {"id": "mod"}, "run": {}}, "Title", relevance)
    assert "<DE> Why this matters." in _labels(panel)
    box = _checkbox(panel)
    assert box is not None
    box.setChecked(True)
    assert "Why this matters." in _labels(panel)


def test_all_open_checkboxes_follow_the_setting(translated, monkeypatch) -> None:
    from crush.ui import knowledge_toggle

    monkeypatch.setattr(knowledge_toggle, "_app_settings", lambda: translated)
    a = knowledge_toggle.knowledge_original_checkbox()
    b = knowledge_toggle.knowledge_original_checkbox()
    assert a is not None and b is not None
    a.setChecked(True)
    assert b.isChecked()


def test_format_info_english_unchanged(qapp) -> None:
    from crush.ui.format_info_dialog import FormatInfoDialog

    fmt = _sqlite()
    dlg = FormatInfoDialog(None, fmt)
    labels = _labels(dlg)
    assert fmt.forensic_relevance in labels
    assert fmt.category.capitalize() in labels
    assert "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00  —  " in "\n".join(labels)
    assert "[offset 0 (0x0)]" in "\n".join(labels)
    assert _checkbox(dlg) is None


def test_format_info_translated_and_toggled(translated, monkeypatch) -> None:
    from crush.ui import knowledge_toggle
    from crush.ui.format_info_dialog import FormatInfoDialog

    monkeypatch.setattr(knowledge_toggle, "_app_settings", lambda: translated)
    fmt = _sqlite()
    description = fmt.magic[0][2]
    dlg = FormatInfoDialog(None, fmt)
    text = "\n".join(_labels(dlg))
    assert f"<DE> {fmt.forensic_relevance}" in text
    assert f"<DE> {description}" in text
    assert f"<DE> {fmt.category}" in text
    box = _checkbox(dlg)
    assert box is not None
    box.setChecked(True)
    text = "\n".join(_labels(dlg))
    assert f"<DE> {fmt.forensic_relevance}" not in text
    assert f"<DE> {description}" not in text
    assert fmt.forensic_relevance in text


def test_format_reference_search_matches_both(translated, monkeypatch) -> None:
    from crush.ui import knowledge_toggle
    from crush.ui.format_reference import _COL_RELEVANCE, FormatReferenceDialog

    monkeypatch.setattr(knowledge_toggle, "_app_settings", lambda: translated)
    dlg = FormatReferenceDialog()
    total = dlg._proxy.rowCount()
    relevance = dlg._model.item(0, _COL_RELEVANCE).text()
    assert relevance.startswith("<DE> ")
    dlg._search.setText("<DE>")
    assert dlg._proxy.rowCount() == total
    english = relevance.removeprefix("<DE> ")
    dlg._search.setText(english[:40])
    assert dlg._proxy.rowCount() >= 1

    box = _checkbox(dlg)
    assert box is not None
    box.setChecked(True)
    assert dlg._model.item(0, _COL_RELEVANCE).text() == english
    dlg.close()


def test_format_reference_english_unchanged(qapp) -> None:
    from crush.ui.format_reference import _COL_CAT, _COL_RELEVANCE, FormatReferenceDialog

    dlg = FormatReferenceDialog()
    formats = FormatDatabase.get().all_formats()
    for row, fmt in enumerate(formats):
        assert dlg._model.item(row, _COL_CAT).text() == fmt.category
        assert dlg._model.item(row, _COL_RELEVANCE).text() == fmt.forensic_relevance
    assert _checkbox(dlg) is None
    dlg.close()
