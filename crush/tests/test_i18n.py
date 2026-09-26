# SPDX-License-Identifier: Apache-2.0
"""Tests for the translation infrastructure: catalog extraction, loading,
localized ParseIssue rendering and the pseudo locale."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from crush.__main__ import _parse_args
from crush.core import issues
from crush.core.issues import MESSAGES, ParseIssue, render, render_value
from crush.ui import i18n

ROOT = Path(__file__).resolve().parents[2]


def _load_script():
    spec = importlib.util.spec_from_file_location("i18n_script", ROOT / "scripts" / "i18n.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script()


def _tool(name: str) -> str:
    here = Path(sys.executable).parent
    found = shutil.which(f"pyside6-{name}") or shutil.which(
        f"pyside6-{name}", path=f"{here}{os.pathsep}{here / 'Scripts'}"
    )
    assert found, f"pyside6-{name} not found (installed with PySide6)"
    return found


@pytest.fixture
def clean_translators(qapp):
    """Remove whatever a test installed -- the QApplication is shared."""
    yield qapp
    for translator in i18n._installed:
        qapp.removeTranslator(translator)
    i18n._installed.clear()
    issues.set_translator(None)


# -- Catalog extraction ---------------------------------------------------------

def test_every_message_is_extracted_with_its_code(tmp_path: Path) -> None:
    """lupdate silently skips a text it can't read (e.g. one wrapped in
    extra parentheses), and the disambiguation must be the entry's code."""
    ts = tmp_path / "issues.ts"
    subprocess.run(
        [_tool("lupdate"), str(ROOT / "crush" / "core" / "issues.py"), "-ts", str(ts)],
        check=True, capture_output=True,
    )
    extracted = {
        (m.findtext("comment"), m.findtext("source"))
        for ctx in ET.parse(ts).getroot().iter("context")
        if ctx.findtext("name") == issues.TRANSLATION_CONTEXT
        for m in ctx.iter("message")
    }
    assert extracted == {(code, text) for code, text in MESSAGES.items()}


# -- Localized rendering ----------------------------------------------------------

def _fake_translator(table: dict[tuple[str, str], str]):
    def translate(context: str, source: str, disambiguation: str) -> str:
        assert context == issues.TRANSLATION_CONTEXT
        return table.get((disambiguation, source), source)
    return translate


def test_str_stays_english_with_translator(clean_translators) -> None:
    issues.set_translator(_fake_translator({("exif.present", "Present"): "Vorhanden"}))
    issue = ParseIssue("exif.present")
    assert str(issue) == "Present"
    assert render(issue) == "Present"
    assert render(issue, localized=True) == "Vorhanden"


def test_localized_without_translator_is_english() -> None:
    issue = ParseIssue("json.not_utf8", {"offset": 1234}, detail="boom")
    assert render(issue, localized=True) == render(issue)


def test_same_english_text_translated_per_code(clean_translators) -> None:
    issues.set_translator(_fake_translator({
        ("exif.present", "Present"): "A",
        ("xmp.present", "Present"): "B",
    }))
    assert render(ParseIssue("exif.present"), localized=True) == "A"
    assert render(ParseIssue("xmp.present"), localized=True) == "B"


def test_detail_and_params_kept_verbatim(clean_translators) -> None:
    template = MESSAGES["json.not_utf8"]
    issues.set_translator(_fake_translator({
        ("json.not_utf8", template): "Kein UTF-8 bei {offset:,}: {detail}",
    }))
    issue = ParseIssue("json.not_utf8", {"offset": 12345}, detail="codec can't decode")
    assert render(issue, localized=True) == "Kein UTF-8 bei 12,345: codec can't decode"


def test_broken_translation_falls_back_to_english(clean_translators) -> None:
    template = MESSAGES["json.not_utf8"]
    issues.set_translator(_fake_translator({
        ("json.not_utf8", template): "Kein UTF-8 bei {offst}: {detail}",
    }))
    issue = ParseIssue("json.not_utf8", {"offset": 7}, detail="x")
    assert render(issue, localized=True) == render(issue)


def test_nested_issues_rendered_localized(clean_translators) -> None:
    issues.set_translator(_fake_translator({
        ("ufdr.other_file", "file"): "Datei",
    }))
    outer = ParseIssue("ufdr.path_collision", {"other": ParseIssue("ufdr.other_file")})
    assert "Datei" in render(outer, localized=True)
    assert "Datei" not in str(outer)
    assert render_value([ParseIssue("ufdr.other_file")], localized=True) == "Datei"


# -- Loading ----------------------------------------------------------------------

def test_source_language_loads_nothing(clean_translators) -> None:
    assert i18n.load_language(clean_translators, "en") is None
    assert i18n._installed == []


@pytest.mark.parametrize("code", ["../x", "de/../../y", "DE", ""])
def test_invalid_code_rejected(clean_translators, tmp_path: Path, code: str) -> None:
    note = i18n.load_language(clean_translators, code or "?", directory=tmp_path)
    assert note and "not a valid language code" in note
    assert i18n._installed == []


def test_missing_translation_says_so(clean_translators, tmp_path: Path) -> None:
    note = i18n.load_language(clean_translators, "es", directory=tmp_path)
    assert note and "'es'" in note and "English" in note
    assert i18n._installed == []


def _compile(
    tmp_path: Path, code: str, translations: dict[tuple[str, str], tuple[str, bool]]
) -> None:
    """Write and compile (as `release` does) a catalog for *code*:
    (code, source) -> (translation, finished)."""
    root = ET.Element("TS", version="2.1", language=code)
    ctx = ET.SubElement(root, "context")
    ET.SubElement(ctx, "name").text = issues.TRANSLATION_CONTEXT
    for (disambiguation, source), (text, finished) in translations.items():
        message = ET.SubElement(ctx, "message")
        ET.SubElement(message, "source").text = source
        ET.SubElement(message, "comment").text = disambiguation
        translation = ET.SubElement(message, "translation")
        translation.text = text
        if not finished:
            translation.set("type", "unfinished")
    ts = tmp_path / f"crush_{code}.ts"
    ET.ElementTree(root).write(ts, encoding="utf-8", xml_declaration=True)
    script.compile_catalog(ts, ts.with_suffix(".qm"))


def test_compiled_translation_end_to_end(clean_translators, tmp_path: Path) -> None:
    _compile(tmp_path, "de", {
        ("exif.present", "Present"): ("Vorhanden", True),
        ("xmp.present", "Present"): ("XMP vorhanden", True),
        ("exif.not_present", "Not present"): ("Entwurf", False),
    })
    assert i18n.load_language(clean_translators, "de", directory=tmp_path) is None
    # Same English text, translated per code.
    assert render(ParseIssue("exif.present"), localized=True) == "Vorhanden"
    assert render(ParseIssue("xmp.present"), localized=True) == "XMP vorhanden"
    # A draft still marked unfinished is not shown.
    assert render(ParseIssue("exif.not_present"), localized=True) == "Not present"
    assert str(ParseIssue("exif.present")) == "Present"


def test_untranslated_code_never_borrows_another_codes_translation(
    clean_translators, tmp_path: Path
) -> None:
    """Qt's lookup falls back to the translation of another message with
    the identical source text -- which may mean something else. release
    gives every untranslated text its own English entry, also a code the
    catalog doesn't list yet (merged from the current code)."""
    _compile(tmp_path, "de", {
        ("exif.present", "Present"): ("Vorhanden", True),
        ("xmp.present", "Present"): ("", False),
        # pdf.js_present ("Present") is not in this catalog at all.
    })
    assert i18n.load_language(clean_translators, "de", directory=tmp_path) is None
    assert render(ParseIssue("exif.present"), localized=True) == "Vorhanden"
    assert render(ParseIssue("xmp.present"), localized=True) == "Present"
    assert render(ParseIssue("pdf.js_present"), localized=True) == "Present"


def test_release_counts_against_current_code(tmp_path: Path) -> None:
    _compile(tmp_path, "de", {("exif.present", "Present"): ("Vorhanden", True)})
    ts = tmp_path / "crush_de.ts"
    translated, total = script.compile_catalog(ts, tmp_path / "again.qm")
    assert translated == 1
    assert total >= len(MESSAGES)   # every code in the source tree, not just the 1 listed
    # The catalog itself is left as it was.
    assert script.count_messages(ts) == (1, 1)


# -- Menu offer -------------------------------------------------------------------

def test_available_languages_and_threshold(tmp_path: Path) -> None:
    (tmp_path / i18n.MANIFEST_NAME).write_text(json.dumps({
        "de": {"translated": 90, "total": 100},
        "es": {"translated": 89, "total": 100},
        "fr": {"translated": 100, "total": 100},   # no .qm -> not available
        "pseudo": {"translated": 100, "total": 100},
    }))
    for code in ("de", "es", "pseudo"):
        (tmp_path / f"crush_{code}.qm").write_bytes(b"")
    langs = {lang.code: lang for lang in i18n.available_languages(tmp_path)}
    assert set(langs) == {"de", "es", "pseudo"}
    assert langs["de"].offered
    assert not langs["es"].offered
    assert not langs["pseudo"].offered


def test_no_manifest_means_no_languages(tmp_path: Path) -> None:
    assert i18n.available_languages(tmp_path) == []


def test_display_names() -> None:
    assert i18n.display_name("en") == "English"
    assert i18n.display_name("de") == "Deutsch — German"
    assert "Brasil" in i18n.display_name("pt_BR")


def test_language_flag_parsed() -> None:
    assert _parse_args(["--language", "pseudo"]).language == "pseudo"
    assert _parse_args([]).language is None


# -- scripts/i18n.py --------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Not valid UTF-8 (offset {offset:,}: {detail})",
    "Unsupported (glInternalFormat 0x{fmt:04X})",
    "<b>Bold</b> &amp; &Open %1",
])
def test_pseudo_keeps_placeholders_markup_mnemonics(text: str) -> None:
    out = script.pseudo_translate(text)
    assert out.startswith("[") and out.endswith("]")
    for token in script._PROTECTED.findall(text):
        assert token in out
    if "{" in text:
        out.format(offset=1, detail="d", fmt=10)  # placeholders still fill
    ascii_letters = [c for c in out if c.isascii() and c.isalpha()]
    protected = "".join(script._PROTECTED.findall(text))
    assert all(c in protected for c in ascii_letters)


def test_count_messages(tmp_path: Path) -> None:
    ts = tmp_path / "x.ts"
    ts.write_text(
        '<?xml version="1.0" encoding="utf-8"?><TS version="2.1" language="de"><context>'
        "<name>C</name>"
        "<message><source>a</source><translation>A</translation></message>"
        '<message><source>b</source><translation type="unfinished"></translation></message>'
        '<message><source>c</source><translation type="unfinished">C?</translation></message>'
        '<message><source>d</source><translation type="vanished">D</translation></message>'
        "<message numerus=\"yes\"><source>%n e</source><translation>"
        "<numerusform>1</numerusform><numerusform></numerusform></translation></message>"
        "</context></TS>",
        encoding="utf-8",
    )
    assert script.count_messages(ts) == (1, 4)
