# SPDX-License-Identifier: Apache-2.0
"""scripts/build_format_pages.py: the format reference site built from
build_formats_db.py."""
from __future__ import annotations

import html
import importlib.util
import json
import re
import shutil
import sqlite3
import subprocess
import urllib.parse
import sys
from pathlib import Path
from typing import Any

import pytest

from crush.data import build_formats_db as source

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
GENERATED = "2026-10-05 06:00:00"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "build_format_pages_script", ROOT / "scripts" / "build_format_pages.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pages = _load_script()


def _build(out: Path) -> Path:
    pages.build(out, COMMIT, GENERATED)
    return out / "formats"


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> Path:
    return _build(tmp_path_factory.mktemp("site"))


@pytest.fixture(scope="module")
def published(site) -> dict[str, Any]:
    return json.loads((site / "formats.json").read_text(encoding="utf-8"))


def _entry(**overrides: Any) -> dict[str, Any]:
    fmt: dict[str, Any] = {
        "name": "Test Format", "short_name": "TestFmt", "category": "database",
        "forensic_relevance": "Relevance <text> & more.", "platforms": ["Linux"],
        "parser_class": None,
        "magic": [{"offset": 0, "value": b"TSTF", "description": "Test magic"}],
        "extensions": [".TST"], "links": [("Spec", "https://example.org/spec")],
        "status": "reviewed", "last_reviewed": "2026-10-05",
    }
    fmt.update(overrides)
    return fmt


def test_every_entry_has_a_page_and_a_json_record(site, published):
    slugs = {source.url_slug(f["short_name"]) for f in source.FORMATS}
    assert len(slugs) == len(source.FORMATS)
    pages_built = {p.name for p in site.iterdir() if (p / "index.html").is_file()}
    assert pages_built == slugs | set(pages.SITE_LANGUAGES)
    for code in pages.SITE_LANGUAGES:
        assert {p.name for p in (site / code).iterdir() if p.is_dir()} == slugs
    assert {r["slug"] for r in published["formats"]} == slugs


def test_json_holds_every_field_of_every_entry(published):
    by_name = {r["name"]: r for r in published["formats"]}
    assert len(by_name) == len(source.FORMATS)
    for fmt in source.FORMATS:
        e = source.entry(fmt)
        r = by_name[e["name"]]
        for key in ("short_name", "category", "forensic_relevance", "platforms",
                    "parser_class", "status", "last_reviewed", "extensions"):
            assert r[key] == e[key], (e["name"], key)
        assert r["links"] == [{"label": lb, "url": u} for lb, u in e["links"]]
        assert r["signatures"] == [
            {"offset": m["offset"], "hex": m["value"].hex().upper(),
             "length": len(m["value"]), "description": m["description"]}
            for m in e["magic"]
        ], e["name"]
        assert r["url"] == f"{pages.DEFAULT_SITE_URL}{r['slug']}/"


def test_json_matches_the_formats_db_built_from_the_same_source(site, published):
    """The site and formats.db both read the entries through entry()."""
    conn = sqlite3.connect(site / "formats.db")
    rows = {
        name: (short, cat, rel, plat, parser, reviewed, fid)
        for fid, name, short, cat, rel, plat, parser, reviewed in conn.execute(
            "SELECT id, name, short_name, category, forensic_relevance, platforms, "
            "parser_class, last_reviewed FROM formats"
        )
    }
    reviewed = [r for r in published["formats"] if r["status"] == "reviewed"]
    assert len(rows) == len(reviewed)
    for r in reviewed:
        short, cat, rel, plat, parser, last, fid = rows[r["name"]]
        assert (short, cat, rel, plat, parser, last) == (
            r["short_name"], r["category"], r["forensic_relevance"],
            ",".join(r["platforms"]), r["parser_class"], r["last_reviewed"],
        )
        sigs = [
            {"offset": off, "hex": bytes(pat).hex().upper(), "length": len(pat),
             "description": desc}
            for off, pat, desc in conn.execute(
                "SELECT offset, pattern, description FROM magic_bytes "
                "WHERE format_id = ? ORDER BY id", (fid,))
        ]
        assert sigs == r["signatures"]
        exts = [e for (e,) in conn.execute(
            "SELECT extension FROM extensions WHERE format_id = ?", (fid,))]
        assert exts == r["extensions"]
        links = [{"label": lb, "url": u} for lb, u in conn.execute(
            "SELECT label, url FROM links WHERE format_id = ? ORDER BY id", (fid,))]
        assert links == r["links"]
    conn.close()


def test_format_page_shows_every_text(site, published):
    for r in published["formats"]:
        page = (site / r["slug"] / "index.html").read_text(encoding="utf-8")
        assert html.escape(r["name"]) in page
        assert html.escape(r["forensic_relevance"]) in page
        for s in r["signatures"]:
            assert html.escape(s["description"]) in page, (r["name"], s)
            assert " ".join(re.findall("..", s["hex"])) in page
        for link in r["links"]:
            assert f'href="{html.escape(link["url"])}"' in page
        for ext in r["extensions"]:
            assert html.escape(ext) in page
        assert COMMIT in page


def test_index_lists_every_format(site, published):
    index = (site / "index.html").read_text(encoding="utf-8")
    body = index[index.index("<tbody>"):index.index("</tbody>")]
    assert body.count("<tr ") == len(published["formats"])
    for r in published["formats"]:
        assert f'href="{r["slug"]}/"' in body


def test_json_header(published):
    assert published["schema_version"] == pages.SCHEMA_VERSION
    assert published["commit"] == COMMIT
    assert published["generated"] == GENERATED
    assert published["license"] == "Apache-2.0"
    assert published["source"].endswith(f"/blob/{COMMIT}/crush/data/build_formats_db.py")


def test_build_is_deterministic(site, tmp_path):
    again = _build(tmp_path)
    first = sorted(p.relative_to(site) for p in site.rglob("*") if p.is_file())
    second = sorted(p.relative_to(again) for p in again.rglob("*") if p.is_file())
    assert first == second
    for rel in first:
        assert (site / rel).read_bytes() == (again / rel).read_bytes(), rel


def test_no_external_resources(site):
    """Scripts and styles come from the site itself."""
    for page in site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        for src in re.findall(r'<script[^>]*\ssrc="([^"]+)"', text):
            assert "://" not in src, (page, src)
        # canonical / alternate name the page's address; they load nothing.
        for href in re.findall(r'<link rel="stylesheet"[^>]*\shref="([^"]+)"', text):
            assert "://" not in href, (page, href)
        assert len(re.findall(r"<link ", text)) == len(re.findall(
            r'<link rel="(?:stylesheet|canonical|alternate)"', text)), page
    for asset in (site / "static").iterdir():
        assert "://" not in asset.read_text(encoding="utf-8").replace(
            "SPDX-License-Identifier", ""
        ), asset


def test_published_addresses_stay():
    """short_name is a format's permanent address on the site. A renamed
    short_name breaks every link to the old one; a new format adds its
    address to published_slugs.txt."""
    pinned = (ROOT / "scripts" / "format_pages" / "published_slugs.txt").read_text(
        encoding="utf-8").split()
    current = {source.url_slug(f["short_name"]) for f in source.FORMATS}
    assert not set(pinned) - current, "published address(es) gone: short_name changed?"
    assert not current - set(pinned), "new format(s): add the address to published_slugs.txt"


def test_draft_is_published_and_marked(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [
        _entry(), _entry(name="Draft Format", short_name="DraftFmt", status="draft"),
    ])
    site = _build(tmp_path)
    data = json.loads((site / "formats.json").read_text(encoding="utf-8"))
    assert {r["name"]: r["status"] for r in data["formats"]} == {
        "Test Format": "reviewed", "Draft Format": "draft",
    }
    assert "draft-banner" in (site / "draftfmt" / "index.html").read_text(encoding="utf-8")
    assert "draft-banner" not in (site / "testfmt" / "index.html").read_text(encoding="utf-8")
    conn = sqlite3.connect(site / "formats.db")
    assert [n for (n,) in conn.execute("SELECT name FROM formats")] == ["Test Format"]
    conn.close()


def test_text_is_escaped_not_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [_entry()])
    site = _build(tmp_path)
    page = (site / "testfmt" / "index.html").read_text(encoding="utf-8")
    assert "Relevance &lt;text&gt; &amp; more." in page
    assert ".tst" in page  # stored lower case, as in formats.db


def test_empty_fields_are_stated(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [
        _entry(magic=[], extensions=[], links=[], platforms=[], forensic_relevance="",
               last_reviewed=None),
    ])
    site = _build(tmp_path)
    page = (site / "testfmt" / "index.html").read_text(encoding="utf-8")
    assert page.count("None recorded") == 5
    assert "Not recorded" in page


def test_unknown_offset_is_shown(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [
        _entry(magic=[{"offset": None, "value": b"\x00TRL", "description": "Trailer"}]),
    ])
    site = _build(tmp_path)
    page = (site / "testfmt" / "index.html").read_text(encoding="utf-8")
    assert "unknown" in page and "00 54 52 4C" in page and ".TRL" in page
    index = (site / "index.html").read_text(encoding="utf-8")
    # The signature lookup finds it as well, with its offset as unknown.
    assert _format_data(index)["formats"][0]["signatures"] == [[None, "0054524C", "Trailer"]]


def _format_data(index: str) -> dict[str, Any]:
    return json.loads(re.search(
        r'<script type="application/json" id="format-data">(.*?)</script>', index, re.S
    ).group(1))


def _lookup(site: Path, value: str) -> list[dict[str, Any]] | None:
    """Run search.js's lookup() under Node on the site's own data."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not found: the signature lookup (JavaScript) can't be run")
    data = _format_data((site / "index.html").read_text(encoding="utf-8"))
    script = (
        "const s = require(process.argv[1]);"
        "const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "const h = s.lookup(d.formats, process.argv[2]);"
        "console.log(JSON.stringify(h === null ? null : h.map(x => ({"
        "name: x.format.name, offset: x.offset, hex: x.hex, start: x.start,"
        "length: x.length}))));"
    )
    out = subprocess.run(
        [node, "-e", script, str(site / "static" / "search.js"), value],
        input=json.dumps(data), capture_output=True, text=True, check=True,
    )
    result: list[dict[str, Any]] | None = json.loads(out.stdout)
    return result


def test_signature_lookup_finds_part_of_a_signature(site):
    """'37 7A' is the start of the 7-Zip signature; it must be found
    although the signature is longer."""
    hits = _lookup(site, "37 7A")
    assert hits is not None
    seven = [h for h in hits if h["name"] == "7-Zip Archive"]
    assert seven == [{"name": "7-Zip Archive", "offset": 0, "hex": "377ABCAF271C",
                      "start": 0, "length": 2}]
    # In the middle of the signature, any spelling of hex.
    assert any(h["name"] == "7-Zip Archive" and h["start"] == 4
               for h in _lookup(site, "0x271c") or [])
    full = _lookup(site, "377ABCAF271C")
    assert full is not None and [h["name"] for h in full] == ["7-Zip Archive"]


def test_signature_lookup_is_byte_aligned_and_lists_every_hit(site, published):
    # "7A BC" shifted by half a byte ("7ABC" inside "37ABC...") is no match.
    assert all(h["start"] * 2 % 2 == 0 for h in _lookup(site, "7A BC") or [])
    assert _lookup(site, "A B") is None          # not whole bytes
    assert _lookup(site, "0x37,0x7A") == _lookup(site, "377a")
    assert _lookup(site, "zz") is None
    assert _lookup(site, "") == []
    # One byte: every signature containing it, none left out.
    expected = sum(
        1 for r in published["formats"] for s in r["signatures"]
        if any(s["hex"][i:i + 2] == "00" for i in range(0, len(s["hex"]), 2))
    )
    assert len(_lookup(site, "00") or []) == expected


def test_signature_lookup_includes_unknown_offsets(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [
        _entry(magic=[{"offset": None, "value": b"\x00TRL", "description": "Trailer"}]),
    ])
    hits = _lookup(_build(tmp_path), "54 52")
    assert hits == [{"name": "Test Format", "offset": None, "hex": "0054524C",
                     "start": 1, "length": 2}]


def test_extensions_note_only_on_the_overview(site):
    note = html.escape(pages._ui("extensions_note"))
    assert note in (site / "index.html").read_text(encoding="utf-8")
    for page in site.glob("*/index.html"):
        assert note not in page.read_text(encoding="utf-8"), page


@pytest.mark.parametrize("overrides, message", [
    ({"status": "wip"}, "status"),
    ({"links": [("Spec", "ftp://example.org")]}, "http"),
    ({"links": [("Spec", "javascript:alert(1)")]}, "http"),
    ({"magic": [{"offset": -1, "value": b"X", "description": ""}]}, "offset"),
    ({"magic": [{"offset": 0, "value": b"", "description": ""}]}, "empty"),
])
def test_unpublishable_entry_fails_the_build(tmp_path, monkeypatch, overrides, message):
    monkeypatch.setattr(source, "FORMATS", [_entry(**overrides)])
    with pytest.raises(pages.PagesError, match=message):
        _build(tmp_path)


@pytest.mark.parametrize("formats, message", [
    ([_entry(), _entry(name="Other", short_name="testfmt")], "same site address"),
    ([_entry(short_name="")], "short_name is missing"),
    ([_entry(short_name="$")], "short_name is missing"),
])
def test_bad_short_name_fails(tmp_path, monkeypatch, formats, message):
    monkeypatch.setattr(source, "FORMATS", formats)
    with pytest.raises(ValueError, match=message):
        _build(tmp_path)


def test_main_reports_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(source, "FORMATS", [_entry(status="wip")])
    assert pages.main(["--out", str(tmp_path), "--commit", COMMIT]) == 2
    assert "status" in capsys.readouterr().err


def test_bad_commit_is_rejected(tmp_path):
    with pytest.raises(pages.PagesError, match="commit"):
        pages.build(tmp_path, "main", GENERATED)


def test_workflows_publish_the_format_reference():
    workflows = ROOT / ".github" / "workflows"
    pages_yml = (workflows / "pages.yml").read_text(encoding="utf-8")
    assert "scripts/build_format_pages.py" in pages_yml
    assert "--site-index" in pages_yml
    assert "uses: ./.github/workflows/pages.yml" in (workflows / "build.yml").read_text(
        encoding="utf-8")
    assert "uses: ./.github/workflows/pages.yml" in (workflows / "nightly.yml").read_text(
        encoding="utf-8")


# -- Site texts in the translation catalogs ----------------------------------------

def _translate_calls() -> set[tuple[str, str]]:
    """(context, text) of every literal translate() / QT_TRANSLATE_NOOP call
    in the app's code (single-literal texts, which every label is)."""
    pattern = re.compile(r'(?:translate|QT_TRANSLATE_NOOP)\(\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)"\s*[,)]')
    calls: set[tuple[str, str]] = set()
    for path in (ROOT / "crush").rglob("*.py"):
        if "tests" in path.relative_to(ROOT / "crush").parts:
            continue
        for ctx, text in pattern.findall(path.read_text(encoding="utf-8")):
            calls.add((ctx, text.encode().decode("unicode_escape")))
    return calls


def test_app_texts_are_the_apps_catalog_entries():
    """A reused label must be a text the app marks for translation, in that
    context, or a translated site would find no translation for it."""
    from crush.data import format_pages_text as site_text

    calls = _translate_calls()
    missing = {k: v for k, v in site_text.APP_TEXTS.items() if v not in calls}
    assert missing == {}


def test_website_texts_are_marked_with_the_website_context():
    from crush.data import format_pages_text as site_text

    source_text = (ROOT / "crush" / "data" / "format_pages_text.py").read_text(encoding="utf-8")
    assert site_text.WEBSITE_CONTEXT.startswith(site_text.WEBSITE_CONTEXT_PREFIX)
    marked = source_text.count(f'QT_TRANSLATE_NOOP(\n        "{site_text.WEBSITE_CONTEXT}"')
    marked += source_text.count(f'QT_TRANSLATE_NOOP("{site_text.WEBSITE_CONTEXT}"')
    assert marked == len(site_text.WEBSITE_TEXTS)
    # No key in two kinds, and every key the builder uses has a text.
    kinds = [site_text.APP_TEXTS, site_text.WEBSITE_TEXTS, site_text.ENGLISH_TEXTS]
    keys = [k for kind in kinds for k in kind]
    assert len(keys) == len(set(keys))
    used = set(re.findall(r'_ui\(\s*"(\w+)"', (ROOT / "scripts" / "build_format_pages.py")
                          .read_text(encoding="utf-8")))
    assert used - set(keys) == set()


def test_i18n_skips_the_same_website_contexts():
    spec = importlib.util.spec_from_file_location("i18n_script", ROOT / "scripts" / "i18n.py")
    assert spec and spec.loader
    i18n_script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(i18n_script)
    from crush.data import format_pages_text as site_text

    assert i18n_script.WEBSITE_CONTEXT_PREFIX == site_text.WEBSITE_CONTEXT_PREFIX


def test_filesig_hint_only_once_on_the_overview(site):
    """One global hint on the overview; no format page links it."""
    overviews = [site, *(site / code for code in pages.SITE_LANGUAGES)]
    for overview in overviews:
        index = (overview / "index.html").read_text(encoding="utf-8")
        assert index.count(f'href="{pages.FILESIG_URL}"') == 1
        for page in overview.glob("*/index.html"):
            if page.parent in overviews:
                continue
            assert pages.FILESIG_URL not in page.read_text(encoding="utf-8"), page


def test_footer_links_to_a_prefilled_issue(site, published):
    """Every page's footer reports errors or missing sources as an issue:
    a format page for that entry, the overview in general."""
    def footer(path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        return text[text.index("<footer>"):text.index("</footer>")]

    index_footer = footer(site / "index.html")
    assert "/issues/new?title=Format+reference&amp;body=" in index_footer
    for r in published["formats"]:
        page_footer = footer(site / r["slug"] / "index.html")
        assert "/issues/new?" in page_footer
        assert html.escape(urllib.parse.quote_plus(r["url"])) in page_footer, r["name"]


def test_app_links_to_the_site():
    """Format Reference dialog and About link to the address the site is
    published at."""
    from crush.core.format_db import FORMAT_REFERENCE_URL

    assert pages.DEFAULT_SITE_URL == FORMAT_REFERENCE_URL
    for module in ("format_reference.py", "about_dialog.py"):
        assert "FORMAT_REFERENCE_URL" in (ROOT / "crush" / "ui" / module).read_text(
            encoding="utf-8")


def test_format_reference_dialog_and_about_show_the_link(qapp, tmp_path, monkeypatch):
    from PySide6.QtCore import QSettings

    from crush.core.format_db import FORMAT_REFERENCE_URL
    from crush.ui import knowledge_toggle
    from crush.ui.about_dialog import _about_html
    from crush.ui.format_reference import FormatReferenceDialog

    # Never the analyst's own settings.
    monkeypatch.setattr(knowledge_toggle, "_app_settings",
                        lambda: QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat))
    dlg = FormatReferenceDialog()
    assert f'href="{FORMAT_REFERENCE_URL}"' in dlg._online_label.text()
    assert "latest Crush build" in dlg._online_label.text()
    dlg.close()
    assert f'href="{FORMAT_REFERENCE_URL}"' in _about_html()


# -- Dark/light theme -----------------------------------------------------------

def test_every_page_has_the_theme(site):
    from crush.data import site_theme

    assert (site / "static" / "style.css").read_text(encoding="utf-8").startswith(site_theme.CSS)
    for page in site.rglob("index.html"):
        text = page.read_text(encoding="utf-8")
        assert site_theme.HEAD_SCRIPT in text, page
        # The remembered choice applies before the stylesheet loads.
        assert text.index(site_theme.HEAD_SCRIPT) < text.index("style.css"), page
        assert 'id="theme-toggle"' in text, page


def test_site_index_has_the_theme(tmp_path):
    from crush.data import site_theme

    pages.write_site_index(tmp_path)
    text = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "THEME_" not in text
    assert site_theme.CSS in text and site_theme.HEAD_SCRIPT in text
    assert 'id="theme-toggle"' in text
    assert 'href="formats/"' in text and 'href="audit/"' in text


def test_stylesheets_take_colours_from_the_theme():
    """A colour written into a stylesheet directly would stay the same in
    both themes."""
    sheets = {
        "format pages": (ROOT / "scripts" / "format_pages" / "style.css").read_text(
            encoding="utf-8"),
        "site index": (ROOT / "scripts" / "pages_index.html").read_text(encoding="utf-8"),
    }
    for name, css in sheets.items():
        assert not re.findall(r"#[0-9a-fA-F]{3,6}\b", css), name


# -- Translated site ------------------------------------------------------------

def _catalog(path: Path, messages: list[tuple[str, str, str, str | None, str | None]]) -> Path:
    """A .ts with (context, source, disambiguation, translation, type) messages."""
    import xml.etree.ElementTree as ET

    ts = ET.Element("TS", version="2.1", language="de_DE")
    contexts: dict[str, ET.Element] = {}
    for context, src, disambiguation, translation, kind in messages:
        if context not in contexts:
            contexts[context] = ET.SubElement(ts, "context")
            ET.SubElement(contexts[context], "name").text = context
        message = ET.SubElement(contexts[context], "message")
        ET.SubElement(message, "source").text = src
        if disambiguation:
            ET.SubElement(message, "comment").text = disambiguation
        tr = ET.SubElement(message, "translation")
        tr.text = translation
        if kind:
            tr.set("type", kind)
    path.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(ts).write(path / "crush_de.ts", encoding="utf-8", xml_declaration=True)
    return path


def test_load_catalog_keeps_only_finished_translations(tmp_path):
    directory = _catalog(tmp_path, [
        ("C", "done", "", "fertig", None),
        ("C", "same", "", "same", None),
        ("C", "open", "", "offen", "unfinished"),
        ("C", "old", "", "alt", "vanished"),
        ("C", "gone", "", "weg", "obsolete"),
        ("C", "empty", "", None, None),
        ("K", "text", "Fmt A", "Text A", None),
        ("K", "text", "Fmt B", "Text B", None),
    ])
    assert pages.load_catalog(directory / "crush_de.ts") == {
        ("C", "done", ""): "fertig",
        ("C", "same", ""): "same",
        ("K", "text", "Fmt A"): "Text A",
        ("K", "text", "Fmt B"): "Text B",
    }


def test_every_language_has_every_page_with_switch_and_alternates(site, published):
    url = pages.DEFAULT_SITE_URL
    for code in (pages.SOURCE_LANG, *pages.SITE_LANGUAGES):
        base = site if code == pages.SOURCE_LANG else site / code
        for slug in (None, *(r["slug"] for r in published["formats"])):
            page = (base / slug / "index.html" if slug else base / "index.html").read_text(
                encoding="utf-8")
            assert f'<html lang="{code}">' in page
            assert f'<link rel="canonical" href="{pages.page_url(url, code, slug)}">' in page
            for other in (pages.SOURCE_LANG, *pages.SITE_LANGUAGES):
                assert (f'<link rel="alternate" hreflang="{other}" '
                        f'href="{pages.page_url(url, other, slug)}">') in page
            assert (f'<link rel="alternate" hreflang="x-default" '
                    f'href="{pages.page_url(url, pages.SOURCE_LANG, slug)}">') in page
            # The switch: the current language marked, the others linked to
            # the same page -- the link resolves to an existing file.
            nav = page[page.index('<nav class="lang"'):page.index("</nav>")]
            assert f'<strong lang="{code}">' in nav
            here = base / slug if slug else base
            for href in re.findall(r'href="([^"]+)"', nav):
                assert (here / href / "index.html").resolve().is_file(), (code, slug, href)


def test_translated_site_uses_the_catalog(tmp_path, monkeypatch):
    from crush.data import format_pages_text as site_text

    monkeypatch.setattr(source, "FORMATS", [_entry(category="database")])
    directory = _catalog(tmp_path / "i18n", [
        ("FormatKnowledge", "Relevance <text> & more.", "Test Format", "Relevanz <Text>.", None),
        ("FormatKnowledge", "Test magic", "Test Format", "Testsignatur", None),
        ("FormatCategory", "database", "", "Datenbank", None),
        *[(site_text.WEBSITE_CONTEXT, text, "", f"DE {key}", None)
          for key, text in site_text.WEBSITE_TEXTS.items()],
        *[(context, text, "", f"DE {key}", None)
          for key, (context, text) in site_text.APP_TEXTS.items()],
    ])
    result = pages.build(tmp_path / "out", COMMIT, GENERATED, catalog_dir=directory)
    assert result.untranslated == {"de": set()}
    page = (tmp_path / "out" / "formats" / "de" / "testfmt" / "index.html").read_text(
        encoding="utf-8")
    assert "Relevanz &lt;Text&gt;." in page and "Testsignatur" in page and "Datenbank" in page
    assert "DE f_relevance" in page
    assert "untranslated" not in page
    # The citation and the correction issue name the German page.
    assert f"{pages.DEFAULT_SITE_URL}de/testfmt/" in page
    index = (tmp_path / "out" / "formats" / "de" / "index.html").read_text(encoding="utf-8")
    # The filter finds the category in German and in English.
    search = re.search(r'data-search="([^"]*)"', index).group(1).split()
    assert "database" in search and "datenbank" in search
    assert 'href="../formats.json"' in index and 'src="../static/search.js"' in index


def test_untranslated_text_is_shown_in_english_and_marked(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [_entry()])
    # The relevance translated for another format only; nothing else.
    directory = _catalog(tmp_path / "i18n", [
        ("FormatKnowledge", "Relevance <text> & more.", "Other Format", "Relevanz.", None),
        ("FormatKnowledge", "Test magic", "Test Format", "Testsignatur", "unfinished"),
    ])
    result = pages.build(tmp_path / "out", COMMIT, GENERATED, catalog_dir=directory)
    assert ("FormatKnowledge", "Relevance <text> & more.", "Test Format") in result.untranslated["de"]
    assert ("FormatKnowledge", "Test magic", "Test Format") in result.untranslated["de"]
    assert ("FormatCategory", "database", "") in result.untranslated["de"]
    page = (tmp_path / "out" / "formats" / "de" / "testfmt" / "index.html").read_text(
        encoding="utf-8")
    assert ('<span lang="en">Relevance &lt;text&gt; &amp; more.</span> '
            '<span class="badge untranslated">') in page
    assert '<span lang="en">Test magic</span>' in page
    assert 'class="untranslated-note"' in page
    index = (tmp_path / "out" / "formats" / "de" / "index.html").read_text(encoding="utf-8")
    assert 'class="untranslated-note"' in index
    assert _format_data(index)["formats"][0]["signatures"] == [[0, "54535446", "Test magic", True]]
    # The English site has no marks.
    english = (tmp_path / "out" / "formats" / "testfmt" / "index.html").read_text(encoding="utf-8")
    assert "untranslated" not in english


def test_lookup_reports_an_untranslated_description(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [_entry()])
    directory = _catalog(tmp_path / "i18n", [("C", "x", "", "y", None)])
    pages.build(tmp_path / "out", COMMIT, GENERATED, catalog_dir=directory)
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not found")
    data = _format_data((tmp_path / "out" / "formats" / "de" / "index.html").read_text(
        encoding="utf-8"))
    out = subprocess.run(
        [node, "-e", "const s = require(process.argv[1]);"
         "const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
         "console.log(JSON.stringify(s.lookup(d.formats, '54 53').map(h => h.untranslated)));",
         str(tmp_path / "out" / "formats" / "static" / "search.js")],
        input=json.dumps(data), capture_output=True, text=True, check=True,
    )
    assert json.loads(out.stdout) == [True]


def test_missing_catalog_fails_the_build(tmp_path):
    with pytest.raises(pages.PagesError, match="not found"):
        pages.build(tmp_path / "out", COMMIT, GENERATED, catalog_dir=tmp_path / "none")


def test_slug_taken_by_a_site_language_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "FORMATS", [_entry(short_name="DE")])
    with pytest.raises(pages.PagesError, match="site language"):
        _build(tmp_path)


def test_language_names_match_the_app(qapp):
    from crush.data import format_pages_text as site_text
    from crush.ui import i18n

    assert set(site_text.LANGUAGE_NAMES) == {pages.SOURCE_LANG, *pages.SITE_LANGUAGES}
    for code, name in site_text.LANGUAGE_NAMES.items():
        assert i18n.display_name(code) == name


def test_site_index_links_every_site_language(tmp_path):
    pages.write_site_index(tmp_path)
    text = (tmp_path / "index.html").read_text(encoding="utf-8")
    for code in pages.SITE_LANGUAGES:
        assert f'href="formats/{code}/"' in text
