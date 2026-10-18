#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Build the format reference site for GitHub Pages from build_formats_db.py.

The only source is FORMATS in crush/data/build_formats_db.py, read through
its entry() -- the same normalisation that writes formats.db. Texts go to
the pages unchanged (HTML-escaped only). Draft entries are included and
marked; formats.db leaves them out. Every entry is rendered or the build
fails; nothing is skipped.

Output (--out is the site root; everything goes to <out>/formats/):
  formats/index.html           all formats, filterable, plus signature lookup
  formats/<slug>/index.html    one page per format; slug = url_slug(short_name),
                               a permanent address (published_slugs.txt)
  formats/formats.json         every entry, machine-readable
  formats/formats.db           formats.db built from the same source
  formats/static/              style.css, search.js (no external resources)
  formats/<lang>/              overview and format pages in each language of
                               SITE_LANGUAGES (same slugs); the downloads and
                               static/ are shared

Usage:
    python scripts/build_format_pages.py --out site --commit <sha> \\
        [--generated "YYYY-MM-DD HH:MM:SS"]
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import html
import io
import json
import re
import shutil
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crush.data import build_formats_db as source  # noqa: E402
from crush.data import format_pages_text as site_text  # noqa: E402
from crush.core.format_db import FORMAT_REFERENCE_URL  # noqa: E402
from crush.data import site_theme  # noqa: E402

ASSETS = Path(__file__).resolve().parent / "format_pages"
SOURCE_PATH = "crush/data/build_formats_db.py"
DEFAULT_REPOSITORY = "https://github.com/kalink0/crush-forensics"
DEFAULT_SITE_URL = FORMAT_REFERENCE_URL  # the address the app links to
FILESIG_URL = "https://filesig.search.org/"
SCHEMA_VERSION = 1
LICENSE = "Apache-2.0"
STATUSES = ("reviewed", "draft")
_COMMIT = re.compile(r"[0-9a-f]{7,40}")
_NAME_LINE = re.compile(r'^\s*"name":\s*"(.*)",\s*$')

# Site languages. English is the source and stays at formats/; every
# language in SITE_LANGUAGES is written to formats/<code>/. The site's own
# texts are in crush/data/format_pages_text.py, where scripts/i18n.py finds
# them for the translation catalogs; knowledge texts (forensic relevance,
# signature descriptions, categories) are the app's (contexts
# FormatKnowledge / FormatCategory, disambiguation = the format's name).
# A translation looks both up in crush/i18n/crush_<code>.ts; a text without
# a finished translation there is shown in English and marked.
SOURCE_LANG = "en"
SITE_LANGUAGES = ("de",)
CATALOG_DIR = ROOT / "crush" / "i18n"
KNOWLEDGE_CONTEXT = "FormatKnowledge"
CATEGORY_CONTEXT = "FormatCategory"

Catalog = dict[tuple[str, str, str], str]


def load_catalog(path: Path) -> Catalog:
    """The finished translations of a .ts catalog by (context, source,
    disambiguation). Unfinished, obsolete and vanished entries are left
    out: they aren't a translation of the current text."""
    catalog: Catalog = {}
    for context in ElementTree.parse(path).getroot().iter("context"):
        name = context.findtext("name") or ""
        for message in context.iter("message"):
            translation = message.find("translation")
            if translation is None or translation.get("type") or not translation.text:
                continue
            key = (name, message.findtext("source") or "", message.findtext("comment") or "")
            catalog[key] = translation.text
    return catalog


class _Language:
    """The language pages are being rendered in, and which of their texts
    had no translation."""

    def __init__(self, code: str, catalog: Catalog | None) -> None:
        self.code = code
        self.catalog = catalog  # None: the source language
        self.page_missing = False   # an untranslated text on the current page
        self.missing: set[tuple[str, str, str]] = set()

    def lookup(self, context: str, text: str, disambiguation: str = "") -> tuple[str, bool]:
        """(text in this language, translated?). The source language and
        an empty text count as translated."""
        if self.catalog is None or not text:
            return text, True
        key = (context, text, disambiguation)
        found = self.catalog.get(key)
        if found is None:
            self.page_missing = True
            self.missing.add(key)
            return text, False
        return found, True


_lang = _Language(SOURCE_LANG, None)


def _ui(key: str, **kwargs: Any) -> str:
    if key in site_text.ENGLISH_TEXTS:
        text = site_text.ENGLISH_TEXTS[key]
    elif key in site_text.APP_TEXTS:
        text, _ = _lang.lookup(*site_text.APP_TEXTS[key])
    else:
        text, _ = _lang.lookup(site_text.WEBSITE_CONTEXT, site_text.WEBSITE_TEXTS[key])
    return text.format(**kwargs) if kwargs else text


def _knowledge(text: str, name: str = "", *, category: bool = False) -> tuple[str, bool]:
    """A knowledge text of format *name* (a category: no name) in the site
    language, and whether it is translated."""
    if category:
        return _lang.lookup(CATEGORY_CONTEXT, text)
    return _lang.lookup(KNOWLEDGE_CONTEXT, text, name)


def _knowledge_html(text: str, name: str = "", *, category: bool = False) -> str:
    """A knowledge text as HTML; untranslated: the English original, marked."""
    shown, translated = _knowledge(text, name, category=category)
    if translated:
        return _e(shown)
    return (f'<span lang="en">{_e(shown)}</span> '
            f'<span class="badge untranslated">{_e(_ui("untranslated"))}</span>')


class PagesError(Exception):
    pass


def _e(text: str) -> str:
    return html.escape(text, quote=True)


def _ascii(value: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in value)


def _offset_text(offset: int | None) -> str:
    if offset is None:
        return _ui("offset_unknown")
    return _ui("offset_known", offset=offset, offset_hex=f"{offset:X}")


def _source_lines(path: Path) -> dict[str, int]:
    """Line of each entry's "name" in the source, for links to it."""
    lines: dict[str, int] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = _NAME_LINE.match(line)
        if m:
            lines.setdefault(m.group(1), number)
    return lines


def records(site_url: str) -> list[dict[str, Any]]:
    """Every FORMATS entry as published: all fields of entry(), plus slug,
    url and crush_support. Sorted by category, then name (as Crush's
    Format Reference). Raises PagesError for an entry that can't be
    published as it is."""
    source.check_slugs(source.FORMATS)
    out = []
    for fmt in source.FORMATS:
        e = source.entry(fmt)
        name = e["name"]
        if e["status"] not in STATUSES:
            raise PagesError(f"{name}: status {e['status']!r} is not one of {STATUSES}")
        for m in e["magic"]:
            if not isinstance(m["value"], bytes) or not m["value"]:
                raise PagesError(f"{name}: a signature value is empty or not bytes")
            if m["offset"] is not None and (
                not isinstance(m["offset"], int) or m["offset"] < 0
            ):
                raise PagesError(f"{name}: signature offset {m['offset']!r} is invalid")
        for label, url in e["links"]:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc or not label:
                raise PagesError(f"{name}: link {label!r} -> {url!r} is not an http(s) link")
        slug = source.url_slug(e["short_name"])
        out.append({
            "slug": slug,
            "url": f"{site_url}{slug}/",
            "name": name,
            "short_name": e["short_name"],
            "category": e["category"],
            "platforms": e["platforms"],
            "parser_class": e["parser_class"],
            "crush_support": _ui("supported") if e["parser_class"] else _ui("not_supported"),
            "status": e["status"],
            "last_reviewed": e["last_reviewed"],
            "forensic_relevance": e["forensic_relevance"],
            "signatures": [
                {
                    "offset": m["offset"],
                    "hex": m["value"].hex().upper(),
                    "length": len(m["value"]),
                    "description": m["description"],
                }
                for m in e["magic"]
            ],
            "extensions": e["extensions"],
            "links": [{"label": label, "url": url} for label, url in e["links"]],
        })
    out.sort(key=lambda r: (r["category"], r["name"]))
    return out


def _json_document(recs: list[dict[str, Any]], meta: dict[str, str]) -> str:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated": meta["generated"],
        "commit": meta["commit"],
        "source": f"{meta['repository']}/blob/{meta['commit']}/{SOURCE_PATH}",
        "license": LICENSE,
        "notes": {
            "signatures": (
                "hex: the signature bytes. offset: byte offset in the file, null "
                "when unknown (shown, never matched by Crush)."
            ),
            "extensions": _ui("extensions_note"),
            "status": _ui("draft_note"),
            "crush_support": _ui("support_note"),
        },
        "formats": recs,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def _issue_url(repository: str, title: str, body: str) -> str:
    """A new GitHub issue, prefilled."""
    return f"{repository}/issues/new?" + urllib.parse.urlencode({"title": title, "body": body})


def _languages() -> tuple[str, ...]:
    return (SOURCE_LANG, *SITE_LANGUAGES)


def page_url(site_url: str, code: str, slug: str | None = None) -> str:
    """The address of the overview (slug None) or a format page in *code*."""
    base = site_url if code == SOURCE_LANG else f"{site_url}{code}/"
    return f"{base}{slug}/" if slug else base


def _root() -> str:
    """Relative path from the overview of the current language to formats/."""
    return "" if _lang.code == SOURCE_LANG else "../"


def _page(title: str, body: str, meta: dict[str, str], report_url: str, *,
          slug: str | None = None, scripts: str = "") -> str:
    """A whole page; *slug* None is the overview."""
    commit = meta["commit"]
    # From this page to formats/.
    root = ("../" if slug else "") + _root()
    # The template is escaped first; the link markup goes in afterwards.
    disclaimer = _e(_ui("disclaimer")).format(
        link=f'<a href="{_e(report_url)}">{_e(_ui("report_issue"))}</a>'
    )
    commit_link = (
        f'<a href="{_e(meta["repository"])}/tree/{_e(commit)}"><code>{_e(commit[:12])}</code></a>'
    )
    built = _ui(
        "built_from",
        source=f"<code>{_e(SOURCE_PATH)}</code>",
        commit=commit_link,
        generated=_e(meta["generated"]),
    )
    draft_disclaimer = _ui("draft_disclaimer")
    license_text = _ui("license", license=LICENSE)
    theme_toggle = _ui("theme_toggle")
    heading = _ui("heading")
    switch = []
    alternates = []
    for code in _languages():
        name = _e(site_text.LANGUAGE_NAMES[code])
        url = page_url(meta["site_url"], code, slug)
        alternates.append(f'<link rel="alternate" hreflang="{code}" href="{_e(url)}">')
        if code == _lang.code:
            switch.append(f'<strong lang="{code}">{name}</strong>')
        else:
            rel = root + page_url("", code, slug)
            switch.append(f'<a href="{_e(rel)}" hreflang="{code}" lang="{code}">{name}</a>')
    alternates.append(
        f'<link rel="alternate" hreflang="x-default" '
        f'href="{_e(page_url(meta["site_url"], SOURCE_LANG, slug))}">'
    )
    canonical = page_url(meta["site_url"], _lang.code, slug)
    nav = (f'<nav class="lang" aria-label="{_e(_ui("language"))}">'
           + " &middot; ".join(switch) + "</nav>")
    # Last: every text of the page has been looked up by now.
    notice = (
        f'<section class="untranslated-note">{_e(_ui("page_untranslated"))}</section>\n'
        if _lang.page_missing else ""
    )
    return f"""<!DOCTYPE html>
<html lang="{_lang.code}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_e(title)}</title>
  <link rel="canonical" href="{_e(canonical)}">
  {chr(10).join("  " + a if i else a for i, a in enumerate(alternates))}
  {site_theme.HEAD_SCRIPT}
  <link rel="stylesheet" href="{root}static/style.css">
</head>
<body>
<header>
  {site_theme.toggle(theme_toggle)}
  <h1>{_e(heading)}</h1>
  <div class="meta">{built}</div>
  {nav}
</header>
<main>
{notice}{body}
</main>
<footer>
  <p>{disclaimer}</p>
  <p>{_e(draft_disclaimer)}</p>
  <p>{_e(license_text)}</p>
</footer>
{scripts}</body>
</html>
"""


def _list_or_none(items: list[str]) -> str:
    return _e(", ".join(items)) if items else f'<span class="none">{_e(_ui("none_recorded"))}</span>'


def _support_html(rec: dict[str, Any]) -> str:
    if rec["parser_class"]:
        return (f'<span class="supported">{_e(_ui("supported"))}</span> '
                f'<code>({_e(rec["parser_class"])})</code>')
    return f'<span class="unsupported">{_e(_ui("not_supported"))}</span>'


def _index_html(recs: list[dict[str, Any]], meta: dict[str, str]) -> str:
    _lang.page_missing = False
    rows = []
    unsupported_class = ' class="row-unsupported"'
    for r in recs:
        draft = r["status"] == "draft"
        # The category in the site language and in English: the filter
        # finds a format by either.
        category, _ = _knowledge(r["category"], category=True)
        search = " ".join(dict.fromkeys([
            r["name"], r["short_name"], r["category"], category, *r["platforms"],
            *r["extensions"], r["parser_class"] or "",
        ])).lower()
        badge = f' <span class="badge draft">{_e(_ui("draft"))}</span>' if draft else ""
        rows.append(
            f'<tr data-search="{_e(search)}" data-category="{_e(r["category"])}" '
            f'data-support="{"supported" if r["parser_class"] else "unsupported"}" '
            f'data-status="{_e(r["status"])}"'
            f'{"" if r["parser_class"] else unsupported_class}>'
            f'<td><a href="{_e(r["slug"])}/">{_e(r["name"])}</a>{badge}</td>'
            f"<td>{_e(r['short_name'])}</td>"
            f"<td>{_knowledge_html(r['category'], category=True)}</td>"
            f"<td>{_list_or_none(r['platforms'])}</td>"
            f"<td>{_list_or_none(r['extensions'])}</td>"
            f"<td>{_support_html(r)}</td>"
            "</tr>"
        )
    categories = sorted({r["category"] for r in recs})
    cat_options = "".join(
        f'<option value="{_e(c)}">{_e(_knowledge(c, category=True)[0])}</option>'
        for c in categories
    )

    def signature(s: dict[str, Any], name: str) -> list[Any]:
        # [offset, hex, description] -- plus true when the description is
        # the untranslated English original.
        text, translated = _knowledge(s["description"], name)
        return [s["offset"], s["hex"], text] + ([] if translated else [True])

    search_data = {
        "ui": {k: _ui(k) for k in (
            "count", "count_filtered", "sig_invalid", "sig_none", "sig_hits",
            "offset_known", "offset_unknown", "untranslated",
        )},
        "formats": [
            {
                "slug": r["slug"],
                "name": r["name"],
                # Every signature, an unknown offset as null: the lookup
                # finds signatures by their bytes, wherever they sit.
                "signatures": [signature(s, r["name"]) for s in r["signatures"]],
            }
            for r in recs
        ],
    }
    data_json = json.dumps(search_data, ensure_ascii=False).replace("</", "<\\/")
    total = len(recs)
    # The template is escaped first; the link markup goes in afterwards.
    filesig_note = _e(_ui("filesig_note")).format(
        link=f'<a href="{_e(FILESIG_URL)}" rel="noopener noreferrer">GCK File Signature Table</a>'
    )
    body = f"""<section>
  <p>{_e(_ui("intro"))}</p>
  <ul class="notes">
    <li>{_e(_ui("support_note"))}</li>
    <li>{_e(_ui("extensions_note"))}</li>
    <li>{_e(_ui("draft_note"))}</li>
    <li>{filesig_note}</li>
  </ul>
  <p class="downloads">{_e(_ui("downloads"))}
    <a href="{_root()}formats.json">formats.json</a> &middot;
    <a href="{_root()}formats.db">formats.db</a></p>
</section>
<section id="sig-search" hidden>
  <h2>{_e(_ui("sig_search"))}</h2>
  <p class="help">{_e(_ui("sig_search_help"))}</p>
  <input id="sig-input" type="text" spellcheck="false" autocomplete="off"
         placeholder="{_e(_ui("sig_placeholder"))}">
  <div id="sig-result" aria-live="polite"></div>
</section>
<section>
  <div id="tools" class="tools" hidden>
    <label>{_e(_ui("filter"))}
      <input id="filter-text" type="search" placeholder="{_e(_ui("filter_placeholder"))}"></label>
    <select id="filter-category"><option value="">{_e(_ui("all_categories"))}</option>{cat_options}</select>
    <select id="filter-support">
      <option value="">{_e(_ui("all_support"))}</option>
      <option value="supported">{_e(_ui("supported"))}</option>
      <option value="unsupported">{_e(_ui("not_supported"))}</option>
    </select>
    <select id="filter-status">
      <option value="">{_e(_ui("all_statuses"))}</option>
      <option value="reviewed">{_e(_ui("reviewed"))}</option>
      <option value="draft">{_e(_ui("draft"))}</option>
    </select>
  </div>
  <p id="count" class="count">{_e(_ui("count", total=total))}</p>
  <table id="formats">
    <thead><tr>
      <th>{_e(_ui("col_name"))}</th><th>{_e(_ui("col_short"))}</th>
      <th>{_e(_ui("col_category"))}</th><th>{_e(_ui("col_platforms"))}</th>
      <th>{_e(_ui("col_extensions"))}</th><th>{_e(_ui("col_support"))}</th>
    </tr></thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>
</section>"""
    scripts = (
        f'<script type="application/json" id="format-data">{data_json}</script>\n'
        f'<script src="{_root()}static/search.js"></script>\n'
    )
    report_url = _issue_url(
        meta["repository"], _ui("issue_title_general"),
        _ui("issue_body_general", url=page_url(meta["site_url"], _lang.code)),
    )
    return _page(_ui("site_title"), body, meta, report_url, scripts=scripts)


def _format_html(r: dict[str, Any], meta: dict[str, str], source_line: int | None) -> str:
    _lang.page_missing = False
    repo, commit = meta["repository"], meta["commit"]
    url = page_url(meta["site_url"], _lang.code, r["slug"])
    rows = [
        (_ui("f_name"), _e(r["name"])),
        (_ui("f_short"), _e(r["short_name"])),
        (_ui("f_category"),
         _knowledge_html(r["category"], category=True) or _e(_ui("none_recorded"))),
        (_ui("f_platforms"), _list_or_none(r["platforms"])),
        (_ui("f_support"), _support_html(r)),
        (_ui("f_status"), _e(_ui("draft") if r["status"] == "draft" else _ui("reviewed"))),
        (_ui("f_reviewed"), _e(r["last_reviewed"] or _ui("not_recorded"))),
    ]
    facts = "\n".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows)

    if r["signatures"]:
        sig_rows = "\n".join(
            "<tr>"
            f'<td class="mono">{_e(_offset_text(s["offset"]))}</td>'
            f'<td class="mono">{_e(" ".join(s["hex"][i:i + 2] for i in range(0, len(s["hex"]), 2)))}</td>'
            f'<td class="mono">{_e(_ascii(bytes.fromhex(s["hex"])))}</td>'
            f'<td>{_knowledge_html(s["description"], r["name"])}</td>'
            "</tr>"
            for s in r["signatures"]
        )
        signatures = f"""<table class="sigs">
    <thead><tr><th>{_e(_ui("sig_offset"))}</th><th>{_e(_ui("sig_hex"))}</th>
      <th>{_e(_ui("sig_ascii"))}</th><th>{_e(_ui("sig_description"))}</th></tr></thead>
    <tbody>
{sig_rows}
    </tbody>
  </table>"""
    else:
        signatures = f'<p class="none">{_e(_ui("none_recorded"))}</p>'

    if r["links"]:
        links = "<ul>" + "".join(
            f'<li><a href="{_e(link["url"])}" rel="noopener noreferrer">{_e(link["label"])}</a>'
            f' <small class="url">{_e(link["url"])}</small></li>'
            for link in r["links"]
        ) + "</ul>"
    else:
        links = f'<p class="none">{_e(_ui("none_recorded"))}</p>'

    relevance = (
        f'<p class="relevance">{_knowledge_html(r["forensic_relevance"], r["name"])}</p>'
        if r["forensic_relevance"]
        else f'<p class="none">{_e(_ui("none_recorded"))}</p>'
    )
    banner = (
        f'<section class="draft-banner">{_e(_ui("draft_banner"))}</section>'
        if r["status"] == "draft" else ""
    )
    anchor = f"#L{source_line}" if source_line else ""
    source_url = f"{repo}/blob/{commit}/{SOURCE_PATH}{anchor}"
    history_url = f"{repo}/commits/main/{SOURCE_PATH}"
    issue_url = _issue_url(
        repo, _ui("issue_title", name=r["name"]), _ui("issue_body", url=url),
    )
    cite = _ui(
        "cite_text", name=r["name"], url=url, source=SOURCE_PATH,
        commit=commit, generated=meta["generated"],
    )
    body = f"""<p class="back"><a href="../">{_e(_ui("all_formats"))}</a></p>
{banner}
<section>
  <h2>{_e(r["name"])}</h2>
  <table class="facts">
{facts}
  </table>
</section>
<section>
  <h3>{_e(_ui("f_relevance"))}</h3>
  {relevance}
</section>
<section>
  <h3>{_e(_ui("f_signatures"))}</h3>
  {signatures}
</section>
<section>
  <h3>{_e(_ui("f_extensions"))}</h3>
  <p>{_list_or_none(r["extensions"])}</p>
</section>
<section>
  <h3>{_e(_ui("f_links"))}</h3>
  {links}
</section>
<section>
  <h3>{_e(_ui("cite"))}</h3>
  <p class="cite">{_e(cite)}</p>
  <p class="actions">
    <a href="{_e(source_url)}">{_e(_ui("view_source"))}</a> &middot;
    <a href="{_e(history_url)}">{_e(_ui("history"))}</a> &middot;
    <a href="{_e(issue_url)}">{_e(_ui("report"))}</a>
  </p>
</section>"""
    return _page(f"{r['name']} — {_ui('site_title')}", body, meta, issue_url, slug=r["slug"])


@dataclass
class BuildResult:
    formats: int
    # Per site language: the texts shown untranslated, as (context, source,
    # disambiguation).
    untranslated: dict[str, set[tuple[str, str, str]]] = field(default_factory=dict)


def _write_pages(target: Path, recs: list[dict[str, Any]], meta: dict[str, str]) -> None:
    """Overview and format pages in the current language, into *target*."""
    (target / "index.html").write_text(_index_html(recs, meta), encoding="utf-8")
    lines = _source_lines(ROOT / SOURCE_PATH)
    for r in recs:
        page = target / r["slug"]
        page.mkdir()
        (page / "index.html").write_text(
            _format_html(r, meta, lines.get(r["name"])), encoding="utf-8",
        )


def build(out: Path, commit: str, generated: str,
          repository: str = DEFAULT_REPOSITORY, site_url: str = DEFAULT_SITE_URL,
          catalog_dir: Path = CATALOG_DIR) -> BuildResult:
    """Write <out>/formats/ (must not exist yet): English there, every
    language of SITE_LANGUAGES in formats/<code>/."""
    global _lang
    if not _COMMIT.fullmatch(commit):
        raise PagesError(f"commit {commit!r} is not a hex commit id")
    if not site_url.endswith("/"):
        site_url += "/"
    meta = {"commit": commit, "generated": generated, "repository": repository.rstrip("/"),
            "site_url": site_url}
    _lang = _Language(SOURCE_LANG, None)
    recs = records(site_url)
    clash = {r["slug"] for r in recs} & set(SITE_LANGUAGES)
    if clash:
        raise PagesError(f"format address(es) {sorted(clash)} are taken by a site language")
    catalogs = {}
    for code in SITE_LANGUAGES:
        path = catalog_dir / f"crush_{code}.ts"
        if not path.is_file():
            raise PagesError(f"site language {code!r}: {path} not found")
        catalogs[code] = load_catalog(path)

    base = out / "formats"
    base.mkdir(parents=True)
    # formats.db from the same source; build() reports on stdout.
    with contextlib.redirect_stdout(io.StringIO()):
        source.build(base / "formats.db")
    (base / "static").mkdir()
    # The theme's colour variables go in front of the site's own CSS.
    (base / "static" / "style.css").write_text(
        site_theme.CSS + (ASSETS / "style.css").read_text(encoding="utf-8"), encoding="utf-8",
    )
    shutil.copyfile(ASSETS / "search.js", base / "static" / "search.js")

    (base / "formats.json").write_text(_json_document(recs, meta), encoding="utf-8")
    _write_pages(base, recs, meta)
    result = BuildResult(len(recs))
    try:
        for code, catalog in catalogs.items():
            _lang = _Language(code, catalog)
            (base / code).mkdir()
            _write_pages(base / code, recs, meta)
            result.untranslated[code] = _lang.missing
    finally:
        _lang = _Language(SOURCE_LANG, None)
    return result


def write_site_index(out: Path) -> None:
    """<out>/index.html, the site's front page, from scripts/pages_index.html
    with the theme filled in."""
    page = (Path(__file__).resolve().parent / "pages_index.html").read_text(encoding="utf-8")
    for marker, value in (
        ("/*THEME_CSS*/", site_theme.CSS),
        ("<!--THEME_HEAD-->", site_theme.HEAD_SCRIPT),
        ("<!--THEME_TOGGLE-->", site_theme.toggle()),
    ):
        if marker not in page:
            raise PagesError(f"pages_index.html has no {marker}")
        page = page.replace(marker, value)
    (out / "index.html").write_text(page, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True, help="site root; formats/ must not exist")
    ap.add_argument("--commit", required=True, help="commit the source was checked out at")
    ap.add_argument("--generated", help="build stamp, UTC 'YYYY-MM-DD HH:MM:SS' (default: now)")
    ap.add_argument("--repository", default=DEFAULT_REPOSITORY)
    ap.add_argument("--site-url", default=DEFAULT_SITE_URL)
    ap.add_argument("--site-index", action="store_true",
                    help="also write the site's front page, <out>/index.html")
    args = ap.parse_args(argv)

    generated = args.generated or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    try:
        result = build(args.out, args.commit, generated, args.repository, args.site_url)
        if args.site_index:
            write_site_index(args.out)
    except (PagesError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Format pages built: {result.formats} formats at commit {args.commit[:12]}, "
          f"languages: {', '.join(_languages())}")
    for code, missing in result.untranslated.items():
        if missing:
            print(f"  {code}: {len(missing)} text(s) not translated, shown in English and marked:")
            for context, text, disambiguation in sorted(missing):
                where = f"{context} / {disambiguation}" if disambiguation else context
                print(f"    [{where}] {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
