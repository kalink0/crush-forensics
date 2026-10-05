# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Texts of the format reference website (scripts/build_format_pages.py).

The site is not part of the app; its texts live here, inside crush/, so
scripts/i18n.py puts them into the translation catalogs. Three kinds:

APP_TEXTS      labels the app already has: the (context, text) of its
               catalog entry. A translated site uses the app's translation,
               so they add nothing for translators.
WEBSITE_TEXTS  texts only the website has, marked with
               QT_TRANSLATE_NOOP(WEBSITE_CONTEXT, ...). Contexts starting
               with WEBSITE_CONTEXT_PREFIX don't count towards a language's
               completeness in the app (scripts/i18n.py count_messages),
               and translators see from the context that they're website
               texts.
ENGLISH_TEXTS  never translated: the prefilled issue for a correction,
               read by the maintainers on GitHub.

Only English is published so far. A translated site would look each text
up by (context, text) in crush/i18n/crush_<code>.ts.
"""
from __future__ import annotations

from crush.core.issues import QT_TRANSLATE_NOOP

WEBSITE_CONTEXT_PREFIX = "Website"
WEBSITE_CONTEXT = "WebsiteFormatReference"

APP_TEXTS: dict[str, tuple[str, str]] = {
    "count": ("FormatReferenceDialog", "{total} formats"),
    "count_filtered": ("FormatReferenceDialog", "{visible} of {total} formats"),
    "col_name": ("FormatReferenceDialog", "Name"),
    "col_category": ("FormatReferenceDialog", "Category"),
    "col_platforms": ("FormatReferenceDialog", "Platforms"),
    "col_short": ("FormatInfoDialog", "Short name"),
    "f_name": ("FormatInfoDialog", "Format"),
    "f_short": ("FormatInfoDialog", "Short name"),
    "f_category": ("FormatInfoDialog", "Category"),
    "f_platforms": ("FormatInfoDialog", "Platforms"),
    "f_reviewed": ("FormatInfoDialog", "Last reviewed"),
    "f_relevance": ("MetadataLabel", "Forensic relevance"),
    "f_signatures": ("MetadataLabel", "Signatures"),
    "f_status": ("MetadataLabel", "Status"),
    "supported": ("FormatInfoDialog", "Supported"),
    "not_supported": ("FormatInfoDialog", "Not yet supported"),
    "not_recorded": ("FormatInfoDialog", "Not recorded"),
    "offset_known": ("FormatInfoDialog", "offset {offset} (0x{offset_hex})"),
    "offset_unknown": ("FormatInfoDialog", "offset unknown"),
    "sig_offset": ("HexViewer", "Offset"),
    "sig_hex": ("HexViewer", "Hex"),
    "sig_description": ("GeneratedView", "Description"),
}

WEBSITE_TEXTS: dict[str, str] = {
    "site_title": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Crush Format Reference"),
    "heading": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Crush — Format Reference"),
    "intro": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "The file formats Crush knows: what each one contains, where it is found, "
        "its signatures and whether Crush can analyse it. This site is built from "
        "the format database in the Crush source code; formats.db, bundled with "
        "Crush, is built from the same source.",
    ),
    "built_from": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "Built from {source} at commit {commit} on {generated} UTC."
    ),
    "disclaimer": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Reviewed entries were checked manually. Sources were verified and refined; "
        "signatures and structural details were checked against the specification "
        "where one exists, and for undocumented formats against published "
        "reverse-engineering research and own research. Practical knowledge \u2014 "
        "such as which OS versions introduced a format \u2014 comes from casework and "
        "from findings shared by the DFIR community. Each entry lists its references "
        "(sources and related tools) and review date. Should you find an error or "
        "have additional knowledge, corrections and additions are welcome and "
        "credited: {link}.",
    ),
    "draft_disclaimer": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Draft entries were compiled from a brief web search (search engine or "
        "AI-assisted) and have not been reviewed yet.",
    ),
    "filesig_note": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Another curated list of file signatures: {link}, started by Gary Kessler "
        "in 2002 and since 2025 maintained by SEARCH.",
    ),
    "extensions_note": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Known extensions are a hint, never proof. Evidence files are routinely "
        "renamed, carved or exported without an extension. Crush identifies "
        "formats by their content, not by their name.",
    ),
    "support_note": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Crush support: “Supported” means Crush has a parser or container "
        "backend for the format (named in brackets). “Not yet supported” "
        "means it has none.",
    ),
    "draft_note": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Draft: compiled from a brief web search (search engine or AI-assisted) and "
        "not reviewed yet. Drafts are not part of formats.db, so Crush neither shows "
        "them nor uses their signatures.",
    ),
    "downloads": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Machine-readable:"),
    "filter": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Filter"),
    "filter_placeholder": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "Name, category, platform, extension, parser…"
    ),
    "all_categories": QT_TRANSLATE_NOOP("WebsiteFormatReference", "All categories"),
    "all_support": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Any support"),
    "all_statuses": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Any status"),
    "sig_search": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Signature lookup"),
    "sig_search_help": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Enter hex bytes (e.g. 37 7A or 53 51 4C 69 74 65). Lists every signature "
        "that contains them, with the offset the signature has in a file. To "
        "identify a file, open it in Crush (Show Format Info).",
    ),
    "sig_placeholder": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Hex bytes, e.g. 37 7A"),
    "sig_invalid": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "Not valid hex: use pairs of 0-9 / A-F."
    ),
    "sig_none": QT_TRANSLATE_NOOP("WebsiteFormatReference", "No signature contains these bytes."),
    "sig_hits": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "{count} signature(s) contain these bytes:"
    ),
    "col_extensions": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Known extensions"),
    "col_support": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Crush support"),
    "draft": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Draft"),
    "reviewed": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Reviewed"),
    "all_formats": QT_TRANSLATE_NOOP("WebsiteFormatReference", "← All formats"),
    "draft_banner": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Draft — this entry was compiled from a brief web search (search engine "
        "or AI-assisted) and has not been reviewed yet. It is not part of formats.db, so Crush "
        "neither shows it nor uses its signatures.",
    ),
    "f_support": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Crush support"),
    "f_extensions": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Known extensions"),
    "f_links": QT_TRANSLATE_NOOP("WebsiteFormatReference", "References"),
    "sig_ascii": QT_TRANSLATE_NOOP("WebsiteFormatReference", "ASCII (non-printable as .)"),
    "none_recorded": QT_TRANSLATE_NOOP("WebsiteFormatReference", "None recorded"),
    "cite": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Cite this entry"),
    "cite_text": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Crush Format Reference, “{name}”. {url} — source: {source} "
        "at commit {commit}, built {generated} UTC.",
    ),
    "view_source": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "Entry in the source at this commit"
    ),
    "history": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Change history of the source"),
    "report": QT_TRANSLATE_NOOP("WebsiteFormatReference", "Report a correction"),
    "report_issue": QT_TRANSLATE_NOOP("WebsiteFormatReference", "open an issue on GitHub"),
    "theme_toggle": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference", "Switch between dark and light theme"
    ),
    "license": QT_TRANSLATE_NOOP(
        "WebsiteFormatReference",
        "Content licensed under {license}, like the Crush repository. Linked "
        "sources are subject to their own terms.",
    ),
}

ENGLISH_TEXTS: dict[str, str] = {
    "issue_title": "Format reference: {name}",
    "issue_body": "Entry: {url}\n\nWhat is wrong or missing:\n",
    "issue_title_general": "Format reference",
    "issue_body_general": "Page: {url}\n\nWhat is wrong or missing:\n",
}


def english(key: str) -> str:
    """The English text of *key*, whichever kind it is."""
    if key in APP_TEXTS:
        return APP_TEXTS[key][1]
    if key in WEBSITE_TEXTS:
        return WEBSITE_TEXTS[key]
    return ENGLISH_TEXTS[key]
