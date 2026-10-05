# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FormatDatabase — runtime wrapper around the bundled formats.db knowledge base."""
from __future__ import annotations

import sqlite3
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from crush.core.issues import QT_TRANSLATE_NOOP, CatalogText
from crush.core.magic import XML_PLIST_SIG, _looks_like_plist_xml


def _resolve_db_path() -> Path:
    # PyInstaller extracts data files to sys._MEIPASS when frozen
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).parent.parent
    return base / "data" / "formats.db"


_DB_PATH = _resolve_db_path()


# Translation contexts. formats.db stays English; build_formats_db.py marks
# each format's forensic_relevance and magic-byte descriptions with
# QT_TRANSLATE_NOOP(KNOWLEDGE_CONTEXT, text, <format name>), and the UI
# translates them at display time. A text whose English changed has no
# matching translation any more and is shown in English.
KNOWLEDGE_CONTEXT = "FormatKnowledge"
CATEGORY_CONTEXT = "FormatCategory"

# Every category value build_formats_db.py may use. The English label is
# the value itself, shown as it always was.
FORMAT_CATEGORIES = (
    QT_TRANSLATE_NOOP("FormatCategory", "archive"),
    QT_TRANSLATE_NOOP("FormatCategory", "configuration"),
    QT_TRANSLATE_NOOP("FormatCategory", "database"),
    QT_TRANSLATE_NOOP("FormatCategory", "disk_image"),
    QT_TRANSLATE_NOOP("FormatCategory", "document"),
    QT_TRANSLATE_NOOP("FormatCategory", "execution"),
    QT_TRANSLATE_NOOP("FormatCategory", "filesystem"),
    QT_TRANSLATE_NOOP("FormatCategory", "log"),
    QT_TRANSLATE_NOOP("FormatCategory", "logical_image"),
    QT_TRANSLATE_NOOP("FormatCategory", "media"),
    QT_TRANSLATE_NOOP("FormatCategory", "memory"),
    QT_TRANSLATE_NOOP("FormatCategory", "network"),
    QT_TRANSLATE_NOOP("FormatCategory", "serialization"),
    QT_TRANSLATE_NOOP("FormatCategory", "uncategorized"),
)


@dataclass
class FormatMatch:
    name: str
    short_name: str
    category: str
    forensic_relevance: str
    platforms: str
    parser_class: str | None   # e.g. "SQLiteParser", or None if unsupported
    links: list[tuple[str, str]]  # [(label, url), ...]
    magic: list[tuple[int | None, bytes, str]]  # [(offset, pattern, description), ...]
    last_reviewed: str | None  # ISO date of the entry's last manual review, None if not recorded

    def relevance_text(self) -> CatalogText:
        return CatalogText(KNOWLEDGE_CONTEXT, self.forensic_relevance, self.name, knowledge=True)

    def magic_description_text(self, description: str) -> CatalogText:
        return CatalogText(KNOWLEDGE_CONTEXT, description, self.name, knowledge=True)

    def category_text(self) -> CatalogText:
        return CatalogText(CATEGORY_CONTEXT, self.category)


class _TrieNode:
    """One byte position in the signatures starting at one offset: the
    next bytes, and the formats whose signature ends here (a format once
    per signature, as each signature adds to its score)."""

    __slots__ = ("children", "ends")

    def __init__(self) -> None:
        self.children: dict[int, _TrieNode] = {}
        self.ends: list[int] = []


class FormatDatabase:
    """Singleton read-only wrapper around formats.db."""

    _instance: FormatDatabase | None = None

    @classmethod
    def get(cls) -> FormatDatabase:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        # Built on first use by _load(): every format by id, and per
        # signature offset a byte trie of the patterns starting there.
        self._load_lock = threading.Lock()
        self._formats: dict[int, FormatMatch] | None = None
        self._tries: list[tuple[int, _TrieNode]] = []
        if not _DB_PATH.exists():
            return
        try:
            self._conn = sqlite3.connect(
                f"file:{_DB_PATH}?mode=ro", uri=True, check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
        except Exception:
            self._conn = None

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def identify(
        self, peek_bytes: bytes, filename: str, *, parser_class: str | None = None
    ) -> FormatMatch | None:
        """Return the format the magic bytes single out, or None.

        None also when several formats share the top score (see
        top_matches): picking one by table order would show the knowledge
        of a format the file may not be.
        """
        top = self.top_matches(peek_bytes, parser_class=parser_class)
        return top[0] if len(top) == 1 else None

    def top_matches(
        self, peek_bytes: bytes, *, parser_class: str | None = None
    ) -> list[FormatMatch]:
        """Every format with the highest magic-byte score; empty if none matched.

        Score = sum of lengths of all patterns that match for a given format.
        This ensures formats with multiple complementary patterns (e.g. WAV:
        RIFF at offset 0 + WAVE at offset 8) beat formats that only match on
        the shared prefix (e.g. AVI also starts with RIFF but 'AVI ' at
        offset 8 would not match a WAV file). More than one entry means the
        bytes don't single out one format. With *parser_class*, only that
        parser's entries compete.

        Runs once per file while a source is indexed, so it reads no SQL:
        the signatures are walked in per-offset byte tries, and the cost
        grows with the number of distinct offsets and the matched length,
        not with the number of signatures.
        """
        formats = self._load()
        n = len(peek_bytes)
        is_plist_xml: bool | None = None
        scores: dict[int, int] = {}
        for offset, root in self._tries:
            if offset >= n:
                break  # sorted by offset: no later one fits either
            children = root.children
            i = offset
            while i < n:
                node = children.get(peek_bytes[i])
                if node is None:
                    break
                i += 1
                for fid in node.ends:
                    fmt = formats[fid]
                    if parser_class is not None and fmt.parser_class != parser_class:
                        continue
                    # "<?xml" is shared by the XML plist and the generic XML
                    # entry: a plist counts only for the plist entry, any
                    # other XML only for the generic one.
                    if offset == 0 and i == len(XML_PLIST_SIG) and peek_bytes[:i] == XML_PLIST_SIG:
                        if is_plist_xml is None:
                            is_plist_xml = _looks_like_plist_xml(peek_bytes)
                        if is_plist_xml != (fmt.parser_class == "PlistParser"):
                            continue
                    scores[fid] = scores.get(fid, 0) + (i - offset)
                children = node.children

        if not scores:
            return []
        top = max(scores.values())
        return [formats[fid] for fid in sorted(scores) if scores[fid] == top]

    def by_short_name(self, short_name: str) -> FormatMatch | None:
        """Look up format metadata by short_name (e.g. 'SEGB', 'SQLite')."""
        return next((f for f in self._load().values() if f.short_name == short_name), None)

    def parser_formats(self, class_name: str) -> list[FormatMatch]:
        """Every format whose entry names *class_name* as its parser."""
        return [f for f in self._load().values() if f.parser_class == class_name]

    def for_parser(self, class_name: str, peek_bytes: bytes) -> list[FormatMatch]:
        """The format of a file the parser *class_name* handled, as a list:
        one entry when it is determined, else every candidate.

        A parser that reads one format has one entry: that one. A parser
        that reads several (ImageParser, MediaParser, ...) has one entry per
        format, and the file's magic bytes pick among them. When they don't
        single one out, the result is the formats tied at the top score, or
        all of the parser's formats when none matched -- never the first
        entry by table order. Empty when no entry names the parser.
        """
        candidates = self.parser_formats(class_name)
        if len(candidates) <= 1:
            return candidates
        return self.top_matches(peek_bytes, parser_class=class_name) or candidates

    def all_formats(self) -> list[FormatMatch]:
        """Return all known formats ordered by category then name."""
        return sorted(self._load().values(), key=lambda f: (f.category, f.name))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self) -> dict[int, FormatMatch]:
        """Every format by id, read once; also builds the signature tries.
        formats.db is read-only and bundled, so it can't change while
        Crush runs."""
        if self._formats is not None:
            return self._formats
        with self._load_lock:
            if self._formats is not None:
                return self._formats
            formats: dict[int, FormatMatch] = {}
            tries: dict[int, _TrieNode] = {}
            if self._conn is not None:
                for row in self._conn.execute("SELECT * FROM formats ORDER BY id"):
                    formats[row["id"]] = self._row_to_match(row)
                for row in self._conn.execute(
                    "SELECT format_id, offset, pattern FROM magic_bytes "
                    "WHERE offset IS NOT NULL ORDER BY id"
                ):
                    pattern: bytes = row["pattern"]
                    if not pattern or row["format_id"] not in formats:
                        continue
                    node = tries.setdefault(row["offset"], _TrieNode())
                    for byte in pattern:
                        node = node.children.setdefault(byte, _TrieNode())
                    node.ends.append(row["format_id"])
            self._tries = sorted(tries.items())
            self._formats = formats
            return formats

    def _row_to_match(self, row: sqlite3.Row) -> FormatMatch:
        fid = row["id"]
        links: list[tuple[str, str]] = []
        if self._conn:
            links = [
                (r["label"], r["url"])
                for r in self._conn.execute(
                    "SELECT label, url FROM links WHERE format_id = ? ORDER BY id",
                    (fid,),
                )
            ]
        magic: list[tuple[int | None, bytes, str]] = []
        if self._conn:
            magic = [
                (r["offset"], r["pattern"], r["description"] or "")
                for r in self._conn.execute(
                    "SELECT offset, pattern, description FROM magic_bytes "
                    "WHERE format_id = ? ORDER BY id",
                    (fid,),
                )
            ]
        return FormatMatch(
            name=row["name"],
            short_name=row["short_name"] or "",
            category=row["category"] or "",
            forensic_relevance=row["forensic_relevance"] or "",
            platforms=row["platforms"] or "",
            parser_class=row["parser_class"],
            links=links,
            magic=magic,
            last_reviewed=row["last_reviewed"],
        )
