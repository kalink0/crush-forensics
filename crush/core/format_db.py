# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""FormatDatabase — runtime wrapper around the bundled formats.db knowledge base."""
from __future__ import annotations

import sqlite3
import sys
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

    def relevance_text(self) -> CatalogText:
        return CatalogText(KNOWLEDGE_CONTEXT, self.forensic_relevance, self.name, knowledge=True)

    def magic_description_text(self, description: str) -> CatalogText:
        return CatalogText(KNOWLEDGE_CONTEXT, description, self.name, knowledge=True)

    def category_text(self) -> CatalogText:
        return CatalogText(CATEGORY_CONTEXT, self.category)


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

    def identify(self, peek_bytes: bytes, filename: str) -> FormatMatch | None:
        """Return the best format match by magic bytes, or None.

        Score = sum of lengths of all patterns that match for a given format.
        This ensures formats with multiple complementary patterns (e.g. WAV:
        RIFF at offset 0 + WAVE at offset 8) beat formats that only match on
        the shared prefix (e.g. AVI also starts with RIFF but 'AVI ' at
        offset 8 would not match a WAV file).
        """
        if self._conn is None:
            return None

        cur = self._conn.execute(
            "SELECT f.id, m.offset, m.pattern "
            "FROM formats f JOIN magic_bytes m ON m.format_id = f.id "
            "ORDER BY f.id"
        )

        scores: dict[int, int] = {}
        for row in cur:
            offset = row["offset"]
            if offset is None:
                continue
            pattern: bytes = row["pattern"]
            end = offset + len(pattern)
            if len(peek_bytes) >= end and peek_bytes[offset:end] == pattern:
                if pattern == XML_PLIST_SIG and not _looks_like_plist_xml(peek_bytes):
                    continue
                scores[row["id"]] = scores.get(row["id"], 0) + len(pattern)

        if not scores:
            return None

        best_id = max(scores, key=lambda fid: scores[fid])
        row = self._conn.execute(
            "SELECT * FROM formats WHERE id = ?", (best_id,)
        ).fetchone()
        return self._row_to_match(row) if row else None

    def by_short_name(self, short_name: str) -> FormatMatch | None:
        """Look up format metadata by short_name (e.g. 'SEGB', 'SQLite')."""
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT * FROM formats WHERE short_name = ? LIMIT 1",
            (short_name,),
        ).fetchone()
        return self._row_to_match(row) if row else None

    def by_parser_class(self, class_name: str) -> FormatMatch | None:
        """Look up format metadata for a parser that successfully handled a file."""
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT * FROM formats WHERE parser_class = ? LIMIT 1",
            (class_name,),
        ).fetchone()
        return self._row_to_match(row) if row else None

    def all_formats(self) -> list[FormatMatch]:
        """Return all known formats ordered by category then name."""
        if self._conn is None:
            return []
        return [
            self._row_to_match(r)
            for r in self._conn.execute(
                "SELECT * FROM formats ORDER BY category, name"
            )
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

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
        )
