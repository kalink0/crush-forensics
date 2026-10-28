# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Structured parse issues -- the public contract for "why" a parser
couldn't decode something, or what a result does not contain.

A parser never writes the sentence itself. It returns a ParseIssue: a
stable *code*, the *params* (facts: offsets, counts, table names), and,
where a library produced one, the verbatim *detail* text (e.g. the
json/lxml/sqlite3 exception message). The English sentence lives once, in
MESSAGES below, and is rendered at display time.

Why codes instead of free text:
- A UI translation (planned: Qt Linguist) can translate the catalog
  without touching any parser, and a stale or missing translation falls
  back to the English template here.
- Tests and callers check `issue.code`, never displayed wording.
- `detail` is the library's own diagnosis. It is never translated or
  shortened. A template leaves it out only where the library's wording is
  known to mislead (say why next to the template); it then stays on the
  issue and is logged.

str(issue) renders the English sentence, so an issue can sit anywhere a
string used to (a metadata value, a status bar message) and exports stay
English.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger(__name__)

# Translation context of every MESSAGES template in the .ts catalog.
TRANSLATION_CONTEXT = "ParseIssue"


def QT_TRANSLATE_NOOP(  # noqa: N802
    context: str, text: str, disambiguation: str | None = None
) -> str:
    """Mark *text* for extraction into the translation catalog.

    lupdate recognises this call by its name, so this Qt-free stand-in
    keeps crush.core free of PySide6. It returns *text* unchanged: the
    catalog stays English, translation happens in render(localized=True).

    Other core modules use it too for text the UI shows (e.g. ts_decode's
    menu labels, context "TimestampFormat").

    lupdate reads the arguments literally: in MESSAGES the context must be
    the string "ParseIssue", the disambiguation must repeat the entry's code (the
    translator sees it next to the text, and two codes with the same
    English wording can be translated differently), and a multi-line text
    must be written as adjacent string literals *without* extra
    parentheses around them -- lupdate silently skips a parenthesised text.
    test_i18n checks both.
    """
    return text


# Installed by the UI (crush.ui.i18n) once a translator is loaded; None
# means no translation, i.e. localized rendering returns English.
_translate: Callable[[str, str, str], str] | None = None


def set_translator(translate: Callable[[str, str, str], str] | None) -> None:
    """Install the function (context, source, disambiguation) -> translation
    used by render(localized=True)."""
    global _translate
    _translate = translate


# Set by the UI from the analyst's "English original" setting: knowledge
# texts (see CatalogText) are then displayed in English even when a
# translation is loaded.
_knowledge_original = False


def set_knowledge_original(on: bool) -> None:
    global _knowledge_original
    _knowledge_original = on


def knowledge_original() -> bool:
    return _knowledge_original


def translation_loaded() -> bool:
    return _translate is not None


@dataclass(frozen=True, eq=True)
class CatalogText:
    """A text from one of Crush's own catalogs (formats.db, analyzer
    modules) placed where a string would go, e.g. a metadata value.

    *text* is the English original, marked where it is written with
    QT_TRANSLATE_NOOP(context, text, disambiguation); str() returns it, so
    logs, copies and exports stay English. render_value(localized=True)
    shows the translation. *knowledge* marks written forensic guidance (a
    format's relevance, a magic-byte description): the analyst can switch
    those back to the English original; labels (a category) always follow
    the UI language.
    """

    context: str
    text: str
    disambiguation: str = ""
    knowledge: bool = False

    def __str__(self) -> str:
        return self.text

    def localized(self) -> str:
        if _translate is None or (self.knowledge and _knowledge_original):
            return self.text
        return _translate(self.context, self.text, self.disambiguation) or self.text


@dataclass(frozen=True, eq=True)
class ParseIssue:
    code: str
    params: dict[str, Any] = field(default_factory=dict, hash=False)
    detail: str = ""

    def __str__(self) -> str:
        return render(self)


class ParseIssueError(ValueError):
    """Carries a ParseIssue out of a decoder's helper functions.

    For code paths that report a failure by raising (so the caller's
    existing `except ValueError` still applies) -- str(exc) renders the
    issue, and the caller reads `exc.issue` for the code.
    """

    def __init__(self, issue: ParseIssue) -> None:
        super().__init__(issue)
        self.issue = issue


def issue_from_exception(exc: BaseException) -> ParseIssue:
    """The ParseIssue an exception carries, or the library's own message
    wrapped verbatim as `common.library_error`."""
    if isinstance(exc, ParseIssueError):
        return exc.issue
    return ParseIssue("common.library_error", detail=str(exc))


# code -> English template. Placeholders are filled from params, plus
# {detail}. A param holding a ParseIssue (or a list of them) is rendered
# recursively; lists are joined with "; ".
MESSAGES: dict[str, str] = {
    # -- Shared -----------------------------------------------------------
    # A library exception's own message, when there is no finer code.
    "common.library_error": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "common.library_error"),
    # -- JSON -------------------------------------------------------------
    "json.syntax_error": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not valid JSON: {detail}. The tree shows only an excerpt around the "
        "error position; full content: Open as → Text / Hex",
        "json.syntax_error",
    ),
    "json.not_utf8": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not valid UTF-8 (first invalid byte at offset {offset:,}: {detail}); "
        "invalid bytes are shown as U+FFFD — Open as → Hex for the original bytes",
        "json.not_utf8",
    ),
    # -- Logs (Multi-Log Studio) -------------------------------------------
    "log.format_detected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} (heuristic)",
        "log.format_detected",
    ),
    "log.format_selected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} (selected by analyst)",
        "log.format_selected",
    ),
    "log.format_custom": QT_TRANSLATE_NOOP("ParseIssue", "Custom: {name}", "log.format_custom"),
    "log.format_score": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} {hits:,}/{total:,}",
        "log.format_score",
    ),
    "log.detection_rule": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Plain-text logs have no format marker. The first of JSON Lines "
        "(≥ 60 % of lines), Android logcat (≥ 50 %), Syslog (≥ 50 %) and Generic "
        "(≥ 2 lines) that reaches its threshold is used, otherwise plain text. "
        "Another format can be chosen via Format → Re-parse as",
        "log.detection_rule",
    ),
    "log.lines_unmatched": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} line(s) kept as separate entries with level UNKNOWN",
        "log.lines_unmatched",
    ),
    "log.ts_no_zone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} entries: no time zone in the log — shown as recorded, never converted",
        "log.ts_no_zone",
    ),
    "log.level_guessed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} entries: this format has no level field — level guessed from a "
        "keyword in the message (marked \"guessed\")",
        "log.level_guessed",
    ),
    "log.ts_no_year": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} entries: no year in the log — shown as ????",
        "log.ts_no_year",
    ),
    "log.ts_unparsed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} entries: timestamp present but not decodable — see the raw line",
        "log.ts_unparsed",
    ),
    "log.not_utf8": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not valid UTF-8 (first invalid byte at offset {offset:,}: {detail}); "
        "invalid bytes are shown as U+FFFD — Open as → Hex for the original bytes",
        "log.not_utf8",
    ),
    # -- SQLite -----------------------------------------------------------
    "sqlite.parse_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "sqlite.parse_failed"),
    "sqlite.invalid_hex_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a valid hex key: {detail}",
        "sqlite.invalid_hex_key",
    ),
    # No {detail}: SQLCipher's message for a page that fails to decrypt is
    # always "file is not a database", which reads as "this isn't a
    # database" in a password prompt. The detail stays on the issue and in
    # the log.
    "sqlite.custom_params_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect key, or the given parameters don't match this file",
        "sqlite.custom_params_rejected",
    ),
    "sqlite.password_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect password, or an unsupported SQLCipher version/parameters",
        "sqlite.password_rejected",
    ),
    "sqlite.encrypted_password": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes (SQLCipher, password supplied)",
        "sqlite.encrypted_password",
    ),
    "sqlite.encrypted_raw_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes (SQLCipher, raw key supplied)",
        "sqlite.encrypted_raw_key",
    ),
    "sqlite.pragma_read_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page size, journal mode and encoding could not be read: {detail}",
        "sqlite.pragma_read_failed",
    ),
    "sqlite.journal_mode_rollback": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Rollback journal (the file doesn't record which variant: "
        "delete/truncate/persist)",
        "sqlite.journal_mode_rollback",
    ),
    "sqlite.row_limit": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "First {limit:,} rows shown for: {tables}",
        "sqlite.row_limit",
    ),
    "sqlite.companion_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "VFS found {name} (path={path}, vfs_size={size} B) but read returned 0 bytes — "
        "ZIP entry may be empty in the archive",
        "sqlite.companion_empty",
    ),
    "sqlite.companion_copied": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Copied {name} ({size:,} B) from {path}",
        "sqlite.companion_copied",
    ),
    "sqlite.companion_loaded_fs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Loaded filesystem companion {name} ({size:,} B)",
        "sqlite.companion_loaded_fs",
    ),
    "sqlite.companion_not_in_vfs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "find_sibling returned None for db_node.path={path}",
        "sqlite.companion_not_in_vfs",
    ),
    "sqlite.companion_read_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "VFS found {name} but read raised: {detail}",
        "sqlite.companion_read_failed",
    ),
    "sqlite.companion_fs_read_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} could not be read from disk: {detail}",
        "sqlite.companion_fs_read_failed",
    ),
    "sqlite.journal_present": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "present, {size:,} B, {status}",
        "sqlite.journal_present",
    ),
    "sqlite.journal_merged": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "valid/hot, {segments} segment(s), {records} page record(s) -- merged into "
        "current view (see 'Show pre-rollback state' toggle and the 'Rollback "
        "Journal' tab)",
        "sqlite.journal_merged",
    ),
    "sqlite.journal_valid_not_merged": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "valid/hot, {segments} segment(s), {records} page record(s) -- NOT merged, "
        "{reason} (see the 'Rollback Journal' tab for the raw, unmerged record "
        "inventory)",
        "sqlite.journal_valid_not_merged",
    ),
    "sqlite.journal_not_merged": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "NOT merged -- {reason} (see the 'Rollback Journal' tab for the raw, "
        "unmerged record inventory)",
        "sqlite.journal_not_merged",
    ),
    "sqlite.journal_checksum_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "one or more page checksums did not validate",
        "sqlite.journal_checksum_mismatch",
    ),
    "sqlite.journal_stale_wal_mode": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the database's own header shows WAL mode is active, so this -journal "
        "predates the switch to WAL and is stale, not \"hot\"",
        "sqlite.journal_stale_wal_mode",
    ),
    # -- SQLite rollback journal -----------------------------------------
    "sqlite_journal.invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a valid rollback journal",
        "sqlite_journal.invalid",
    ),
    "sqlite_journal.no_valid_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No valid rollback-journal header found at the start of this file "
        "(magic mismatch) -- likely a stale/invalidated PERSIST-mode "
        "journal, a truncated/corrupt journal, or not a SQLite rollback "
        "journal at all",
        "sqlite_journal.no_valid_header",
    ),
    "sqlite_journal.valid_hot": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Valid / hot — every segment header and page checksum validated",
        "sqlite_journal.valid_hot",
    ),
    "sqlite_journal.not_fully_valid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "NOT fully valid — {mismatches} checksum mismatch(es); shown raw, unmerged",
        "sqlite_journal.not_fully_valid",
    ),
    "sqlite_journal.standalone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This is the journal's own pre-transaction page content, shown standalone "
        "(no companion database opened alongside it). Open the companion database "
        "normally instead to see this same inventory in its own 'Rollback Journal' "
        "tab, with a valid journal's content automatically merged into the "
        "database's default table view (never applied to any file on disk).",
        "sqlite_journal.standalone",
    ),
    # -- SQLite WAL -------------------------------------------------------
    "sqlite_wal.invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a valid WAL file (magic mismatch or file too short)",
        "sqlite_wal.invalid",
    ),
    "sqlite_wal.standalone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Shown standalone (no companion database opened alongside it), so rows are "
        "raw decoded values, not resolved to real column names. Open the companion "
        "database normally instead to see this content with column names, table "
        "attribution, and (for Active frames) merged transparently into the live "
        "table view, plus this same per-frame inventory in its own 'WAL Frames' tab.",
        "sqlite_wal.standalone",
    ),
    "sqlite_wal.header_checksum_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The WAL header checksum does not match, so SQLite ignores the whole file: "
        "no frame is part of the current database state",
        "sqlite_wal.header_checksum_mismatch",
    ),
    "sqlite_wal.header_page_size_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The WAL header declares a page size of {page_size:,} B, not a power of two "
        "from 512 to 65,536, so SQLite ignores the whole file: no frame is part of "
        "the current database state",
        "sqlite_wal.header_page_size_invalid",
    ),
    "sqlite_wal.frame_checksum_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Frame checksum does not match; SQLite stops reading the log before this frame. "
        "A transaction still open when the file was captured also leaves this: SQLite "
        "rewrites its frames in place and updates the checksums only at commit",
        "sqlite_wal.frame_checksum_mismatch",
    ),
    "sqlite_wal.frame_after_checksum_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "After the checksum mismatch at frame {frame:,}; SQLite stops reading the log there",
        "sqlite_wal.frame_after_checksum_mismatch",
    ),
    "sqlite_wal.frame_after_salt_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "After the salt mismatch at frame {frame:,}; SQLite stops reading the log there",
        "sqlite_wal.frame_after_salt_mismatch",
    ),
    "sqlite_wal.frame_after_header_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The WAL header is not valid; SQLite ignores the whole file",
        "sqlite_wal.frame_after_header_mismatch",
    ),
    "sqlite_wal.log_end_salt": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "At frame {frame:,}: its salts do not match the WAL header; SQLite reads no frame "
        "from there on",
        "sqlite_wal.log_end_salt",
    ),
    "sqlite_wal.log_end_checksum": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "At frame {frame:,}: its checksum does not match; SQLite reads no frame from there "
        "on. A transaction still open when the file was captured also leaves this: SQLite "
        "rewrites its frames in place and updates the checksums only at commit",
        "sqlite_wal.log_end_checksum",
    ),
    "sqlite_wal.log_end_file": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "At the last full frame: every frame's salts and checksum match",
        "sqlite_wal.log_end_file",
    ),
    "sqlite_wal.log_end_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Before frame 1: the WAL header is not valid, so SQLite reads no frame",
        "sqlite_wal.log_end_header",
    ),
    # -- Realm ------------------------------------------------------------
    "realm.encrypted_key_supplied": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes (AES-256, key supplied)",
        "realm.encrypted_key_supplied",
    ),
    "realm.header_not_detected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not detected (corrupt or non-standard)",
        "realm.header_not_detected",
    ),
    "realm.try_encrypted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Try Open as → Realm DB (Encrypted)…",
        "realm.try_encrypted",
    ),
    "realm.streaming_footer_ok": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes — top ref resolved from end-of-file footer (offset {top_ref})",
        "realm.streaming_footer_ok",
    ),
    "realm.streaming_footer_bad": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes — but the footer is missing or its magic cookie doesn't match; top "
        "ref could not be resolved (truncated or corrupt file)",
        "realm.streaming_footer_bad",
    ),
    "realm.tables_unresolved": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unresolved (see Streaming form)",
        "realm.tables_unresolved",
    ),
    "realm.pre_cluster_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Decoded via legacy pre-Cluster layout",
        "realm.pre_cluster_decoded",
    ),
    "realm.pre_cluster_partial": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Pre-Cluster layout — {reasons}",
        "realm.pre_cluster_partial",
    ),
    "realm.pre_cluster_undecoded_columns": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{columns} column(s) across {tables} table(s) not yet decoded "
        "(unimplemented old column type)",
        "realm.pre_cluster_undecoded_columns",
    ),
    "realm.table_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{table}: {reason}",
        "realm.table_failed",
    ),
    "realm.group_top_malformed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Group top array is malformed or has no references",
        "realm.group_top_malformed",
    ),
    "realm.group_no_table_refs_slot": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Group top array has no table-refs slot (fewer than 2 children)",
        "realm.group_no_table_refs_slot",
    ),
    "realm.table_refs_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table-refs reference is invalid or points outside the file",
        "realm.table_refs_ref_invalid",
    ),
    "realm.table_refs_malformed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table-refs array is malformed or has no references",
        "realm.table_refs_malformed",
    ),
    "realm.table_refs_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table-refs array has 0 entries, but {classes} class name(s) in schema",
        "realm.table_refs_empty",
    ),
    # Per-table reasons (rendered after "<table>: " via realm.table_failed).
    "realm.table_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "table reference is invalid or points outside the file",
        "realm.table_ref_invalid",
    ),
    "realm.table_top_no_cluster_tree_slot": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table top array is malformed or missing its ClusterTree slot",
        "realm.table_top_no_cluster_tree_slot",
    ),
    "realm.cluster_tree_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ClusterTree reference is invalid or points outside the file",
        "realm.cluster_tree_ref_invalid",
    ),
    "realm.colkeys_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Spec/colkeys array has no columns (empty or malformed)",
        "realm.colkeys_empty",
    ),
    "realm.cluster_tree_root_malformed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ClusterTree root is malformed or has no leaves",
        "realm.cluster_tree_root_malformed",
    ),
    "realm.table_top_no_spec_slots": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table top array is malformed or missing its spec/columns slots",
        "realm.table_top_no_spec_slots",
    ),
    "realm.table_top_zero_width": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table top array has a zero element width",
        "realm.table_top_zero_width",
    ),
    "realm.spec_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Spec reference is invalid or points outside the file",
        "realm.spec_ref_invalid",
    ),
    "realm.spec_no_columns": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Spec array has no columns (empty or malformed)",
        "realm.spec_no_columns",
    ),
    # -- Images (ImageParser) ----------------------------------------------
    "image.format_unrecognised": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not recognised by content (file extension: {ext})",
        "image.format_unrecognised",
    ),
    "image.frames_first_only": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} frames/pages/images in the file; only the first is shown",
        "image.frames_first_only",
    ),
    "image.c2pa_detection_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Detection failed: {detail}",
        "image.c2pa_detection_failed",
    ),
    # -- EXIF -------------------------------------------------------------
    "exif.present": QT_TRANSLATE_NOOP("ParseIssue", "Present", "exif.present"),
    "exif.present_no_listed_fields": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present, but none of the fields shown here are set",
        "exif.present_no_listed_fields",
    ),
    "exif.not_present": QT_TRANSLATE_NOOP("ParseIssue", "Not present", "exif.not_present"),
    "exif.not_checked": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not checked for this format yet",
        "exif.not_checked",
    ),
    "exif.png_not_checked": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "PNG eXIf chunk not checked yet; tEXt chunks are shown under PNG text, "
        "zTXt and iTXt chunks are not read",
        "exif.png_not_checked",
    ),
    "exif.not_defined": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not defined for this format",
        "exif.not_defined",
    ),
    "exif.heif_plugin_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not checked (pillow-heif is not installed)",
        "exif.heif_plugin_missing",
    ),
    "exif.parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present, but could not be parsed: {reason}",
        "exif.parse_failed",
    ),
    "exif.bad_tiff_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "TIFF header is not valid",
        "exif.bad_tiff_header",
    ),
    "exif.ifd_out_of_range": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "IFD offset {offset} lies outside the EXIF data",
        "exif.ifd_out_of_range",
    ),
    "exif.ifd_truncated": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "IFD at offset {offset} declares {count} entries, only {read} fit in the data",
        "exif.ifd_truncated",
    ),
    "exif.value_out_of_range": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{tag}: value offset {offset} lies outside the EXIF data",
        "exif.value_out_of_range",
    ),
    "exif.unknown_type": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{tag}: TIFF type {dtype} is not decoded",
        "exif.unknown_type",
    ),
    "exif.invalid_rational": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Invalid (rational {value}, denominator 0)",
        "exif.invalid_rational",
    ),
    "exif.gps_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Invalid (a rational has denominator 0): latitude {lat}, longitude {lon}",
        "exif.gps_invalid",
    ),
    "exif.gps_latitude_only": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Latitude {lat} recorded, longitude missing",
        "exif.gps_latitude_only",
    ),
    "exif.gps_longitude_only": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Longitude {lon} recorded, latitude missing",
        "exif.gps_longitude_only",
    ),
    # -- XMP --------------------------------------------------------------
    "xmp.present": QT_TRANSLATE_NOOP("ParseIssue", "Present", "xmp.present"),
    "xmp.present_multiple": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present ({count} packets; fields shown are from the first)",
        "xmp.present_multiple",
    ),
    "xmp.present_no_listed_fields": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present, but none of the fields shown here are set",
        "xmp.present_no_listed_fields",
    ),
    "xmp.not_present": QT_TRANSLATE_NOOP("ParseIssue", "Not present", "xmp.not_present"),
    "xmp.unclosed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Packet start found at offset {offset:,}, but no closing tag",
        "xmp.unclosed",
    ),
    "xmp.parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present, but not parseable as XML: {detail}",
        "xmp.parse_failed",
    ),
    # -- C2PA -------------------------------------------------------------
    "c2pa.not_present": QT_TRANSLATE_NOOP("ParseIssue", "Not present", "c2pa.not_present"),
    "c2pa.not_defined": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not defined by the C2PA spec for this format",
        "c2pa.not_defined",
    ),
    "c2pa.not_checked": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not checked (detection only implemented for common image containers so far)",
        "c2pa.not_checked",
    ),
    "c2pa.unparseable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Manifest found, but could not be parsed",
        "c2pa.unparseable",
    ),
    "c2pa.parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Manifest found, but could not be parsed: {detail}",
        "c2pa.parse_failed",
    ),
    "c2pa.store_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Manifest Store found, but contains no manifest",
        "c2pa.store_empty",
    ),
    "c2pa.manifest_found": QT_TRANSLATE_NOOP("ParseIssue", "Manifest found", "c2pa.manifest_found"),
    "c2pa.manifests_found": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} manifest(s) found",
        "c2pa.manifests_found",
    ),
    "c2pa.ingredient_untitled": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "(untitled)",
        "c2pa.ingredient_untitled",
    ),
    "c2pa.signature_present": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present (structure parsed, not cryptographically verified)",
        "c2pa.signature_present",
    ),
    "c2pa.cert_unparseable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Present, but not parseable as X.509: {detail}",
        "c2pa.cert_unparseable",
    ),
    # -- Apple ATX --------------------------------------------------------
    "atx.not_atx": QT_TRANSLATE_NOOP("ParseIssue", "Not an AAPL ATX container", "atx.not_atx"),
    "atx.unexpected_eof": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unexpected end of ATX data",
        "atx.unexpected_eof",
    ),
    "atx.chunk_beyond_eof": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Chunk {tag} at offset {offset} extends beyond EOF",
        "atx.chunk_beyond_eof",
    ),
    "atx.trailing_bytes": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} trailing byte(s) after last complete chunk",
        "atx.trailing_bytes",
    ),
    "atx.no_head": QT_TRANSLATE_NOOP("ParseIssue", "No HEAD chunk found", "atx.no_head"),
    "atx.head_too_small": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "HEAD chunk too small for documented ATX header: {size} bytes",
        "atx.head_too_small",
    ),
    "atx.no_payload": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No astc, ASTC, or LZFS texture payload chunk found",
        "atx.no_payload",
    ),
    "atx.payload_no_inner_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{tag} chunk is too small to include an inner size",
        "atx.payload_no_inner_size",
    ),
    "atx.pixel_format_inferred_label": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Inferred ASTC 4x4 ({a}, {b})",
        "atx.pixel_format_inferred_label",
    ),
    "atx.pixel_format_unknown": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unknown ({a}, {b})",
        "atx.pixel_format_unknown",
    ),
    "atx.invalid_dimensions": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "invalid ATX dimensions: {width}x{height}",
        "atx.invalid_dimensions",
    ),
    "atx.too_large": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ATX image dimensions are too large: {width}x{height}",
        "atx.too_large",
    ),
    "atx.unexpected_depth": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected ATX depth {depth}; attempting 2D decode",
        "atx.unexpected_depth",
    ),
    "atx.unexpected_layers": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected ATX array layer count {count}; attempting first image decode",
        "atx.unexpected_layers",
    ),
    "atx.unexpected_mipmaps": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected ATX mipmap count {count}; attempting first image decode",
        "atx.unexpected_mipmaps",
    ),
    "atx.unsupported_pixel_format": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unsupported ATX pixel format {format}",
        "atx.unsupported_pixel_format",
    ),
    "atx.pixel_format_inferred": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ATX pixel format {format} inferred as ASTC 4x4",
        "atx.pixel_format_inferred",
    ),
    "atx.lzfs_too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LZFS payload decompressed to {size} bytes; expected at least {expected}",
        "atx.lzfs_too_short",
    ),
    "atx.astc_too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ASTC payload is {size} bytes; expected at least {expected}",
        "atx.astc_too_short",
    ),
    "atx.decode_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ATX image decode failed: {reason}",
        "atx.decode_failed",
    ),
    "atx.decoded": QT_TRANSLATE_NOOP("ParseIssue", "Decoded ATX to PNG", "atx.decoded"),
    "atx.decode_unavailable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ATX metadata parsed; image decode unavailable",
        "atx.decode_unavailable",
    ),
    "atx.block_order_heuristic": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic — the file does not record it. Used: Morton X/Y {chosen} "
        "(seam score {chosen_score:.2f}); other candidate: Morton X/Y {other} "
        "(seam score {other_score:.2f}). Lower score = smaller brightness jumps "
        "at the 128-pixel macro-tile boundaries",
        "atx.block_order_heuristic",
    ),
    "atx.morton_as_stored": QT_TRANSLATE_NOOP("ParseIssue", "as stored", "atx.morton_as_stored"),
    "atx.morton_swapped": QT_TRANSLATE_NOOP("ParseIssue", "swapped", "atx.morton_swapped"),
    # -- Khronos KTX ------------------------------------------------------
    "ktx.unsupported_version": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unsupported KTX version",
        "ktx.unsupported_version",
    ),
    "ktx.not_ktx": QT_TRANSLATE_NOOP("ParseIssue", "Not a KTX 1.1 file", "ktx.not_ktx"),
    "ktx.header_too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "File is {size} bytes; a KTX header needs {needed}",
        "ktx.header_too_short",
    ),
    "ktx.kv_beyond_eof": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key/value block claims {size} bytes but the file ends first",
        "ktx.kv_beyond_eof",
    ),
    "ktx.kv_entry_overflow": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key/value entry extends beyond the key/value block",
        "ktx.kv_entry_overflow",
    ),
    "ktx.no_payload": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No texture payload after the key/value block",
        "ktx.no_payload",
    ),
    "ktx.no_lzfs_marker": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key/value block declares Compression_APPLE but no LZFS marker follows imageSize",
        "ktx.no_lzfs_marker",
    ),
    "ktx.not_lzfse": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LZFS marker is present but the block that follows is not LZFSE",
        "ktx.not_lzfse",
    ),
    "ktx.lzfse_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LZFSE block declares {declared:,} bytes but only {present:,} are present",
        "ktx.lzfse_short",
    ),
    "ktx.pixel_format_unsupported_label": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unsupported (glInternalFormat 0x{fmt:04X})",
        "ktx.pixel_format_unsupported_label",
    ),
    "ktx.unsupported_pixel_format": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unsupported KTX pixel format {format}",
        "ktx.unsupported_pixel_format",
    ),
    "ktx.invalid_dimensions": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "invalid KTX dimensions: {width}x{height}",
        "ktx.invalid_dimensions",
    ),
    "ktx.too_large": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "KTX image dimensions are too large: {width}x{height}",
        "ktx.too_large",
    ),
    "ktx.unexpected_depth": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected KTX depth {depth}; attempting 2D decode",
        "ktx.unexpected_depth",
    ),
    "ktx.unexpected_layers": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected KTX array layer count {count}; decoding first",
        "ktx.unexpected_layers",
    ),
    "ktx.unexpected_faces": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected KTX face count {count}; decoding first face",
        "ktx.unexpected_faces",
    ),
    "ktx.unexpected_mipmaps": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected KTX mipmap count {count}; decoding first level",
        "ktx.unexpected_mipmaps",
    ),
    "ktx.lzfse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LZFSE decompression failed: {detail}",
        "ktx.lzfse_failed",
    ),
    "ktx.decode_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "KTX image decode failed: {reason}",
        "ktx.decode_failed",
    ),
    "ktx.decoded": QT_TRANSLATE_NOOP("ParseIssue", "Decoded KTX to PNG", "ktx.decoded"),
    "ktx.decode_unavailable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "KTX metadata parsed; image decode unavailable",
        "ktx.decode_unavailable",
    ),
    # -- PDF --------------------------------------------------------------
    "pdf.pypdf_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Install pypdf for text extraction: pip install pypdf",
        "pdf.pypdf_missing",
    ),
    "pdf.try_encrypted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Try Open as → PDF (Encrypted)…",
        "pdf.try_encrypted",
    ),
    "pdf.wrong_password": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Wrong password for encrypted PDF: {path}",
        "pdf.wrong_password",
    ),
    "pdf.encrypted_password": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Yes (password supplied)",
        "pdf.encrypted_password",
    ),
    "pdf.parse_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "pdf.parse_failed"),
    "pdf.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "PDF (parse failed)",
        "pdf.format_parse_failed",
    ),
    "pdf.js_present": QT_TRANSLATE_NOOP("ParseIssue", "Present", "pdf.js_present"),
    "pdf.js_not_present": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not present (checked: document-level /Names/JavaScript and /OpenAction; "
        "not checked: annotation and form-field actions)",
        "pdf.js_not_present",
    ),
    "pdf.js_check_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be checked: {detail}",
        "pdf.js_check_failed",
    ),
    "pdf.signatures_signed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{signed}/{total} signature field(s) signed",
        "pdf.signatures_signed",
    ),
    "pdf.signatures_none": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "None (checked: top-level AcroForm fields; not checked: fields nested in /Kids)",
        "pdf.signatures_none",
    ),
    "pdf.signatures_check_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be checked: {detail}",
        "pdf.signatures_check_failed",
    ),
    "pdf.attachments": QT_TRANSLATE_NOOP("ParseIssue", "{count} file(s)", "pdf.attachments"),
    "pdf.attachments_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} file(s) read, then reading failed: {detail}",
        "pdf.attachments_failed",
    ),
    "pdf.no_text": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No extractable text in this PDF",
        "pdf.no_text",
    ),
    "pdf.text_pages_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Text extraction failed on {count} page(s): {failures}",
        "pdf.text_pages_failed",
    ),
    "pdf.text_page_failure": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "page {page}: {detail}",
        "pdf.text_page_failure",
    ),
    "pdf.xmp_present": QT_TRANSLATE_NOOP("ParseIssue", "Present", "pdf.xmp_present"),
    "pdf.xmp_not_present": QT_TRANSLATE_NOOP("ParseIssue", "Not present", "pdf.xmp_not_present"),
    "pdf.xmp_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be read: {detail}",
        "pdf.xmp_failed",
    ),
    "pdf.revision_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This revision could not be opened: {detail}",
        "pdf.revision_failed",
    ),
    "pdf.revchain_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stopped after {count} revision(s): the trailer of the oldest one found "
        "could not be read: {detail}",
        "pdf.revchain_parse_failed",
    ),
    "pdf.revchain_bad_prev": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stopped after {count} revision(s): the trailer's /Prev value is not a "
        "byte offset: {detail}",
        "pdf.revchain_bad_prev",
    ),
    "pdf.revchain_no_eof": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stopped after {count} revision(s): no %%EOF after /Prev offset {offset:,}",
        "pdf.revchain_no_eof",
    ),
    "pdf.revchain_cycle": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stopped after {count} revision(s): /Prev offset {offset:,} repeats (cyclic chain)",
        "pdf.revchain_cycle",
    ),
    # -- Media (audio/video) ------------------------------------------------
    "media.metadata_not_checked": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Codec/tag metadata is read for OGG/Opus/AMR only so far",
        "media.metadata_not_checked",
    ),
    "media.pyav_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not read (PyAV is not installed)",
        "media.pyav_missing",
    ),
    "media.no_audio_stream": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No audio stream found",
        "media.no_audio_stream",
    ),
    "media.metadata_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be read: {detail}",
        "media.metadata_failed",
    ),
    # -- plist ------------------------------------------------------------
    "plist.parse_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "plist.parse_failed"),
    "plist.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "plist (parse failed)",
        "plist.format_parse_failed",
    ),
    "plist.format_nska_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "binary (NSKeyedArchiver — deserialization failed)",
        "plist.format_nska_failed",
    ),
    "plist.nska_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "NSKeyedArchiver deserialization failed, so the tree shows the archive's "
        "undecoded object table: {detail}",
        "plist.nska_failed",
    ),
    "plist.nska_failed_text": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "NSKeyedArchiver deserialization failed, so below is the archive's "
        "undecoded object table: {detail}",
        "plist.nska_failed_text",
    ),
    "plist.format_nska_xml": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "XML (NSKeyedArchiver — not resolved)",
        "plist.format_nska_xml",
    ),
    "plist.format_nska_xml_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "XML (NSKeyedArchiver — deserialization failed)",
        "plist.format_nska_xml_failed",
    ),
    "plist.nska_dates_kept": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} (NS.time is not a representable date, so the NSDate is shown as stored)",
        "plist.nska_dates_kept",
    ),
    "plist.embedded_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not decoded: the bytes start like a plist but can't be read as one: {detail}",
        "plist.embedded_failed",
    ),
    "plist.embedded_nska_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "NSKeyedArchiver deserialization failed: {detail}. Inspect BLOB on the bytes "
        "shows the archive as stored",
        "plist.embedded_nska_failed",
    ),
    "plist.embedded_nska_missing_refs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: {count:,} reference(s) point past the end of $objects. Inspect "
        "BLOB on the bytes shows the archive as stored",
        "plist.embedded_nska_missing_refs",
    ),
    "plist.embedded_nska_cycle": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: an object reaches itself through its references (a cycle). "
        "Inspect BLOB on the bytes shows the archive as stored",
        "plist.embedded_nska_cycle",
    ),
    "plist.nska_missing_refs_text": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: {count:,} reference(s) point past the end of $objects, "
        "so below is the archive's undecoded object table",
        "plist.nska_missing_refs_text",
    ),
    "plist.nska_cycle_text": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: an object reaches itself through its references (a cycle), "
        "so below is the archive's undecoded object table",
        "plist.nska_cycle_text",
    ),
    "plist.nska_shared": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} (plus {classes:,} class definitions)",
        "plist.nska_shared",
    ),
    "plist.format_nska_unresolved": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "binary (NSKeyedArchiver — not resolved)",
        "plist.format_nska_unresolved",
    ),
    "plist.nska_missing_refs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: {count:,} reference(s) point past the end of $objects, "
        "so the tree shows the archive's undecoded object table",
        "plist.nska_missing_refs",
    ),
    "plist.nska_cycle": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not resolved: an object reaches itself through its references (a cycle), "
        "so the tree shows the archive's undecoded object table",
        "plist.nska_cycle",
    ),
    "plist.nska_root_none": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "none ($top has no root key)",
        "plist.nska_root_none",
    ),
    "plist.nska_root_plain": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "none (root is a plain {type} value)",
        "plist.nska_root_plain",
    ),
    "plist.nska_root_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unknown (root or its class points past the end of $objects)",
        "plist.nska_root_missing",
    ),
    "plist.nska_root_no_classname": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unknown (the root object's class definition has no $classname)",
        "plist.nska_root_no_classname",
    ),
    "plist.nska_top_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "none ($top is empty)",
        "plist.nska_top_empty",
    ),
    "plist.nska_no_graph": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not counted: $objects is not a list or $top is not a dictionary",
        "plist.nska_no_graph",
    ),
    # -- XML --------------------------------------------------------------
    "xml.syntax_error": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not well-formed XML: {detail}. The tree shows only an excerpt around the "
        "error position; full content: Open as → Text / Hex",
        "xml.syntax_error",
    ),
    "xml.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "XML (parse error)",
        "xml.format_parse_failed",
    ),
    # -- ABX (Android Binary XML) -----------------------------------------
    "abx.truncated": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "TRUNCATED: decode error at offset {offset} (0x{offset:x}): {detail} — "
        "{remaining} of {total} bytes not decoded",
        "abx.truncated",
    ),
    "abx.no_magic": QT_TRANSLATE_NOOP("ParseIssue", "Missing ABX magic header", "abx.no_magic"),
    "abx.empty_start_tag": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Empty start tag name",
        "abx.empty_start_tag",
    ),
    "abx.unsupported_token": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unsupported {token} token encountered (rare/unverified format)",
        "abx.unsupported_token",
    ),
    "abx.dangling_attribute": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Dangling attribute token",
        "abx.dangling_attribute",
    ),
    "abx.unknown_token": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unknown token: {token}",
        "abx.unknown_token",
    ),
    "abx.control_chars": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Raw XML-illegal control character(s) found in decoded value(s); "
        "re-encoded as \\xHH to keep the XML well-formed",
        "abx.control_chars",
    ),
    "abx.multiple_roots": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Multiple root elements ({count}) found; wrapped in synthetic <abx-root> "
        "for well-formed XML",
        "abx.multiple_roots",
    ),
    "abx.xml_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "abx.xml_failed"),
    "abx.xml_failed_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "XML reconstruction failed; see right pane",
        "abx.xml_failed_hint",
    ),
    "abx.parse_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "abx.parse_failed"),
    "abx.parse_failed_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "File may be a newer ABX version",
        "abx.parse_failed_hint",
    ),
    "abx.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ABX (parse error)",
        "abx.format_parse_failed",
    ),
    # -- Protobuf (schema-less) --------------------------------------------
    "protobuf.truncated_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated varint key",
        "protobuf.truncated_key",
    ),
    "protobuf.truncated_varint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated varint value",
        "protobuf.truncated_varint",
    ),
    "protobuf.truncated_fixed64": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated 64-bit value",
        "protobuf.truncated_fixed64",
    ),
    "protobuf.truncated_fixed32": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated 32-bit value",
        "protobuf.truncated_fixed32",
    ),
    "protobuf.truncated_length": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated length-delimited size",
        "protobuf.truncated_length",
    ),
    "protobuf.truncated_payload": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated length-delimited payload",
        "protobuf.truncated_payload",
    ),
    "protobuf.truncated_group": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Truncated group field {field}",
        "protobuf.truncated_group",
    ),
    "protobuf.unexpected_end_group": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unexpected end-group tag for field {field}",
        "protobuf.unexpected_end_group",
    ),
    "protobuf.unknown_wire_type": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unknown wire type: {wire_type}",
        "protobuf.unknown_wire_type",
    ),
    "protobuf.decode_error": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Decode error: {detail}",
        "protobuf.decode_error",
    ),
    "protobuf.depth_limit": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} length-delimited field(s) at nesting depth {limit} were not tried "
        "as nested messages (depth limit, the protobuf libraries' default); shown "
        "as string/bytes",
        "protobuf.depth_limit",
    ),
    "protobuf.ambiguous_payloads": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} length-delimited field(s) decode both as a nested message and as "
        "UTF-8 text; wire type 2 doesn't record which it is. Both readings are shown "
        "as candidates (heuristic), neither as the field's value",
        "protobuf.ambiguous_payloads",
    ),
    # -- FlatBuffers (schema-less) ----------------------------------------
    "flatbuffers.no_root": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not read as a FlatBuffer: no root layout validates ({reasons})",
        "flatbuffers.no_root",
    ),
    "flatbuffers.root_layout": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{layout} buffer (the other root layout doesn't validate)",
        "flatbuffers.root_layout",
    ),
    "flatbuffers.root_both_layouts": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Both root layouts validate (plain and size-prefixed); the bytes don't record "
        "which one was written. Both are shown",
        "flatbuffers.root_both_layouts",
    ),
    "flatbuffers.layout_plain": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "plain",
        "flatbuffers.layout_plain",
    ),
    "flatbuffers.layout_size_prefixed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "size-prefixed",
        "flatbuffers.layout_size_prefixed",
    ),
    "flatbuffers.layout_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{layout}: {reason}",
        "flatbuffers.layout_failed",
    ),
    "flatbuffers.widths_heuristic": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "A field's width and type are not recorded without a schema: each width is "
        "inferred from the gap to the next stored slot (heuristic; padding makes it "
        "ambiguous), every width that fits is offered. Vectors are read with 1-, 2-, 4- "
        "and 8-byte elements and as offsets to strings or tables; elements of other "
        "sizes (structs) aren't listed as readings",
        "flatbuffers.widths_heuristic",
    ),
    "flatbuffers.ambiguous_fields": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} field(s) or vector(s) have more than one structurally consistent "
        "reading. All are shown as candidates (heuristic), none as the value",
        "flatbuffers.ambiguous_fields",
    ),
    "flatbuffers.cycles": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} offset(s) lead back into a table or vector that contains them; "
        "shown as a cycle, not followed again",
        "flatbuffers.cycles",
    ),
    "flatbuffers.unreferenced": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{bytes:,} B in {ranges:,} range(s) not covered by any structure or reading "
        "(padding, or remnants of earlier data); listed under \"unreferenced bytes\"",
        "flatbuffers.unreferenced",
    ),
    "flatbuffers.too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{size:,} B is too short for a root offset and a table",
        "flatbuffers.too_short",
    ),
    "flatbuffers.prefix_too_large": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the size prefix ({size:,} B) is larger than the {available:,} B after it",
        "flatbuffers.prefix_too_large",
    ),
    "flatbuffers.root_offset_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "root offset {offset:,} is 0 or negative",
        "flatbuffers.root_offset_invalid",
    ),
    "flatbuffers.root_out_of_bounds": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the root table at {table:#x} lies outside the {size:,}-byte buffer",
        "flatbuffers.root_out_of_bounds",
    ),
    "flatbuffers.table_unaligned": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the table at {table:#x} isn't 4-byte aligned",
        "flatbuffers.table_unaligned",
    ),
    "flatbuffers.table_out_of_bounds": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the table at {table:#x} lies outside the buffer",
        "flatbuffers.table_out_of_bounds",
    ),
    "flatbuffers.vtable_out_of_bounds": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the vtable of the table at {table:#x} ({vtable:#x}) lies outside the buffer",
        "flatbuffers.vtable_out_of_bounds",
    ),
    "flatbuffers.vtable_unaligned": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the vtable of the table at {table:#x} ({vtable:#x}) isn't 2-byte aligned",
        "flatbuffers.vtable_unaligned",
    ),
    "flatbuffers.vtable_size_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the vtable at {vtable:#x} states {size} B (must be even and at least 4)",
        "flatbuffers.vtable_size_invalid",
    ),
    "flatbuffers.table_inline_out_of_bounds": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the table at {table:#x} states {size} B of inline data, which doesn't fit the buffer",
        "flatbuffers.table_inline_out_of_bounds",
    ),
    "flatbuffers.slot_outside_table": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "slot {slot} of the table at {table:#x} points to offset {offset}, outside its "
        "{size} B of inline data",
        "flatbuffers.slot_outside_table",
    ),
    # -- FlatBuffers schema -------------------------------------------------
    "flatbuffers.schema.unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The schema file couldn't be read: {detail}",
        "flatbuffers.schema.unreadable",
    ),
    "flatbuffers.schema.not_bfbs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a binary schema: bytes 4-7 aren't the BFBS identifier",
        "flatbuffers.schema.not_bfbs",
    ),
    "flatbuffers.schema.bfbs_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The binary schema is damaged or not a reflection schema: {detail}",
        "flatbuffers.schema.bfbs_invalid",
    ),
    "flatbuffers.schema.no_tables": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The schema declares no table that could be a buffer's root",
        "flatbuffers.schema.no_tables",
    ),
    "flatbuffers.schema.flatc_no_platform": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "A .fbs schema needs flatc, and Crush bundles none for {platform}; load a "
        ".bfbs instead (flatc -b --schema)",
        "flatbuffers.schema.flatc_no_platform",
    ),
    "flatbuffers.schema.flatc_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "A .fbs schema needs the bundled flatc, which isn't there ({path}); when "
        "running from source, run scripts/download_flatc_binaries.py, or load a .bfbs",
        "flatbuffers.schema.flatc_missing",
    ),
    "flatbuffers.schema.flatc_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "flatc couldn't be started: {detail}",
        "flatbuffers.schema.flatc_failed",
    ),
    "flatbuffers.schema.fbs_compile_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "flatc couldn't compile the schema (exit code {code}): {detail}",
        "flatbuffers.schema.fbs_compile_failed",
    ),
    "flatbuffers.schema.identifier_differs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "bytes 4-7 are \"{stored}\", not the schema's file_identifier \"{expected}\" "
        "(the identifier is optional; the bytes may also be other data)",
        "flatbuffers.schema.identifier_differs",
    ),
    "flatbuffers.schema.cycle": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the offset leads back to the table at {offset:#x}, which contains it (cycle); "
        "not followed again",
        "flatbuffers.schema.cycle",
    ),
    "flatbuffers.schema.slot_not_in_schema": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "slot {slot} is stored (at {offset:#x}) but the schema has no field for it; its "
        "width isn't known, the {gap} B up to the next stored slot are shown",
        "flatbuffers.schema.slot_not_in_schema",
    ),
    "flatbuffers.schema.required_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{field} is required by the schema but not stored",
        "flatbuffers.schema.required_missing",
    ),
    "flatbuffers.schema.out_of_bounds": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{size} B at {offset:#x} lie outside the buffer",
        "flatbuffers.schema.out_of_bounds",
    ),
    "flatbuffers.schema.offset_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the offset at {offset:#x} is 0, negative or points outside the buffer",
        "flatbuffers.schema.offset_invalid",
    ),
    "flatbuffers.schema.type_unsupported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "type {type} isn't decoded here",
        "flatbuffers.schema.type_unsupported",
    ),
    "flatbuffers.schema.flags_undeclared": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "bits {bits:#x} are set but not declared in {enum}",
        "flatbuffers.schema.flags_undeclared",
    ),
    "flatbuffers.schema.enum_undeclared": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{value} is not a value {enum} declares (if {enum} is a bit_flags enum, a "
        ".bfbs written without --bfbs-builtins doesn't record that, and a "
        "combination of flags shows here too)",
        "flatbuffers.schema.enum_undeclared",
    ),
    "flatbuffers.schema.union_member_undeclared": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "union type {value} is not a member {enum} declares",
        "flatbuffers.schema.union_member_undeclared",
    ),
    "flatbuffers.schema.string_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the string at {offset:#x} doesn't fit the buffer or lacks its 0 terminator",
        "flatbuffers.schema.string_invalid",
    ),
    "flatbuffers.schema.string_not_utf8": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the string isn't valid UTF-8 (first invalid byte at {offset:#x}); its bytes are shown",
        "flatbuffers.schema.string_not_utf8",
    ),
    "flatbuffers.schema.vector_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the vector at {offset:#x} doesn't fit the buffer",
        "flatbuffers.schema.vector_invalid",
    ),
    "flatbuffers.schema.flexbuffer_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "declared as FlexBuffers content, which isn't decoded; its bytes are shown",
        "flatbuffers.schema.flexbuffer_not_decoded",
    ),
    "flatbuffers.schema.union_type_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the union's type field ({field}_type) isn't stored, so its member is unknown",
        "flatbuffers.schema.union_type_missing",
    ),
    "flatbuffers.schema.nested_type_unknown": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "declared as a nested FlatBuffer of {type}, which the schema doesn't define as a table",
        "flatbuffers.schema.nested_type_unknown",
    ),
    "flatbuffers.schema.nested_no_root": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "declared as a nested FlatBuffer, but no root layout validates ({reasons})",
        "flatbuffers.schema.nested_no_root",
    ),
    "flatbuffers.schema.mismatches": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} field(s) disagree with the schema (marked on each field)",
        "flatbuffers.schema.mismatches",
    ),
    # -- Chromium Disk Cache ----------------------------------------------
    "chromium_cache.file_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be read: {detail}",
        "chromium_cache.file_unreadable",
    ),
    "chromium_cache.files_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} file(s) couldn't be read; see Read problems in the Overview",
        "chromium_cache.files_unreadable",
    ),
    "chromium_cache.file_not_recognised": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a file of the cache's format (no Simple or Blockfile magic, not addressed by an entry)",
        "chromium_cache.file_not_recognised",
    ),
    "chromium_cache.file_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} is addressed by the cache but not in the folder",
        "chromium_cache.file_missing",
    ),
    "chromium_cache.file_too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "File too short for its header ({size:,} B)",
        "chromium_cache.file_too_short",
    ),
    "chromium_cache.both_formats": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The folder holds files of both cache formats (Simple and Blockfile); both are read",
        "chromium_cache.both_formats",
    ),
    "chromium_cache.second_index": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "A further index file ({name}) wasn't used: one index is read per format",
        "chromium_cache.second_index",
    ),
    "chromium_cache.no_entries": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No entries: the folder holds no entry file, and the index reaches no entry record",
        "chromium_cache.no_entries",
    ),
    "chromium_cache.no_orphans_simple": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "None found: every hash the index lists has an entry file here (or there is no index)",
        "chromium_cache.no_orphans_simple",
    ),
    "chromium_cache.no_orphans_blockfile": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "None found: no block the allocation bitmaps mark free holds an entry record whose stored "
        "key hash matches its key",
        "chromium_cache.no_orphans_blockfile",
    ),
    "chromium_cache.entry_alone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Entry file opened on its own: the cache's other files of this entry, its index record "
        "and the cache kind from the folder aren't read -- open the cache folder for those",
        "chromium_cache.entry_alone",
    ),
    "chromium_cache.index_alone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Index opened on its own: its records are listed, the entry files aren't checked -- "
        "open the cache folder for those",
        "chromium_cache.index_alone",
    ),
    "chromium_cache.marker_alone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Backend marker of a Simple cache (holds only magic and version) -- open the cache folder",
        "chromium_cache.marker_alone",
    ),
    "chromium_cache.version_unexpected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Version {version}, Chromium writes version {expected}; read with that version's layout",
        "chromium_cache.version_unexpected",
    ),
    "chromium_cache.fake_index_version": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Backend marker version {version}: outside the versions Chromium opens (8 and 9)",
        "chromium_cache.fake_index_version",
    ),
    "chromium_cache.key_past_end": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key length {length:,} reaches past the file's end ({size:,} B); the entry isn't read",
        "chromium_cache.key_past_end",
    ),
    "chromium_cache.header_and_key_only": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The file holds only the header and the key (version {version}): no EOF record, no streams",
        "chromium_cache.header_and_key_only",
    ),
    "chromium_cache.eof_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No EOF record at the file's end: the streams' sizes aren't known, the streams aren't read",
        "chromium_cache.eof_missing",
    ),
    "chromium_cache.eof_magic_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Final magic doesn't match",
        "chromium_cache.eof_magic_wrong",
    ),
    "chromium_cache.stream1_eof_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No EOF record for stream 1 where stream 0's size ({stream0:,} B) puts it; the streams "
        "aren't read",
        "chromium_cache.stream1_eof_missing",
    ),
    "chromium_cache.key_sha256_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The stored SHA-256 of the key doesn't match the key in the header",
        "chromium_cache.key_sha256_mismatch",
    ),
    "chromium_cache.crc_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "doesn't match (stored {stored})",
        "chromium_cache.crc_mismatch",
    ),
    "chromium_cache.sparse_cut_off": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Sparse range at offset {offset:,} is cut off by the file's end",
        "chromium_cache.sparse_cut_off",
    ),
    "chromium_cache.sparse_magic_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No sparse range header at offset {offset:,}; reading the ranges stopped there",
        "chromium_cache.sparse_magic_wrong",
    ),
    "chromium_cache.name_hash_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "File name {name} doesn't carry the hash of the key the file holds",
        "chromium_cache.name_hash_mismatch",
    ),
    "chromium_cache.duplicate_role": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} holds the same key and the same kind of file as another file of this entry; "
        "it is listed in the Overview, not read into the entry",
        "chromium_cache.duplicate_role",
    ),
    "chromium_cache.doomed_simple_file": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Doomed: Chromium renamed the file to todelete_… to delete it",
        "chromium_cache.doomed_simple_file",
    ),
    "chromium_cache.not_in_index": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not listed in the index (index written before the entry, or the entry not yet flushed)",
        "chromium_cache.not_in_index",
    ),
    "chromium_cache.index_crc_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "doesn't match: Chromium discards such an index and rebuilds it from the files; its "
        "records are shown as stored",
        "chromium_cache.index_crc_mismatch",
    ),
    "chromium_cache.index_entry_size_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Record(s) {records}: the packed entry size field doesn't fit in 38 bits -- Chromium "
        "rejects the whole index on reading such a record and rebuilds it from the files; all "
        "records are shown as stored",
        "chromium_cache.index_entry_size_rejected",
    ),
    "chromium_cache.index_record_size_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The packed entry size field doesn't fit in 38 bits: Chromium rejects the whole index "
        "because of this record",
        "chromium_cache.index_record_size_rejected",
    ),
    "chromium_cache.index_in_opened_folder": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The index lies in the opened folder itself, not in an index-dir subfolder: records are "
        "matched to the entry files in this folder by key hash; a record without one is listed "
        "with its entry files not checked, since Chromium keeps them in the folder above "
        "index-dir -- open that cache folder for those",
        "chromium_cache.index_in_opened_folder",
    ),
    "chromium_cache.index_version": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Index version {version}: outside the versions Chromium reads (8 and 9)",
        "chromium_cache.index_version",
    ),
    "chromium_cache.index_field_both": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic: the cache type isn't known from the entries (no HTTP or Code Cache key, no "
        "CacheStorage index.txt), so the index's first record field is shown both ways -- as the "
        "last-used time (most cache types) and as the trailer prefetch size (net::APP_CACHE: "
        "CacheStorage, Service Worker scripts)",
        "chromium_cache.index_field_both",
    ),
    "chromium_cache.pickle_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Too short for a pickle header ({size} B)",
        "chromium_cache.pickle_short",
    ),
    "chromium_cache.pickle_past_end": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Reading {what} ({size:,} B at offset {offset:,}) runs past the pickle's end; read up to there",
        "chromium_cache.pickle_past_end",
    ),
    "chromium_cache.pickle_negative_length": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Negative length for {what} at offset {offset:,}; read up to there",
        "chromium_cache.pickle_negative_length",
    ),
    "chromium_cache.pickle_size_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The pickle's stored payload size ({payload:,} B) isn't the stream's ({size:,} B)",
        "chromium_cache.pickle_size_mismatch",
    ),
    "chromium_cache.response_info_version": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Response info version {version}; Chromium reads version {supported} only",
        "chromium_cache.response_info_version",
    ),
    "chromium_cache.status_line_not_http": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The stored status line doesn't start with HTTP/",
        "chromium_cache.status_line_not_http",
    ),
    "chromium_cache.scts_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} signed certificate timestamp(s) in an earlier layout that isn't decoded; the "
        "fields after them aren't read",
        "chromium_cache.scts_not_decoded",
    ),
    "chromium_cache.vary_earlier_layout": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Earlier layout: the 16-byte MD5 digest without a hash type",
        "chromium_cache.vary_earlier_layout",
    ),
    "chromium_cache.body_zstd_by_cache": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The cache stored the body zstd-compressed itself (independent of Content-Encoding)",
        "chromium_cache.body_zstd_by_cache",
    ),
    "chromium_cache.code_header_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stream 0 ({size} B) is shorter than the Code Cache header (12 B)",
        "chromium_cache.code_header_short",
    ),
    "chromium_cache.code_header_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stream 0 is {size:,} B, the header's code size calls for {expected:,} B (Chromium "
        "treats such an entry as invalid)",
        "chromium_cache.code_header_size",
    ),
    "chromium_cache.sha_key_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The key isn't the SHA-256 of the entry's data",
        "chromium_cache.sha_key_mismatch",
    ),
    "chromium_cache.proto_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not decodable as {message}: {detail}",
        "chromium_cache.proto_failed",
    ),
    "chromium_cache.proto_missing_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Required fields missing: {fields}",
        "chromium_cache.proto_missing_required",
    ),
    "chromium_cache.proto_unknown_fields": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Fields the schema doesn't define: {numbers}",
        "chromium_cache.proto_unknown_fields",
    ),
    "chromium_cache.cs_index_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "index.txt in the parent folder couldn't be read: {detail}",
        "chromium_cache.cs_index_unreadable",
    ),
    "chromium_cache.cs_index_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "index.txt in the parent folder isn't a CacheStorage index: {detail}",
        "chromium_cache.cs_index_not_decoded",
    ),
    "chromium_cache.cs_index_other_dir": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "index.txt in the parent folder is a CacheStorage index but doesn't name this folder ({name})",
        "chromium_cache.cs_index_other_dir",
    ),
    "chromium_cache.heuristic_reading": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic: the key shows no cache kind; stream 0 is read as {readings} because it is a "
        "complete, valid record of that type",
        "chromium_cache.heuristic_reading",
    ),
    "chromium_cache.content_kind_undetermined": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Content not decoded: the cache kind isn't determined from the key (e.g. GPU/shader "
        "caches); streams shown as stored",
        "chromium_cache.content_kind_undetermined",
    ),
    "chromium_cache.body_v8_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "V8 bytecode – not decoded",
        "chromium_cache.body_v8_not_decoded",
    ),
    "chromium_cache.cs_body_stored_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Body as the page received it: the network stack removes the transfer encoding before "
        "fetch() hands the response over, CacheStorage keeps the response's headers -- the "
        "Content-Encoding header ({coding}) doesn't describe these bytes; not decompressed",
        "chromium_cache.cs_body_stored_decoded",
    ),
    "chromium_cache.heuristic_body_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not decompressed: the HTTP cache stores bodies as transferred, other caches holding a "
        "response info (Service Worker scripts) store them decoded -- which kind this is isn't "
        "known, so the Content-Encoding header ({coding}) may not describe these bytes",
        "chromium_cache.heuristic_body_not_decoded",
    ),
    "chromium_cache.coding_unsupported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Content-Encoding {coding} isn't supported; the body is shown as stored only",
        "chromium_cache.coding_unsupported",
    ),
    "chromium_cache.coding_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The body doesn't decode as the declared Content-Encoding {coding}: {detail}",
        "chromium_cache.coding_failed",
    ),
    "chromium_cache.cache_zstd_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The body the cache stored zstd-compressed doesn't decompress: {detail}",
        "chromium_cache.cache_zstd_failed",
    ),
    "chromium_cache.coding_partial": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Partial: the body doesn't decode completely as the declared Content-Encoding {coding} "
        "({detail}); the derived body holds the {size:,} B decoded before that point (input "
        "{input:,} B)",
        "chromium_cache.coding_partial",
    ),
    "chromium_cache.cache_zstd_partial": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Partial: the body the cache stored zstd-compressed doesn't decompress completely "
        "({detail}); the derived body holds the {size:,} B decompressed before that point "
        "(input {input:,} B)",
        "chromium_cache.cache_zstd_partial",
    ),
    "chromium_cache.coding_partial_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Partial: the body's {input:,} B end before the end of the declared Content-Encoding "
        "{coding} stream; the derived body holds the {size:,} B decoded from them",
        "chromium_cache.coding_partial_short",
    ),
    "chromium_cache.cache_zstd_partial_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Partial: the body the cache stored zstd-compressed ({input:,} B) ends before the end "
        "of its zstd frame; the derived body holds the {size:,} B decompressed from it",
        "chromium_cache.cache_zstd_partial_short",
    ),
    "chromium_cache.coding_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The body's {input:,} B end before the declared Content-Encoding {coding} gives a "
        "single decoded byte; no derived body",
        "chromium_cache.coding_short",
    ),
    "chromium_cache.cache_zstd_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The body the cache stored zstd-compressed ({input:,} B) ends before a single byte "
        "decompresses; no derived body",
        "chromium_cache.cache_zstd_short",
    ),
    "chromium_cache.coding_trailing_ignored": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} B follow the end of the {coding} stream (from offset {offset:,} of its "
        "input): Chromium ignores them, so they aren't in the derived body; RAW holds them",
        "chromium_cache.coding_trailing_ignored",
    ),
    "chromium_cache.body_truncated_flag": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The response info marks this entry TRUNCATED: the download didn't finish, the body "
        "holds only the part received",
        "chromium_cache.body_truncated_flag",
    ),
    "chromium_cache.body_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The entry has a body that couldn't be read: {reason}",
        "chromium_cache.body_unreadable",
    ),
    "chromium_cache.no_body": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No body stored for this entry",
        "chromium_cache.no_body",
    ),
    "chromium_cache.certificate_not_decoded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Certificate not decodable: {detail}",
        "chromium_cache.certificate_not_decoded",
    ),
    "chromium_cache.blockfile_version": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Blockfile version {version} isn't one Chromium writes (2.0, 2.1, 3.0); read with the 3.0 layout",
        "chromium_cache.blockfile_version",
    ),
    "chromium_cache.index_table_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The hash table has {length:,} buckets, the file holds {available:,}; those are read",
        "chromium_cache.index_table_short",
    ),
    "chromium_cache.block_file_number": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The header says block file {stored}, the file is named {name}",
        "chromium_cache.block_file_number",
    ),
    "chromium_cache.block_file_not_addressed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Block file not named data_<number>: the cache's addresses can't point into it",
        "chromium_cache.block_file_not_addressed",
    ),
    "chromium_cache.addr_not_initialized": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Address not initialized",
        "chromium_cache.addr_not_initialized",
    ),
    "chromium_cache.addr_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Invalid address {addr}",
        "chromium_cache.addr_invalid",
    ),
    "chromium_cache.data_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Only {size:,} of {expected:,} B are in the file",
        "chromium_cache.data_short",
    ),
    "chromium_cache.data_exceeds_blocks": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stored size {size:,} B is larger than the address's blocks ({capacity:,} B); the blocks are shown",
        "chromium_cache.data_exceeds_blocks",
    ),
    "chromium_cache.entry_self_hash": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The entry record's self hash doesn't match its bytes",
        "chromium_cache.entry_self_hash",
    ),
    "chromium_cache.rankings_self_hash": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The rankings node's self hash doesn't match its bytes",
        "chromium_cache.rankings_self_hash",
    ),
    "chromium_cache.key_length_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key length {length} isn't valid; no key read",
        "chromium_cache.key_length_invalid",
    ),
    "chromium_cache.key_past_blocks": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Key length {length:,} is longer than the entry's blocks hold ({span:,} B); the key is cut there",
        "chromium_cache.key_past_blocks",
    ),
    "chromium_cache.key_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The key stored outside the entry couldn't be read",
        "chromium_cache.key_unreadable",
    ),
    "chromium_cache.key_hash_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The stored key hash isn't the hash of the key",
        "chromium_cache.key_hash_mismatch",
    ),
    "chromium_cache.state_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Entry state {state} isn't one Chromium defines",
        "chromium_cache.state_invalid",
    ),
    "chromium_cache.entry_dirty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Marked dirty by run {dirty} (the index's current run is {current}): the entry wasn't "
        "closed properly and Chromium would discard it",
        "chromium_cache.entry_dirty",
    ),
    "chromium_cache.chain_loop": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Hash bucket {bucket}: the entry chain loops; followed up to the repeat",
        "chromium_cache.chain_loop",
    ),
    "chromium_cache.chain_bad_addr": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Hash bucket {bucket}: address {addr} doesn't point to an entry record; the chain ends there",
        "chromium_cache.chain_bad_addr",
    ),
    "chromium_cache.list_loop": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LRU list {list} loops; followed up to the repeat",
        "chromium_cache.list_loop",
    ),
    "chromium_cache.list_bad_addr": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LRU list {list}: address {addr} doesn't point to a rankings node; the list ends there",
        "chromium_cache.list_bad_addr",
    ),
    "chromium_cache.carved_key_hash": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic: block {block} of {file} is free in the allocation bitmap and holds an entry "
        "record whose stored key hash is the hash of the key read there",
        "chromium_cache.carved_key_hash",
    ),
    "chromium_cache.carved_self_hash_ok": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "record self hash matches",
        "chromium_cache.carved_self_hash_ok",
    ),
    "chromium_cache.carved_self_hash_bad": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "record self hash doesn't match",
        "chromium_cache.carved_self_hash_bad",
    ),
    "chromium_cache.carved_rankings_back": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "its rankings node points back to it",
        "chromium_cache.carved_rankings_back",
    ),
    "chromium_cache.carved_rankings_not_back": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "no rankings node points back to it (no last-used time)",
        "chromium_cache.carved_rankings_not_back",
    ),
    "chromium_cache.carved_also_listed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the same block is also reached from the index",
        "chromium_cache.carved_also_listed",
    ),
    "chromium_cache.carved_long_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic: block {block} of {file} is free in the allocation bitmap and holds an entry "
        "record whose key, stored outside the record at {addr}, has the stored key hash",
        "chromium_cache.carved_long_key",
    ),
    "chromium_cache.carved_long_key_unread": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Heuristic, weak: block {block} of {file} is free in the allocation bitmap and holds an "
        "entry record whose key is stored outside it at {addr}; that key couldn't be read "
        "({reason}), so the key hash isn't checked",
        "chromium_cache.carved_long_key_unread",
    ),
    "chromium_cache.sparse_child_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not part of the parent's data (Chromium checks a child so before reading it): {reasons}",
        "chromium_cache.sparse_child_rejected",
    ),
    "chromium_cache.sparse_parent_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The parent's sparse header isn't one Chromium opens ({reasons}); no child is used for "
        "the body, every child is listed apart",
        "chromium_cache.sparse_parent_invalid",
    ),
    "chromium_cache.sparse_children_apart": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} sparse child entr(ies) not part of the body: listed apart with why",
        "chromium_cache.sparse_children_apart",
    ),
    "chromium_cache.sparse_last_block_reset": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Sparse child #{child}: its header names block {block} as partly written with length "
        "{length}, outside 0–1,023 -- Chromium resets that to no partly written block, so that "
        "block isn't part of the data",
        "chromium_cache.sparse_last_block_reset",
    ),
    "chromium_cache.sparse_key_id": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "its key doesn't end in a signature and a child number in hex, each after a colon",
        "chromium_cache.sparse_key_id",
    ),
    "chromium_cache.sparse_key_signature": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the signature in its key ({key}) isn't the parent's ({parent}), so Chromium never looks it up",
        "chromium_cache.sparse_key_signature",
    ),
    "chromium_cache.sparse_not_in_map": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the parent's child bitmap doesn't mark child {child}",
        "chromium_cache.sparse_not_in_map",
    ),
    "chromium_cache.sparse_no_child_flag": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the entry isn't flagged CHILD_ENTRY",
        "chromium_cache.sparse_no_child_flag",
    ),
    "chromium_cache.sparse_child_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "its stream 2 ({size:,} B) is shorter than the sparse header and block bitmap ({expected:,} B)",
        "chromium_cache.sparse_child_short",
    ),
    "chromium_cache.sparse_signature": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the signature in its sparse header ({child}) isn't the parent's ({parent})",
        "chromium_cache.sparse_signature",
    ),
    "chromium_cache.sparse_magic": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the magic in its sparse header ({magic}) isn't {expected}",
        "chromium_cache.sparse_magic",
    ),
    "chromium_cache.sparse_no_data": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "its data stream couldn't be read, so its blocks aren't known",
        "chromium_cache.sparse_no_data",
    ),
    "chromium_cache.sparse_parent_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "stream 2 ({size:,} B) is shorter than the sparse header and bitmap ({expected:,} B)",
        "chromium_cache.sparse_parent_short",
    ),
    "chromium_cache.sparse_parent_has_data": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "stream 1 isn't empty",
        "chromium_cache.sparse_parent_has_data",
    ),
    "chromium_cache.sparse_parent_map_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the child bitmap is {size:,} B (at most 8,192 B and a multiple of 4)",
        "chromium_cache.sparse_parent_map_size",
    ),
    "chromium_cache.sparse_parent_key_len": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the header's parent key length ({stored}) isn't the key's ({actual})",
        "chromium_cache.sparse_parent_key_len",
    ),
    "chromium_cache.carved_blocks_reused": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The record's streams point to blocks that may have been reused since it was freed",
        "chromium_cache.carved_blocks_reused",
    ),
    # -- LevelDB ----------------------------------------------------------
    "leveldb.data_files_not_read": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} of {total:,} data files could not be read whole; "
        "Overview → Read problems says why",
        "leveldb.data_files_not_read",
    ),
    "leveldb.smallest_key_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Smallest key is {length} bytes, shorter than the 8-byte sequence/type tag an "
        "internal key ends with, so it isn't a valid internal key; shown as stored",
        "leveldb.smallest_key_short",
    ),
    "leveldb.largest_key_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Largest key is {length} bytes, shorter than the 8-byte sequence/type tag an "
        "internal key ends with, so it isn't a valid internal key; shown as stored",
        "leveldb.largest_key_short",
    ),
    "leveldb.records_checksum": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} record(s) whose stored checksum doesn't match; shown, marked in the "
        "Records tab (LevelDB doesn't apply them)",
        "leveldb.records_checksum",
    ),
    "leveldb.records_checksum_total": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} record(s) whose stored checksum doesn't match; Overview → Read problems "
        "says where",
        "leveldb.records_checksum_total",
    ),
    "leveldb.manifest_checksum": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} edit(s) whose stored checksum doesn't match, read and counted here "
        "(LevelDB doesn't apply them); at offsets {offsets}",
        "leveldb.manifest_checksum",
    ),
    "leveldb.parts_skipped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} damaged part(s) skipped, reading on after each as LevelDB does: {detail}",
        "leveldb.parts_skipped",
    ),
    "leveldb.current_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No CURRENT file: no MANIFEST is taken as the current one, and files have no level",
        "leveldb.current_missing",
    ),
    "leveldb.current_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "CURRENT could not be read ({detail}): no MANIFEST is taken as the current one, "
        "and files have no level",
        "leveldb.current_unreadable",
    ),
    "leveldb.current_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "CURRENT does not name a MANIFEST: no MANIFEST is taken as the current one, "
        "and files have no level",
        "leveldb.current_invalid",
    ),
    "leveldb.current_target_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} is not in the directory: no MANIFEST is taken as the current one, "
        "and files have no level",
        "leveldb.current_target_missing",
    ),
    "leveldb.current_target_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{name} could not be read (Read problems says why): no MANIFEST is taken "
        "as the current one, and files have no level",
        "leveldb.current_target_unreadable",
    ),
    "leveldb.current_no_newline": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Does not end with a line break: LevelDB treats this CURRENT as corrupt and would "
        "not open the database. The MANIFEST it names is still used here for the files' levels",
        "leveldb.current_no_newline",
    ),
    "leveldb.named_by_invalid_current": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named by a CURRENT that LevelDB treats as corrupt (no line break at its end)",
        "leveldb.named_by_invalid_current",
    ),
    "leveldb.rocksdb_format": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "RocksDB (not supported)",
        "leveldb.rocksdb_format",
    ),
    "leveldb.rocksdb_not_read": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "RocksDB database, not read: RocksDB uses LevelDB's file names, but its table, log "
        "and MANIFEST formats differ, and read as LevelDB parts of it would come out wrong",
        "leveldb.rocksdb_not_read",
    ),
    "leveldb.rocksdb_options": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "OPTIONS file naming a RocksDB version (rocksdb_version=)",
        "leveldb.rocksdb_options",
    ),
    "leveldb.rocksdb_table": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table file ending in RocksDB's {kind} magic {magic}",
        "leveldb.rocksdb_table",
    ),
    "leveldb.rocksdb_manifest_tag": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Tag {tag}, which RocksDB writes and LevelDB doesn't define",
        "leveldb.rocksdb_manifest_tag",
    ),
    "leveldb.manifest_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Empty file (0 bytes)",
        "leveldb.manifest_empty",
    ),
    "leveldb.manifest_nothing_shown": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Records no comparator, log or sequence numbers, or files",
        "leveldb.manifest_nothing_shown",
    ),
    "leveldb.manifest_after_current": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Higher-numbered than the MANIFEST named by CURRENT",
        "leveldb.manifest_after_current",
    ),
    "leveldb.read_stopped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Reading stopped after {count:,} records: {detail}",
        "leveldb.read_stopped",
    ),
    "leveldb.manifest_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be parsed: {detail}",
        "leveldb.manifest_failed",
    ),
    "leveldb.manifest_partial": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Read only up to an error: {detail}",
        "leveldb.manifest_partial",
    ),
    "leveldb.file_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be read: {detail}",
        "leveldb.file_unreadable",
    ),
    # -- MMKV -------------------------------------------------------------
    "mmkv.encrypted_error": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This MMKV store is AES-encrypted.",
        "mmkv.encrypted_error",
    ),
    "mmkv.encrypted_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        'Use "Open as -> MMKV (Encrypted)..." and supply the key.',
        "mmkv.encrypted_hint",
    ),
    "mmkv.format_encrypted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "MMKV Key-Value Store (encrypted)",
        "mmkv.format_encrypted",
    ),
    "mmkv.encrypted_yes": QT_TRANSLATE_NOOP("ParseIssue", "yes", "mmkv.encrypted_yes"),
    "mmkv.read_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "mmkv.read_failed"),
    "mmkv.read_failed_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "MMKV store could not be read",
        "mmkv.read_failed_hint",
    ),
    "mmkv.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "MMKV Key-Value Store (parse failed)",
        "mmkv.format_parse_failed",
    ),
    "mmkv.wrong_key": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "mmkv.wrong_key"),
    "mmkv.meta_not_found": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not found (.crc companion missing) — encryption status unverified",
        "mmkv.meta_not_found",
    ),
    "mmkv.meta_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "found, but could not be read ({detail}) — encryption status unverified",
        "mmkv.meta_unreadable",
    ),
    "mmkv.meta_not_found_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not found (.crc companion missing)",
        "mmkv.meta_not_found_short",
    ),
    "mmkv.meta_too_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "found, but only {size} B — too short for the meta layout ({needed} B) — "
        "encryption status unverified",
        "mmkv.meta_too_short",
    ),
    "mmkv.meta_too_short_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "found, but only {size} B — too short for the meta layout ({needed} B)",
        "mmkv.meta_too_short_short",
    ),
    "mmkv.meta_unreadable_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "found, but could not be read ({detail})",
        "mmkv.meta_unreadable_short",
    ),
    "mmkv.encrypted_decrypted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "yes (decrypted)",
        "mmkv.encrypted_decrypted",
    ),
    "mmkv.key_ignored_no_meta": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unverified — a key was supplied but ignored: no .crc meta file was found, "
        "so there is no AES vector to decrypt with and the store was read as plaintext",
        "mmkv.key_ignored_no_meta",
    ),
    "mmkv.key_ignored_bad_meta": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unverified — a key was supplied but ignored: the .crc meta file was {meta}, "
        "so there is no AES vector to decrypt with and the store was read as plaintext",
        "mmkv.key_ignored_bad_meta",
    ),
    "mmkv.key_ignored_zero_vector": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "no — a key was supplied but ignored: the .crc meta file's AES vector is "
        "zero, so the store is not encrypted",
        "mmkv.key_ignored_zero_vector",
    ),
    "mmkv.encrypted_false_positive": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "no — {note}",
        "mmkv.encrypted_false_positive",
    ),
    "mmkv.false_positive_note": QT_TRANSLATE_NOOP(
        "ParseIssue",
        ".crc meta file's vector field is non-zero, which normally flags AES "
        "encryption, but the store read cleanly as plaintext anyway, so that flag "
        "is treated as a false positive here",
        "mmkv.false_positive_note",
    ),
    "mmkv.offsets_unavailable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Entry byte offsets could not be derived; Locate in Hex is unavailable",
        "mmkv.offsets_unavailable",
    ),
    "mmkv.offsets_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Entry byte offsets found for {found:,} of {total:,} entries; Locate in Hex "
        "is unavailable",
        "mmkv.offsets_mismatch",
    ),
    # -- SEGB -------------------------------------------------------------
    "segb.unrecognized": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a recognized SEGB v1/v2 file",
        "segb.unrecognized",
    ),
    "segb.format_unrecognized": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "SEGB (unrecognized)",
        "segb.format_unrecognized",
    ),
    "segb.parse_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "segb.parse_failed"),
    "segb.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "SEGB (parse failed)",
        "segb.format_parse_failed",
    ),
    "segb.record_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Reading stopped at record {index}: {detail}; later records not read",
        "segb.record_failed",
    ),
    "segb.stream_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Reading stopped after {count:,} records: {detail}",
        "segb.stream_failed",
    ),
    "segb.payload_heuristic": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Payload column: schema-less rendering (heuristic), valid UTF-8 shown as text and "
        "64/32-bit fields as double/float. The selected record's payload is shown below "
        "the table with every candidate reading of each field",
        "segb.payload_heuristic",
    ),
    "segb.detail_no_payload": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This record's payload offsets could not be read ({reason}): no payload bytes to decode",
        "segb.detail_no_payload",
    ),
    "segb.detail_payload_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The record states 0 bytes of payload",
        "segb.detail_payload_empty",
    ),
    "segb.detail_payload_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Only {present} of the {stated} bytes the record states for its payload are in the "
        "file; the bytes there are decoded",
        "segb.detail_payload_short",
    ),
    "segb.payload_partial": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} record(s): payload decoded only up to the byte shown in the cell",
        "segb.payload_partial",
    ),
    "segb.payload_stopped_marker": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "[not decoded from byte {offset:,} on]",
        "segb.payload_stopped_marker",
    ),
    "segb.sql_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "SQL view unavailable: the temporary database could not be created: {detail}",
        "segb.sql_failed",
    ),
    "segb.derived_index": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the record's position in the order the reader returned the records",
        "segb.derived_index",
    ),
    "segb.derived_offset_v1": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "file offset of the record's payload, right after its 32-byte record header",
        "segb.derived_offset_v1",
    ),
    "segb.derived_offset_v2": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "file offset of the record's entry, i.e. of its stored CRC",
        "segb.derived_offset_v2",
    ),
    "segb.derived_trailer_offset": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "file offset of the record's trailer entry",
        "segb.derived_trailer_offset",
    ),
    "segb.derived_crc_calc": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "CRC32 that Crush computed over the payload",
        "segb.derived_crc_calc",
    ),
    "segb.derived_crc_passed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "whether CRC Stored equals CRC Calc",
        "segb.derived_crc_passed",
    ),
    "segb.derived_payload_size_v2": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "SEGB v2 stores no payload length; computed from the trailer's entry end offsets",
        "segb.derived_payload_size_v2",
    ),
    # -- Hex fallback -------------------------------------------------------
    "hexfallback.read_error": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "hexfallback.read_error"),
    "hexfallback.not_identified": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not identified (no signature in the format database matched)",
        "hexfallback.not_identified",
    ),
    "hexfallback.identify_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Identification failed: {detail}",
        "hexfallback.identify_failed",
    ),
    "hexfallback.parser_open_as": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Supported — not detected from content; use Open as → {name}",
        "hexfallback.parser_open_as",
    ),
    "hexfallback.parser_source": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Supported as a browsable source — right-click → Open in New Window",
        "hexfallback.parser_source",
    ),
    "hexfallback.parser_folder": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Supported for the whole LevelDB folder — select the folder, not a single file",
        "hexfallback.parser_folder",
    ),
    "hexfallback.parser_folder_chromium_cache": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Part of a Chromium Blockfile cache — open the folder holding index and data_ files, "
        "not a single file",
        "hexfallback.parser_folder_chromium_cache",
    ),
    "hexfallback.parser_logs": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Supported in Multi-Log Studio — right-click → Open in Multi-Log Studio",
        "hexfallback.parser_logs",
    ),
    "hexfallback.parser_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "A parser exists for this format, but this file's content did not match it",
        "hexfallback.parser_mismatch",
    ),
    "hexfallback.parser_none": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not yet supported",
        "hexfallback.parser_none",
    ),
    # -- SQLite page scans (Freelist Recovery, Freeblocks, Unallocated, WAL) --
    "sqlite_scan.file_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The database file could not be read: {detail}",
        "sqlite_scan.file_unreadable",
    ),
    "sqlite_scan.read_stopped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Reading stopped at page {page:,}: {detail}; later pages were not scanned",
        "sqlite_scan.read_stopped",
    ),
    "sqlite_scan.page_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page:,} holds only {size:,} of {page_size:,} bytes (file ends) "
        "and was not scanned",
        "sqlite_scan.page_short",
    ),
    "sqlite_page.cells_skipped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page}: {count:,} of {total:,} cell(s) could not be decoded and are not shown",
        "sqlite_page.cells_skipped",
    ),
    "freelist.header_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page 1 (the database header) could not be read, so the freelist could not be located",
        "freelist.header_unreadable",
    ),
    "freelist.none": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The database header records no freelist pages",
        "freelist.none",
    ),
    "freelist.trunk_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Freelist trunk page {page:,} could not be read; the rest of the chain was not followed",
        "freelist.trunk_unreadable",
    ),
    "freelist.cycle": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The freelist chain returns to page {page:,} (a cycle); stopped there",
        "freelist.cycle",
    ),
    "freelist.over_count": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The freelist chain holds more pages than the {declared:,} the header declares; "
        "stopped there",
        "freelist.over_count",
    ),
    "freelist.leaf_count_clamped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Trunk page {page:,} declares {declared:,} leaf pages, but only {fits:,} fit on "
        "a page; {fits:,} were read",
        "freelist.leaf_count_clamped",
    ),
    "freelist.summary": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{pages:,} freelist page(s) walked ({trunks:,} trunk, {leaves:,} leaf): "
        "{carved:,} still hold table rows, {empty:,} are table-leaf pages without cells, "
        "{not_leaf:,} no longer hold a table-leaf page (zeroed or reused), "
        "{unreadable:,} could not be read",
        "freelist.summary",
    ),
    "freeblock.ptr_outside": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page:,}: the freeblock chain points to offset {offset:,}, outside the page; "
        "stopped there",
        "freeblock.ptr_outside",
    ),
    "freeblock.too_small": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page:,}: freeblock at offset {offset:,} declares {size} B, below the 4-byte "
        "minimum; the chain stopped there",
        "freeblock.too_small",
    ),
    "freeblock.overruns_page": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page:,}: freeblock at offset {offset:,} declares {size:,} B, but only "
        "{available:,} fit on the page; shown up to the page end",
        "freeblock.overruns_page",
    ),
    "unallocated.bad_content_start": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Page {page:,}: the cell content area starts at {start:,}, beyond the page; "
        "its unallocated gap was not read",
        "unallocated.bad_content_start",
    ),
    "sqlite_wal.table_map_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table attribution unavailable: the schema could not be read: {detail}",
        "sqlite_wal.table_map_failed",
    ),
    "sqlite_wal.table_map_no_file": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table attribution incomplete: the database file could not be read ({detail}); "
        "only pages in the -wal file were attributed",
        "sqlite_wal.table_map_no_file",
    ),
    # -- SQLite Strings tab (sqlite_strings.py) ------------------------------
    "strings.file_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The {file} could not be read; its strings are not listed: {detail}",
        "strings.file_unreadable",
    ),
    "realm_strings.header_not_detected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No Realm file header: the strings are listed, but no region is attributed",
        "realm_strings.header_not_detected",
    ),
    "realm_strings.footer_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The file is in streaming form, but its footer doesn't resolve a top reference: "
        "no array is attributed",
        "realm_strings.footer_invalid",
    ),
    "realm_strings.refs_not_followed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} reference(s) lead to no array and were not followed; what they would "
        "reach is listed as not reached",
        "realm_strings.refs_not_followed",
    ),
    "strings.file_empty": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The {file} is empty (0 B)",
        "strings.file_empty",
    ),
    "strings.no_page_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The db file has no valid SQLite header page size; its strings are listed "
        "without page attribution",
        "strings.no_page_size",
    ),
    "strings.wal_no_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The -wal file has no valid WAL header; its strings are listed without frame "
        "attribution",
        "strings.wal_no_header",
    ),
    "strings.journal_no_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The -journal file has no valid journal header ({reason}); its strings are listed "
        "without record attribution",
        "strings.journal_no_header",
    ),
    "strings.child_out_of_range": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{file}: a b-tree points to page {page:,}, outside the {pages:,} pages; "
        "not followed",
        "strings.child_out_of_range",
    ),
    "strings.overflow_chain_stopped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{file}: an overflow chain from page {page:,} leads to page {target:,}, outside the "
        "database or already part of a chain; not followed further, later pages of that "
        "chain are not labelled as overflow",
        "strings.overflow_chain_stopped",
    ),
    "strings.freeblock_chain_stopped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{file}, page {page:,}: the freeblock chain is inconsistent at offset {offset:,}; "
        "later freeblocks on this page are labelled as cell content area",
        "strings.freeblock_chain_stopped",
    ),
    # -- SQLite File Structure tab -------------------------------------------
    "sqlite_structure.page_size_unavailable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "page size unavailable",
        "sqlite_structure.page_size_unavailable",
    ),
    "sqlite_structure.file_unavailable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "file unavailable",
        "sqlite_structure.file_unavailable",
    ),
    "sqlite_structure.no_unallocated": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "none/non-empty bytes not found",
        "sqlite_structure.no_unallocated",
    ),
    "sqlite_structure.page_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "could not be read (read error or file ends)",
        "sqlite_structure.page_unreadable",
    ),
    "sqlite_structure.cells_not_shown": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{problems}",
        "sqlite_structure.cells_not_shown",
    ),
    # -- Realm File Structure tab --------------------------------------------
    "realm_structure.header_not_detected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not detected (possibly encrypted or non-standard)",
        "realm_structure.header_not_detected",
    ),
    "realm_structure.top_unresolved": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unresolved -- no valid active top reference",
        "realm_structure.top_unresolved",
    ),
    "realm_structure.top_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unreadable at offset 0x{offset:x}",
        "realm_structure.top_unreadable",
    ),
    "realm_structure.ref_unresolved": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "unresolved",
        "realm_structure.ref_unresolved",
    ),
    "realm_structure.table_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table reference is invalid or points outside the file",
        "realm_structure.table_ref_invalid",
    ),
    "realm_structure.table_top_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table top array is malformed or unreadable",
        "realm_structure.table_top_unreadable",
    ),
    "realm_structure.no_columns": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "(no columns)",
        "realm_structure.no_columns",
    ),
    "realm_structure.no_cluster_tree_slot": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Table top array is missing its ClusterTree slot",
        "realm_structure.no_cluster_tree_slot",
    ),
    "realm_structure.cluster_tree_ref_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ClusterTree reference is invalid or points outside the file",
        "realm_structure.cluster_tree_ref_invalid",
    ),
    # -- Locate in Hex ----------------------------------------------------------
    "locate.no_range": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No byte range for this cell: {reason}",
        "locate.no_range",
    ),
    "locate.not_recorded": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the decoder recorded none for it",
        "locate.not_recorded",
    ),
    "locate.segb_record_offsets": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the record's offsets could not be read ({detail})",
        "locate.segb_record_offsets",
    ),
    # -- Several notes about one thing ------------------------------------------
    "common.notes": QT_TRANSLATE_NOOP("ParseIssue", "{notes}", "common.notes"),
    # -- Password / key rejections (shown above the retry prompt) ----------------
    "password.zip_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP archive is password-protected: {path}",
        "password.zip_required",
    ),
    "password.zip_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect ZIP archive password",
        "password.zip_wrong",
    ),
    "password.7z_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "7z archive is password-protected: {path}",
        "password.7z_required",
    ),
    "password.7z_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect 7z archive password",
        "password.7z_wrong",
    ),
    "password.ab_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Android backup is password-protected: {path}",
        "password.ab_required",
    ),
    "password.ab_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect Android backup password",
        "password.ab_wrong",
    ),
    "password.ab_padding": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Payload padding invalid after decryption (wrong password?)",
        "password.ab_padding",
    ),
    "password.itunes_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "iTunes backup is password-protected: {path}",
        "password.itunes_required",
    ),
    "password.itunes_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Incorrect backup password",
        "password.itunes_wrong",
    ),
    "password.itunes_padding": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Padding invalid after decryption (wrong password?)",
        "password.itunes_padding",
    ),
    "password.itunes_no_class_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Backup keybag has no usable class key for class {class_num}",
        "password.itunes_no_class_key",
    ),
    "password.image_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Disk image is encrypted: {path} — {detail}",
        "password.image_required",
    ),
    "password.image_wrong": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The password does not open this disk image — {detail}",
        "password.image_wrong",
    ),
    "password.image_key_required": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Disk image is sealed to a certificate and opens with its private key: {path} "
        "— {detail}",
        "password.image_key_required",
    ),
    "password.image_wrong_key": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The private key does not open this disk image — {detail}",
        "password.image_wrong_key",
    ),
    "password.realm_not_hex": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a valid hex key: {detail}",
        "password.realm_not_hex",
    ),
    "password.realm_key_length": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Realm encryption key must be {size} bytes ({hex_chars} hex characters) — "
        "got {got} bytes",
        "password.realm_key_length",
    ),
    "password.realm_key_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Realm encryption key must be {size} bytes",
        "password.realm_key_size",
    ),
    "password.realm_hmac": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "HMAC mismatch decrypting Realm file (wrong key, or the file is corrupt)",
        "password.realm_hmac",
    ),
    "vfs.ab_unsupported_encryption": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Unsupported Android backup encryption: {value}",
        "vfs.ab_unsupported_encryption",
    ),
    "vfs.ab_not_backup": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not an Android backup: {path}",
        "vfs.ab_not_backup",
    ),
    # -- Opening a source (status bar notes) ---------------------------------------
    "vfs.named_but_not": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named {suffix}, but no {label} signature found",
        "vfs.named_but_not",
    ),
    "vfs.contains_zip_after": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Contains a ZIP archive after {leading:,} leading bytes — right-click → "
        "Open in New Window to browse it",
        "vfs.contains_zip_after",
    ),
    "vfs.zip_opened_after": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP archive opened after {leading:,} leading bytes",
        "vfs.zip_opened_after",
    ),
    "vfs.ufdr_as_zip": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "UFDR layout found, but not opened as UFDR ({detail}); shown as plain ZIP",
        "vfs.ufdr_as_zip",
    ),
    "vfs.zip_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP signature found, but not opened as ZIP — {detail}",
        "vfs.zip_not_opened",
    ),
    "vfs.7z_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "7z signature found, but not opened as 7z — {detail}",
        "vfs.7z_not_opened",
    ),
    "vfs.tar_signature_found": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "TAR signature found",
        "vfs.tar_signature_found",
    ),
    "vfs.compressed_tar_found": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Compressed TAR found",
        "vfs.compressed_tar_found",
    ),
    "vfs.named_as": QT_TRANSLATE_NOOP("ParseIssue", "Named {suffix}", "vfs.named_as"),
    "vfs.tar_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{what}, but not opened as TAR — {detail}",
        "vfs.tar_not_opened",
    ),
    "vfs.not_disk_image": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not opened as a disk image — {detail}",
        "vfs.not_disk_image",
    ),
    "vfs.disk_image_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Opened as a single file; its {what} suggests a disk image — use "
        "Open Disk Image… to read it as one",
        "vfs.disk_image_hint",
    ),
    "vfs.disk_image_hint_name": QT_TRANSLATE_NOOP(
        "ParseIssue", "name", "vfs.disk_image_hint_name",
    ),
    "vfs.disk_image_hint_acquisition": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "signature of a disk image container (forensic acquisition, Apple disk image or "
        "virtual disk)",
        "vfs.disk_image_hint_acquisition",
    ),
    "vfs.disk_image_hint_container": QT_TRANSLATE_NOOP(
        "ParseIssue", "content ({label} container)", "vfs.disk_image_hint_container",
    ),
    "vfs.disk_image_hint_ad_encrypted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "content (FTK Imager AD-encrypted: a disk image or AD1 logical evidence)",
        "vfs.disk_image_hint_ad_encrypted",
    ),
    "vfs.ad_encrypted_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Opened as a single file: it is encrypted with FTK Imager's AD encryption and holds "
        "a disk image or AD1 logical evidence, which shows once it is opened — use Open "
        "Disk Image… to open it with its password or key",
        "vfs.ad_encrypted_hint",
    ),
    "vfs.disk_image_hint_bundle": QT_TRANSLATE_NOOP(
        "ParseIssue", "folder (a file of the Apple sparse bundle {bundle})",
        "vfs.disk_image_hint_bundle",
    ),
    "vfs.logical_evidence": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Opened as a single file: it is EnCase Lx01 logical evidence, which Crush doesn't "
        "read (L01 and FTK Imager AD1 logical evidence open as sources of their own)",
        "vfs.logical_evidence",
    ),
    "vfs.logical_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Logical evidence (L01/AD1) signature found, but not opened as logical evidence — "
        "{detail}",
        "vfs.logical_not_opened",
    ),
    "vfs.sparse_bundle_folder": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Apple sparse bundle shown as the folder it is stored in (its band files and "
        "bookkeeping) — open it as a disk image, or use Open Disk Image… on any of its "
        "files, to read the disk it holds",
        "vfs.sparse_bundle_folder",
    ),
    "vfs.sparse_bundle_from_member": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{file} is a file of the Apple sparse bundle {bundle}: the whole bundle was opened",
        "vfs.sparse_bundle_from_member",
    ),
    "vfs.aff4_as_zip": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "AFF4 container shown as the ZIP archive it is stored in (its streams, maps and "
        "metadata) — use Open Disk Image… to read the disk it holds",
        "vfs.aff4_as_zip",
    ),
    "vfs.image_container": QT_TRANSLATE_NOOP(
        "ParseIssue", "Read as {detail}", "vfs.image_container",
    ),
    "vfs.acquisition_missing_pages": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} pages of this acquisition are not in its files; they read as the image's "
        "bad-sector marker, not as data from the device",
        "vfs.acquisition_missing_pages",
    ),
    "vfs.acquisition_padded_chunks": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} {unit}(s) of this acquisition read so far hold less data than the bytes "
        "they cover; the reader reads {zeros} zero bytes in their place, so what is "
        "listed or read from them can hold those zeros",
        "vfs.acquisition_padded_chunks",
    ),
    "vfs.atime_platform": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Crush does not prevent access-time updates on this platform; mount the "
        "evidence read-only to prevent them",
        "vfs.atime_platform",
    ),
    "vfs.atime_not_owned": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} file(s) are not owned by the current user, so Crush can't read "
        "them with O_NOATIME: reading them may update their access time (mount the "
        "evidence read-only to prevent this)",
        "vfs.atime_not_owned",
    ),
    # -- Stored timestamps of an entry (Properties: where a time comes from) -----
    "time.zip_dos_central": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP DOS date/time (central directory)",
        "time.zip_dos_central",
    ),
    "time.zip_dos_local": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP DOS date/time (local header)",
        "time.zip_dos_local",
    ),
    "time.zip_extra_central": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP extra field {name} ({id}, central directory)",
        "time.zip_extra_central",
    ),
    "time.zip_extra_local": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "ZIP extra field {name} ({id}, local header)",
        "time.zip_extra_local",
    ),
    "time.zip_extra_short": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the field holds {size} bytes, too few for its layout; no time read from it",
        "time.zip_extra_short",
    ),
    "time.zip_local_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The local header's times were not read: no local file header at offset {offset}",
        "time.zip_local_missing",
    ),
    "time.zip_local_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The local header's times were not read: {detail}",
        "time.zip_local_unreadable",
    ),
    "time.dos_invalid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not a valid date/time; stored words: date {date}, time {time}",
        "time.dos_invalid",
    ),
    "time.ad1_record": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "AD1 \"{name}\" record",
        "time.ad1_record",
    ),
    "time.l01_column": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "L01 entry column \"{name}\"",
        "time.l01_column",
    ),
    "time.fat_entry": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "FAT directory entry",
        "time.fat_entry",
    ),
    "time.exfat_entry": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "exFAT directory entry",
        "time.exfat_entry",
    ),
    "time.gzip_header": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "gzip header MTIME",
        "time.gzip_header",
    ),
    "time.gzip_mtime_zero": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "stored as 0, which the gzip format (RFC 1952) defines as no time stamp",
        "time.gzip_mtime_zero",
    ),
    "time.offset_not_applied": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "UTC offset {offset} stored beside it, not applied",
        "time.offset_not_applied",
    ),
    # -- Entries in a browsed source (Properties: Entry status) --------------------
    "entry.duplicate": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Stored {count} times in this archive under this name; this is occurrence "
        "{k} of {count} (archive order)",
        "entry.duplicate",
    ),
    "entry.symlink_target": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link → {target} (content shown is the target)",
        "entry.symlink_target",
    ),
    "entry.symlink_stored_target": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link (content shown is the stored link target)",
        "entry.symlink_stored_target",
    ),
    "entry.symlink_folder": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link → {target} (not followed; content shown is the target)",
        "entry.symlink_folder",
    ),
    "entry.symlink_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link (not followed); its target could not be read: {detail}",
        "entry.symlink_unreadable",
    ),
    "entry.symlink_no_target": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link (the backup records no target for it)",
        "entry.symlink_no_target",
    ),
    "entry.symlink_raw": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Symbolic link — its target/content is not decoded by the filesystem reader",
        "entry.symlink_raw",
    ),
    "entry.hard_link": QT_TRANSLATE_NOOP("ParseIssue", "Hard link to {target}", "entry.hard_link"),
    "entry.stream": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named stream of {owner} — not part of its size or content",
        "entry.stream",
    ),
    "entry.stream_front_hole": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named stream of {owner} — read from its first stored cluster: the {skipped} bytes "
        "of hole before it (recorded size {recorded} bytes) are not included, so an offset "
        "here is {skipped} bytes less than in the stream",
        "entry.stream_front_hole",
    ),
    "entry.stream_nothing_stored": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named stream of {owner} — recorded size {recorded} bytes, all of it hole: nothing "
        "is stored",
        "entry.stream_nothing_stored",
    ),
    "entry.stream_no_reader": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Named stream of {owner} — recorded size {recorded} bytes; its content is not read "
        "(the filesystem reader lists it but has no reader for it)",
        "entry.stream_no_reader",
    ),
    "entry.streams_unlisted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The named streams of this entry could not be listed — {detail}",
        "entry.streams_unlisted",
    ),
    "entry.special_stored": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Special file ({kind}) — no content stored",
        "entry.special_stored",
    ),
    "entry.special_not_read": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Special file ({kind}) — no content is read",
        "entry.special_not_read",
    ),
    "entry.special_raw": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Special file (mode {mode}) — no content",
        "entry.special_raw",
    ),
    "entry.unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Could not be read: {detail}",
        "entry.unreadable",
    ),
    "entry.folder_unlisted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Folder could not be listed: {detail}",
        "entry.folder_unlisted",
    ),
    "entry.no_backup_content": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "No content stored in the backup for this entry (fileID {file_id})",
        "entry.no_backup_content",
    ),
    "entry.file_key_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Encrypted in the backup, but its file key could not be read ({detail}); "
        "the content is shown as stored (ciphertext)",
        "entry.file_key_unreadable",
    ),
    "entry.logical_own_data": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The data the entry {name} stores itself; the entry also holds the entries "
        "beside this one, so it is shown as a folder",
        "entry.logical_own_data",
    ),
    "entry.name_has_slash": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The stored name contains \"/\", shown here as \"∕\" (a path separator can't "
        "be part of a name in the tree)",
        "entry.name_has_slash",
    ),
    "entry.ad1_deleted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Marked as deleted in the AD1 (item type 2, which FTK Imager lists as deleted)",
        "entry.ad1_deleted",
    ),
    "entry.l01_sparse_duplicate": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Marked sparse in the L01: its content is read from the data stored at its "
        "duplicate data offset",
        "entry.l01_sparse_duplicate",
    ),
    "entry.l01_sparse_byte": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Marked sparse in the L01: its content is one stored byte, repeated to its size",
        "entry.l01_sparse_byte",
    ),
    "entry.raw_depth": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not listed: nested deeper than {limit} directories (guard against a "
        "directory loop in a damaged filesystem)",
        "entry.raw_depth",
    ),
    "entry.raw_loop": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not listed again: this directory was already reached by another path "
        "(a directory loop in the filesystem structure)",
        "entry.raw_loop",
    ),
    "entry.raw_unlisted": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Directory could not be listed: {detail}",
        "entry.raw_unlisted",
    ),
    "entry.raw_entry_unreadable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Entry metadata could not be read: {detail}",
        "entry.raw_entry_unreadable",
    ),
    "entry.raw_deleted_enum_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Deleted files could not be enumerated: {detail}",
        "entry.raw_deleted_enum_failed",
    ),
    "entry.recovered_intact": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "recovered (content intact)",
        "entry.recovered_intact",
    ),
    "entry.recovered_assumed_contiguous": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "recovered on an assumption: the cluster chain is gone, so the content is read "
        "as one run from the first cluster, which the volume cannot confirm; a file "
        "that was fragmented reads with other data in it",
        "entry.recovered_assumed_contiguous",
    ),
    "entry.not_recoverable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not recoverable: {detail}",
        "entry.not_recoverable",
    ),
    "entry.recovery_note": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "recovery note: {detail}",
        "entry.recovery_note",
    ),
    "entry.original_folder_gone": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "(folder no longer present)",
        "entry.original_folder_gone",
    ),
    "entry.raw_volume_note": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Filesystem reader note: {detail}",
        "entry.raw_volume_note",
    ),
    "entry.raw_no_reader": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "no reader for this content — showing raw bytes",
        "entry.raw_no_reader",
    ),
    "entry.raw_lvm_run": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "volume bytes {start}–{end} at image offset {offset}",
        "entry.raw_lvm_run",
    ),
    "entry.raw_lvm_stripes": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "volume bytes {start}–{end} striped in {stripe}-byte stripes across image "
        "offsets {offsets}",
        "entry.raw_lvm_stripes",
    ),
    "entry.raw_lvm_copy_read": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{kind} volume: read from its copy {copy} only; whether its other copies hold "
        "the same data is not checked",
        "entry.raw_lvm_copy_read",
    ),
    "entry.raw_lvm_raid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{raid} volume in {stripe}-byte stripes over {images} image volume(s), {missing} "
        "of them not read",
        "entry.raw_lvm_raid",
    ),
    "entry.raw_lvm_raid_image_run": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "image volume {image}: its bytes {start}–{end} at image offset(s) {offsets}",
        "entry.raw_lvm_raid_image_run",
    ),
    "entry.raw_lvm_raid_image_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "image volume {image}: not read (missing, or marked as not to be read); its bytes "
        "are read from another copy or rebuilt from parity",
        "entry.raw_lvm_raid_image_missing",
    ),
    "entry.raw_volume_damage": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} damaged structure(s) recorded and skipped while the volume was listed, "
        "first: {first}",
        "entry.raw_volume_damage",
    ),
    "entry.raw_volume_damage_listed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count} file(s) recorded as damage while the volume was listed, and listed as "
        "stored, first: {first}",
        "entry.raw_volume_damage_listed",
    ),
    "entry.raw_volume_past_end": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{bytes} bytes of this volume lie past the end of the image: the image holds "
        "only part of it",
        "entry.raw_volume_past_end",
    ),
    "entry.raw_luks_argon2": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "keyslot {slot}: {type}, {memory} MiB of memory, {time} iteration(s), "
        "{cpus} thread(s)",
        "entry.raw_luks_argon2",
    ),
    "entry.raw_luks_pbkdf2": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "keyslot {slot}: PBKDF2-{hash}, {iterations} iterations",
        "entry.raw_luks_pbkdf2",
    ),
    "entry.format_not_singled_out": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not determined — the signature bytes don't single out one of: "
        "{candidates}; no format knowledge shown",
        "entry.format_not_singled_out",
    ),
    # -- UFDR ------------------------------------------------------------------------
    "ufdr.not_recorded": QT_TRANSLATE_NOOP("ParseIssue", "(not recorded)", "ufdr.not_recorded"),
    "logical.not_recorded": QT_TRANSLATE_NOOP(
        "ParseIssue", "(not recorded)", "logical.not_recorded",
    ),
    "ufdr.not_located": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not located in container",
        "ufdr.not_located",
    ),
    "ufdr.not_readable": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a readable UFDR container -- if this was exported as multiple parts, "
        "rejoin them first; segmented UFDR exports aren't supported yet.",
        "ufdr.not_readable",
    ),
    "ufdr.missing_members": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not a UFDR container -- missing {members}",
        "ufdr.missing_members",
    ),
    "ufdr.no_space": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not enough space in the temp directory to extract the UFDR's database "
        "({needed:,} bytes needed, {free:,} available at {location})",
        "ufdr.no_space",
    ),
    "ufdr.no_device_schema": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "UFDR database has no per-device schema -- unrecognised layout",
        "ufdr.no_device_schema",
    ),
    "ufdr.missing_columns": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "UFDR database's {tag} table is missing expected column(s): {columns}",
        "ufdr.missing_columns",
    ),
    "ufdr.no_table": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "UFDR database has no {tag} table in schema {schema}",
        "ufdr.no_table",
    ),
    "ufdr.content_not_located": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Content not located in UFDR container: {path}",
        "ufdr.content_not_located",
    ),
    "ufdr.path_collision": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Its path collides with a {other} of the same name; shown under this name instead",
        "ufdr.path_collision",
    ),
    "ufdr.device_id_mismatch": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "database.json names device {device}, which the database dump doesn't contain; "
        "the tree shows the device(s) the dump holds: {found}",
        "ufdr.device_id_mismatch",
    ),
    "ufdr.other_directory": QT_TRANSLATE_NOOP("ParseIssue", "directory", "ufdr.other_directory"),
    "ufdr.other_file": QT_TRANSLATE_NOOP("ParseIssue", "file", "ufdr.other_file"),
    "ufdr.rows_skipped": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} Nodes row(s) with an unreadable Type were left out of the tree",
        "ufdr.rows_skipped",
    ),
    "ufdr.duplicate": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Listed {count} times under this path in the UFDR's file catalog; this is "
        "entry {k} of {count} (catalog order)",
        "ufdr.duplicate",
    ),
    "ufdr.rows_other_type": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} Nodes row(s) of Type {type}, which isn't decoded, were left out of the tree",
        "ufdr.rows_other_type",
    ),
    "ufdr.derived_from": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{path} -- an item Cellebrite derived from that file (e.g. decrypted or extracted "
        "from it), not a file in the device's filesystem",
        "ufdr.derived_from",
    ),
    "ufdr.derived_from_not_exported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{path} -- an item Cellebrite derived from that file (e.g. decrypted or extracted "
        "from it), not a file in the device's filesystem; the UFDR doesn't contain "
        "{path} itself",
        "ufdr.derived_from_not_exported",
    ),
    "ufdr.derived_folder": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Holds the items Cellebrite derived from {path} (e.g. decrypted or extracted from "
        "it); not a folder in the device's filesystem",
        "ufdr.derived_folder",
    ),
    "ufdr.derived_folder_not_exported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Holds the items Cellebrite derived from {path} (e.g. decrypted or extracted from "
        "it); not a folder in the device's filesystem. The UFDR doesn't contain {path} "
        "itself",
        "ufdr.derived_folder_not_exported",
    ),
    "ufdr.not_exported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not contained in this UFDR: Cellebrite exported items derived from this file, "
        "not the file. It records only its path and size ({size:,} bytes); no content, "
        "hashes or times",
        "ufdr.not_exported",
    ),
    "ufdr.not_exported_no_size": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not contained in this UFDR: Cellebrite exported items derived from this file, "
        "not the file. It records only its path; no size, content, hashes or times",
        "ufdr.not_exported_no_size",
    ),
    "ufdr.not_exported_content": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not contained in this UFDR: {path} -- Cellebrite exported items derived from "
        "this file, not the file's content",
        "ufdr.not_exported_content",
    ),
    "ufdr.partial_export": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This UFDR holds {in_ufdr:,} of the {extraction:,} files Cellebrite counted in "
        "the extraction: only these were exported into it. Each folder's Properties "
        "show both counts",
        "ufdr.partial_export",
    ),
    "ufdr.files_not_exported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{missing:,} of the {counted:,} files below this folder in the extraction aren't "
        "in this UFDR: Cellebrite didn't export them, and records nothing about them but "
        "this count. They aren't listed",
        "ufdr.files_not_exported",
    ),
    "ufdr.partial_export_folders": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "This UFDR holds only the files Physical Analyzer exported into it, not the whole "
        "extraction. Each folder's Properties show how many files Cellebrite counted there "
        "in the extraction and how many of them this UFDR holds",
        "ufdr.partial_export_folders",
    ),
    # -- UFD / UFDX ------------------------------------------------------------------
    "vfs.ufd_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue", "Looks like a Cellebrite UFD/UFDX but couldn't be read", "vfs.ufd_not_opened",
    ),
    "vfs.itunes_zip_no_space": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Not enough space in the temp directory to extract the iTunes backup "
        "({needed:,} bytes needed, {free:,} available at {location})",
        "vfs.itunes_zip_no_space",
    ),
    "ufd.not_text": QT_TRANSLATE_NOOP(
        "ParseIssue", "Not readable as text (no byte-order mark, not UTF-8)", "ufd.not_text",
    ),
    "ufd.no_sections": QT_TRANSLATE_NOOP("ParseIssue", "No [section] in the file", "ufd.no_sections"),
    "ufd.other_lines": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{count:,} line(s) are neither a [section] nor key=value; shown as written",
        "ufd.other_lines",
    ),
    "ufd.no_dumps": QT_TRANSLATE_NOOP(
        "ParseIssue", "The UFD lists no dumps ([Dumps] is missing or empty)", "ufd.no_dumps",
    ),
    "ufd.dump_file_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The UFD names {file} for this dump; it isn't beside the UFD",
        "ufd.dump_file_missing",
    ),
    "ufd.dump_no_section": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The UFD names {file} for this dump but has no section saying how to read it",
        "ufd.dump_no_section",
    ),
    "ufd.dump_type_unsupported": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Dump type \"{type}\" ({file}) isn't read; only ZIPfolder is supported",
        "ufd.dump_type_unsupported",
    ),
    "ufd.zip_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue", "{file} couldn't be opened as a ZIP", "ufd.zip_not_opened",
    ),
    "ufd.dump_path_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The UFD names folder {path} of {file} for this dump; the ZIP has no such folder",
        "ufd.dump_path_missing",
    ),
    "ufd.dump_folder": QT_TRANSLATE_NOOP(
        "ParseIssue", "Folder {path} of {file}, as the UFD names it", "ufd.dump_folder",
    ),
    "ufd.other_content": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "What {file} holds outside the folders the UFD names for its dumps",
        "ufd.other_content",
    ),
    "vfs.itunes_backup_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "An iTunes backup, opened as one ({password}); the files the ZIP stores for it "
        "are shown when the ZIP is opened as a plain ZIP",
        "vfs.itunes_backup_opened",
    ),
    "ufd.password_from_ufd": QT_TRANSLATE_NOOP(
        "ParseIssue", "with the BackupPassword the UFD records", "ufd.password_from_ufd",
    ),
    "vfs.password_typed": QT_TRANSLATE_NOOP(
        "ParseIssue", "with the password entered", "vfs.password_typed",
    ),
    "vfs.password_none": QT_TRANSLATE_NOOP(
        "ParseIssue", "no password recorded or entered", "vfs.password_none",
    ),
    "vfs.itunes_backup_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Holds an iTunes backup that couldn't be opened as one; its stored files are shown",
        "vfs.itunes_backup_not_opened",
    ),
    "ufd.backup_password_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The BackupPassword the UFD records doesn't open the iTunes backup in its dump",
        "ufd.backup_password_rejected",
    ),
    "ufdx.not_xml": QT_TRANSLATE_NOOP("ParseIssue", "Not well-formed XML", "ufdx.not_xml"),
    "ufdx.not_evidence_collection": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The XML's root is <{root}>, not <EvidenceCollection>",
        "ufdx.not_evidence_collection",
    ),
    "ufdx.no_extractions": QT_TRANSLATE_NOOP(
        "ParseIssue", "The UFDX lists no extractions", "ufdx.no_extractions",
    ),
    "ufdx.extraction": QT_TRANSLATE_NOOP(
        "ParseIssue", "Extraction {path} ({type}), as the UFDX lists it", "ufdx.extraction",
    ),
    "ufdx.extraction_missing": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The UFDX lists extraction {path} ({type}); it isn't there",
        "ufdx.extraction_missing",
    ),
    "ufdx.extraction_not_opened": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "The UFDX lists extraction {path} ({type}); it couldn't be read as a UFD",
        "ufdx.extraction_not_opened",
    ),
    "ufdx.extraction_password_rejected": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "Extraction {path} ({type}): {reason}. One password is entered for the whole UFDX; "
        "if its extractions need different ones, open each extraction's UFD on its own",
        "ufdx.extraction_password_rejected",
    ),
    # -- Timestamp column decoding (cell markers) ------------------------------
    "ts_decode.not_a_number": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not a number",
        "ts_decode.not_a_number",
    ),
    "ts_decode.out_of_range": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "out of range for this format",
        "ts_decode.out_of_range",
    ),
    "ts_decode.not_an_integer": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not an integer (this format packs bit fields)",
        "ts_decode.not_an_integer",
    ),
    "ts_decode.not_bytes": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "neither a BLOB nor hex text",
        "ts_decode.not_bytes",
    ),
    "ts_decode.wrong_length": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "{length} bytes, this format has {expected}",
        "ts_decode.wrong_length",
    ),
    "ts_decode.not_bcd": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not BCD (a nibble above 9)",
        "ts_decode.not_bcd",
    ),
    "ts_decode.invalid_fields": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "date/time fields outside their valid ranges",
        "ts_decode.invalid_fields",
    ),
    "ts_decode.not_a_uuid": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not a UUID",
        "ts_decode.not_a_uuid",
    ),
    "ts_decode.uuid_not_v1": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "not a version 1 UUID",
        "ts_decode.uuid_not_v1",
    ),
    # -- Timestamp decoding as a plain-SQLite expression (ts_sql) -------------
    "ts_sql.fractional_days": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "the value is a fractional day count, which plain SQLite can't convert exactly",
        "ts_sql.fractional_days",
    ),
    "ts_sql.no_hex_to_number": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "plain SQLite has no way to turn hex bytes into numbers",
        "ts_sql.no_hex_to_number",
    ),
}


def _render_param(value: Any, localized: bool = False) -> Any:
    if isinstance(value, ParseIssue):
        return render(value, localized=localized)
    if isinstance(value, CatalogText):
        return value.localized() if localized else value.text
    if isinstance(value, (list, tuple)) and any(isinstance(v, ParseIssue) for v in value):
        return "; ".join(str(_render_param(v, localized)) for v in value)
    return value


def render(issue: ParseIssue, *, localized: bool = False) -> str:
    """Return the sentence for *issue* -- English by default.

    English is what str(issue), logs and exports use. localized=True is
    for display in the UI: the template is looked up in the loaded
    translation; with none loaded, or none for this template, it is the
    English one (scripts/i18n.py release gives every untranslated text its
    own English entry, so a code never borrows the translation of another
    code with the same English wording). A translation whose placeholders
    don't fit the issue's
    params falls back to the English template (and is logged), so a
    faulty translation can never drop the facts the issue carries.

    An unknown code (a parser newer than its catalog entry) still renders
    everything it carries -- code, params and detail -- never an empty
    string. `detail` is never translated.
    """
    template = MESSAGES.get(issue.code)
    params = {k: _render_param(v, localized) for k, v in issue.params.items()}
    if template is None:
        parts = [f"[{issue.code}]"]
        if params:
            parts.append(", ".join(f"{k}={v}" for k, v in params.items()))
        if issue.detail:
            parts.append(issue.detail)
        return " ".join(parts)
    if localized and _translate is not None:
        translated = _translate(TRANSLATION_CONTEXT, template, issue.code)
        if translated and translated != template:
            try:
                return translated.format(detail=issue.detail, **params)
            except (KeyError, IndexError, ValueError, AttributeError) as exc:
                _log.warning(
                    "Translation of %s does not fit its params (%s); showing English",
                    issue.code, exc,
                )
    return template.format(detail=issue.detail, **params)


def render_value(value: Any, *, localized: bool = False) -> str:
    """Display text for a metadata value that may be (or contain) issues."""
    rendered = _render_param(value, localized)
    return rendered if isinstance(rendered, str) else str(rendered)
