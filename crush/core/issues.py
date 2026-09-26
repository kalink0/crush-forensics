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
        "PNG eXIf chunk not checked yet (tEXt chunks are read)",
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
    # -- LevelDB ----------------------------------------------------------
    "leveldb.open_failed": QT_TRANSLATE_NOOP("ParseIssue", "{detail}", "leveldb.open_failed"),
    "leveldb.open_failed_hint": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LevelDB could not be opened",
        "leveldb.open_failed_hint",
    ),
    "leveldb.format_parse_failed": QT_TRANSLATE_NOOP(
        "ParseIssue",
        "LevelDB (parse failed)",
        "leveldb.format_parse_failed",
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
        "Schema-less rendering (heuristic): valid UTF-8 is shown as text and "
        "64/32-bit fields as double/float; the exact bytes are in the cell "
        "(Inspect BLOB / Open as Protobuf)",
        "segb.payload_heuristic",
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
    "vfs.disk_image_hint_ewf": QT_TRANSLATE_NOOP(
        "ParseIssue", "EWF signature", "vfs.disk_image_hint_ewf",
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
    # -- UFDR ------------------------------------------------------------------------
    "ufdr.not_recorded": QT_TRANSLATE_NOOP("ParseIssue", "(not recorded)", "ufdr.not_recorded"),
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
}


def _render_param(value: Any, localized: bool = False) -> Any:
    if isinstance(value, ParseIssue):
        return render(value, localized=localized)
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
