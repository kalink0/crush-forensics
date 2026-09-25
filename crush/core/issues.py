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

from dataclasses import dataclass, field
from typing import Any


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
    "common.library_error": "{detail}",
    # -- JSON -------------------------------------------------------------
    "json.syntax_error": (
        "Not valid JSON: {detail}. The tree shows only an excerpt around the "
        "error position; full content: Open as → Text / Hex"
    ),
    "json.not_utf8": (
        "Not valid UTF-8 (first invalid byte at offset {offset:,}: {detail}); "
        "invalid bytes are shown as U+FFFD — Open as → Hex for the original bytes"
    ),
    # -- Logs (Multi-Log Studio) -------------------------------------------
    "log.format_detected": "{name} (heuristic)",
    "log.format_selected": "{name} (selected by analyst)",
    "log.format_custom": "Custom: {name}",
    "log.format_score": "{name} {hits:,}/{total:,}",
    "log.detection_rule": (
        "Plain-text logs have no format marker. The first of JSON Lines "
        "(≥ 60 % of lines), Android logcat (≥ 50 %), Syslog (≥ 50 %) and Generic "
        "(≥ 2 lines) that reaches its threshold is used, otherwise plain text. "
        "Another format can be chosen via Format → Re-parse as"
    ),
    "log.lines_unmatched": "{count:,} line(s) kept as separate entries with level UNKNOWN",
    "log.ts_no_zone": (
        "{count:,} entries: no time zone in the log — shown as recorded, never converted"
    ),
    "log.level_guessed": (
        "{count:,} entries: this format has no level field — level guessed from a "
        "keyword in the message (marked \"guessed\")"
    ),
    "log.ts_no_year": "{count:,} entries: no year in the log — shown as ????",
    "log.ts_unparsed": (
        "{count:,} entries: timestamp present but not decodable — see the raw line"
    ),
    "log.not_utf8": (
        "Not valid UTF-8 (first invalid byte at offset {offset:,}: {detail}); "
        "invalid bytes are shown as U+FFFD — Open as → Hex for the original bytes"
    ),
    # -- SQLite -----------------------------------------------------------
    "sqlite.parse_failed": "{detail}",
    "sqlite.invalid_hex_key": "Not a valid hex key: {detail}",
    # No {detail}: SQLCipher's message for a page that fails to decrypt is
    # always "file is not a database", which reads as "this isn't a
    # database" in a password prompt. The detail stays on the issue and in
    # the log.
    "sqlite.custom_params_rejected": (
        "Incorrect key, or the given parameters don't match this file"
    ),
    "sqlite.password_rejected": (
        "Incorrect password, or an unsupported SQLCipher version/parameters"
    ),
    "sqlite.encrypted_password": "Yes (SQLCipher, password supplied)",
    "sqlite.encrypted_raw_key": "Yes (SQLCipher, raw key supplied)",
    "sqlite.pragma_read_failed": (
        "Page size, journal mode and encoding could not be read: {detail}"
    ),
    "sqlite.journal_mode_rollback": (
        "Rollback journal (the file doesn't record which variant: "
        "delete/truncate/persist)"
    ),
    "sqlite.row_limit": "First {limit:,} rows shown for: {tables}",
    "sqlite.companion_empty": (
        "VFS found {name} (path={path}, vfs_size={size} B) but read returned 0 bytes — "
        "ZIP entry may be empty in the archive"
    ),
    "sqlite.companion_copied": "Copied {name} ({size:,} B) from {path}",
    "sqlite.companion_loaded_fs": "Loaded filesystem companion {name} ({size:,} B)",
    "sqlite.companion_not_in_vfs": "find_sibling returned None for db_node.path={path}",
    "sqlite.companion_read_failed": "VFS found {name} but read raised: {detail}",
    "sqlite.companion_fs_read_failed": "{name} could not be read from disk: {detail}",
    "sqlite.journal_present": "present, {size:,} B, {status}",
    "sqlite.journal_merged": (
        "valid/hot, {segments} segment(s), {records} page record(s) -- merged into "
        "current view (see 'Show pre-rollback state' toggle and the 'Rollback "
        "Journal' tab)"
    ),
    "sqlite.journal_valid_not_merged": (
        "valid/hot, {segments} segment(s), {records} page record(s) -- NOT merged, "
        "{reason} (see the 'Rollback Journal' tab for the raw, unmerged record "
        "inventory)"
    ),
    "sqlite.journal_not_merged": (
        "NOT merged -- {reason} (see the 'Rollback Journal' tab for the raw, "
        "unmerged record inventory)"
    ),
    "sqlite.journal_checksum_mismatch": "one or more page checksums did not validate",
    "sqlite.journal_stale_wal_mode": (
        "the database's own header shows WAL mode is active, so this -journal "
        "predates the switch to WAL and is stale, not \"hot\""
    ),
    # -- SQLite rollback journal -----------------------------------------
    "sqlite_journal.invalid": "Not a valid rollback journal",
    "sqlite_journal.no_valid_header": (
        "No valid rollback-journal header found at the start of this file "
        "(magic mismatch) -- likely a stale/invalidated PERSIST-mode "
        "journal, a truncated/corrupt journal, or not a SQLite rollback "
        "journal at all"
    ),
    "sqlite_journal.valid_hot": (
        "Valid / hot — every segment header and page checksum validated"
    ),
    "sqlite_journal.not_fully_valid": (
        "NOT fully valid — {mismatches} checksum mismatch(es); shown raw, unmerged"
    ),
    "sqlite_journal.standalone": (
        "This is the journal's own pre-transaction page content, shown standalone "
        "(no companion database opened alongside it). Open the companion database "
        "normally instead to see this same inventory in its own 'Rollback Journal' "
        "tab, with a valid journal's content automatically merged into the "
        "database's default table view (never applied to any file on disk)."
    ),
    # -- SQLite WAL -------------------------------------------------------
    "sqlite_wal.invalid": "Not a valid WAL file (magic mismatch or file too short)",
    "sqlite_wal.standalone": (
        "Shown standalone (no companion database opened alongside it), so rows are "
        "raw decoded values, not resolved to real column names. Open the companion "
        "database normally instead to see this content with column names, table "
        "attribution, and (for Active frames) merged transparently into the live "
        "table view, plus this same per-frame inventory in its own 'WAL Frames' tab."
    ),
    # -- Realm ------------------------------------------------------------
    "realm.encrypted_key_supplied": "Yes (AES-256, key supplied)",
    "realm.header_not_detected": "Not detected (corrupt or non-standard)",
    "realm.try_encrypted": "Try Open as → Realm DB (Encrypted)…",
    "realm.streaming_footer_ok": (
        "Yes — top ref resolved from end-of-file footer (offset {top_ref})"
    ),
    "realm.streaming_footer_bad": (
        "Yes — but the footer is missing or its magic cookie doesn't match; top "
        "ref could not be resolved (truncated or corrupt file)"
    ),
    "realm.tables_unresolved": "Unresolved (see Streaming form)",
    "realm.pre_cluster_decoded": "Decoded via legacy pre-Cluster layout",
    "realm.pre_cluster_partial": "Pre-Cluster layout — {reasons}",
    "realm.pre_cluster_undecoded_columns": (
        "{columns} column(s) across {tables} table(s) not yet decoded "
        "(unimplemented old column type)"
    ),
    "realm.table_failed": "{table}: {reason}",
    "realm.group_top_malformed": "Group top array is malformed or has no references",
    "realm.group_no_table_refs_slot": (
        "Group top array has no table-refs slot (fewer than 2 children)"
    ),
    "realm.table_refs_ref_invalid": (
        "Table-refs reference is invalid or points outside the file"
    ),
    "realm.table_refs_malformed": "Table-refs array is malformed or has no references",
    "realm.table_refs_empty": (
        "Table-refs array has 0 entries, but {classes} class name(s) in schema"
    ),
    # Per-table reasons (rendered after "<table>: " via realm.table_failed).
    "realm.table_ref_invalid": "table reference is invalid or points outside the file",
    "realm.table_top_no_cluster_tree_slot": (
        "Table top array is malformed or missing its ClusterTree slot"
    ),
    "realm.cluster_tree_ref_invalid": (
        "ClusterTree reference is invalid or points outside the file"
    ),
    "realm.colkeys_empty": "Spec/colkeys array has no columns (empty or malformed)",
    "realm.cluster_tree_root_malformed": "ClusterTree root is malformed or has no leaves",
    "realm.table_top_no_spec_slots": (
        "Table top array is malformed or missing its spec/columns slots"
    ),
    "realm.table_top_zero_width": "Table top array has a zero element width",
    "realm.spec_ref_invalid": "Spec reference is invalid or points outside the file",
    "realm.spec_no_columns": "Spec array has no columns (empty or malformed)",
    # -- Images (ImageParser) ----------------------------------------------
    "image.format_unrecognised": (
        "Not recognised by content (file extension: {ext})"
    ),
    "image.frames_first_only": (
        "{count:,} frames/pages/images in the file; only the first is shown"
    ),
    "image.c2pa_detection_failed": "Detection failed: {detail}",
    # -- EXIF -------------------------------------------------------------
    "exif.present": "Present",
    "exif.present_no_listed_fields": (
        "Present, but none of the fields shown here are set"
    ),
    "exif.not_present": "Not present",
    "exif.not_checked": "Not checked for this format yet",
    "exif.png_not_checked": (
        "PNG eXIf chunk not checked yet (tEXt chunks are read)"
    ),
    "exif.not_defined": "Not defined for this format",
    "exif.heif_plugin_missing": "Not checked (pillow-heif is not installed)",
    "exif.parse_failed": "Present, but could not be parsed: {reason}",
    "exif.bad_tiff_header": "TIFF header is not valid",
    "exif.ifd_out_of_range": "IFD offset {offset} lies outside the EXIF data",
    "exif.ifd_truncated": (
        "IFD at offset {offset} declares {count} entries, only {read} fit in the data"
    ),
    "exif.value_out_of_range": (
        "{tag}: value offset {offset} lies outside the EXIF data"
    ),
    "exif.unknown_type": "{tag}: TIFF type {dtype} is not decoded",
    "exif.invalid_rational": "Invalid (rational {value}, denominator 0)",
    "exif.gps_invalid": (
        "Invalid (a rational has denominator 0): latitude {lat}, longitude {lon}"
    ),
    "exif.gps_latitude_only": "Latitude {lat} recorded, longitude missing",
    "exif.gps_longitude_only": "Longitude {lon} recorded, latitude missing",
    # -- XMP --------------------------------------------------------------
    "xmp.present": "Present",
    "xmp.present_multiple": (
        "Present ({count} packets; fields shown are from the first)"
    ),
    "xmp.present_no_listed_fields": (
        "Present, but none of the fields shown here are set"
    ),
    "xmp.not_present": "Not present",
    "xmp.unclosed": "Packet start found at offset {offset:,}, but no closing tag",
    "xmp.parse_failed": "Present, but not parseable as XML: {detail}",
    # -- C2PA -------------------------------------------------------------
    "c2pa.not_present": "Not present",
    "c2pa.not_defined": "Not defined by the C2PA spec for this format",
    "c2pa.not_checked": (
        "Not checked (detection only implemented for common image containers so far)"
    ),
    "c2pa.unparseable": "Manifest found, but could not be parsed",
    "c2pa.parse_failed": "Manifest found, but could not be parsed: {detail}",
    "c2pa.store_empty": "Manifest Store found, but contains no manifest",
    "c2pa.manifest_found": "Manifest found",
    "c2pa.manifests_found": "{count} manifest(s) found",
    "c2pa.ingredient_untitled": "(untitled)",
    "c2pa.signature_present": (
        "Present (structure parsed, not cryptographically verified)"
    ),
    "c2pa.cert_unparseable": "Present, but not parseable as X.509: {detail}",
    # -- Apple ATX --------------------------------------------------------
    "atx.not_atx": "Not an AAPL ATX container",
    "atx.unexpected_eof": "unexpected end of ATX data",
    "atx.chunk_beyond_eof": "Chunk {tag} at offset {offset} extends beyond EOF",
    "atx.trailing_bytes": "{count} trailing byte(s) after last complete chunk",
    "atx.no_head": "No HEAD chunk found",
    "atx.head_too_small": (
        "HEAD chunk too small for documented ATX header: {size} bytes"
    ),
    "atx.no_payload": "No astc, ASTC, or LZFS texture payload chunk found",
    "atx.payload_no_inner_size": "{tag} chunk is too small to include an inner size",
    "atx.pixel_format_inferred_label": "Inferred ASTC 4x4 ({a}, {b})",
    "atx.pixel_format_unknown": "Unknown ({a}, {b})",
    "atx.invalid_dimensions": "invalid ATX dimensions: {width}x{height}",
    "atx.too_large": "ATX image dimensions are too large: {width}x{height}",
    "atx.unexpected_depth": "Unexpected ATX depth {depth}; attempting 2D decode",
    "atx.unexpected_layers": (
        "Unexpected ATX array layer count {count}; attempting first image decode"
    ),
    "atx.unexpected_mipmaps": (
        "Unexpected ATX mipmap count {count}; attempting first image decode"
    ),
    "atx.unsupported_pixel_format": "unsupported ATX pixel format {format}",
    "atx.pixel_format_inferred": "ATX pixel format {format} inferred as ASTC 4x4",
    "atx.lzfs_too_short": (
        "LZFS payload decompressed to {size} bytes; expected at least {expected}"
    ),
    "atx.astc_too_short": "ASTC payload is {size} bytes; expected at least {expected}",
    "atx.decode_failed": "ATX image decode failed: {reason}",
    "atx.decoded": "Decoded ATX to PNG",
    "atx.decode_unavailable": "ATX metadata parsed; image decode unavailable",
    "atx.block_order_heuristic": (
        "Heuristic — the file does not record it. Used: Morton X/Y {chosen} "
        "(seam score {chosen_score:.2f}); other candidate: Morton X/Y {other} "
        "(seam score {other_score:.2f}). Lower score = smaller brightness jumps "
        "at the 128-pixel macro-tile boundaries"
    ),
    "atx.morton_as_stored": "as stored",
    "atx.morton_swapped": "swapped",
    # -- Khronos KTX ------------------------------------------------------
    "ktx.unsupported_version": "Unsupported KTX version",
    "ktx.not_ktx": "Not a KTX 1.1 file",
    "ktx.header_too_short": "File is {size} bytes; a KTX header needs {needed}",
    "ktx.kv_beyond_eof": "Key/value block claims {size} bytes but the file ends first",
    "ktx.kv_entry_overflow": "Key/value entry extends beyond the key/value block",
    "ktx.no_payload": "No texture payload after the key/value block",
    "ktx.no_lzfs_marker": (
        "Key/value block declares Compression_APPLE but no LZFS marker follows imageSize"
    ),
    "ktx.not_lzfse": "LZFS marker is present but the block that follows is not LZFSE",
    "ktx.lzfse_short": (
        "LZFSE block declares {declared:,} bytes but only {present:,} are present"
    ),
    "ktx.pixel_format_unsupported_label": "Unsupported (glInternalFormat 0x{fmt:04X})",
    "ktx.unsupported_pixel_format": "unsupported KTX pixel format {format}",
    "ktx.invalid_dimensions": "invalid KTX dimensions: {width}x{height}",
    "ktx.too_large": "KTX image dimensions are too large: {width}x{height}",
    "ktx.unexpected_depth": "Unexpected KTX depth {depth}; attempting 2D decode",
    "ktx.unexpected_layers": "Unexpected KTX array layer count {count}; decoding first",
    "ktx.unexpected_faces": "Unexpected KTX face count {count}; decoding first face",
    "ktx.unexpected_mipmaps": "Unexpected KTX mipmap count {count}; decoding first level",
    "ktx.lzfse_failed": "LZFSE decompression failed: {detail}",
    "ktx.decode_failed": "KTX image decode failed: {reason}",
    "ktx.decoded": "Decoded KTX to PNG",
    "ktx.decode_unavailable": "KTX metadata parsed; image decode unavailable",
    # -- PDF --------------------------------------------------------------
    "pdf.pypdf_missing": "Install pypdf for text extraction: pip install pypdf",
    "pdf.try_encrypted": "Try Open as → PDF (Encrypted)…",
    "pdf.wrong_password": "Wrong password for encrypted PDF: {path}",
    "pdf.encrypted_password": "Yes (password supplied)",
    "pdf.parse_failed": "{detail}",
    "pdf.format_parse_failed": "PDF (parse failed)",
    "pdf.js_present": "Present",
    "pdf.js_not_present": (
        "Not present (checked: document-level /Names/JavaScript and /OpenAction; "
        "not checked: annotation and form-field actions)"
    ),
    "pdf.js_check_failed": "Could not be checked: {detail}",
    "pdf.signatures_signed": "{signed}/{total} signature field(s) signed",
    "pdf.signatures_none": (
        "None (checked: top-level AcroForm fields; not checked: fields nested in /Kids)"
    ),
    "pdf.signatures_check_failed": "Could not be checked: {detail}",
    "pdf.attachments": "{count} file(s)",
    "pdf.attachments_failed": "{count} file(s) read, then reading failed: {detail}",
    "pdf.no_text": "No extractable text in this PDF",
    "pdf.text_pages_failed": "Text extraction failed on {count} page(s): {failures}",
    "pdf.text_page_failure": "page {page}: {detail}",
    "pdf.xmp_present": "Present",
    "pdf.xmp_not_present": "Not present",
    "pdf.xmp_failed": "Could not be read: {detail}",
    "pdf.revision_failed": "This revision could not be opened: {detail}",
    "pdf.revchain_parse_failed": (
        "Stopped after {count} revision(s): the trailer of the oldest one found "
        "could not be read: {detail}"
    ),
    "pdf.revchain_bad_prev": (
        "Stopped after {count} revision(s): the trailer's /Prev value is not a "
        "byte offset: {detail}"
    ),
    "pdf.revchain_no_eof": (
        "Stopped after {count} revision(s): no %%EOF after /Prev offset {offset:,}"
    ),
    "pdf.revchain_cycle": (
        "Stopped after {count} revision(s): /Prev offset {offset:,} repeats (cyclic chain)"
    ),
    # -- Media (audio/video) ------------------------------------------------
    "media.metadata_not_checked": (
        "Codec/tag metadata is read for OGG/Opus/AMR only so far"
    ),
    "media.pyav_missing": "Not read (PyAV is not installed)",
    "media.no_audio_stream": "No audio stream found",
    "media.metadata_failed": "Could not be read: {detail}",
}


def _render_param(value: Any) -> Any:
    if isinstance(value, ParseIssue):
        return render(value)
    if isinstance(value, (list, tuple)) and any(isinstance(v, ParseIssue) for v in value):
        return "; ".join(str(_render_param(v)) for v in value)
    return value


def render(issue: ParseIssue) -> str:
    """Return the English sentence for *issue*.

    An unknown code (a parser newer than its catalog entry) still renders
    everything it carries -- code, params and detail -- never an empty
    string.
    """
    template = MESSAGES.get(issue.code)
    params = {k: _render_param(v) for k, v in issue.params.items()}
    if template is None:
        parts = [f"[{issue.code}]"]
        if params:
            parts.append(", ".join(f"{k}={v}" for k, v in params.items()))
        if issue.detail:
            parts.append(issue.detail)
        return " ".join(parts)
    return template.format(detail=issue.detail, **params)


def render_value(value: Any) -> str:
    """Display text for a metadata value that may be (or contain) issues."""
    rendered = _render_param(value)
    return rendered if isinstance(rendered, str) else str(rendered)
