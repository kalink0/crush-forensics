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
    # -- plist ------------------------------------------------------------
    "plist.parse_failed": "{detail}",
    "plist.format_parse_failed": "plist (parse failed)",
    "plist.format_nska_failed": "binary (NSKeyedArchiver — deserialization failed)",
    "plist.nska_failed": (
        "NSKeyedArchiver deserialization failed, so the tree shows the archive's "
        "undecoded object table: {detail}"
    ),
    # -- XML --------------------------------------------------------------
    "xml.syntax_error": (
        "Not well-formed XML: {detail}. The tree shows only an excerpt around the "
        "error position; full content: Open as → Text / Hex"
    ),
    "xml.format_parse_failed": "XML (parse error)",
    # -- ABX (Android Binary XML) -----------------------------------------
    "abx.truncated": (
        "TRUNCATED: decode error at offset {offset} (0x{offset:x}): {detail} — "
        "{remaining} of {total} bytes not decoded"
    ),
    "abx.no_magic": "Missing ABX magic header",
    "abx.empty_start_tag": "Empty start tag name",
    "abx.unsupported_token": "Unsupported {token} token encountered (rare/unverified format)",
    "abx.dangling_attribute": "Dangling attribute token",
    "abx.unknown_token": "Unknown token: {token}",
    "abx.control_chars": (
        "Raw XML-illegal control character(s) found in decoded value(s); "
        "re-encoded as \\xHH to keep the XML well-formed"
    ),
    "abx.multiple_roots": (
        "Multiple root elements ({count}) found; wrapped in synthetic <abx-root> "
        "for well-formed XML"
    ),
    "abx.xml_failed": "{detail}",
    "abx.xml_failed_hint": "XML reconstruction failed; see right pane",
    "abx.parse_failed": "{detail}",
    "abx.parse_failed_hint": "File may be a newer ABX version",
    "abx.format_parse_failed": "ABX (parse error)",
    # -- Protobuf (schema-less) --------------------------------------------
    "protobuf.truncated_key": "Truncated varint key",
    "protobuf.truncated_varint": "Truncated varint value",
    "protobuf.truncated_fixed64": "Truncated 64-bit value",
    "protobuf.truncated_fixed32": "Truncated 32-bit value",
    "protobuf.truncated_length": "Truncated length-delimited size",
    "protobuf.truncated_payload": "Truncated length-delimited payload",
    "protobuf.truncated_group": "Truncated group field {field}",
    "protobuf.unexpected_end_group": "Unexpected end-group tag for field {field}",
    "protobuf.unknown_wire_type": "Unknown wire type: {wire_type}",
    "protobuf.decode_error": "Decode error: {detail}",
    "protobuf.depth_limit": (
        "{count:,} length-delimited field(s) at nesting depth {limit} were not tried "
        "as nested messages (depth limit, the protobuf libraries' default); shown "
        "as string/bytes"
    ),
    # -- LevelDB ----------------------------------------------------------
    "leveldb.open_failed": "{detail}",
    "leveldb.open_failed_hint": "LevelDB could not be opened",
    "leveldb.format_parse_failed": "LevelDB (parse failed)",
    "leveldb.read_stopped": "Reading stopped after {count:,} records: {detail}",
    "leveldb.manifest_failed": "Could not be parsed: {detail}",
    "leveldb.manifest_partial": "Read only up to an error: {detail}",
    "leveldb.file_unreadable": "Could not be read: {detail}",
    # -- MMKV -------------------------------------------------------------
    "mmkv.encrypted_error": "This MMKV store is AES-encrypted.",
    "mmkv.encrypted_hint": 'Use "Open as -> MMKV (Encrypted)..." and supply the key.',
    "mmkv.format_encrypted": "MMKV Key-Value Store (encrypted)",
    "mmkv.encrypted_yes": "yes",
    "mmkv.read_failed": "{detail}",
    "mmkv.read_failed_hint": "MMKV store could not be read",
    "mmkv.format_parse_failed": "MMKV Key-Value Store (parse failed)",
    "mmkv.wrong_key": "{detail}",
    "mmkv.meta_not_found": (
        "not found (.crc companion missing) — encryption status unverified"
    ),
    "mmkv.meta_unreadable": (
        "found, but could not be read ({detail}) — encryption status unverified"
    ),
    "mmkv.meta_not_found_short": "not found (.crc companion missing)",
    "mmkv.meta_too_short": (
        "found, but only {size} B — too short for the meta layout ({needed} B) — "
        "encryption status unverified"
    ),
    "mmkv.meta_too_short_short": (
        "found, but only {size} B — too short for the meta layout ({needed} B)"
    ),
    "mmkv.meta_unreadable_short": "found, but could not be read ({detail})",
    "mmkv.encrypted_decrypted": "yes (decrypted)",
    "mmkv.key_ignored_no_meta": (
        "unverified — a key was supplied but ignored: no .crc meta file was found, "
        "so there is no AES vector to decrypt with and the store was read as plaintext"
    ),
    "mmkv.key_ignored_bad_meta": (
        "unverified — a key was supplied but ignored: the .crc meta file was {meta}, "
        "so there is no AES vector to decrypt with and the store was read as plaintext"
    ),
    "mmkv.key_ignored_zero_vector": (
        "no — a key was supplied but ignored: the .crc meta file's AES vector is "
        "zero, so the store is not encrypted"
    ),
    "mmkv.encrypted_false_positive": "no — {note}",
    "mmkv.false_positive_note": (
        ".crc meta file's vector field is non-zero, which normally flags AES "
        "encryption, but the store read cleanly as plaintext anyway, so that flag "
        "is treated as a false positive here"
    ),
    "mmkv.offsets_unavailable": (
        "Entry byte offsets could not be derived; Locate in Hex is unavailable"
    ),
    "mmkv.offsets_mismatch": (
        "Entry byte offsets found for {found:,} of {total:,} entries; Locate in Hex "
        "is unavailable"
    ),
    # -- SEGB -------------------------------------------------------------
    "segb.unrecognized": "Not a recognized SEGB v1/v2 file",
    "segb.format_unrecognized": "SEGB (unrecognized)",
    "segb.parse_failed": "{detail}",
    "segb.format_parse_failed": "SEGB (parse failed)",
    "segb.record_failed": (
        "Reading stopped at record {index}: {detail}; later records not read"
    ),
    "segb.stream_failed": "Reading stopped after {count:,} records: {detail}",
    "segb.payload_heuristic": (
        "Schema-less rendering (heuristic): valid UTF-8 is shown as text and "
        "64/32-bit fields as double/float; the exact bytes are in the cell "
        "(Inspect BLOB / Open as Protobuf)"
    ),
    "segb.payload_partial": (
        "{count:,} record(s): payload decoded only up to the byte shown in the cell"
    ),
    "segb.payload_stopped_marker": "[not decoded from byte {offset:,} on]",
    "segb.sql_failed": (
        "SQL view unavailable: the temporary database could not be created: {detail}"
    ),
    # -- Hex fallback -------------------------------------------------------
    "hexfallback.read_error": "{detail}",
    "hexfallback.not_identified": (
        "Not identified (no signature in the format database matched)"
    ),
    "hexfallback.identify_failed": "Identification failed: {detail}",
    "hexfallback.parser_open_as": (
        "Supported — not detected from content; use Open as → {name}"
    ),
    "hexfallback.parser_source": (
        "Supported as a browsable source — right-click → Open in New Window"
    ),
    "hexfallback.parser_folder": (
        "Supported for the whole LevelDB folder — select the folder, not a single file"
    ),
    "hexfallback.parser_logs": "Supported in Multi-Log Studio — right-click → Open in Multi-Log Studio",
    "hexfallback.parser_mismatch": (
        "A parser exists for this format, but this file's content did not match it"
    ),
    "hexfallback.parser_none": "Not yet supported",
    # -- SQLite page scans (Freelist Recovery, Freeblocks, Unallocated, WAL) --
    "sqlite_scan.file_unreadable": "The database file could not be read: {detail}",
    "sqlite_scan.read_stopped": (
        "Reading stopped at page {page:,}: {detail}; later pages were not scanned"
    ),
    "sqlite_scan.page_short": (
        "Page {page:,} holds only {size:,} of {page_size:,} bytes (file ends) "
        "and was not scanned"
    ),
    "sqlite_page.cells_skipped": (
        "Page {page}: {count:,} of {total:,} cell(s) could not be decoded and are not shown"
    ),
    "freelist.header_unreadable": (
        "Page 1 (the database header) could not be read, so the freelist could not be located"
    ),
    "freelist.none": "The database header records no freelist pages",
    "freelist.trunk_unreadable": (
        "Freelist trunk page {page:,} could not be read; the rest of the chain was not followed"
    ),
    "freelist.cycle": "The freelist chain returns to page {page:,} (a cycle); stopped there",
    "freelist.over_count": (
        "The freelist chain holds more pages than the {declared:,} the header declares; "
        "stopped there"
    ),
    "freelist.leaf_count_clamped": (
        "Trunk page {page:,} declares {declared:,} leaf pages, but only {fits:,} fit on "
        "a page; {fits:,} were read"
    ),
    "freelist.summary": (
        "{pages:,} freelist page(s) walked ({trunks:,} trunk, {leaves:,} leaf): "
        "{carved:,} still hold table rows, {empty:,} are table-leaf pages without cells, "
        "{not_leaf:,} no longer hold a table-leaf page (zeroed or reused), "
        "{unreadable:,} could not be read"
    ),
    "freeblock.ptr_outside": (
        "Page {page:,}: the freeblock chain points to offset {offset:,}, outside the page; "
        "stopped there"
    ),
    "freeblock.too_small": (
        "Page {page:,}: freeblock at offset {offset:,} declares {size} B, below the 4-byte "
        "minimum; the chain stopped there"
    ),
    "freeblock.overruns_page": (
        "Page {page:,}: freeblock at offset {offset:,} declares {size:,} B, but only "
        "{available:,} fit on the page; shown up to the page end"
    ),
    "unallocated.bad_content_start": (
        "Page {page:,}: the cell content area starts at {start:,}, beyond the page; "
        "its unallocated gap was not read"
    ),
    "sqlite_wal.table_map_failed": (
        "Table attribution unavailable: the schema could not be read: {detail}"
    ),
    "sqlite_wal.table_map_no_file": (
        "Table attribution incomplete: the database file could not be read ({detail}); "
        "only pages in the -wal file were attributed"
    ),
    # -- SQLite File Structure tab -------------------------------------------
    "sqlite_structure.page_size_unavailable": "page size unavailable",
    "sqlite_structure.file_unavailable": "file unavailable",
    "sqlite_structure.no_unallocated": "none/non-empty bytes not found",
    "sqlite_structure.page_unreadable": "could not be read (read error or file ends)",
    "sqlite_structure.cells_not_shown": "{problems}",
    # -- Realm File Structure tab --------------------------------------------
    "realm_structure.header_not_detected": "Not detected (possibly encrypted or non-standard)",
    "realm_structure.top_unresolved": "Unresolved -- no valid active top reference",
    "realm_structure.top_unreadable": "Unreadable at offset 0x{offset:x}",
    "realm_structure.ref_unresolved": "unresolved",
    "realm_structure.table_ref_invalid": "Table reference is invalid or points outside the file",
    "realm_structure.table_top_unreadable": "Table top array is malformed or unreadable",
    "realm_structure.no_columns": "(no columns)",
    "realm_structure.no_cluster_tree_slot": "Table top array is missing its ClusterTree slot",
    "realm_structure.cluster_tree_ref_invalid": (
        "ClusterTree reference is invalid or points outside the file"
    ),
    # -- Locate in Hex ----------------------------------------------------------
    "locate.no_range": "No byte range for this cell: {reason}",
    "locate.not_recorded": "the decoder recorded none for it",
    "locate.segb_record_offsets": "the record's offsets could not be read ({detail})",
    # -- Several notes about one thing ------------------------------------------
    "common.notes": "{notes}",
    # -- Password / key rejections (shown above the retry prompt) ----------------
    "password.zip_required": "ZIP archive is password-protected: {path}",
    "password.zip_wrong": "Incorrect ZIP archive password",
    "password.7z_required": "7z archive is password-protected: {path}",
    "password.7z_wrong": "Incorrect 7z archive password",
    "password.ab_required": "Android backup is password-protected: {path}",
    "password.ab_wrong": "Incorrect Android backup password",
    "password.ab_padding": "Payload padding invalid after decryption (wrong password?)",
    "password.itunes_required": "iTunes backup is password-protected: {path}",
    "password.itunes_wrong": "Incorrect backup password",
    "password.itunes_padding": "Padding invalid after decryption (wrong password?)",
    "password.itunes_no_class_key": "Backup keybag has no usable class key for class {class_num}",
    "password.realm_not_hex": "Not a valid hex key: {detail}",
    "password.realm_key_length": (
        "Realm encryption key must be {size} bytes ({hex_chars} hex characters) — "
        "got {got} bytes"
    ),
    "password.realm_key_size": "Realm encryption key must be {size} bytes",
    "password.realm_hmac": (
        "HMAC mismatch decrypting Realm file (wrong key, or the file is corrupt)"
    ),
    "vfs.ab_unsupported_encryption": "Unsupported Android backup encryption: {value}",
    "vfs.ab_not_backup": "Not an Android backup: {path}",
    # -- Opening a source (status bar notes) ---------------------------------------
    "vfs.named_but_not": "Named {suffix}, but no {label} signature found",
    "vfs.contains_zip_after": (
        "Contains a ZIP archive after {leading:,} leading bytes — right-click → "
        "Open in New Window to browse it"
    ),
    "vfs.zip_opened_after": "ZIP archive opened after {leading:,} leading bytes",
    "vfs.ufdr_as_zip": "UFDR layout found, but not opened as UFDR ({detail}); shown as plain ZIP",
    "vfs.zip_not_opened": "ZIP signature found, but not opened as ZIP — {detail}",
    "vfs.7z_not_opened": "7z signature found, but not opened as 7z — {detail}",
    "vfs.tar_signature_found": "TAR signature found",
    "vfs.compressed_tar_found": "Compressed TAR found",
    "vfs.named_as": "Named {suffix}",
    "vfs.tar_not_opened": "{what}, but not opened as TAR — {detail}",
    "vfs.not_disk_image": "Not opened as a disk image — {detail}",
    "vfs.atime_platform": (
        "Crush does not prevent access-time updates on this platform; mount the "
        "evidence read-only to prevent them"
    ),
    "vfs.atime_not_owned": (
        "{count:,} file(s) are not owned by the current user, so Crush can't read "
        "them with O_NOATIME: reading them may update their access time (mount the "
        "evidence read-only to prevent this)"
    ),
    # -- Entries in a browsed source (Properties: Entry status) --------------------
    "entry.duplicate": (
        "Stored {count} times in this archive under this name; this is occurrence "
        "{k} of {count} (archive order)"
    ),
    "entry.symlink_target": "Symbolic link → {target} (content shown is the target)",
    "entry.symlink_stored_target": "Symbolic link (content shown is the stored link target)",
    "entry.symlink_folder": (
        "Symbolic link → {target} (not followed; content shown is the target)"
    ),
    "entry.symlink_unreadable": (
        "Symbolic link (not followed); its target could not be read: {detail}"
    ),
    "entry.symlink_no_target": "Symbolic link (the backup records no target for it)",
    "entry.symlink_raw": (
        "Symbolic link — its target/content is not decoded by the filesystem reader"
    ),
    "entry.hard_link": "Hard link to {target}",
    "entry.special_stored": "Special file ({kind}) — no content stored",
    "entry.special_not_read": "Special file ({kind}) — no content is read",
    "entry.special_raw": "Special file (mode {mode}) — no content",
    "entry.unreadable": "Could not be read: {detail}",
    "entry.folder_unlisted": "Folder could not be listed: {detail}",
    "entry.no_backup_content": "No content stored in the backup for this entry (fileID {file_id})",
    "entry.file_key_unreadable": (
        "Encrypted in the backup, but its file key could not be read ({detail}); "
        "the content is shown as stored (ciphertext)"
    ),
    "entry.raw_depth": (
        "Not listed: nested deeper than {limit} directories (guard against a "
        "directory loop in a damaged filesystem)"
    ),
    "entry.raw_loop": (
        "Not listed again: this directory was already reached by another path "
        "(a directory loop in the filesystem structure)"
    ),
    "entry.raw_unlisted": "Directory could not be listed: {detail}",
    "entry.raw_entry_unreadable": "Entry metadata could not be read: {detail}",
    "entry.raw_deleted_enum_failed": (
        "Deleted files could not be enumerated: {detail}"
    ),
    "entry.recovered_intact": "recovered (content intact)",
    "entry.not_recoverable": "not recoverable: {detail}",
    "entry.raw_no_reader": "no reader for this content — showing raw bytes",
    # -- UFDR ------------------------------------------------------------------------
    "ufdr.not_recorded": "(not recorded)",
    "ufdr.not_located": "not located in container",
    "ufdr.not_readable": (
        "Not a readable UFDR container -- if this was exported as multiple parts, "
        "rejoin them first; segmented UFDR exports aren't supported yet."
    ),
    "ufdr.missing_members": "Not a UFDR container -- missing {members}",
    "ufdr.no_space": (
        "Not enough space in the temp directory to extract the UFDR's database "
        "({needed:,} bytes needed, {free:,} available at {location})"
    ),
    "ufdr.no_device_schema": "UFDR database has no per-device schema -- unrecognised layout",
    "ufdr.missing_columns": (
        "UFDR database's {tag} table is missing expected column(s): {columns}"
    ),
    "ufdr.no_table": "UFDR database has no {tag} table in schema {schema}",
    "ufdr.content_not_located": "Content not located in UFDR container: {path}",
    "ufdr.path_collision": (
        "Its path collides with a {other} of the same name; shown under this name instead"
    ),
    "ufdr.device_id_mismatch": (
        "database.json names device {device}, which the database dump doesn't contain; "
        "the tree shows the device(s) the dump holds: {found}"
    ),
    "ufdr.other_directory": "directory",
    "ufdr.other_file": "file",
    "ufdr.rows_skipped": (
        "{count:,} Nodes row(s) with an unreadable Type were left out of the tree"
    ),
    # -- Timestamp column decoding (cell markers) ------------------------------
    "ts_decode.not_a_number": "not a number",
    "ts_decode.out_of_range": "out of range for this format",
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
