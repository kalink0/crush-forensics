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


# code -> English template. Placeholders are filled from params, plus
# {detail}. A param holding a ParseIssue (or a list of them) is rendered
# recursively; lists are joined with "; ".
MESSAGES: dict[str, str] = {
    # -- JSON -------------------------------------------------------------
    "json.syntax_error": (
        "Not valid JSON: {detail}. The tree shows only an excerpt around the "
        "error position; full content: Open as → Text / Hex"
    ),
    "json.not_utf8": (
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
