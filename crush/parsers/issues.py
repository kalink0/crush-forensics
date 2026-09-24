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
- `detail` is the library's own diagnosis. It is never translated, never
  shortened, and always rendered where the template places it.

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
