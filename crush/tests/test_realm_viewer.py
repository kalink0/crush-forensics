# SPDX-License-Identifier: Apache-2.0
"""Tests for the Realm viewer's Views-tab link resolution (no Qt required)."""
from __future__ import annotations

from crush.viewers.realm_viewer import _build_resolved_view


def _participant_table() -> dict:
    # class_MessageParticipantLocalDto-shaped: obj_keys [10, 20, 30]
    return {
        "column_names": ["id", "email", "name"],
        "columns": {
            0: ["p10", "p20", "p30"],
            1: ["a@x.com", "b@x.com", "c@x.com"],
            2: ["Alice", "", "Carol"],
        },
        "obj_keys": [10, 20, 30],
        "row_count": 3,
    }


def _attachment_table() -> dict:
    return {
        "column_names": ["id", "name", "size"],
        "columns": {
            0: ["a1", "a2"],
            1: ["invoice.pdf", "photo.jpg"],
            2: [1024, 2048],
        },
        "obj_keys": [100, 200],
        "row_count": 2,
    }


def test_build_resolved_view_single_link_uses_only_selected_columns() -> None:
    source = {
        "column_names": ["subject", "sender"],
        "columns": {0: ["Hello", "Bye"], 1: [10, 30]},
        "obj_keys": [1, 2],
        "row_count": 2,
    }
    result = _build_resolved_view(source, [("sender", _participant_table(), ["email"])])
    assert result["columns"] == ["subject", "sender"]
    assert result["rows"] == [
        ["Hello", "email=a@x.com"],
        ["Bye", "email=c@x.com"],
    ]
    assert result["__obj_keys"] == [1, 2]


def test_build_resolved_view_single_link_multiple_selected_columns() -> None:
    source = {
        "column_names": ["subject", "sender"],
        "columns": {0: ["Hello"], 1: [20]},
        "obj_keys": [1],
        "row_count": 1,
    }
    result = _build_resolved_view(source, [("sender", _participant_table(), ["name", "email"])])
    # name is empty for objkey 20 -- selected columns are shown as-is, no
    # guessing/fallback here (that heuristic-avoidance was the whole point).
    assert result["rows"] == [["Hello", "name=, email=b@x.com"]]


def test_build_resolved_view_linklist_joins_multiple_targets() -> None:
    source = {
        "column_names": ["subject", "recipients"],
        "columns": {0: ["Meeting"], 1: [[10, 30]]},
        "obj_keys": [5],
        "row_count": 1,
    }
    result = _build_resolved_view(source, [("recipients", _participant_table(), ["email"])])
    assert result["rows"] == [["Meeting", "email=a@x.com; email=c@x.com"]]


def test_build_resolved_view_empty_linklist_and_unresolved_link_become_none() -> None:
    source = {
        "column_names": ["subject", "recipients", "sender"],
        "columns": {0: ["No one"], 1: [[]], 2: [None]},
        "obj_keys": [9],
        "row_count": 1,
    }
    result = _build_resolved_view(source, [("recipients", _participant_table(), ["email"])])
    assert result["rows"] == [["No one", None, None]]


def test_build_resolved_view_resolves_multiple_link_columns_in_one_pass() -> None:
    """A table with several Link/LinkList columns (e.g. class_MessageAttributesLocalDto's
    from/to/attachments) can be resolved together in one call, each against
    its own target table and column selection -- the scenario that needed
    one tab per column before."""
    source = {
        "column_names": ["subject", "from", "attachments"],
        "columns": {
            0: ["Invoice"],
            1: [10],
            2: [[100, 200]],
        },
        "obj_keys": [1],
        "row_count": 1,
    }
    result = _build_resolved_view(
        source,
        [
            ("from", _participant_table(), ["email"]),
            ("attachments", _attachment_table(), ["name"]),
        ],
    )
    assert result["rows"] == [
        ["Invoice", "email=a@x.com", "name=invoice.pdf; name=photo.jpg"]
    ]


def test_build_resolved_view_link_column_not_configured_stays_raw() -> None:
    """Only the configured link columns are touched -- others (e.g. because
    the user left that group's checklist empty) keep their raw value."""
    source = {
        "column_names": ["subject", "from", "attachments"],
        "columns": {0: ["Invoice"], 1: [10], 2: [[100]]},
        "obj_keys": [1],
        "row_count": 1,
    }
    result = _build_resolved_view(source, [("from", _participant_table(), ["email"])])
    assert result["rows"] == [["Invoice", "email=a@x.com", [100]]]
