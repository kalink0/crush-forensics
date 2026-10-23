# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Stored bytes that carry a form Crush derived from them.

A parser that decodes a value's bytes (e.g. a plist embedded in a plist's
data value) keeps the bytes as the value -- they are what the file holds
-- and hangs the decoded form next to them, labelled as derived. Viewers
show it as a child of the bytes; text exports write both.
"""
from __future__ import annotations

from typing import Any


class DerivedBytes(bytes):
    """The stored bytes, unchanged (equal to them, usable as them), plus
    *derived*: what Crush decoded from them as *kind* (e.g. "plist"), or a
    ParseIssue saying why decoding failed. *resolved_archive*: *derived* is
    a tree resolved from an NSKeyedArchiver archive (its $class keys are
    class metadata, not data)."""

    kind: str
    derived: Any
    resolved_archive: bool

    def __new__(
        cls, value: bytes, kind: str, derived: Any, *, resolved_archive: bool = False
    ) -> DerivedBytes:
        obj = super().__new__(cls, value)
        obj.kind = kind
        obj.derived = derived
        obj.resolved_archive = resolved_archive
        return obj


def derived_label(kind: str) -> str:
    """Key of the derived form next to the bytes in text exports."""
    return f"decoded ({kind})"


def expand_derived(value: Any) -> Any:
    """*value* for a text export: each DerivedBytes as a dict of its bytes
    (key "bytes") and its derived form (derived_label), all the way down."""
    if isinstance(value, DerivedBytes):
        return {"bytes": bytes(value), derived_label(value.kind): expand_derived(value.derived)}
    if isinstance(value, dict):
        return {key: expand_derived(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_derived(item) for item in value]
    return value
