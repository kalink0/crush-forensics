# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Facts about an NSKeyedArchiver archive's object graph, read before (and
independent of) resolving it into a tree.

Layout, as written by Apple's open-source Foundation
(swift-corelibs-foundation, Sources/Foundation/NSKeyedArchiver.swift):
- `$archiver`, `$version` (100000), `$top`, `$objects`.
- `$objects[0]` is the string "$null"; every nil reference is UID 0.
- `$top` is the archiver's top-level encoding context: `root` for
  archivedData(withRootObject:), but any key encoded at the top level lands
  there too.
- An object refers to other objects by UID (an index into `$objects`), to
  its class via `$class`. In XML plists a UID is a `{"CF$UID": n}` dict
  (swift-corelibs-foundation, Sources/CoreFoundation/CFPropertyList.c). A class definition is a dict with `$classname`
  and `$classes` (optionally `$classhints`), written once per class.
- The archiver keys objects by identity, so an object encoded twice is
  stored once and referenced by several UIDs.

Resolving the graph into a tree (ccl_bplist) copies a shared object into
every place that refers to it, drops objects no UID path from `$top`
reaches, and follows `$top["root"]` only. These counts say what the tree
alone doesn't show.
"""
from __future__ import annotations

import plistlib
from collections import Counter
from dataclasses import dataclass
from typing import Any

from crush.third_party.ccl_bplist.ccl_bplist import BplistUID

ARCHIVERS = ("NSKeyedArchiver", "NRKeyedArchiver")
_NULL = "$null"


def is_keyed_archive(obj: Any) -> bool:
    return isinstance(obj, dict) and obj.get("$archiver") in ARCHIVERS


def _uid_index(value: Any) -> int | None:
    """The `$objects` index a UID points to; None for anything else.

    Binary plists store a UID as its own type (ccl_bplist's BplistUID,
    plistlib.UID). XML plists have none: a UID is written as a dict whose
    only entry is `CF$UID` with an integer, which CoreFoundation reads back
    as a UID (CFPropertyList.c) -- plistlib leaves it a plain dict."""
    if isinstance(value, plistlib.UID):
        return value.data
    if isinstance(value, BplistUID):
        index = value.value
        return index if isinstance(index, int) else None
    if isinstance(value, dict) and len(value) == 1:
        index = value.get("CF$UID")
        if isinstance(index, int) and not isinstance(index, bool):
            return index
    return None


def _uids_in(value: Any) -> list[int]:
    """Every UID inside *value*, however deeply nested in lists/dicts (an
    object's own structure -- never following a UID)."""
    found: list[int] = []
    stack = [value]
    while stack:
        item = stack.pop()
        index = _uid_index(item)
        if index is not None:
            found.append(index)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return found


@dataclass(frozen=True)
class ArchiveStats:
    objects: int              # entries in $objects, including $null
    shared: int               # data objects referenced by more than one UID
    shared_classes: int       # class definitions referenced by more than one UID
    unreachable: int          # objects no UID path from $top reaches
    missing_references: int   # UIDs pointing past the end of $objects
    top_keys: tuple[str, ...]


def archive_stats(archive: dict[str, Any]) -> ArchiveStats | None:
    """Counts over the archive's object graph; None if `$objects` isn't a
    list or `$top` isn't a dict (then there is no graph to count)."""
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        return None

    def is_null_slot(index: int) -> bool:
        return index == 0 and objects[0] == _NULL

    references: Counter[int] = Counter(_uids_in(list(top.values())))
    for entry in objects:
        references.update(_uids_in(entry))

    reachable: set[int] = set()
    pending = [i for i in _uids_in(list(top.values())) if 0 <= i < len(objects)]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        pending.extend(i for i in _uids_in(objects[index]) if 0 <= i < len(objects))

    shared = shared_classes = 0
    for index, count in references.items():
        if count < 2 or not 0 <= index < len(objects) or is_null_slot(index):
            continue
        entry = objects[index]
        if isinstance(entry, dict) and "$classname" in entry:
            shared_classes += 1
        else:
            shared += 1

    unreachable = sum(
        1 for index in range(len(objects))
        if index not in reachable and not is_null_slot(index)
    )
    missing = sum(count for index, count in references.items() if not 0 <= index < len(objects))
    return ArchiveStats(
        objects=len(objects),
        shared=shared,
        shared_classes=shared_classes,
        unreachable=unreachable,
        missing_references=missing,
        top_keys=tuple(str(k) for k in top),
    )
