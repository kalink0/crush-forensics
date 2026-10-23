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

Resolving the graph into a tree (resolve_keyed_archive, on ccl_bplist)
copies a shared object into every place that refers to it and drops
objects no UID path from `$top` reaches. When `$top` holds `root` only,
the tree starts at the root object; when it holds other keys too (or no
`root`), the tree is `$top` itself, each key resolved under its name.
These counts say what the tree alone doesn't show.
"""
from __future__ import annotations

import datetime
import plistlib
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from typing import Any, cast

from crush.core.issues import ParseIssue
from crush.third_party.ccl_bplist import (
    deserialise_NsKeyedArchiver,
    load as bplist_load,
    set_object_converter,
)
from crush.third_party.ccl_bplist.ccl_bplist import (
    BplistUID,
    NSKeyedArchiver_common_objects_convertor,
    is_nsdate,
    is_nsmutabledictionary,
)

ARCHIVERS = ("NSKeyedArchiver", "NRKeyedArchiver")
_NULL = "$null"
# NSDate's reference date, as ccl_bplist converts NS.time (naive, UTC).
_NSDATE_EPOCH = datetime.datetime(2001, 1, 1)


def convert_common_objects(obj: Any) -> Any:
    """ccl_bplist's NSKeyedArchiver_common_objects_convertor, except that an
    NSDictionary which can't become a Python dict stays as stored (its
    `NS.keys` and `NS.objects`, paired by index) instead of failing the
    whole archive: NSDictionary takes any NSCopying object as a key, e.g.
    another dictionary (unhashable here), and keys that compare equal once
    resolved would collapse."""
    try:
        return cast(Any, NSKeyedArchiver_common_objects_convertor)(obj)
    except (TypeError, ValueError):
        if cast(Any, is_nsmutabledictionary)(obj):
            return obj
        raise


def _class_name(obj: dict[str, Any]) -> str:
    class_meta = obj.get("$class")
    return str(class_meta.get("$classname", "")) if isinstance(class_meta, dict) else ""


def _nsdate(seconds: Any) -> datetime.datetime | None:
    """NS.time as ccl_bplist converts it; None when that's no datetime
    (NaN, beyond year 1..9999, not a number)."""
    try:
        return _NSDATE_EPOCH + datetime.timedelta(seconds=seconds)
    except (OverflowError, ValueError, TypeError):
        return None


_DATE_COMPONENT_LABELS = (
    ("NS.year", "year"), ("NS.month", "month"), ("NS.day", "day"),
    ("NS.hour", "hour"), ("NS.minute", "min"), ("NS.second", "sec"),
    ("NS.weekday", "weekday"), ("NS.weekOfYear", "week"),
)


def convert_object(obj: Any) -> Any:
    """The object converter for resolving an archive: convert_common_objects
    plus NSData, NSNull, NSUUID and NSDateComponents. An NSDate whose
    NS.time isn't a representable date and an NSUUID whose NS.uuidbytes
    aren't 16 bytes stay as stored instead of failing the whole archive."""
    if cast(Any, is_nsdate)(obj) and _nsdate(obj["NS.time"]) is None:
        return obj
    result = convert_common_objects(obj)
    if result is not obj or not isinstance(obj, dict):
        return result
    classname = _class_name(obj)
    if classname in ("NSData", "NSMutableData"):
        return obj.get("NS.data", b"")
    if classname == "NSNull":
        return None
    if classname == "NSUUID":
        # Foundation's uuidString: the 16 bytes, uppercase, 8-4-4-4-12.
        raw = obj.get("NS.uuidbytes")
        if isinstance(raw, bytes) and len(raw) == 16:
            return str(uuid.UUID(bytes=raw)).upper()
        return obj
    if classname == "NSDateComponents":
        parts = [
            f"{label}={obj[field]}"
            for field, label in _DATE_COMPONENT_LABELS
            if field in obj and obj[field] not in (None, -1)
        ]
        return f"NSDateComponents({', '.join(parts)})"
    return result


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


def root_class(archive: dict[str, Any]) -> str | ParseIssue:
    """`$classname` of the object `$top["root"]` points to -- the resolved
    tree starts at that object and has no row of its own to show it in."""
    top = archive.get("$top")
    objects = archive.get("$objects")
    if not isinstance(top, dict) or "root" not in top:
        return ParseIssue("plist.nska_root_none")
    index = _uid_index(top["root"])
    if index is None:
        # Stored in $top itself rather than referenced: a plain value.
        return ParseIssue("plist.nska_root_plain", {"type": type(top["root"]).__name__})
    if not isinstance(objects, list) or not 0 <= index < len(objects):
        return ParseIssue("plist.nska_root_missing")
    entry = objects[index]
    class_index = _uid_index(entry.get("$class")) if isinstance(entry, dict) else None
    if class_index is None:
        # Strings, numbers and data are stored as plain values, without a class.
        return ParseIssue("plist.nska_root_plain", {"type": type(entry).__name__})
    if not 0 <= class_index < len(objects):
        return ParseIssue("plist.nska_root_missing")
    definition = objects[class_index]
    name = definition.get("$classname") if isinstance(definition, dict) else None
    return str(name) if name is not None else ParseIssue("plist.nska_root_no_classname")


@dataclass(frozen=True)
class ArchiveStats:
    objects: int              # entries in $objects, including $null
    shared: int               # data objects referenced by more than one UID
    shared_classes: int       # class definitions referenced by more than one UID
    unreachable: int          # objects no UID path from $top reaches
    missing_references: int   # UIDs pointing past the end of $objects
    has_cycle: bool           # an object reaches itself through its UIDs
    top_keys: tuple[str, ...]


def _has_cycle(objects: list[Any]) -> bool:
    """Whether any `$objects` entry reaches itself by following UIDs (e.g. a
    child pointing back at its parent) -- anywhere in the table, reachable
    from `$top` or not. A resolved tree of such a graph has no end."""
    count = len(objects)

    def targets(index: int) -> list[int]:
        return [i for i in _uids_in(objects[index]) if 0 <= i < count]

    # Depth-first, without recursion: 1 = on the current path, 2 = done.
    state = [0] * count
    for start in range(count):
        if state[start]:
            continue
        state[start] = 1
        path = [(start, iter(targets(start)))]
        while path:
            index, pending = path[-1]
            target = next(pending, None)
            if target is None:
                state[index] = 2
                path.pop()
            elif state[target] == 1:
                return True
            elif state[target] == 0:
                state[target] = 1
                path.append((target, iter(targets(target))))
    return False


def _reachable(objects: list[Any], top: dict[Any, Any]) -> set[int]:
    """`$objects` indexes some UID path from `$top` reaches."""
    reachable: set[int] = set()
    pending = [i for i in _uids_in(list(top.values())) if 0 <= i < len(objects)]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        pending.extend(i for i in _uids_in(objects[index]) if 0 <= i < len(objects))
    return reachable


def unconvertible_dates(archive: dict[str, Any]) -> int | None:
    """NSDate objects in the resolved tree whose NS.time is no representable
    date (convert_object keeps those as stored): the ones some UID path
    from `$top` reaches, counted once each however often they're
    referenced. None when there is no graph (see archive_stats)."""
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        return None
    count = 0
    for index in _reachable(objects, top):
        entry = objects[index]
        if not isinstance(entry, dict) or "NS.time" not in entry:
            continue
        class_index = _uid_index(entry.get("$class"))
        if class_index is None or not 0 <= class_index < len(objects):
            continue
        # The class resolved as the converter sees it, checked by
        # ccl_bplist's own NSDate test so both count the same objects.
        definition = objects[class_index]
        if not isinstance(definition, dict) or not isinstance(definition.get("$classname"), str):
            continue
        if cast(Any, is_nsdate)({**entry, "$class": definition}):
            count += _nsdate(entry["NS.time"]) is None
    return count


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

    reachable = _reachable(objects, top)

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
        has_cycle=_has_cycle(objects),
        top_keys=tuple(str(k) for k in top),
    )


@dataclass(frozen=True)
class Resolution:
    """resolve_keyed_archive's outcome: the resolved *tree*, or -- when the
    archive wasn't resolved -- None and why: *unresolvable* (missing
    references, a cycle; resolving not attempted) or *error* (resolving
    raised; the library's message)."""

    tree: Any = None
    unresolvable: tuple[ParseIssue, ...] = ()
    error: str | None = None

    @property
    def resolved(self) -> bool:
        return not self.unresolvable and self.error is None


def _with_uids(value: Any) -> Any:
    """An XML archive with each `{"CF$UID": n}` as a UID, as CoreFoundation
    reads it back (same test as _uid_index), for the binary form."""
    index = _uid_index(value)
    if index is not None:
        return plistlib.UID(index)
    if isinstance(value, dict):
        return {key: _with_uids(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_with_uids(item) for item in value]
    return value


def _materialize(value: Any) -> Any:
    """ccl_bplist's lazily resolved tree as plain dicts and lists, each
    object converted once: what every view and the text show is then one
    fixed tree."""
    if isinstance(value, dict):
        return {key: _materialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_materialize(item) for item in value]
    return value


def resolve_keyed_archive(archive: dict[str, Any], *, xml: bool) -> Resolution:
    """*archive* (as loaded: ccl_bplist's binary form, or plistlib's for
    *xml*) resolved into a tree, the one way every view resolves one.

    Not attempted when a UID points past the end of `$objects` or an object
    reaches itself (archive_stats): ccl_bplist resolves lazily, so the
    first fails only where something reaches it and the second never ends.
    An XML archive is written as a binary plist in memory (its CF$UID dicts
    as UIDs) and resolved like one. `$top` holding `root` only resolves to
    the root object; any other key (or no `root`) resolves all of `$top`."""
    stats = archive_stats(archive)
    unresolvable: list[ParseIssue] = []
    if stats is not None and stats.missing_references:
        unresolvable.append(ParseIssue("plist.nska_missing_refs", {"count": stats.missing_references}))
    if stats is not None and stats.has_cycle:
        unresolvable.append(ParseIssue("plist.nska_cycle"))
    if unresolvable:
        return Resolution(unresolvable=tuple(unresolvable))
    try:
        stored: Any = archive
        if xml:
            binary = plistlib.dumps(_with_uids(archive), fmt=plistlib.FMT_BINARY, sort_keys=False)
            stored = cast(Any, bplist_load)(BytesIO(binary))
        top = stored.get("$top")
        whole = isinstance(top, dict) and any(key != "root" for key in top)
        cast(Callable[[Any], None], set_object_converter)(convert_object)
        tree = _materialize(
            cast(Any, deserialise_NsKeyedArchiver)(stored, parse_whole_structure=whole)
        )
    except Exception as exc:
        return Resolution(error=str(exc))
    return Resolution(tree=tree)
