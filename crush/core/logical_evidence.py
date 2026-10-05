# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Logical evidence: EnCase L01 and FTK Imager AD1, read with the vendored
ewfprobe -- no Qt dependency.

Logical evidence holds copies of the files an examiner selected, not a
disk: its own entry list is the tree. Every entry is shown as stored:

- An entry can hold data of its own and entries beneath it at once (an
  L01 plist with its parsed children, an AD1 file with a named stream, an
  AD1 folder with its index data). It is shown as a folder, and its own
  data as an entry inside it that says so -- nothing is hidden.
- Names can repeat (an AD1 lists a deleted file more than once) and can
  hold "\\" or ":" (an AD1's top entries are named for their sources);
  both are kept. A "/" in a name can't be a path separator here and shows
  as "∕", which the entry's status says.
- The hashes and times each entry stores are shown with where they come
  from; nothing is converted. AD1 times are UTC (checked against FTK
  Imager's own listing of the same image); L01 times are POSIX (UTC).

Lx01 (EWF2 logical evidence) is not read by ewfprobe and stays refused.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crush.core.issues import ParseIssue
from crush.core.passwords import (
    PasswordRequiredError,
    PrivateKeyRequiredError,
    WrongPasswordError,
    WrongPrivateKeyError,
)
from crush.core.stored_times import ACCESSED, BIRTH, CHANGED, MODIFIED, StoredTime
from crush.third_party.ewfprobe import ewfprobe as _ewfprobe

# qnxprobe resolves ewfprobe by its bare name (see raw_image).
sys.modules.setdefault("ewfprobe", _ewfprobe)

if TYPE_CHECKING:
    from crush.core.vfs import VFSNode

FORMAT_L01 = _ewfprobe.FORMAT_L01
FORMAT_AD1 = _ewfprobe.FORMAT_AD1
_LOGICAL_FORMATS = (FORMAT_L01, FORMAT_AD1)

# L01 time columns (EWF-L01 ltree): which MACB kind each one is. dl (deleted)
# and aq (acquired) are no MACB kind and are listed with the entry's info.
_L01_TIME_KINDS = {"cr": BIRTH, "ac": ACCESSED, "wr": MODIFIED, "mo": CHANGED}
_L01_OTHER_TIMES = {"dl": "Deleted (L01)", "aq": "Acquired (L01)"}
_AD1_TIME_KINDS = {"created": BIRTH, "modified": MODIFIED, "accessed": ACCESSED}


class LogicalEvidenceOpenError(ValueError):
    """The path is logical evidence ewfprobe can't read (a damaged or
    incomplete set, an unsupported version)."""


class NotLogicalEvidenceError(ValueError):
    """The path opened, but holds a disk rather than files (an AD-encrypted
    E01 or raw set): it is read as a disk image instead."""


class LogicalEntryUnreadableError(OSError):
    """ewfprobe could not return this entry's content."""


@dataclass
class LogicalHandle:
    """An opened L01 or AD1 set."""

    path: Path
    image: Any  # ewfprobe.EwfImage
    # The reader's description: the files the set is read from and what
    # opened it when encrypted.
    container: str = ""
    entries: dict[str, Any] = field(default_factory=dict)  # virtual path -> entry

    @property
    def kind(self) -> str:
        return str(self.image.format)

    def close(self) -> None:
        try:
            self.image.close()
        except Exception:  # pragma: no cover — best-effort cleanup
            pass


def open_logical_evidence(
    path: Path, *, password: str = "", private_key: str = ""
) -> LogicalHandle:
    """Open the L01 or AD1 set *path* belongs to (from any of its files),
    AD-encrypted or not. Raises the password errors (crush.core.passwords)
    for an encrypted set, NotLogicalEvidenceError when it holds a disk, and
    LogicalEvidenceOpenError when ewfprobe can't read it."""
    from crush.third_party import qnxprobe

    try:
        image = _ewfprobe.open_ewf(
            str(path), password=password or None, private_key=private_key or None,
        )
    except _ewfprobe.EwfPasswordRequiredError as exc:
        by_key = exc.needs == "private key"
        required = PrivateKeyRequiredError if by_key else PasswordRequiredError
        raise required(ParseIssue(
            "password.image_key_required" if by_key else "password.image_required",
            {"path": str(path)}, detail=str(exc),
        )) from exc
    except _ewfprobe.EwfWrongPasswordError as exc:
        wrong = WrongPrivateKeyError if private_key and not password else WrongPasswordError
        raise wrong(ParseIssue(
            "password.image_wrong_key" if wrong is WrongPrivateKeyError
            else "password.image_wrong",
            detail=str(exc),
        )) from exc
    except (_ewfprobe.EwfError, OSError) as exc:
        raise LogicalEvidenceOpenError(f"{path.name}: {exc}") from exc
    if image.format not in _LOGICAL_FORMATS:
        image.close()  # type: ignore[no-untyped-call]
        raise NotLogicalEvidenceError(f"{path.name} holds {image.format}, not logical evidence")
    container = qnxprobe.describe_acquisition(image)  # type: ignore[no-untyped-call]
    return LogicalHandle(path=path, image=image, container=str(container))


def build_tree(handle: LogicalHandle) -> "VFSNode":
    """The source's tree from the set's own entry list; fills
    handle.entries (virtual path -> entry, for reading)."""
    from crush.core.vfs import VFSNode, _mark_duplicates

    root = VFSNode(name=handle.path.name, path="/", is_dir=True)
    nodes: dict[str, VFSNode] = {"/": root}
    occurrences: dict[str, list[VFSNode]] = {}
    _add_children(handle, handle.image.logical_root, root, nodes, occurrences)
    _mark_duplicates(occurrences)
    for node in nodes.values():
        node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
    return root


def _add_children(
    handle: LogicalHandle, entry: Any, parent: "VFSNode",
    nodes: dict[str, "VFSNode"], occurrences: dict[str, list["VFSNode"]],
) -> None:
    from crush.core.vfs import VFSNode, _free_sibling, join_notes

    for child in entry.children:
        # A name is one path component: a "/" in it shows as "∕" (status says so).
        name = child.name.replace("/", "∕")
        stored_path = f"{parent.path.rstrip('/')}/{name}"
        shown, path = name, stored_path
        if path in nodes:
            shown, path = _free_sibling(nodes, parent.path, name)
        times = entry_times(handle, child)
        statuses = _statuses(handle, child)
        is_dir = bool(child.children) or child.is_folder
        node = VFSNode(
            name=shown, path=path, is_dir=is_dir, size=0 if is_dir else child.size,
            stored_times=times, status=join_notes(statuses),
        )
        _set_floats(node, times)
        parent.children.append(node)
        nodes[path] = node
        occurrences.setdefault(stored_path, []).append(node)
        if not is_dir:
            handle.entries[path] = child
            continue
        _add_children(handle, child, node, nodes, occurrences)
        if child.size:
            # The entry's own data: beside the entries beneath it, never
            # hidden behind them.
            own_name, own_path = name, f"{path}/{name}"
            if own_path in nodes:
                own_name, own_path = _free_sibling(nodes, path, name)
            own = VFSNode(
                name=own_name, path=own_path, is_dir=False, size=child.size,
                stored_times=times,
                status=join_notes([ParseIssue("entry.logical_own_data", {"name": name}),
                                   *statuses]),
            )
            _set_floats(own, times)
            node.children.append(own)
            nodes[own_path] = own
            handle.entries[own_path] = child


def _statuses(handle: LogicalHandle, entry: Any) -> list[ParseIssue]:
    """What the analyst must know about *entry* that its name and bytes
    don't show."""
    out: list[ParseIssue] = []
    if "/" in entry.name:
        out.append(ParseIssue("entry.name_has_slash"))
    if handle.kind == FORMAT_AD1 and entry.is_deleted:
        out.append(ParseIssue("entry.ad1_deleted"))
    if handle.kind == FORMAT_L01 and entry.flags & _ewfprobe.L01_FLAG_SPARSE:
        out.append(ParseIssue(
            "entry.l01_sparse_duplicate" if entry.duplicate_offset is not None
            else "entry.l01_sparse_byte"
        ))
    return out


def entry_times(handle: LogicalHandle, entry: Any) -> list[StoredTime]:
    """The MACB times *entry* stores, as instants (UTC), with their source."""
    out: list[StoredTime] = []
    if handle.kind == FORMAT_AD1:
        for key, kind in _AD1_TIME_KINDS.items():
            if key in entry.times:
                out.append(StoredTime(
                    kind, ParseIssue("time.ad1_record", {"name": key}), utc=float(entry.times[key]),
                ))
    else:
        for key, kind in _L01_TIME_KINDS.items():
            if key in entry.times:
                out.append(StoredTime(
                    kind, ParseIssue("time.l01_column", {"name": key}), utc=float(entry.times[key]),
                ))
    return out


def _set_floats(node: "VFSNode", times: list[StoredTime]) -> None:
    for t in times:
        if t.utc is None:
            continue
        if t.kind == MODIFIED and not node.modified:
            node.modified = t.utc
        elif t.kind == ACCESSED and not node.accessed:
            node.accessed = t.utc
        elif t.kind == CHANGED and not node.changed:
            node.changed = t.utc
        elif t.kind == BIRTH and not node.birth:
            node.birth = t.utc


def entry_info(handle: LogicalHandle, entry: Any) -> dict[str, Any]:
    """What the set stores about *entry* beyond its name, size and MACB
    times: its MD5/SHA-1 (as the acquisition tool recorded them), L01's
    deletion and acquisition times, AD1's item type and type record -- each
    as stored."""
    from crush.core.ts_decode import unix_to_utc

    not_recorded = ParseIssue("logical.not_recorded")
    info: dict[str, Any] = {
        "Recorded MD5": entry.md5 or not_recorded,
        "Recorded SHA-1": entry.sha1 or not_recorded,
    }
    if handle.kind == FORMAT_L01:
        for key, label in _L01_OTHER_TIMES.items():
            raw = entry.values.get(key, "")
            if raw.lstrip("-").isdigit():
                ts = unix_to_utc(int(raw))
                info[label] = (
                    ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts is not None
                    else ParseIssue("ts_decode.out_of_range")
                )
    else:
        info["AD1 item type"] = str(entry.item_type)
        if entry.type_code is not None:
            info["AD1 type record"] = entry.type_code
    return info


def read_entry(handle: LogicalHandle, entry: Any) -> bytes:
    try:
        return bytes(handle.image.read_entry(entry))
    except _ewfprobe.EwfError as exc:
        raise LogicalEntryUnreadableError(f"{entry.path}: {exc}") from exc


def open_entry(handle: LogicalHandle, entry: Any) -> Any:
    try:
        return handle.image.open_entry(entry)
    except _ewfprobe.EwfError as exc:
        raise LogicalEntryUnreadableError(f"{entry.path}: {exc}") from exc
