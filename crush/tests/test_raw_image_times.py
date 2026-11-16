# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Times from the inode or catalog record of ext, APFS, HFS+ and Btrfs
entries in a disk image (qnxprobe's walker.times()), read when Properties
asks for them (RawImageVFS.stored_times).

The decoding itself is qnxprobe's, checked there against known-data
fixtures (ext, APFS, HFS+); these tests check what Crush makes of it."""
from __future__ import annotations

import gzip
import threading
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QLabel

from crush.core.issues import ParseIssue
from crush.core.raw_image import walker_stored_times
from crush.core.stored_times import ACCESSED, BACKUP, BIRTH, CHANGED, MODIFIED, StoredTime
from crush.core.vfs import RawImageVFS, VFSNode
from crush.third_party.qnxprobe.qnxprobe import ApfsWalker, ExtWalker, HfsPlusWalker

FIXTURES = Path(__file__).parent / "fixtures"


def _vfs(tmp_path: Path, name: str) -> RawImageVFS:
    img = tmp_path / f"{name}.img"
    img.write_bytes(gzip.decompress((FIXTURES / f"{name}.img.gz").read_bytes()))
    return RawImageVFS(img)


def _node(vfs: RawImageVFS, path: str) -> VFSNode:
    stack = list(vfs.root().children)
    while stack:
        n = stack.pop()
        if n.path == path:
            return n
        stack.extend(n.children)
    raise AssertionError(f"{path} not in the tree")


def _fake(cls: type, times: Any) -> Any:
    """A walker of *cls* whose times() returns *times* (counting the calls)."""
    walker = object.__new__(cls)
    walker.calls = 0

    def _times(_node: Any) -> Any:
        walker.calls += 1
        if isinstance(times, Exception):
            raise times
        return times

    walker.times = _times
    return walker


@pytest.mark.parametrize(("name", "path", "source"), [
    ("raw_decmpfs_apfs", "/lba0/DECMPFS", "APFS inode record"),
    ("raw_decmpfs_hfsplus", "/lba0/method01", "HFS+ catalog record"),
    ("raw_btrfs", "/lba0/dir", "Btrfs inode item"),
])
def test_entry_shows_every_time_its_record_holds(
    tmp_path: Path, name: str, path: str, source: str
) -> None:
    vfs = _vfs(tmp_path, name)
    node = _node(vfs, path)
    times = vfs.stored_times(node)
    assert isinstance(times, list)
    assert [t.kind for t in times] == [MODIFIED, ACCESSED, CHANGED, BIRTH]
    assert {str(t.source) for t in times} == {source}
    # the same record the listing's Modified comes from, to the second
    assert int(times[0].utc or 0) == int(node.modified or 0)


def test_apfs_container_has_no_record_and_keeps_the_listing(tmp_path: Path) -> None:
    vfs = _vfs(tmp_path, "raw_decmpfs_apfs")
    root = _node(vfs, "/lba0")
    assert vfs.stored_times(root) == root.stored_times == []


def test_kinds_sources_and_unstored_times() -> None:
    walker = _fake(HfsPlusWalker, {
        "modified": (1_700_000_000, 0), "accessed": None, "changed": (1_700_000_001, 0),
        "created": (1_600_000_000, 0), "backup": (1_650_000_000, 0),
    })
    times = walker_stored_times(walker, object())
    assert times == [
        StoredTime(MODIFIED, ParseIssue("time.hfsplus_catalog"), utc=1_700_000_000.0),
        StoredTime(CHANGED, ParseIssue("time.hfsplus_catalog"), utc=1_700_000_001.0),
        StoredTime(BIRTH, ParseIssue("time.hfsplus_catalog"), utc=1_600_000_000.0),
        StoredTime(BACKUP, ParseIssue("time.hfsplus_catalog"), utc=1_650_000_000.0),
    ]


def test_ext_nanoseconds_and_negative_seconds() -> None:
    walker = _fake(ExtWalker, {
        "modified": (1_700_000_000, 500_000_000), "accessed": (-1, 0),
        "changed": (0, 0), "created": None,
    })
    times = walker_stored_times(walker, object())
    assert times is not None
    assert [(t.kind, t.utc) for t in times] == [
        (MODIFIED, 1_700_000_000.5), (ACCESSED, -1.0), (CHANGED, 0.0),
    ]
    assert str(times[0].source) == "ext inode"


def test_apfs_zero_is_the_stored_time() -> None:
    """The APFS reference has no "unset" value: a stored 0 is 1970-01-01."""
    walker = _fake(ApfsWalker, {
        "modified": (0, 0), "accessed": (0, 0), "changed": (0, 0), "created": (0, 0),
    })
    times = walker_stored_times(walker, object())
    assert times is not None
    assert [t.utc for t in times] == [0.0, 0.0, 0.0, 0.0]


def test_no_record_gives_none() -> None:
    assert walker_stored_times(_fake(ExtWalker, None), object()) is None


def _vfs_with(walker: Any, path: str = "/lba0/f") -> tuple[RawImageVFS, VFSNode]:
    vfs = object.__new__(RawImageVFS)
    vfs._lock = threading.Lock()
    vfs._times_map = {path: (walker, object())}
    vfs._times_read = {}
    return vfs, VFSNode(name="f", path=path, is_dir=False, modified=5.0)


def test_read_once_on_request_then_kept() -> None:
    walker = _fake(ExtWalker, {"modified": (5, 0)})
    vfs, node = _vfs_with(walker)
    assert walker.calls == 0
    first = vfs.stored_times(node)
    assert vfs.stored_times(node) is first
    assert walker.calls == 1


def test_unreadable_record_is_said() -> None:
    vfs, node = _vfs_with(_fake(ExtWalker, ValueError("inode 12 past the end")))
    issue = vfs.stored_times(node)
    assert isinstance(issue, ParseIssue)
    assert issue.code == "time.raw_times_unreadable"
    assert "inode 12 past the end" in str(issue)


def _row_labels(panel: Any) -> list[str]:
    from PySide6.QtWidgets import QFormLayout

    labels = []
    for row in range(panel._layout.rowCount()):
        item = panel._layout.itemAt(row, QFormLayout.ItemRole.LabelRole)
        if item is not None and isinstance(item.widget(), QLabel):
            labels.append(item.widget().text())
    return labels


def test_backup_row_only_where_stored(qapp, widgets) -> None:
    from crush.ui.props_panel import PropertiesPanel

    src = ParseIssue("time.hfsplus_catalog")
    panel = widgets(PropertiesPanel())
    panel._add_stored_times([StoredTime(MODIFIED, src, utc=0.0), StoredTime(BACKUP, src, utc=1.0)])
    assert _row_labels(panel) == ["Modified:", "Accessed:", "Changed:", "Birth:", "Backup:"]

    panel = widgets(PropertiesPanel())
    panel._add_stored_times([StoredTime(MODIFIED, src, utc=0.0)])
    assert "Backup:" not in _row_labels(panel)
