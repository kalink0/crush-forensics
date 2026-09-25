"""VFS layer reports why an entry is missing, empty or shown as stored
(parser-reason audit, part 2f): disk-image walk failures, an iTunes file
key that can't be read, UFDR rows left out, and password/key rejections
as ParseIssue codes."""
from __future__ import annotations

import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue
from crush.core.passwords import WrongPasswordError
from crush.core.vfs import ITunesBackupVFS, VFSNode, join_notes


def _children(node: VFSNode) -> dict[str, VFSNode]:
    return {c.name: c for c in node.children}


class _Walker:
    """listdir/entry over a small tree, with failures on request."""

    def __init__(self) -> None:
        self.tree = {0: ["ok.txt", "broken", "locked"]}

    def listdir(self, handle: int) -> list[tuple[str, int]]:
        if handle == 3:
            raise OSError("bad directory block")
        return [(name, i + 1) for i, name in enumerate(self.tree.get(handle, []))]

    def entry(self, handle: int) -> tuple[int, int, float]:
        if handle == 2:
            raise ValueError("inode checksum mismatch")
        if handle == 3:
            return stat.S_IFDIR, 0, 0.0
        return stat.S_IFREG, 3, 0.0

    def deleted_files(self) -> Any:
        raise RuntimeError("MFT unreadable")


def test_raw_walk_keeps_unreadable_entries_and_unlisted_folders() -> None:
    from crush.core.raw_image import _walk_into

    walker = _Walker()
    root = VFSNode(name="vol", path="/vol", is_dir=True)
    read_map: dict[str, Any] = {}
    _walk_into(walker, 0, root, read_map, "/vol", set())
    names = _children(root)
    assert names["broken"].status == ParseIssue(
        "entry.raw_entry_unreadable", detail="inode checksum mismatch",
    )
    assert read_map["/vol/broken"].stored == b""
    assert names["locked"].status == ParseIssue("entry.raw_unlisted", detail="bad directory block")
    assert names["ok.txt"].status == ""


def test_raw_deleted_file_enumeration_failure_is_noted() -> None:
    from crush.core.raw_image import _add_deleted_files_node

    volume = VFSNode(name="vol", path="/vol", is_dir=True)
    _add_deleted_files_node(_Walker(), volume, {}, "/vol")
    assert volume.status == ParseIssue("entry.raw_deleted_enum_failed", detail="MFT unreadable")


def test_itunes_unreadable_file_key_says_content_is_ciphertext(
    itunes_backup_fixture: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from crush.core import ios_keybag

    conn = sqlite3.connect(itunes_backup_fixture / "Manifest.db")
    conn.execute("UPDATE Files SET file = ?", (b"not a keyed archive",))
    conn.commit()
    conn.close()

    monkeypatch.setattr(ios_keybag, "extract_file_protection", _raise_value_error)
    vfs = ITunesBackupVFS(itunes_backup_fixture)
    vfs._keybag = object()  # type: ignore[assignment]  # as if encrypted: per-file keys are read
    tree = vfs._build_tree()
    sms = _children(_children(_children(_children(tree)["HomeDomain"])["Library"])["SMS"])["sms.db"]
    assert sms.status.code == "entry.file_key_unreadable"
    assert "ciphertext" in str(sms.status)


def _raise_value_error(_blob: bytes) -> Any:
    raise ValueError("malformed MBFile")


def test_join_notes() -> None:
    first, second = ParseIssue("entry.raw_loop"), ParseIssue("entry.hard_link", {"target": "x"})
    assert join_notes([]) == ""
    assert join_notes(["", first]) == first
    assert str(join_notes([first, second])) == f"{first}; {second}"


def test_password_rejections_are_codes() -> None:
    from crush.core.realm_crypto import parse_hex_key

    with pytest.raises(WrongPasswordError) as excinfo:
        parse_hex_key("00" * 10)
    issue = excinfo.value.args[0]
    assert issue.code == "password.realm_key_length"
    assert str(excinfo.value) == (
        "Realm encryption key must be 64 bytes (128 hex characters) — got 10 bytes"
    )
