# SPDX-License-Identifier: Apache-2.0
"""A ZIP holding an iTunes backup, opened with the backup: the whole ZIP is
shown, the backup's folder holding the opened backup. Shaped like a real
UFADE ZIP (backup under iPhoneDump/Backup Service/<UDID>/Snapshot/ next to
AFC Service/, Applications/ and Lockdown Service/) and like a plainly
zipped backup (one wrapper folder)."""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from crush.core.mounted import ZipWithITunesBackupVFS
from crush.core.passwords import PasswordRequiredError, WrongPasswordError
from crush.core.vfs import ITunesBackupVFS, VFSNode

UDID = "00008030-000A2D6E3601C01F"
SNAPSHOT = f"iPhoneDump/Backup Service/{UDID}/Snapshot"


def _find(node: VFSNode, *parts: str) -> VFSNode:
    for part in parts:
        node = next(c for c in node.children if c.name == part)
    return node


def _names(node: VFSNode) -> list[str]:
    return [c.name for c in node.children]


def _extraction_zip(tmp_path: Path, factory: Any, password: str = "") -> Path:
    build = tmp_path / "build"
    build.mkdir()
    backup: Path = factory(build, password=password)
    zip_path = tmp_path / "extraction.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("iPhoneDump/Applications/it.twsweb.Nextcloud/chat.zip", b"PK\x05\x06" + bytes(18))
        zf.writestr("iPhoneDump/Lockdown Service/device_values.plist", b"<plist/>")
        for f in backup.rglob("*"):
            if f.is_file():
                zf.write(f, f"{SNAPSHOT}/{f.relative_to(backup).as_posix()}")
    return zip_path


def test_everything_beside_the_backup_is_shown(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    vfs = ZipWithITunesBackupVFS(_extraction_zip(tmp_path, itunes_backup_keybag_factory))
    dump = _find(vfs.root(), "iPhoneDump")
    assert _names(dump) == ["Applications", "Backup Service", "Lockdown Service"]
    chat = _find(dump, "Applications", "it.twsweb.Nextcloud", "chat.zip")
    assert vfs.read(chat) == b"PK\x05\x06" + bytes(18)

    snapshot = _find(dump, "Backup Service", UDID, "Snapshot")
    assert str(snapshot.status) == (
        "An iTunes backup, opened as one (no password recorded or entered); the files the "
        "ZIP stores for it are shown when the ZIP is opened as a plain ZIP"
    )
    sms = _find(snapshot, "HomeDomain", "Library", "SMS", "sms.db")
    assert vfs.read(sms) == b"SQLite format 3\x00"
    inner_vfs, inner = vfs.delegate(sms)
    assert isinstance(inner_vfs, ITunesBackupVFS)
    assert inner_vfs.original_backup_path(inner) == "3d/3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"
    vfs.close()


def test_plainly_zipped_backup_sits_in_its_wrapper_folder(itunes_backup_zip_fixture: Path) -> None:
    vfs = ZipWithITunesBackupVFS(itunes_backup_zip_fixture)
    assert _names(vfs.root()) == ["wrapper"]
    wrapper = vfs.root().children[0]
    assert "An iTunes backup, opened as one" in str(wrapper.status)
    sms = _find(wrapper, "HomeDomain", "Library", "SMS", "sms.db")
    assert vfs.read(sms) == b"SQLite format 3\x00"
    vfs.close()


def test_backup_at_the_zip_root_opens_as_the_root(
    tmp_path: Path, itunes_backup_keybag_fixture: Path,
) -> None:
    # Zipped with no folder around it: Manifest.db at the ZIP's root.
    zip_path = tmp_path / "root_backup.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for f in itunes_backup_keybag_fixture.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(itunes_backup_keybag_fixture).as_posix())
    vfs = ZipWithITunesBackupVFS(zip_path)
    assert "An iTunes backup, opened as one" in str(vfs.root().status)
    assert _names(vfs.root()) == ["HomeDomain"]
    sms = _find(vfs.root(), "HomeDomain", "Library", "SMS", "sms.db")
    assert vfs.read(sms) == b"SQLite format 3\x00"
    vfs.close()


def test_encrypted_backup_asks_and_opens_with_the_typed_password(
    tmp_path: Path, itunes_backup_keybag_factory: Any,
) -> None:
    zip_path = _extraction_zip(tmp_path, itunes_backup_keybag_factory, password="secret")
    with pytest.raises(PasswordRequiredError):
        ZipWithITunesBackupVFS(zip_path)
    with pytest.raises(WrongPasswordError):
        ZipWithITunesBackupVFS(zip_path, password="wrong")
    vfs = ZipWithITunesBackupVFS(zip_path, password="secret")
    snapshot = _find(vfs.root(), "iPhoneDump", "Backup Service", UDID, "Snapshot")
    assert "(with the password entered)" in str(snapshot.status)
    notes = _find(snapshot, "HomeDomain", "Library", "Notes", "notes.sqlite")
    assert vfs.read(notes) == b"protected note content" * 4
    vfs.close()
