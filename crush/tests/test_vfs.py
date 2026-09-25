# SPDX-License-Identifier: Apache-2.0
"""Tests for the VFS abstraction layer."""
from __future__ import annotations

import gzip
import plistlib
import zipfile
from pathlib import Path

import pytest

from crush.core.passwords import PasswordRequiredError, WrongPasswordError
from crush.core.vfs import (
    AndroidBackupVFS,
    DirectoryVFS,
    FileVFS,
    GzipVFS,
    ITunesBackupVFS,
    SevenZipVFS,
    TarVFS,
    ZipVFS,
    detect_itunes_backup_in_zip,
    open_itunes_backup_from_zip,
    open_vfs,
)
from crush.tests.conftest import FIXTURES_DIR


def test_directory_vfs(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "test.db").write_bytes(b"SQLite format 3\x00data")
    (tmp_path / "notes.txt").write_bytes(b"hello")

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()

    assert root.is_dir
    names = {child.name for child in root.children}
    assert "subdir" in names
    assert "notes.txt" in names


def test_directory_vfs_read(tmp_path: Path) -> None:
    content = b"SQLite format 3\x00"
    (tmp_path / "test.db").write_bytes(content)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    file_node = next(c for c in root.children if c.name == "test.db")

    assert vfs.read(file_node) == content
    assert vfs.peek(file_node, 16) == content[:16]


def test_zip_vfs(tmp_path: Path) -> None:
    zip_path = tmp_path / "extraction.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("var/mobile/Library/SMS/sms.db", b"SQLite format 3\x00")
        zf.writestr("var/mobile/Library/Preferences/com.apple.test.plist", b"bplist00")

    vfs = ZipVFS(zip_path)
    root = vfs.root()

    assert root.is_dir
    assert root.name == "extraction.zip"


def test_open_vfs_directory(tmp_path: Path) -> None:
    vfs = open_vfs(tmp_path)
    assert isinstance(vfs, DirectoryVFS)


def test_open_vfs_missing_path_raises_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.db"
    with pytest.raises(FileNotFoundError, match="no longer exists"):
        open_vfs(missing)


def test_open_vfs_zip(tmp_path: Path) -> None:
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("file.txt", b"hello")
    vfs = open_vfs(zip_path)
    assert isinstance(vfs, ZipVFS)


def test_gzip_vfs_plain_name_fallback(tmp_path: Path) -> None:
    # gzip.compress() writes no FNAME header field, so GzipVFS must fall
    # back to deriving the member name from the archive's own filename.
    gz_path = tmp_path / "syslog.gz"
    gz_path.write_bytes(gzip.compress(b"Aug 31 12:00:00 host kernel: hello\n"))

    vfs = GzipVFS(gz_path)
    root = vfs.root()

    assert root.is_dir
    assert root.name == "syslog.gz"
    assert len(root.children) == 1
    member = root.children[0]
    assert member.name == "syslog"
    assert member.size == len(b"Aug 31 12:00:00 host kernel: hello\n")
    assert vfs.read(member) == b"Aug 31 12:00:00 host kernel: hello\n"
    assert vfs.file_count(root) == 1
    assert vfs.total_size(root) == member.size


def test_gzip_vfs_uses_original_filename_from_header(tmp_path: Path) -> None:
    gz_path = tmp_path / "data.gz"
    with open(gz_path, "wb") as raw:
        with gzip.GzipFile(
            filename="original_name.log", mode="wb", fileobj=raw, mtime=1_700_000_000
        ) as f:
            f.write(b"content")

    vfs = GzipVFS(gz_path)
    member = vfs.root().children[0]
    assert member.name == "original_name.log"
    assert member.modified == 1_700_000_000.0
    assert vfs.read(member) == b"content"


def test_gzip_vfs_tgz_stem_fallback(tmp_path: Path) -> None:
    # .tgz normally routes through TarVFS via open_vfs(); constructing
    # GzipVFS directly still needs a sane fallback name for the member.
    gz_path = tmp_path / "archive.tgz"
    gz_path.write_bytes(gzip.compress(b"not actually a tar, just testing the stem fallback"))

    vfs = GzipVFS(gz_path)
    assert vfs.root().children[0].name == "archive.tar"


def test_open_vfs_gzip(tmp_path: Path) -> None:
    gz_path = tmp_path / "app.log.gz"
    with gzip.open(gz_path, "wb") as f:
        f.write(b"log line\n")
    vfs = open_vfs(gz_path)
    assert isinstance(vfs, GzipVFS)


def test_open_vfs_tar_gz_is_not_gzip_vfs(tmp_path: Path) -> None:
    vfs = open_vfs(FIXTURES_DIR / "minimal.tar.gz")
    assert isinstance(vfs, TarVFS)
    assert not isinstance(vfs, GzipVFS)


def test_open_vfs_extensionless_gzip_magic_bytes(tmp_path: Path) -> None:
    # No .gz extension — must be recognized from the 0x1f 0x8b magic alone,
    # same as e.g. carved or renamed forensic artifacts.
    src = tmp_path / "carved_artifact"
    src.write_bytes(gzip.compress(b"some log content"))
    vfs = open_vfs(src)
    assert isinstance(vfs, GzipVFS)


def test_open_vfs_extensionless_gzip_wrapped_tar_routes_to_tar_vfs(tmp_path: Path) -> None:
    import shutil
    import tarfile

    tar_path = tmp_path / "inner.tar"
    member_path = tmp_path / "file.txt"
    member_path.write_bytes(b"hello")
    with tarfile.open(tar_path, "w") as tf:
        tf.add(member_path, arcname="file.txt")

    src = tmp_path / "carved_artifact"
    with open(tar_path, "rb") as raw, gzip.open(src, "wb") as gz:
        shutil.copyfileobj(raw, gz)

    vfs = open_vfs(src)
    assert isinstance(vfs, TarVFS)


def test_open_vfs_renamed_gz_that_is_actually_a_tar_gz(tmp_path: Path) -> None:
    # A .tar.gz saved with just a ".gz" extension should still be browsed
    # as a TAR, not as a single opaque blob.
    import shutil
    import tarfile

    tar_path = tmp_path / "inner.tar"
    member_path = tmp_path / "file.txt"
    member_path.write_bytes(b"hello")
    with tarfile.open(tar_path, "w") as tf:
        tf.add(member_path, arcname="file.txt")

    src = tmp_path / "backup.gz"
    with open(tar_path, "rb") as raw, gzip.open(src, "wb") as gz:
        shutil.copyfileobj(raw, gz)

    vfs = open_vfs(src)
    assert isinstance(vfs, TarVFS)


def test_android_backup_vfs(android_backup_fixture: Path) -> None:
    vfs = open_vfs(android_backup_fixture)
    assert isinstance(vfs, AndroidBackupVFS)

    apps = next(c for c in vfs.root().children if c.name == "apps")
    app = next(c for c in apps.children if c.name == "com.example.app")
    db_dir = next(c for c in app.children if c.name == "db")
    db_file = next(c for c in db_dir.children if c.name == "sample.db")

    assert vfs.read(db_file) == b"SQLite format 3\x00"


def test_open_vfs_android_backup_magic_bytes(tmp_path: Path) -> None:
    # No .ab extension — must be detected via the header, not the filename.
    import io
    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass

    src = tmp_path / "extraction.bin"
    src.write_bytes(b"ANDROID BACKUP\n5\n0\nnone\n" + tar_buf.getvalue())

    vfs = open_vfs(src)

    assert isinstance(vfs, AndroidBackupVFS)


def test_android_backup_vfs_requires_password_when_encrypted(tmp_path: Path) -> None:
    path = tmp_path / "backup.ab"
    path.write_bytes(b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"garbage")

    with pytest.raises(PasswordRequiredError):
        open_vfs(path)


def test_android_backup_vfs_decrypts_with_correct_password(
    android_backup_encrypted_fixture: Path,
) -> None:
    vfs = open_vfs(android_backup_encrypted_fixture, password="hunter2")
    assert isinstance(vfs, AndroidBackupVFS)

    apps = next(c for c in vfs.root().children if c.name == "apps")
    app = next(c for c in apps.children if c.name == "com.example.app")
    db_dir = next(c for c in app.children if c.name == "db")
    db_file = next(c for c in db_dir.children if c.name == "sample.db")

    assert vfs.read(db_file) == b"SQLite format 3\x00"


def test_android_backup_vfs_rejects_wrong_password(android_backup_encrypted_fixture: Path) -> None:
    with pytest.raises(WrongPasswordError):
        open_vfs(android_backup_encrypted_fixture, password="not-the-password")


def test_named_android_backup_without_magic_opens_as_file_with_note(tmp_path: Path) -> None:
    path = tmp_path / "backup.ab"
    path.write_bytes(b"not an android backup at all")

    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert vfs.fallback_note == "Named .ab, but no Android backup signature found"


def test_itunes_backup_vfs(itunes_backup_fixture: Path) -> None:
    vfs = open_vfs(itunes_backup_fixture)
    assert isinstance(vfs, ITunesBackupVFS)

    home = next(c for c in vfs.root().children if c.name == "HomeDomain")
    library = next(c for c in home.children if c.name == "Library")
    sms_dir = next(c for c in library.children if c.name == "SMS")
    sms_db = next(c for c in sms_dir.children if c.name == "sms.db")

    assert vfs.read(sms_db) == b"SQLite format 3\x00"


def test_open_vfs_itunes_backup_directory(itunes_backup_fixture: Path) -> None:
    vfs = open_vfs(itunes_backup_fixture)
    assert isinstance(vfs, ITunesBackupVFS)


def test_itunes_backup_vfs_rejects_encrypted(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    (backup_dir / "Manifest.db").write_bytes(b"")
    (backup_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))

    with pytest.raises(PasswordRequiredError):
        open_vfs(backup_dir)


def test_itunes_backup_vfs_decrypts_keybag_manifest(itunes_backup_keybag_fixture: Path) -> None:
    """iOS 10.2+ real-world shape: Manifest.db is KeyBag/AES encrypted even
    though the backup itself has no password (IsEncrypted=False)."""
    vfs = open_vfs(itunes_backup_keybag_fixture)
    assert isinstance(vfs, ITunesBackupVFS)

    home = next(c for c in vfs.root().children if c.name == "HomeDomain")
    library = next(c for c in home.children if c.name == "Library")
    sms_dir = next(c for c in library.children if c.name == "SMS")
    sms_db = next(c for c in sms_dir.children if c.name == "sms.db")

    assert vfs.read(sms_db) == b"SQLite format 3\x00"


def test_itunes_backup_vfs_decrypts_per_file_content(itunes_backup_keybag_fixture: Path) -> None:
    """Password-protected backups additionally encrypt individual file
    contents (protection-class keys) on top of Manifest.db — read() must
    transparently decrypt those too."""
    vfs = open_vfs(itunes_backup_keybag_fixture)
    assert isinstance(vfs, ITunesBackupVFS)

    home = next(c for c in vfs.root().children if c.name == "HomeDomain")
    library = next(c for c in home.children if c.name == "Library")
    notes_dir = next(c for c in library.children if c.name == "Notes")
    notes_db = next(c for c in notes_dir.children if c.name == "notes.sqlite")

    assert notes_db.path in vfs._file_protection
    assert vfs.read(notes_db) == b"protected note content" * 4
    # open() must go through the same decrypt path, not stream raw ciphertext.
    with vfs.open(notes_db) as f:
        assert f.read() == b"protected note content" * 4


def test_detect_itunes_backup_in_zip(itunes_backup_zip_fixture: Path) -> None:
    prefix = detect_itunes_backup_in_zip(itunes_backup_zip_fixture)
    assert prefix == "wrapper/"


def test_detect_itunes_backup_in_zip_ordinary_zip(tmp_path: Path) -> None:
    zip_path = tmp_path / "plain.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("file.txt", b"hello")

    assert detect_itunes_backup_in_zip(zip_path) is None


def test_detect_itunes_backup_in_zip_ignores_coincidental_app_bundle(tmp_path: Path) -> None:
    """Regression: a full iOS filesystem extraction can contain an unrelated
    app with its own Manifest.db sitting next to the Info.plist every app
    bundle has — that alone must not be mistaken for a real backup."""
    zip_path = tmp_path / "iOS_Filesystem.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        base = "private/var/containers/Bundle/Application/1234-5678/SomeApp.app/"
        zf.writestr(f"{base}Info.plist", b"bplist00fakebundleinfo")
        zf.writestr(f"{base}Manifest.db", b"SQLite format 3\x00 unrelated app data")

    assert detect_itunes_backup_in_zip(zip_path) is None


def test_open_vfs_does_not_auto_redirect_zip(itunes_backup_zip_fixture: Path) -> None:
    """A .zip must stay a plain ZipVFS via open_vfs() even if it contains a
    backup — auto-redirecting would be surprising; the UI asks first."""
    vfs = open_vfs(itunes_backup_zip_fixture)
    assert isinstance(vfs, ZipVFS)


def test_open_itunes_backup_from_zip(itunes_backup_zip_fixture: Path) -> None:
    prefix = detect_itunes_backup_in_zip(itunes_backup_zip_fixture)
    assert prefix is not None

    vfs = open_itunes_backup_from_zip(itunes_backup_zip_fixture, prefix)
    try:
        assert isinstance(vfs, ITunesBackupVFS)
        home = next(c for c in vfs.root().children if c.name == "HomeDomain")
        library = next(c for c in home.children if c.name == "Library")
        sms_dir = next(c for c in library.children if c.name == "SMS")
        sms_db = next(c for c in sms_dir.children if c.name == "sms.db")
        assert vfs.read(sms_db) == b"SQLite format 3\x00"

        cleanup_dir = vfs._cleanup_dir
        assert cleanup_dir is not None and cleanup_dir.exists()
    finally:
        vfs.close()

    assert not cleanup_dir.exists()


def test_sevenzip_content_encrypted_requires_password(
    sevenzip_encrypted_content_fixture: Path,
) -> None:
    with pytest.raises(PasswordRequiredError):
        open_vfs(sevenzip_encrypted_content_fixture)


def test_sevenzip_content_encrypted_rejects_wrong_password(
    sevenzip_encrypted_content_fixture: Path,
) -> None:
    with pytest.raises(WrongPasswordError):
        open_vfs(sevenzip_encrypted_content_fixture, password="wrongpass")


def test_sevenzip_content_encrypted_decrypts_with_correct_password(
    sevenzip_encrypted_content_fixture: Path,
) -> None:
    vfs = open_vfs(sevenzip_encrypted_content_fixture, password="secret123")
    assert isinstance(vfs, SevenZipVFS)
    node = next(c for c in vfs.root().children if c.name == "sample.db")
    assert vfs.read(node) == b"SQLite format 3\x00"


def test_sevenzip_header_encrypted_requires_password(
    sevenzip_encrypted_header_fixture: Path,
) -> None:
    with pytest.raises(PasswordRequiredError):
        open_vfs(sevenzip_encrypted_header_fixture)


def test_sevenzip_header_encrypted_rejects_wrong_password(
    sevenzip_encrypted_header_fixture: Path,
) -> None:
    with pytest.raises(WrongPasswordError):
        open_vfs(sevenzip_encrypted_header_fixture, password="wrongpass")


def test_sevenzip_header_encrypted_decrypts_with_correct_password(
    sevenzip_encrypted_header_fixture: Path,
) -> None:
    vfs = open_vfs(sevenzip_encrypted_header_fixture, password="secret123")
    assert isinstance(vfs, SevenZipVFS)
    node = next(c for c in vfs.root().children if c.name == "sample.db")
    assert vfs.read(node) == b"SQLite format 3\x00"


def test_zip_legacy_encrypted_requires_password(legacy_encrypted_zip_fixture: Path) -> None:
    with pytest.raises(PasswordRequiredError):
        open_vfs(legacy_encrypted_zip_fixture)


def test_zip_legacy_encrypted_rejects_wrong_password(legacy_encrypted_zip_fixture: Path) -> None:
    with pytest.raises(WrongPasswordError):
        open_vfs(legacy_encrypted_zip_fixture, password="wrongpass")


def test_zip_legacy_encrypted_decrypts_with_correct_password(
    legacy_encrypted_zip_fixture: Path,
) -> None:
    vfs = open_vfs(legacy_encrypted_zip_fixture, password="secret123")
    assert isinstance(vfs, ZipVFS)
    node = next(c for c in vfs.root().children if c.name == "sample.db")
    assert vfs.read(node) == b"SQLite format 3\x00"
    assert vfs.peek(node, 6) == b"SQLite"


def test_zip_aes_encrypted_requires_password(aes_encrypted_zip_fixture: Path) -> None:
    with pytest.raises(PasswordRequiredError):
        open_vfs(aes_encrypted_zip_fixture)


def test_zip_aes_encrypted_rejects_wrong_password(aes_encrypted_zip_fixture: Path) -> None:
    with pytest.raises(WrongPasswordError):
        open_vfs(aes_encrypted_zip_fixture, password="wrongpass")


def test_zip_aes_encrypted_decrypts_with_correct_password(aes_encrypted_zip_fixture: Path) -> None:
    vfs = open_vfs(aes_encrypted_zip_fixture, password="secret123")
    assert isinstance(vfs, ZipVFS)
    node = next(c for c in vfs.root().children if c.name == "sample.db")
    assert vfs.read(node) == b"SQLite format 3\x00"
    assert vfs.peek(node, 6) == b"SQLite"
