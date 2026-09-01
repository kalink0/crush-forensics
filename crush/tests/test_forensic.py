# SPDX-License-Identifier: Apache-2.0
"""Forensic-quality tests: evidence integrity, read-only enforcement, reproducibility.

A forensic tool has stricter requirements than ordinary software:
  - It must never modify the evidence it reads.
  - It must produce identical results for identical inputs (reproducibility).
  - It must work correctly when evidence is on read-only media.
  - Known reference inputs must always yield known reference outputs.

These tests complement the functional parser tests.  Where functional tests ask
"does it parse?", these tests ask "is it safe to run on real evidence?".
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

from crush.core.vfs import (
    AndroidBackupVFS,
    DirectoryVFS,
    ITunesBackupVFS,
    SevenZipVFS,
    TarVFS,
    VFSNode,
    ZipVFS,
)
from crush.parsers.media_parser import MediaParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.realm_parser import RealmParser
from crush.parsers.segb_parser import SegbParser
from crush.parsers.sqlite_parser import SQLiteParser
from crush.tests.conftest import FIXTURES_DIR

_MP3_STUB  = b"\xff\xfb" + b"\x00" * 128   # MPEG-1 Layer 3 sync word
_OGG_STUB  = b"OggS"    + b"\x00" * 128   # OGG capture pattern
_AMR_STUB  = b"#!AMR\n" + b"\x00" * 128   # AMR-NB magic
_MP4_STUB  = b"\x00\x00\x00\x20ftyp" + b"\x00" * 122  # ISOBMFF ftyp box


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamps(path: Path) -> tuple[int, int, float | None]:
    """Return (mtime_ns, ctime_ns, birthtime).

    ctime: inode-change time on POSIX, creation time on Windows.
    birthtime: float seconds from st_birthtime (macOS); None on Linux/Windows.
    """
    st = path.stat()
    birth: float | None = getattr(st, "st_birthtime", None)
    return st.st_mtime_ns, st.st_ctime_ns, birth


def _assert_timestamps_unchanged(before: tuple, after: tuple, label: str) -> None:
    """Assert mtime, ctime, and (where available) birth time are identical."""
    assert after[0] == before[0], f"{label} changed mtime"
    assert after[1] == before[1], f"{label} changed ctime"
    if before[2] is not None:
        assert after[2] == before[2], f"{label} changed birth time"


def _file_nodes(node: VFSNode) -> list[VFSNode]:
    """Flatten a VFSNode tree, returning only non-directory nodes."""
    if not node.is_dir:
        return [node]
    result: list[VFSNode] = []
    for child in node.children:
        result.extend(_file_nodes(child))
    return result


# ---------------------------------------------------------------------------
# 1. Source immutability — VFS reads must never alter what they read
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="DirectoryVFS read/peek must leave source file bytes unchanged",
)
def test_directory_vfs_does_not_modify_source(tmp_path: Path) -> None:
    content = b"SQLite format 3\x00" + b"\x00" * 100
    src = tmp_path / "evidence.db"
    src.write_bytes(content)
    digest_before = _sha256_file(src)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "evidence.db")
    _ = vfs.read(node)
    _ = vfs.peek(node)

    assert _sha256_file(src) == digest_before, "DirectoryVFS modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="DirectoryVFS read/peek must not change mtime or ctime of source files",
)
def test_directory_vfs_does_not_change_timestamps(tmp_path: Path) -> None:
    src = tmp_path / "evidence.db"
    src.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    ts_before = _timestamps(src)

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.db")
    _ = vfs.read(node)
    _ = vfs.peek(node)

    _assert_timestamps_unchanged(ts_before, _timestamps(src), "DirectoryVFS")


@pytest.mark.skipif(
    sys.platform not in ("linux", "win32"),
    reason="atime preservation via O_NOATIME / utime restore only implemented on Linux and Windows",
)
@pytest.mark.forensic(
    category="Source Immutability",
    desc="DirectoryVFS read/peek must not update atime (Linux: O_NOATIME, Windows: utime restore)",
)
def test_directory_vfs_does_not_change_atime(tmp_path: Path) -> None:
    src = tmp_path / "evidence.db"
    src.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)

    # Push atime 200 s into the past so that relatime would update it on a plain
    # read (relatime only skips the update when atime >= mtime).
    mtime_ns = src.stat().st_mtime_ns
    old_atime_ns = mtime_ns - 200_000_000_000
    os.utime(src, ns=(old_atime_ns, mtime_ns))
    atime_before = src.stat().st_atime_ns

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.db")
    _ = vfs.read(node)
    _ = vfs.peek(node)

    assert src.stat().st_atime_ns == atime_before, "DirectoryVFS changed atime of source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Exhaustively reading every entry of a ZIP archive must leave it byte-identical",
)
def test_zip_vfs_does_not_modify_archive(zip_fixture: Path) -> None:
    digest_before = _sha256_file(zip_fixture)

    vfs = ZipVFS(zip_fixture)
    for node in vfs.storage_ordered_files():
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(zip_fixture) == digest_before, "ZipVFS modified the source archive"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ZipVFS must not change mtime or ctime of the archive file",
)
def test_zip_vfs_does_not_change_timestamps(zip_fixture: Path) -> None:
    ts_before = _timestamps(zip_fixture)

    vfs = ZipVFS(zip_fixture)
    for node in vfs.storage_ordered_files():
        _ = vfs.read(node)
    vfs.close()

    _assert_timestamps_unchanged(ts_before, _timestamps(zip_fixture), "ZipVFS")


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Exhaustively reading every entry of a TAR archive must leave it byte-identical",
)
def test_tar_vfs_does_not_modify_archive(tar_fixture: Path) -> None:
    digest_before = _sha256_file(tar_fixture)

    vfs = TarVFS(tar_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(tar_fixture) == digest_before, "TarVFS modified the source archive"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="TarVFS must not change mtime or ctime of the archive file",
)
def test_tar_vfs_does_not_change_timestamps(tar_fixture: Path) -> None:
    ts_before = _timestamps(tar_fixture)

    vfs = TarVFS(tar_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    _assert_timestamps_unchanged(ts_before, _timestamps(tar_fixture), "TarVFS")


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Exhaustively reading every entry of an Android backup (.ab) must leave it byte-identical",
)
def test_android_backup_vfs_does_not_modify_archive(android_backup_fixture: Path) -> None:
    digest_before = _sha256_file(android_backup_fixture)

    vfs = AndroidBackupVFS(android_backup_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(android_backup_fixture) == digest_before, "AndroidBackupVFS modified the source archive"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="AndroidBackupVFS must not change mtime or ctime of the archive file",
)
def test_android_backup_vfs_does_not_change_timestamps(android_backup_fixture: Path) -> None:
    ts_before = _timestamps(android_backup_fixture)

    vfs = AndroidBackupVFS(android_backup_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    _assert_timestamps_unchanged(ts_before, _timestamps(android_backup_fixture), "AndroidBackupVFS")


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Decrypting a password-protected Android backup must leave the source .ab byte-identical",
)
def test_android_backup_vfs_encrypted_does_not_modify_source(
    android_backup_encrypted_fixture: Path,
) -> None:
    digest_before = _sha256_file(android_backup_encrypted_fixture)
    ts_before = _timestamps(android_backup_encrypted_fixture)

    vfs = AndroidBackupVFS(android_backup_encrypted_fixture, password="hunter2")
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(android_backup_encrypted_fixture) == digest_before, (
        "Decrypting an encrypted Android backup modified the source .ab"
    )
    _assert_timestamps_unchanged(
        ts_before, _timestamps(android_backup_encrypted_fixture), "AndroidBackupVFS (encrypted)"
    )


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Decrypting a password-protected 7z archive must leave the source file byte-identical",
)
def test_sevenzip_encrypted_does_not_modify_source(
    sevenzip_encrypted_header_fixture: Path,
) -> None:
    digest_before = _sha256_file(sevenzip_encrypted_header_fixture)
    ts_before = _timestamps(sevenzip_encrypted_header_fixture)

    vfs = SevenZipVFS(sevenzip_encrypted_header_fixture, password="secret123")
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(sevenzip_encrypted_header_fixture) == digest_before, (
        "Decrypting an encrypted 7z archive modified the source file"
    )
    _assert_timestamps_unchanged(
        ts_before, _timestamps(sevenzip_encrypted_header_fixture), "SevenZipVFS (encrypted)"
    )


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Decrypting a legacy-ZipCrypto-encrypted ZIP must leave the source file byte-identical",
)
def test_zip_legacy_encrypted_does_not_modify_source(legacy_encrypted_zip_fixture: Path) -> None:
    digest_before = _sha256_file(legacy_encrypted_zip_fixture)
    ts_before = _timestamps(legacy_encrypted_zip_fixture)

    vfs = ZipVFS(legacy_encrypted_zip_fixture, password="secret123")
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(legacy_encrypted_zip_fixture) == digest_before, (
        "Decrypting a legacy-encrypted ZIP modified the source file"
    )
    _assert_timestamps_unchanged(
        ts_before, _timestamps(legacy_encrypted_zip_fixture), "ZipVFS (legacy encrypted)"
    )


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Decrypting a WinZip-AES-encrypted ZIP must leave the source file byte-identical",
)
def test_zip_aes_encrypted_does_not_modify_source(aes_encrypted_zip_fixture: Path) -> None:
    digest_before = _sha256_file(aes_encrypted_zip_fixture)
    ts_before = _timestamps(aes_encrypted_zip_fixture)

    vfs = ZipVFS(aes_encrypted_zip_fixture, password="secret123")
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(aes_encrypted_zip_fixture) == digest_before, (
        "Decrypting an AES-encrypted ZIP modified the source file"
    )
    _assert_timestamps_unchanged(
        ts_before, _timestamps(aes_encrypted_zip_fixture), "ZipVFS (AES encrypted)"
    )


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Reading every entry of an iTunes backup must leave the backed file bytes unchanged",
)
def test_itunes_backup_vfs_does_not_modify_source(itunes_backup_fixture: Path) -> None:
    sms_db = itunes_backup_fixture / "3d" / "3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"
    digest_before = _sha256_file(sms_db)

    vfs = ITunesBackupVFS(itunes_backup_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)

    assert _sha256_file(sms_db) == digest_before, "ITunesBackupVFS modified the backed file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Reading every entry of an iTunes backup must not change mtime or ctime of the backed file",
)
def test_itunes_backup_vfs_does_not_change_timestamps(itunes_backup_fixture: Path) -> None:
    sms_db = itunes_backup_fixture / "3d" / "3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"
    ts_before = _timestamps(sms_db)

    vfs = ITunesBackupVFS(itunes_backup_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)

    _assert_timestamps_unchanged(ts_before, _timestamps(sms_db), "ITunesBackupVFS")


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Decrypting a per-file-encrypted entry must leave the encrypted-on-disk bytes unchanged",
)
def test_itunes_backup_vfs_per_file_decrypt_does_not_modify_source(
    itunes_backup_keybag_fixture: Path,
) -> None:
    protected_file = itunes_backup_keybag_fixture / "aa" / "aa11bb22cc33dd44ee55ff667788990011223344"
    digest_before = _sha256_file(protected_file)
    ts_before = _timestamps(protected_file)

    vfs = ITunesBackupVFS(itunes_backup_keybag_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)

    assert _sha256_file(protected_file) == digest_before, (
        "Per-file decryption modified the encrypted source file"
    )
    _assert_timestamps_unchanged(ts_before, _timestamps(protected_file), "ITunesBackupVFS (per-file decrypt)")


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Opening a zip-wrapped iTunes backup must leave the source ZIP byte-identical "
         "(extraction happens in a temp directory, never in place)",
)
def test_open_itunes_backup_from_zip_does_not_modify_source(itunes_backup_zip_fixture: Path) -> None:
    from crush.core.vfs import open_itunes_backup_from_zip

    digest_before = _sha256_file(itunes_backup_zip_fixture)
    ts_before = _timestamps(itunes_backup_zip_fixture)

    vfs = open_itunes_backup_from_zip(itunes_backup_zip_fixture, "wrapper/")
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(itunes_backup_zip_fixture) == digest_before, (
        "open_itunes_backup_from_zip modified the source ZIP"
    )
    _assert_timestamps_unchanged(ts_before, _timestamps(itunes_backup_zip_fixture), "ITunesBackupVFS (zip)")


# ---------------------------------------------------------------------------
# 2. No side-effect files — parsers must not create siblings next to evidence
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="No Side Effects",
    desc="SQLiteParser must preserve the WAL companion intact — parsing must not checkpoint or truncate it",
)
def test_sqlite_parser_preserves_wal_companion(tmp_path: Path) -> None:
    db_path = tmp_path / "wal_test.sqlite"

    # Simulate an app that is running during acquisition: writer commits, then a
    # reader holds an open transaction so SQLite cannot checkpoint on writer close.
    writer = sqlite3.connect(str(db_path))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE t (x TEXT)")
    writer.execute("INSERT INTO t VALUES ('forensic_test')")
    writer.commit()
    reader = sqlite3.connect(str(db_path))
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM t").fetchall()
    writer.close()  # cannot checkpoint — reader holds a snapshot

    wal_path = tmp_path / "wal_test.sqlite-wal"
    assert wal_path.exists() and wal_path.stat().st_size > 0, \
        "Test setup failed: SQLite did not create a WAL file"
    wal_size_before = wal_path.stat().st_size

    try:
        vfs = DirectoryVFS(tmp_path)
        root = vfs.root()
        node = next(c for c in root.children if c.name == "wal_test.sqlite")
        result = SQLiteParser().parse(node, vfs)
    finally:
        reader.close()

    tmp_wal = Path(str(result.data["__db_path"]) + "-wal")
    assert tmp_wal.exists(), \
        "Parser checkpointed and deleted the WAL companion — open the DB connection read-only"
    assert tmp_wal.stat().st_size == wal_size_before, \
        "Parser checkpointed and truncated the WAL companion — open the DB connection read-only"


@pytest.mark.forensic(
    category="No Side Effects",
    desc="SQLiteParser must not create -wal, -journal, or any sibling file next to the evidence",
)
def test_sqlite_parse_creates_no_sibling_files(tmp_path: Path) -> None:
    (tmp_path / "minimal.sqlite").write_bytes(
        (FIXTURES_DIR / "minimal.sqlite").read_bytes()
    )
    files_before = set(tmp_path.iterdir())

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "minimal.sqlite")
    SQLiteParser().parse(node, vfs)

    new_files = set(tmp_path.iterdir()) - files_before
    assert new_files == set(), f"Parser left unexpected files next to evidence: {new_files}"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="SQLiteParser must not change mtime or ctime of source files",
)
def test_sqlite_parser_does_not_change_timestamps(tmp_path: Path) -> None:
    db_path = tmp_path / "minimal.sqlite"
    db_path.write_bytes((FIXTURES_DIR / "minimal.sqlite").read_bytes())
    ts_before = _timestamps(db_path)

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "minimal.sqlite")
    SQLiteParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(db_path), "SQLiteParser")


# ---------------------------------------------------------------------------
# 3. Read-only media — tool must work when evidence is chmod 0o444 / 0o555
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="SQLiteParser must succeed when the evidence directory is 0o555 and file is 0o444",
)
def test_sqlite_parser_works_on_readonly_media(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    db = evidence_dir / "minimal.sqlite"
    db.write_bytes((FIXTURES_DIR / "minimal.sqlite").read_bytes())

    db.chmod(0o444)
    evidence_dir.chmod(0o555)
    try:
        vfs = DirectoryVFS(evidence_dir)
        root = vfs.root()
        node = next(c for c in root.children if c.name == "minimal.sqlite")
        result = SQLiteParser().parse(node, vfs)
        assert result.viewer_type == "table"
        assert "evidence" in result.data
    finally:
        evidence_dir.chmod(0o755)
        db.chmod(0o644)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="ZipVFS must read all entries when the archive file is chmod 0o444",
)
def test_zip_vfs_works_on_readonly_media(zip_fixture: Path) -> None:
    zip_fixture.chmod(0o444)
    try:
        vfs = ZipVFS(zip_fixture)
        for node in vfs.storage_ordered_files():
            _ = vfs.read(node)
        vfs.close()
    finally:
        zip_fixture.chmod(0o644)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="TarVFS must read all entries when the archive file is chmod 0o444",
)
def test_tar_vfs_works_on_readonly_media(tar_fixture: Path) -> None:
    tar_fixture.chmod(0o444)
    try:
        vfs = TarVFS(tar_fixture)
        for node in _file_nodes(vfs.root()):
            _ = vfs.read(node)
        vfs.close()
    finally:
        tar_fixture.chmod(0o644)


# ---------------------------------------------------------------------------
# 4. Known-output verification — committed fixtures must parse to known values
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.sqlite must parse to exactly: table 'evidence', columns [id, note], row (1, 'test_entry')",
)
def test_sqlite_fixture_known_output(sqlite_fixture: Path) -> None:
    vfs = DirectoryVFS(sqlite_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == sqlite_fixture.name)

    result = SQLiteParser().parse(node, vfs)

    assert result.viewer_type == "table"
    assert "evidence" in result.data
    tbl = result.data["evidence"]
    assert tbl["columns"] == ["id", "note"]
    assert tbl["rows"] == [[1, "test_entry"]]


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal_binary.plist must parse to exactly: {application, version=1, verified=True}, format=binary",
)
def test_plist_fixture_known_output(plist_fixture: Path) -> None:
    vfs = DirectoryVFS(plist_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == plist_fixture.name)

    result = PlistParser().parse(node, vfs)

    assert result.viewer_type == "tree_text"
    assert result.data["application"] == "crush-forensics"
    assert result.data["version"] == 1
    assert result.data["verified"] is True
    assert result.metadata["Format"] == "binary"


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.zip must contain exactly: evidence/minimal.sqlite and evidence/minimal_binary.plist",
)
def test_zip_fixture_contains_expected_entries(zip_fixture: Path) -> None:
    vfs = ZipVFS(zip_fixture)
    names = {node.name for node in vfs.storage_ordered_files()}
    assert names == {"minimal.sqlite", "minimal_binary.plist"}
    vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.tar.gz must contain exactly: evidence/minimal.sqlite and evidence/minimal_binary.plist",
)
def test_tar_fixture_contains_expected_entries(tar_fixture: Path) -> None:
    vfs = TarVFS(tar_fixture)
    names = {node.name for node in _file_nodes(vfs.root())}
    assert names == {"minimal.sqlite", "minimal_binary.plist"}
    vfs.close()


# ---------------------------------------------------------------------------
# 5. Reproducibility — identical inputs must always yield identical outputs
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same SQLite file twice must produce structurally identical results",
)
def test_sqlite_parse_is_reproducible(sqlite_fixture: Path) -> None:
    vfs = DirectoryVFS(sqlite_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == sqlite_fixture.name)
    parser = SQLiteParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    # __db_path is a temp-file path that legitimately differs between calls
    d1 = {k: v for k, v in r1.data.items() if k != "__db_path"}
    d2 = {k: v for k, v in r2.data.items() if k != "__db_path"}
    assert d1 == d2
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same binary plist twice must produce identical results",
)
def test_plist_parse_is_reproducible(plist_fixture: Path) -> None:
    vfs = DirectoryVFS(plist_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == plist_fixture.name)
    parser = PlistParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Reading the same ZIP archive entry twice must return byte-identical data",
)
def test_zip_vfs_read_is_reproducible(zip_fixture: Path) -> None:
    vfs = ZipVFS(zip_fixture)
    nodes = vfs.storage_ordered_files()
    assert nodes, "Fixture ZIP is unexpectedly empty"
    node = nodes[0]
    assert vfs.read(node) == vfs.read(node)


# ---------------------------------------------------------------------------
# Realm forensic tests
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="RealmParser read must leave source file bytes unchanged",
)
def test_realm_parser_does_not_modify_source(realm_fixture: Path) -> None:
    digest_before = _sha256_file(realm_fixture)

    vfs = DirectoryVFS(realm_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_fixture.name)
    _ = RealmParser().parse(node, vfs)

    assert _sha256_file(realm_fixture) == digest_before, "RealmParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="RealmParser must not change mtime or ctime of source files",
)
def test_realm_parser_does_not_change_timestamps(realm_fixture: Path) -> None:
    ts_before = _timestamps(realm_fixture)

    vfs = DirectoryVFS(realm_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == realm_fixture.name)
    _ = RealmParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(realm_fixture), "RealmParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="RealmParser must not create any sibling files next to the evidence",
)
def test_realm_parse_creates_no_sibling_files(realm_fixture: Path) -> None:
    files_before = set(realm_fixture.parent.iterdir())

    vfs = DirectoryVFS(realm_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_fixture.name)
    RealmParser().parse(node, vfs)

    new_files = set(realm_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"Parser left unexpected files next to evidence: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="RealmParser must succeed when evidence directory is 0o555 and file is 0o444",
)
def test_realm_parser_works_on_readonly_media(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    realm = evidence_dir / "minimal.realm"
    realm.write_bytes((FIXTURES_DIR / "minimal.realm").read_bytes())

    realm.chmod(0o444)
    evidence_dir.chmod(0o555)
    try:
        vfs = DirectoryVFS(evidence_dir)
        root = vfs.root()
        node = next(c for c in root.children if c.name == "minimal.realm")
        result = RealmParser().parse(node, vfs)
        assert result.viewer_type == "realm"
    finally:
        evidence_dir.chmod(0o755)
        realm.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.realm must parse to exactly: schema ['metadata', 'class_Evidence'], Tables found=2",
)
def test_realm_fixture_known_output(realm_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    schema = result.data["schema"]
    assert schema == ["metadata", "class_Evidence"]
    assert result.metadata["Tables found"] == "2"


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal_format9.realm (file format 9) must parse to exactly: "
    "schema ['metadata', 'class_LegacyRecord'], Row data explicitly marked unsupported",
)
def test_realm_format9_fixture_known_output(realm_format9_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_format9_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_format9_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert result.data["schema"] == ["metadata", "class_LegacyRecord"]
    assert result.data["tables"] == []
    assert "Not supported" in result.metadata.get("Row data", "")


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same Realm file twice must produce structurally identical results",
)
def test_realm_parse_is_reproducible(realm_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_fixture.name)
    parser = RealmParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type
    vfs.close()


# ---------------------------------------------------------------------------
# LevelDB forensic tests
# (uses the same _make_minimal_leveldb helper as test_parsers.py)
# ---------------------------------------------------------------------------

def _varint_f(n: int) -> bytes:
    out = []
    while n > 127:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _make_leveldb_fixture(path: Path) -> Path:
    """Create a minimal LevelDB directory at *path* and return it."""
    path.mkdir(parents=True, exist_ok=True)
    batch = struct.pack("<QI", 1, 1) + b"\x01" + _varint_f(5) + b"mykey" + _varint_f(7) + b"myvalue"
    log = struct.pack("<IHB", 0, len(batch), 1) + batch
    (path / "000001.log").write_bytes(log)
    (path / "MANIFEST-000001").write_bytes(b"")
    return path


def _sha256_dir(path: Path) -> dict[str, str]:
    """SHA-256 of every file in a directory (name → digest)."""
    return {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted(path.iterdir()) if f.is_file()
    }


@pytest.mark.forensic(
    category="Source Immutability",
    desc="LevelDB directory files must be byte-identical after parsing",
)
def test_leveldb_does_not_modify_source(tmp_path: Path) -> None:
    from crush.parsers.leveldb_parser import LeveldbParser
    db = _make_leveldb_fixture(tmp_path / "evidence.leveldb")
    digests_before = _sha256_dir(db)

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.leveldb")
    LeveldbParser().parse(node, vfs)

    assert _sha256_dir(db) == digests_before, "LevelDB parser modified source files"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="LevelDB parser must not change mtime or ctime of source directory files",
)
def test_leveldb_does_not_change_timestamps(tmp_path: Path) -> None:
    from crush.parsers.leveldb_parser import LeveldbParser
    db = _make_leveldb_fixture(tmp_path / "evidence.leveldb")
    ts_before = {f.name: _timestamps(f) for f in sorted(db.iterdir()) if f.is_file()}

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.leveldb")
    LeveldbParser().parse(node, vfs)

    for fname, before in ts_before.items():
        _assert_timestamps_unchanged(before, _timestamps(db / fname), f"LevelDB parser ({fname})")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="LevelDB parsing must not create files next to the evidence directory",
)
def test_leveldb_no_sibling_files(tmp_path: Path) -> None:
    from crush.parsers.leveldb_parser import LeveldbParser
    _make_leveldb_fixture(tmp_path / "evidence.leveldb")
    names_before = {p.name for p in tmp_path.iterdir()}

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.leveldb")
    LeveldbParser().parse(node, vfs)

    names_after = {p.name for p in tmp_path.iterdir()}
    assert names_after == names_before, f"Side-effect files created: {names_after - names_before}"


@pytest.mark.forensic(
    category="Read-only Media",
    desc="LevelDB parser must succeed when directory and files are read-only (0o555/0o444)",
)
def test_leveldb_read_only_media(tmp_path: Path) -> None:
    from crush.parsers.leveldb_parser import LeveldbParser
    db = _make_leveldb_fixture(tmp_path / "evidence.leveldb")
    try:
        for f in db.iterdir():
            f.chmod(0o444)
        db.chmod(0o555)

        vfs = DirectoryVFS(tmp_path)
        node = next(c for c in vfs.root().children if c.name == "evidence.leveldb")
        result = LeveldbParser().parse(node, vfs)
        assert result.viewer_type == "leveldb"
    finally:
        db.chmod(0o755)
        for f in db.iterdir():
            f.chmod(0o644)


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same LevelDB directory twice must produce identical results",
)
def test_leveldb_parse_is_reproducible(tmp_path: Path) -> None:
    from crush.parsers.leveldb_parser import LeveldbParser
    _make_leveldb_fixture(tmp_path / "evidence.leveldb")

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "evidence.leveldb")
    parser = LeveldbParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.viewer_type == r2.viewer_type
    assert r1.metadata == r2.metadata
    assert len(r1.data["records"]) == len(r2.data["records"])
    for rec1, rec2 in zip(r1.data["records"], r2.data["records"]):
        assert rec1["state"] == rec2["state"]
        assert rec1["user_key_bytes"] == rec2["user_key_bytes"]
        assert rec1["value_bytes"] == rec2["value_bytes"]


# ---------------------------------------------------------------------------
# SEGB parser forensic tests
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="SegbParser must not alter the content of the source file",
)
def test_segb_parser_does_not_modify_source(segb_fixture: Path) -> None:
    digest_before = _sha256_file(segb_fixture)

    vfs = DirectoryVFS(segb_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == segb_fixture.name)
    SegbParser().parse(node, vfs)

    assert _sha256_file(segb_fixture) == digest_before, "SegbParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="SegbParser must not change mtime or ctime of source files",
)
def test_segb_parser_does_not_change_timestamps(segb_fixture: Path) -> None:
    ts_before = _timestamps(segb_fixture)

    vfs = DirectoryVFS(segb_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == segb_fixture.name)
    SegbParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(segb_fixture), "SegbParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="SegbParser must not create any sibling files next to the evidence",
)
def test_segb_parse_creates_no_sibling_files(segb_fixture: Path) -> None:
    files_before = set(segb_fixture.parent.iterdir())

    vfs = DirectoryVFS(segb_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == segb_fixture.name)
    SegbParser().parse(node, vfs)

    new_files = set(segb_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"Parser left unexpected files next to evidence: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="SegbParser must succeed when evidence directory is 0o555 and file is 0o444",
)
def test_segb_parser_works_on_readonly_media(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    segb = evidence_dir / "minimal.segb2"
    segb.write_bytes((FIXTURES_DIR / "minimal.segb2").read_bytes())

    segb.chmod(0o444)
    evidence_dir.chmod(0o555)
    try:
        vfs = DirectoryVFS(evidence_dir)
        node = next(c for c in vfs.root().children if c.name == "minimal.segb2")
        result = SegbParser().parse(node, vfs)
        assert result.viewer_type == "table"
    finally:
        evidence_dir.chmod(0o755)
        segb.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.segb2 must parse to at least one record with a non-empty payload",
)
def test_segb_fixture_known_output(segb_fixture: Path) -> None:
    vfs = DirectoryVFS(segb_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == segb_fixture.name)
    result = SegbParser().parse(node, vfs)
    assert result.viewer_type == "table"
    assert len(result.data["SEGB"]["rows"]) > 0


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same SEGB file twice must produce structurally identical results",
)
def test_segb_parse_is_reproducible(segb_fixture: Path) -> None:
    vfs = DirectoryVFS(segb_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == segb_fixture.name)
    parser = SegbParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.viewer_type == r2.viewer_type
    assert r1.metadata == r2.metadata
    assert r1.data["SEGB"]["columns"] == r2.data["SEGB"]["columns"]
    assert len(r1.data["SEGB"]["rows"]) == len(r2.data["SEGB"]["rows"])


# ---------------------------------------------------------------------------
# Blob Inspector decode pipeline — forensic tests
# ---------------------------------------------------------------------------

_BLOB_DB = FIXTURES_DIR / "blob_samples.db"


def _blob_row(label: str) -> bytes:
    import sqlite3
    conn = sqlite3.connect(str(_BLOB_DB))
    row = conn.execute("SELECT data FROM blobs WHERE label = ?", (label,)).fetchone()
    conn.close()
    assert row is not None, f"Fixture row '{label}' not found in blob_samples.db"
    return row[0]


@pytest.mark.forensic(
    category="Source Immutability",
    desc="Reading blob_samples.db must leave the fixture file byte-identical",
)
def test_blob_samples_db_not_modified() -> None:
    digest_before = _sha256_file(_BLOB_DB)
    _blob_row("json_raw")  # trigger a read
    assert _sha256_file(_BLOB_DB) == digest_before


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="blob_samples.db 'b64url_json': Base64url decode must yield JSON starting with {\"sub\"",
)
def test_blob_b64url_json_known_output() -> None:
    from crush.viewers.blob_inspector import _decode_base64url
    decoded = _decode_base64url(_blob_row("b64url_json"))
    assert decoded is not None and decoded.lstrip().startswith(b'{"sub"')


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="blob_samples.db 'b64url_plist': Base64url decode must yield an XML plist",
)
def test_blob_b64url_plist_known_output() -> None:
    from crush.viewers.blob_inspector import _decode_base64url
    decoded = _decode_base64url(_blob_row("b64url_plist"))
    assert decoded is not None and b"<?xml" in decoded and b"<plist" in decoded


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="blob_samples.db 'lzfse_json': lzfse decompress must yield JSON with 'bundleId'",
)
def test_blob_lzfse_json_known_output() -> None:
    from crush.viewers.blob_inspector import _decode_lzfse
    decoded = _decode_lzfse(_blob_row("lzfse_json"))
    assert decoded is not None and b'"bundleId"' in decoded


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="blob_samples.db 'b64url_lzfse_json': two-step Base64url→lzfse pipeline must yield JSON",
)
def test_blob_b64url_lzfse_pipeline_known_output() -> None:
    from crush.viewers.blob_inspector import _decode_base64url, _decode_lzfse
    step1 = _decode_base64url(_blob_row("b64url_lzfse_json"))
    assert step1 is not None, "Base64url step produced None"
    step2 = _decode_lzfse(step1)
    assert step2 is not None and b'"bundleId"' in step2


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Blob Inspector decode functions must produce byte-identical output on repeated calls",
)
def test_blob_decode_functions_are_reproducible() -> None:
    import base64
    import liblzfse
    import zlib
    from crush.viewers.blob_inspector import (
        _decode_base64,
        _decode_base64url,
        _decode_hex,
        _decode_lzfse,
        _decode_zlib,
    )
    payload = b'{"event": "login", "ts": 1718000000}'
    cases = [
        (_decode_base64,    base64.b64encode(payload)),
        (_decode_base64url, base64.urlsafe_b64encode(payload)),
        (_decode_hex,       payload.hex().encode()),
        (_decode_zlib,      zlib.compress(payload)),
        (_decode_lzfse,     liblzfse.compress(payload)),
    ]
    for fn, encoded in cases:
        assert fn(encoded) == fn(encoded), f"{fn.__name__} is not reproducible"


# ---------------------------------------------------------------------------
# Value Inspector — forensic tests
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Unix timestamp 1718000000 must always decode to 2024-06-10 06:13:20 UTC",
)
def test_value_inspector_unix_timestamp_known_output() -> None:
    from crush.viewers.value_inspector import _interpret
    rows = _interpret("1718000000")
    row = next((r for r in rows if r.group == "Timestamp" and r.label == "Unix (s)"), None)
    assert row is not None and row.value == "2024-06-10 06:13:20 UTC"


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Cocoa timestamp 760000000 must always decode to a date in 2025",
)
def test_value_inspector_cocoa_timestamp_known_output() -> None:
    from crush.viewers.value_inspector import _interpret
    rows = _interpret("760000000")
    row = next((r for r in rows if r.group == "Timestamp" and r.label == "Cocoa / Apple (s)"), None)
    assert row is not None and row.value is not None and "2025" in row.value


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Hex bytes 'c0 a8 01 01' must always decode to IPv4 192.168.1.1 (big-endian)",
)
def test_value_inspector_ipv4_known_output() -> None:
    from crush.viewers.value_inspector import _interpret
    rows = _interpret("c0 a8 01 01")
    row = next((r for r in rows if r.group == "Network" and r.label == "IPv4 (big-endian)"), None)
    assert row is not None and row.value == "192.168.1.1"


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Hex bytes 'f7 f8 f9 fa fb fc' must always decode to MAC f7:f8:f9:fa:fb:fc",
)
def test_value_inspector_mac_known_output() -> None:
    from crush.viewers.value_inspector import _interpret
    rows = _interpret("f7 f8 f9 fa fb fc")
    row = next((r for r in rows if r.group == "Network" and r.label == "MAC address"), None)
    assert row is not None and row.value == "f7:f8:f9:fa:fb:fc"


@pytest.mark.forensic(
    category="Completeness",
    desc="Value Inspector must never silently drop any interpretation group for a multi-type value",
)
def test_value_inspector_no_silent_group_omission() -> None:
    from crush.viewers.value_inspector import _interpret
    # 3232235777 = 0xC0A80101: triggers Integer, Float, Timestamp, UUID, Network
    rows = _interpret("3232235777")
    groups = {r.group for r in rows}
    for required in ("Integer", "Float", "Timestamp", "UUID", "Network"):
        assert required in groups, f"Interpretation group '{required}' silently omitted — missed evidence"


@pytest.mark.forensic(
    category="Completeness",
    desc="Value Inspector must always show both big-endian and little-endian integer for hex-byte input",
)
def test_value_inspector_both_endians_present() -> None:
    from crush.viewers.value_inspector import _interpret
    rows = _interpret("c0 a8 01 01")
    labels = {r.label for r in rows if r.group == "Integer"}
    assert "Decimal" in labels,    "BE decimal missing"
    assert "Decimal (LE)" in labels, "LE decimal missing — missed evidence for little-endian values"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Value Inspector must produce identical ordered output on repeated calls for the same input",
)
def test_value_inspector_is_reproducible() -> None:
    from crush.viewers.value_inspector import _interpret
    for value in (
        "1718000000",
        "c0 a8 01 01",
        "3.14159",
        "550e8400-e29b-41d4-a716-446655440000",
        "f7 f8 f9 fa fb fc",
    ):
        r1 = [(r.group, r.label, r.value) for r in _interpret(value)]
        r2 = [(r.group, r.label, r.value) for r in _interpret(value)]
        assert r1 == r2, f"_interpret not reproducible for {value!r}"


# ---------------------------------------------------------------------------
# MediaParser forensic tests
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="MediaParser read must leave source file bytes unchanged",
)
def test_media_parser_does_not_modify_source(tmp_path: Path) -> None:
    src = tmp_path / "voice.mp3"
    src.write_bytes(_MP3_STUB)
    digest_before = _sha256_file(src)

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "voice.mp3")
    MediaParser().parse(node, vfs)

    assert _sha256_file(src) == digest_before, "MediaParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="MediaParser must not change mtime or ctime of source files",
)
def test_media_parser_does_not_change_timestamps(tmp_path: Path) -> None:
    src = tmp_path / "voice.mp3"
    src.write_bytes(_MP3_STUB)
    ts_before = _timestamps(src)

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "voice.mp3")
    MediaParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(src), "MediaParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="MediaParser must not create any sibling files next to the evidence",
)
def test_media_parser_creates_no_sibling_files(tmp_path: Path) -> None:
    (tmp_path / "recording.ogg").write_bytes(_OGG_STUB)
    files_before = set(tmp_path.iterdir())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "recording.ogg")
    MediaParser().parse(node, vfs)

    new_files = set(tmp_path.iterdir()) - files_before
    assert new_files == set(), f"MediaParser left unexpected files next to evidence: {new_files}"


@pytest.mark.forensic(
    category="No Side Effects",
    desc="MediaParser OGG/AMR path (PyAV decode attempt) must not create files next to evidence",
)
def test_media_parser_pyav_path_creates_no_sibling_files(tmp_path: Path) -> None:
    (tmp_path / "note.amr").write_bytes(_AMR_STUB)
    files_before = set(tmp_path.iterdir())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "note.amr")
    MediaParser().parse(node, vfs)

    new_files = set(tmp_path.iterdir()) - files_before
    assert new_files == set(), f"MediaParser (PyAV path) left unexpected files: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="MediaParser must succeed when evidence directory is 0o555 and file is 0o444",
)
def test_media_parser_works_on_readonly_media(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    media = evidence_dir / "video.mp4"
    media.write_bytes(_MP4_STUB)

    media.chmod(0o444)
    evidence_dir.chmod(0o555)
    try:
        vfs = DirectoryVFS(evidence_dir)
        node = next(c for c in vfs.root().children if c.name == "video.mp4")
        result = MediaParser().parse(node, vfs)
        assert result.viewer_type == "media"
    finally:
        evidence_dir.chmod(0o755)
        media.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="MP3 stub must always parse to viewer_type='media' with 'File size' in metadata",
)
def test_media_parser_mp3_known_output(tmp_path: Path) -> None:
    (tmp_path / "audio.mp3").write_bytes(_MP3_STUB)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "audio.mp3")
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"
    assert result.data == _MP3_STUB
    assert "File size" in result.metadata
    assert result.metadata["File size"] == f"{len(_MP3_STUB):,} B"


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="OGG stub (invalid codec data) must parse without crash and return raw bytes intact",
)
def test_media_parser_ogg_stub_known_output(tmp_path: Path) -> None:
    (tmp_path / "voice.ogg").write_bytes(_OGG_STUB)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "voice.ogg")
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"
    assert result.data == _OGG_STUB
    assert "File size" in result.metadata


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same media file twice must produce byte-identical results",
)
def test_media_parse_is_reproducible(tmp_path: Path) -> None:
    (tmp_path / "video.mp4").write_bytes(_MP4_STUB)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "video.mp4")
    parser = MediaParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.viewer_type == r2.viewer_type
    assert r1.data == r2.data
    assert r1.metadata == r2.metadata


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same OGG file twice (PyAV metadata path) must produce identical results",
)
def test_media_parse_ogg_is_reproducible(tmp_path: Path) -> None:
    (tmp_path / "voice.ogg").write_bytes(_OGG_STUB)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "voice.ogg")
    parser = MediaParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.viewer_type == r2.viewer_type
    assert r1.data == r2.data
    assert r1.metadata == r2.metadata


# ---------------------------------------------------------------------------
# PlistParser forensic tests — source immutability, no side effects, read-only
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="PlistParser read must leave source file bytes unchanged",
)
def test_plist_parser_does_not_modify_source(plist_fixture: Path) -> None:
    digest_before = _sha256_file(plist_fixture)

    vfs = DirectoryVFS(plist_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == plist_fixture.name)
    PlistParser().parse(node, vfs)

    assert _sha256_file(plist_fixture) == digest_before, "PlistParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="PlistParser must not change mtime or ctime of source files",
)
def test_plist_parser_does_not_change_timestamps(plist_fixture: Path) -> None:
    ts_before = _timestamps(plist_fixture)

    vfs = DirectoryVFS(plist_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == plist_fixture.name)
    PlistParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(plist_fixture), "PlistParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="PlistParser must not create any sibling files next to the evidence",
)
def test_plist_parse_creates_no_sibling_files(plist_fixture: Path) -> None:
    files_before = set(plist_fixture.parent.iterdir())

    vfs = DirectoryVFS(plist_fixture.parent)
    node = next(c for c in vfs.root().children if c.name == plist_fixture.name)
    PlistParser().parse(node, vfs)

    new_files = set(plist_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"PlistParser left unexpected files next to evidence: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="PlistParser must succeed when evidence directory is 0o555 and file is 0o444",
)
def test_plist_parser_works_on_readonly_media(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    plist = evidence_dir / "minimal_binary.plist"
    plist.write_bytes((FIXTURES_DIR / "minimal_binary.plist").read_bytes())

    plist.chmod(0o444)
    evidence_dir.chmod(0o555)
    try:
        vfs = DirectoryVFS(evidence_dir)
        node = next(c for c in vfs.root().children if c.name == "minimal_binary.plist")
        result = PlistParser().parse(node, vfs)
        assert result.viewer_type == "tree_text"
    finally:
        evidence_dir.chmod(0o755)
        plist.chmod(0o644)
