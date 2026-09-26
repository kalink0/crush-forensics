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

import gzip
import hashlib
import os
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

from crush.core.issues import ParseIssue
from crush.core.vfs import (
    AndroidBackupVFS,
    DirectoryVFS,
    GzipVFS,
    ITunesBackupVFS,
    RawImageVFS,
    SevenZipVFS,
    TarVFS,
    VFSNode,
    ZipVFS,
    open_vfs,
)
from crush.parsers.abx_parser import AbxParser
from crush.parsers.image_parser import ImageParser
from crush.parsers.json_parser import JsonParser
from crush.parsers.media_parser import MediaParser
from crush.parsers.mmkv_parser import MMKVParser
from crush.parsers.pdf_parser import PDFParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.protobuf_parser import ProtobufParser
from crush.parsers.protobuf_schema import (
    decode_message_with_schema,
    load_descriptor_set,
    schema_byte_ranges,
)
from crush.parsers.realm_parser import RealmParser
from crush.parsers.segb_parser import SegbParser
from crush.parsers.sqlite_parser import SQLiteParser
from crush.parsers.xml_parser import XmlParser
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


@pytest.mark.forensic(
    category="No Side Effects",
    desc="SQLiteJournalParser (standalone -journal open) must not create any file next to the evidence",
)
def test_sqlite_journal_parse_creates_no_sibling_files(tmp_path: Path) -> None:
    from crush.parsers.sqlite_journal_parser import SQLiteJournalParser

    conn = sqlite3.connect(str(tmp_path / "crash.db"), isolation_level=None)
    conn.execute("PRAGMA page_size=4096")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO t (body) VALUES ('x')")
    conn.execute("BEGIN")
    conn.execute("UPDATE t SET body = 'y' WHERE id = 1")

    files_before = set(tmp_path.iterdir())
    try:
        vfs = DirectoryVFS(tmp_path)
        node = next(c for c in vfs.root().children if c.name == "crash.db-journal")
        SQLiteJournalParser().parse(node, vfs)
        new_files = set(tmp_path.iterdir()) - files_before
        assert new_files == set(), f"Parser left unexpected files next to evidence: {new_files}"
    finally:
        conn.rollback()
        conn.close()


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
    "schema ['metadata', 'class_LegacyRecord'], missing table structure explicitly flagged",
)
def test_realm_format9_fixture_known_output(realm_format9_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_format9_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_format9_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert result.data["schema"] == ["metadata", "class_LegacyRecord"]
    assert result.data["tables"] == []
    row_data = result.metadata["Row data"]
    assert row_data.code == "realm.pre_cluster_partial"
    assert [r.code for r in row_data.params["reasons"]] == ["realm.group_no_table_refs_slot"]
    assert str(row_data) == (
        "Pre-Cluster layout — Group top array has no table-refs slot (fewer than 2 children)"
    )


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="streaming_form.realm (genuine realm-js writeCopyTo() output, real "
    "streaming-form file, not a hand-rebuilt header) must resolve the real "
    "top ref from the footer and decode its one user table correctly",
)
def test_realm_streaming_form_fixture_known_output(realm_streaming_form_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_streaming_form_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_streaming_form_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert result.data["streaming_form"] == {"top_ref": 600, "footer_valid": True}
    assert result.data["schema"] == ["metadata", "class_Item"]

    tables = {t["name"]: t for t in result.data["tables"]}
    item = tables["class_Item"]
    cols = {name: item["columns"][i] for i, name in enumerate(item["column_names"])}
    assert cols["_id"] == [1, 2]
    assert cols["label"] == ["hello", "world"]


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="ifttt_v9_data.realm (real file format 9 sample, DFRWS/Magnet CTF dataset) "
    "must fully decode: 21 classes, no unsupported columns, correct row values",
)
def test_realm_ifttt_v9_fixture_known_output(realm_ifttt_v9_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_ifttt_v9_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_ifttt_v9_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert len(result.data["schema"]) == 21
    assert "class_UserRecord" in result.data["schema"]

    # Every column in every table decodes -- no unimplemented old column
    # type left in this real sample (Mixed/StringEnum don't occur in it).
    assert result.metadata["Row data"].code == "realm.pre_cluster_decoded"
    assert str(result.metadata["Row data"]) == "Decoded via legacy pre-Cluster layout"
    for t in result.data["tables"]:
        assert t["unsupported_columns"] == [], f"{t['name']} has unsupported columns"

    tables_by_name = {t["name"]: t for t in result.data["tables"]}

    # String (medium/ArrayStringLong form -- issue #55 fix target) and
    # Timestamp, on a real user record.
    user = tables_by_name["class_UserRecord"]
    login_ix = user["column_names"].index("login")
    email_ix = user["column_names"].index("email")
    assert user["columns"][login_ix] == ["abrunswick8675309"]
    assert user["columns"][email_ix] == ["abrunswick8675309@gmail.com"]

    # Link (0=null/N=row-1 encoding) and LinkList (plain row-index list),
    # plus Link target-table resolution via the m_subspecs tagged index.
    conn = tables_by_name["class_LiveConnectionRecord"]
    assert conn["row_count"] == 2
    primary_ix = conn["column_names"].index("primaryService")
    works_ix = conn["column_names"].index("worksWithServices")
    assert conn["columns"][primary_ix] == [0, 2]
    assert conn["columns"][works_ix] == [[1], [1]]
    assert conn["column_target_tables"][primary_ix] == "class_LiveServiceRecord"
    assert conn["column_target_tables"][works_ix] == "class_LiveServiceRecord"

    # Table (subtable) column present and decodes to a (degenerate, in this
    # file) list-of-rows per row rather than being flagged unsupported.
    live_service = tables_by_name["class_LiveServiceRecord"]
    embedded_ix = live_service["column_names"].index("embeddedRedirectURLs")
    assert live_service["columns"][embedded_ix] == [[], [], []]


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="mcdonalds_v9_data.realm (real file format 9 sample, DFRWS 2021 Challenge "
    "dataset) must fully decode: 5 classes, no unsupported columns, correct row values",
)
def test_realm_mcdonalds_v9_fixture_known_output(realm_mcdonalds_v9_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_mcdonalds_v9_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_mcdonalds_v9_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert len(result.data["schema"]) == 5
    assert "class_RealmRestaurant" in result.data["schema"]

    # Every column decodes -- Float and Double both real-validated here
    # (neither appeared with non-trivial values in the IFTTT sample).
    assert result.metadata["Row data"].code == "realm.pre_cluster_decoded"
    assert str(result.metadata["Row data"]) == "Decoded via legacy pre-Cluster layout"
    for t in result.data["tables"]:
        assert t["unsupported_columns"] == [], f"{t['name']} has unsupported columns"

    tables_by_name = {t["name"]: t for t in result.data["tables"]}
    restaurant = tables_by_name["class_RealmRestaurant"]
    assert restaurant["row_count"] == 169
    assert set(restaurant["column_types"]) == {"bool", "double", "float", "int", "linklist", "string"}

    categories = tables_by_name["class_RealmRestaurantOpenHourCategory"]
    assert categories["row_count"] == 299
    name_ix = categories["column_names"].index("categoryName")
    hours_ix = categories["column_names"].index("openingHours")
    assert categories["columns"][name_ix][0] == "Heute"
    assert categories["columns"][hours_ix][0] == [0, 1, 2, 3, 4, 5, 6]


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="all_types_v24.realm (real file format 24, actual realm-js SDK output) "
    "must decode every modern column type correctly, including Decimal128, Link, "
    "LinkList, and nested Mixed collections",
)
def test_realm_all_types_v24_fixture_known_output(realm_all_types_v24_fixture: Path) -> None:
    vfs = DirectoryVFS(realm_all_types_v24_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_all_types_v24_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    t = next(t for t in result.data["tables"] if t["name"] == "class_AllTypesRecord")
    cols = {name: t["columns"][i] for i, name in enumerate(t["column_names"])}

    assert cols["intCol"] == [42, -42, 0, 0]
    assert cols["boolCol"] == [True, False, True, True]
    assert cols["stringCol"][0] == "hello world"
    assert cols["dataCol"][0] == b"\x01\x02\x03\x04\x05"
    assert cols["floatCol"][0] == 3.140000104904175
    assert cols["doubleCol"][0] == 2.718281828

    # Decimal128: found and fixed two real bugs against this exact data --
    # the combination-field bit layout was wrong entirely (not just the
    # earlier "swapped fields" guess), and Python's ambient decimal context
    # silently rounded 34-digit Bid128 coefficients to 28 digits.
    assert cols["decimalCol"] == [
        "12345.6789",
        "-99.99",
        "89999999999999.5",  # MSD 8/9, still compact Bid64
        "1.234567890123456789012345678901234",  # 34 digits, forces full Bid128
    ]

    assert cols["dateCol"][0] == "2024-01-15 10:30:00 UTC"
    assert cols["uuidCol"][0] == "550e8400-e29b-41d4-a716-446655440000"
    assert cols["objectIdCol"][0] == "507f1f77bcf86cd799439011"

    # LinkList: found and fixed a real bug against this exact data -- list
    # elements were wrongly run through the single-Link "+1/0=null"
    # decoder (they're plain 0-based indices with no such adjustment).
    assert cols["linkCol"][0] == 0
    assert cols["linkCol"][1] is None
    assert cols["linkList"][0] == [0, 1]
    assert cols["linkList"][1] == []

    assert cols["mixedCol"][0] == "a plain mixed string"
    assert cols["mixedWithNestedList"][0] == [1.0, "two", 3.0, True]
    assert cols["mixedWithNestedDict"][0] == {"a": 1.0, "b": "two", "c": [1.0, 2.0, 3.0]}
    assert cols["dictCol"][0] == {"keyOne": "val1", "keyTwo": 2.0, "keyThree": True}
    assert cols["setCol"][0] == [10, 20, 30]
    assert cols["listOfInt"][0] == [100, 200, 300]


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="format9_alltypes.realm (real file format 9, realm-core v5.23.9's own public "
    "API output, donated by the issue #55 reporter) must decode every old ColumnType "
    "correctly against the accompanying expected.json, including Mixed and a populated "
    "Table/subtable -- the two pieces this parser's own test suite could previously only "
    "cover synthetically",
)
def test_realm_format9_alltypes_fixture_known_output(realm_format9_alltypes_fixture: Path) -> None:
    import json

    expected = json.loads(
        (FIXTURES_DIR / "format9_alltypes.expected.json").read_text()
    )

    vfs = DirectoryVFS(realm_format9_alltypes_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == realm_format9_alltypes_fixture.name)

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert result.data["schema"] == ["class_Target", "class_AllTypes", "class_EnumStrings"]

    tables = {t["name"]: t for t in result.data["tables"]}
    for t in tables.values():
        assert t["unsupported_columns"] == [], f"{t['name']} has unsupported columns"

    target = tables["class_Target"]
    assert target["row_count"] == expected["class_Target"]["rows"]
    name_ix = target["column_names"].index("name")
    assert target["columns"][name_ix] == expected["class_Target"]["name"]

    at = tables["class_AllTypes"]
    exp = expected["class_AllTypes"]
    assert at["row_count"] == exp["rows"]
    cols = {name: at["columns"][i] for i, name in enumerate(at["column_names"])}

    assert cols["col_int"] == exp["col_int"]  # incl. both int32 boundaries, beyond 2**53
    assert cols["col_bool"] == exp["col_bool"]
    assert cols["col_string_short"] == exp["col_string_short"]
    assert [len(s) for s in cols["col_string_medium"]] == exp["col_string_medium_lengths"]
    assert [len(s) for s in cols["col_string_big"]] == exp["col_string_big_lengths"]
    assert cols["col_binary"] == [s.encode() for s in exp["col_binary"]]
    assert [len(rows) for rows in cols["col_subtable"]] == exp["col_subtable_entry_counts"]

    # Mixed: every subtype tag in one column, incl. a negative int (the
    # trickiest bit-tagging path) -- this and the subtable row above were
    # previously only verified against hand-built synthetic bytes.
    assert cols["col_mixed"][:4] == [0, 123456789, -987654321, True]
    assert cols["col_mixed"][4] == "MIXED_STRING_VALUE"
    assert cols["col_mixed"][5] == b"MIXED_BINARY"
    assert cols["col_mixed"][6] == 2.5
    assert cols["col_mixed"][7] == -4.75
    assert cols["col_mixed"][8].startswith("2023-11-14")

    for i, epoch in enumerate(exp["col_olddatetime_epoch_seconds"]):
        assert str(epoch) or cols["col_olddatetime"][i]  # decoded, not a raw epoch int
    for i, epoch in enumerate(exp["col_timestamp_epoch_seconds"]):
        assert cols["col_timestamp"][i]  # decoded, not a raw epoch int

    assert cols["col_float"] == exp["col_float"]
    assert cols["col_double"] == exp["col_double"]
    assert cols["col_link"] == exp["col_link_target_row"]
    assert cols["col_linklist"] == exp["col_linklist_targets"]

    es = tables["class_EnumStrings"]
    exp_es = expected["class_EnumStrings"]
    assert es["row_count"] == exp_es["rows"]
    es_cols = {name: es["columns"][i] for i, name in enumerate(es["column_names"])}
    assert es_cols["enum_value"] == exp_es["enum_value"]
    assert es_cols["row_id"] == exp_es["row_id"]


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


# ---------------------------------------------------------------------------
# 6. RawImageVFS — raw disk images / EWF acquisitions get the same forensic
#    guarantees as every other VFS backend above. A forensic disk image is,
#    if anything, held to a stricter integrity standard than an ordinary
#    file (courts and chain-of-custody procedures scrutinize whether an
#    acquisition was altered after it was made), so this coverage matters
#    at least as much here as anywhere else in this file.
# ---------------------------------------------------------------------------

@pytest.fixture
def raw_image_fixture(tmp_path: Path) -> Path:
    dst = tmp_path / "evidence.img"
    dst.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes()))
    return dst


def _live_file_nodes(volume: VFSNode) -> list[VFSNode]:
    """Like _file_nodes(), but excludes the synthetic `$Recovered` folder --
    its entries deliberately include not-recoverable ones (e.g. a deleted
    directory record), which is exactly what its own dedicated tests in
    test_raw_image_vfs.py cover; these generic forensic-guarantee tests
    only need a sample of ordinary, always-readable live files.
    """
    return _file_nodes(
        VFSNode(
            name=volume.name, path=volume.path, is_dir=True,
            children=[c for c in volume.children if c.name != "$Recovered"],
        )
    )


@pytest.mark.forensic(
    category="Source Immutability",
    desc="RawImageVFS read/peek must leave the image file's bytes unchanged",
)
def test_raw_image_vfs_does_not_modify_source(raw_image_fixture: Path) -> None:
    digest_before = _sha256_file(raw_image_fixture)

    vfs = open_vfs(raw_image_fixture, as_disk_image=True)
    assert isinstance(vfs, RawImageVFS)
    try:
        volume = vfs.root().children[0]
        for node in _live_file_nodes(volume)[:20]:
            _ = vfs.read(node)
            _ = vfs.peek(node)
    finally:
        vfs.close()

    assert _sha256_file(raw_image_fixture) == digest_before, "RawImageVFS modified the source image"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="RawImageVFS read/peek must not change mtime or ctime of the image file",
)
def test_raw_image_vfs_does_not_change_timestamps(raw_image_fixture: Path) -> None:
    ts_before = _timestamps(raw_image_fixture)

    vfs = open_vfs(raw_image_fixture, as_disk_image=True)
    assert isinstance(vfs, RawImageVFS)
    try:
        volume = vfs.root().children[0]
        for node in _live_file_nodes(volume)[:20]:
            _ = vfs.read(node)
    finally:
        vfs.close()

    _assert_timestamps_unchanged(ts_before, _timestamps(raw_image_fixture), "RawImageVFS")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="RawImageVFS must not create any sibling files next to the image",
)
def test_raw_image_vfs_creates_no_sibling_files(raw_image_fixture: Path) -> None:
    files_before = set(raw_image_fixture.parent.iterdir())

    vfs = open_vfs(raw_image_fixture, as_disk_image=True)
    assert isinstance(vfs, RawImageVFS)
    try:
        volume = vfs.root().children[0]
        for node in _live_file_nodes(volume)[:20]:
            _ = vfs.read(node)
    finally:
        vfs.close()

    new_files = set(raw_image_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"RawImageVFS left unexpected files next to the image: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="RawImageVFS must read all files when the image file is chmod 0o444",
)
def test_raw_image_vfs_works_on_readonly_media(raw_image_fixture: Path) -> None:
    raw_image_fixture.chmod(0o444)
    try:
        vfs = open_vfs(raw_image_fixture, as_disk_image=True)
        assert isinstance(vfs, RawImageVFS)
        try:
            volume = vfs.root().children[0]
            for node in _live_file_nodes(volume)[:20]:
                _ = vfs.read(node)
        finally:
            vfs.close()
    finally:
        raw_image_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Reading the same file from a raw image twice must return byte-identical data",
)
def test_raw_image_vfs_read_is_reproducible(raw_image_fixture: Path) -> None:
    vfs = open_vfs(raw_image_fixture, as_disk_image=True)
    assert isinstance(vfs, RawImageVFS)
    try:
        volume = vfs.root().children[0]
        node = _live_file_nodes(volume)[0]
        assert vfs.read(node) == vfs.read(node)
    finally:
        vfs.close()


# ---------------------------------------------------------------------------
# 7. GzipVFS — standalone .gz files (e.g. a rotated log like syslog.gz)
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="GzipVFS read must leave the .gz file's bytes unchanged",
)
def test_gzip_vfs_does_not_modify_source(gzip_fixture: Path) -> None:
    digest_before = _sha256_file(gzip_fixture)

    vfs = GzipVFS(gzip_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    assert _sha256_file(gzip_fixture) == digest_before, "GzipVFS modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="GzipVFS must not change mtime or ctime of the .gz file",
)
def test_gzip_vfs_does_not_change_timestamps(gzip_fixture: Path) -> None:
    ts_before = _timestamps(gzip_fixture)

    vfs = GzipVFS(gzip_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    _assert_timestamps_unchanged(ts_before, _timestamps(gzip_fixture), "GzipVFS")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="GzipVFS must not create any sibling files next to the .gz file",
)
def test_gzip_vfs_creates_no_sibling_files(gzip_fixture: Path) -> None:
    files_before = set(gzip_fixture.parent.iterdir())

    vfs = GzipVFS(gzip_fixture)
    for node in _file_nodes(vfs.root()):
        _ = vfs.read(node)
    vfs.close()

    new_files = set(gzip_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"GzipVFS left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="GzipVFS must decompress and read the member when the .gz file is chmod 0o444",
)
def test_gzip_vfs_works_on_readonly_media(gzip_fixture: Path) -> None:
    gzip_fixture.chmod(0o444)
    try:
        vfs = GzipVFS(gzip_fixture)
        for node in _file_nodes(vfs.root()):
            _ = vfs.read(node)
        vfs.close()
    finally:
        gzip_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="minimal.sqlite.gz must decompress to exactly minimal.sqlite's bytes, member name 'minimal.sqlite'",
)
def test_gzip_fixture_known_output(gzip_fixture: Path) -> None:
    vfs = GzipVFS(gzip_fixture)
    nodes = _file_nodes(vfs.root())
    assert len(nodes) == 1
    node = nodes[0]

    assert node.name == "minimal.sqlite"
    assert vfs.read(node) == (FIXTURES_DIR / "minimal.sqlite").read_bytes()
    vfs.close()


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Reading the same gzip member twice must return byte-identical data",
)
def test_gzip_vfs_read_is_reproducible(gzip_fixture: Path) -> None:
    vfs = GzipVFS(gzip_fixture)
    node = _file_nodes(vfs.root())[0]
    assert vfs.read(node) == vfs.read(node)
    vfs.close()


# ---------------------------------------------------------------------------
# 8. MMKV parser forensic tests
# ---------------------------------------------------------------------------

def _mmkv_node(mmkv_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(mmkv_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == mmkv_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="MMKVParser.parse must leave the store file's bytes unchanged",
)
def test_mmkv_parser_does_not_modify_source(mmkv_fixture: Path) -> None:
    digest_before = _sha256_file(mmkv_fixture)
    node, vfs = _mmkv_node(mmkv_fixture)

    MMKVParser().parse(node, vfs)

    assert _sha256_file(mmkv_fixture) == digest_before, "MMKVParser modified the source store"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="MMKVParser.parse must not change mtime or ctime of the store file",
)
def test_mmkv_parser_does_not_change_timestamps(mmkv_fixture: Path) -> None:
    ts_before = _timestamps(mmkv_fixture)
    node, vfs = _mmkv_node(mmkv_fixture)

    MMKVParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(mmkv_fixture), "MMKVParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="MMKVParser.parse must not create any sibling files next to the store (its scratch copy for "
    "the third-party mmkv reader lives in a separate temp directory)",
)
def test_mmkv_parse_creates_no_sibling_files(mmkv_fixture: Path) -> None:
    files_before = set(mmkv_fixture.parent.iterdir())
    node, vfs = _mmkv_node(mmkv_fixture)

    MMKVParser().parse(node, vfs)

    new_files = set(mmkv_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"MMKVParser left unexpected files next to the store: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="MMKVParser.parse must work when the store file is chmod 0o444",
)
def test_mmkv_parser_works_on_readonly_media(mmkv_fixture: Path) -> None:
    mmkv_fixture.chmod(0o444)
    try:
        node, vfs = _mmkv_node(mmkv_fixture)
        result = MMKVParser().parse(node, vfs)
        assert "error" not in result.data
    finally:
        mmkv_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic MMKV store must parse to exactly one live string entry: channel='googleplay'",
)
def test_mmkv_fixture_known_output(mmkv_fixture: Path) -> None:
    node, vfs = _mmkv_node(mmkv_fixture)

    result = MMKVParser().parse(node, vfs)

    assert result.viewer_type == "mmkv"
    records = {r["key"]: r for r in result.data["records"]}
    assert records["channel"]["decoded"] == "googleplay"
    assert records["channel"]["type"] == "string"
    assert records["channel"]["state"] == "Live"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same MMKV store twice must produce identical records",
)
def test_mmkv_parse_is_reproducible(mmkv_fixture: Path) -> None:
    node, vfs = _mmkv_node(mmkv_fixture)
    parser = MMKVParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 9. ABX (Android Binary XML) parser forensic tests
# ---------------------------------------------------------------------------

def _abx_node(abx_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(abx_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == abx_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="AbxParser.parse must leave the source file's bytes unchanged",
)
def test_abx_parser_does_not_modify_source(abx_fixture: Path) -> None:
    digest_before = _sha256_file(abx_fixture)
    node, vfs = _abx_node(abx_fixture)

    AbxParser().parse(node, vfs)

    assert _sha256_file(abx_fixture) == digest_before, "AbxParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="AbxParser.parse must not change mtime or ctime of the source file",
)
def test_abx_parser_does_not_change_timestamps(abx_fixture: Path) -> None:
    ts_before = _timestamps(abx_fixture)
    node, vfs = _abx_node(abx_fixture)

    AbxParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(abx_fixture), "AbxParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="AbxParser.parse must not create any sibling files next to the source",
)
def test_abx_parse_creates_no_sibling_files(abx_fixture: Path) -> None:
    files_before = set(abx_fixture.parent.iterdir())
    node, vfs = _abx_node(abx_fixture)

    AbxParser().parse(node, vfs)

    new_files = set(abx_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"AbxParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="AbxParser.parse must work when the source file is chmod 0o444",
)
def test_abx_parser_works_on_readonly_media(abx_fixture: Path) -> None:
    abx_fixture.chmod(0o444)
    try:
        node, vfs = _abx_node(abx_fixture)
        result = AbxParser().parse(node, vfs)
        assert result.viewer_type == "abx"
    finally:
        abx_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc='Synthetic ABX <root attr="value"/> must decode to tag "root" with attribute attr="value"',
)
def test_abx_fixture_known_output(abx_fixture: Path) -> None:
    node, vfs = _abx_node(abx_fixture)

    result = AbxParser().parse(node, vfs)

    assert result.viewer_type == "abx"
    assert "<root" in result.data["xml_str"]
    tree = result.data["tree"]
    assert tree["@tag"] == "root"
    assert tree["@attribs"]["attr"] == "value"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same ABX file twice must produce identical results",
)
def test_abx_parse_is_reproducible(abx_fixture: Path) -> None:
    node, vfs = _abx_node(abx_fixture)
    parser = AbxParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 10. Apple ATX / KTX texture parser forensic tests (both routed through
#     ImageParser)
# ---------------------------------------------------------------------------

def _image_node(fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on an ATX file must leave the source file's bytes unchanged",
)
def test_atx_parser_does_not_modify_source(atx_fixture: Path) -> None:
    digest_before = _sha256_file(atx_fixture)
    node, vfs = _image_node(atx_fixture)

    ImageParser().parse(node, vfs)

    assert _sha256_file(atx_fixture) == digest_before, "ImageParser modified the ATX source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on an ATX file must not change mtime or ctime of the source file",
)
def test_atx_parser_does_not_change_timestamps(atx_fixture: Path) -> None:
    ts_before = _timestamps(atx_fixture)
    node, vfs = _image_node(atx_fixture)

    ImageParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(atx_fixture), "ImageParser (ATX)")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="ImageParser.parse on an ATX file must not create any sibling files next to the source",
)
def test_atx_parse_creates_no_sibling_files(atx_fixture: Path) -> None:
    files_before = set(atx_fixture.parent.iterdir())
    node, vfs = _image_node(atx_fixture)

    ImageParser().parse(node, vfs)

    new_files = set(atx_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"ImageParser left unexpected files next to the ATX source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="ImageParser.parse on an ATX file must work when the source file is chmod 0o444",
)
def test_atx_parser_works_on_readonly_media(atx_fixture: Path) -> None:
    atx_fixture.chmod(0o444)
    try:
        node, vfs = _image_node(atx_fixture)
        result = ImageParser().parse(node, vfs)
        assert result.metadata["Format"] == "ATX"
    finally:
        atx_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic 32x16 ATX HEAD chunk must report Width=32, Height=16, ASTC 4x4, metadata-only",
)
def test_atx_fixture_known_output(atx_fixture: Path) -> None:
    node, vfs = _image_node(atx_fixture)

    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "text"
    assert result.metadata["Format"] == "ATX"
    assert result.metadata["Width"] == 32
    assert result.metadata["Height"] == 16
    assert result.metadata["Pixel format"] == "ASTC 4x4"
    assert result.metadata["Decode status"].code == "atx.decode_unavailable"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same ATX file twice must produce identical results",
)
def test_atx_parse_is_reproducible(atx_fixture: Path) -> None:
    node, vfs = _image_node(atx_fixture)
    parser = ImageParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on a KTX file must leave the source file's bytes unchanged",
)
def test_ktx_parser_does_not_modify_source(ktx_fixture: Path) -> None:
    digest_before = _sha256_file(ktx_fixture)
    node, vfs = _image_node(ktx_fixture)

    ImageParser().parse(node, vfs)

    assert _sha256_file(ktx_fixture) == digest_before, "ImageParser modified the KTX source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on a KTX file must not change mtime or ctime of the source file",
)
def test_ktx_parser_does_not_change_timestamps(ktx_fixture: Path) -> None:
    ts_before = _timestamps(ktx_fixture)
    node, vfs = _image_node(ktx_fixture)

    ImageParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(ktx_fixture), "ImageParser (KTX)")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="ImageParser.parse on a KTX file must not create any sibling files next to the source",
)
def test_ktx_parse_creates_no_sibling_files(ktx_fixture: Path) -> None:
    files_before = set(ktx_fixture.parent.iterdir())
    node, vfs = _image_node(ktx_fixture)

    ImageParser().parse(node, vfs)

    new_files = set(ktx_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"ImageParser left unexpected files next to the KTX source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="ImageParser.parse on a KTX file must work when the source file is chmod 0o444",
)
def test_ktx_parser_works_on_readonly_media(ktx_fixture: Path) -> None:
    ktx_fixture.chmod(0o444)
    try:
        node, vfs = _image_node(ktx_fixture)
        result = ImageParser().parse(node, vfs)
        assert result.metadata["Format"] == "KTX"
    finally:
        ktx_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic 8x8 KTX with an unsupported glInternalFormat must be reported metadata-only",
)
def test_ktx_fixture_known_output(ktx_fixture: Path) -> None:
    node, vfs = _image_node(ktx_fixture)

    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "text"
    assert result.metadata["Format"] == "KTX"
    assert str(result.metadata["Pixel format"]) == "Unsupported (glInternalFormat 0x881A)"
    assert result.metadata["Decode status"].code == "ktx.decode_unavailable"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same KTX file twice must produce identical results",
)
def test_ktx_parse_is_reproducible(ktx_fixture: Path) -> None:
    node, vfs = _image_node(ktx_fixture)
    parser = ImageParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 11. Protobuf (schema-less) parser forensic tests
# ---------------------------------------------------------------------------

def _protobuf_node(protobuf_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(protobuf_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == protobuf_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ProtobufParser.parse must leave the source file's bytes unchanged",
)
def test_protobuf_parser_does_not_modify_source(protobuf_fixture: Path) -> None:
    digest_before = _sha256_file(protobuf_fixture)
    node, vfs = _protobuf_node(protobuf_fixture)

    ProtobufParser().parse(node, vfs)

    assert _sha256_file(protobuf_fixture) == digest_before, "ProtobufParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ProtobufParser.parse must not change mtime or ctime of the source file",
)
def test_protobuf_parser_does_not_change_timestamps(protobuf_fixture: Path) -> None:
    ts_before = _timestamps(protobuf_fixture)
    node, vfs = _protobuf_node(protobuf_fixture)

    ProtobufParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(protobuf_fixture), "ProtobufParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="ProtobufParser.parse must not create any sibling files next to the source",
)
def test_protobuf_parse_creates_no_sibling_files(protobuf_fixture: Path) -> None:
    files_before = set(protobuf_fixture.parent.iterdir())
    node, vfs = _protobuf_node(protobuf_fixture)

    ProtobufParser().parse(node, vfs)

    new_files = set(protobuf_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"ProtobufParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="ProtobufParser.parse must work when the source file is chmod 0o444",
)
def test_protobuf_parser_works_on_readonly_media(protobuf_fixture: Path) -> None:
    protobuf_fixture.chmod(0o444)
    try:
        node, vfs = _protobuf_node(protobuf_fixture)
        result = ProtobufParser().parse(node, vfs)
        assert result.viewer_type == "protobuf"
    finally:
        protobuf_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic message (field 1 varint=42, field 2 string='evidence') must decode exactly",
)
def test_protobuf_fixture_known_output(protobuf_fixture: Path) -> None:
    node, vfs = _protobuf_node(protobuf_fixture)

    result = ProtobufParser().parse(node, vfs)

    assert result.viewer_type == "protobuf"
    entries = result.data["decoded"]["entries"]
    assert len(entries) == 2
    assert entries[0]["field"] == 1
    assert entries[0]["wire_type"] == "varint"
    assert entries[0]["value"] == 42
    assert entries[1]["field"] == 2
    assert entries[1]["wire_type"] == "length-delimited"
    assert entries[1]["value"] == {"type": "string", "text": "evidence"}
    assert entries[1]["raw"] == b"evidence"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same protobuf message twice must produce identical results",
)
def test_protobuf_parse_is_reproducible(protobuf_fixture: Path) -> None:
    node, vfs = _protobuf_node(protobuf_fixture)
    parser = ProtobufParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 12. XML parser forensic tests
# ---------------------------------------------------------------------------

def _xml_node(xml_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(xml_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == xml_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="XmlParser.parse must leave the source file's bytes unchanged",
)
def test_xml_parser_does_not_modify_source(xml_fixture: Path) -> None:
    digest_before = _sha256_file(xml_fixture)
    node, vfs = _xml_node(xml_fixture)

    XmlParser().parse(node, vfs)

    assert _sha256_file(xml_fixture) == digest_before, "XmlParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="XmlParser.parse must not change mtime or ctime of the source file",
)
def test_xml_parser_does_not_change_timestamps(xml_fixture: Path) -> None:
    ts_before = _timestamps(xml_fixture)
    node, vfs = _xml_node(xml_fixture)

    XmlParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(xml_fixture), "XmlParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="XmlParser.parse must not create any sibling files next to the source",
)
def test_xml_parse_creates_no_sibling_files(xml_fixture: Path) -> None:
    files_before = set(xml_fixture.parent.iterdir())
    node, vfs = _xml_node(xml_fixture)

    XmlParser().parse(node, vfs)

    new_files = set(xml_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"XmlParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="XmlParser.parse must work when the source file is chmod 0o444",
)
def test_xml_parser_works_on_readonly_media(xml_fixture: Path) -> None:
    xml_fixture.chmod(0o444)
    try:
        node, vfs = _xml_node(xml_fixture)
        result = XmlParser().parse(node, vfs)
        assert result.viewer_type == "tree_text"
    finally:
        xml_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc='Synthetic <root attr="value"><child>text</child></root> must decode to that exact tree',
)
def test_xml_fixture_known_output(xml_fixture: Path) -> None:
    node, vfs = _xml_node(xml_fixture)

    result = XmlParser().parse(node, vfs)

    assert result.viewer_type == "tree_text"
    assert result.data["@tag"] == "root"
    assert result.data["@attribs"]["attr"] == "value"
    assert result.data["@children"][0]["@tag"] == "child"
    assert result.data["@children"][0]["@text"] == "text"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same XML file twice must produce identical results",
)
def test_xml_parse_is_reproducible(xml_fixture: Path) -> None:
    node, vfs = _xml_node(xml_fixture)
    parser = XmlParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 13. JSON parser forensic tests
# ---------------------------------------------------------------------------

def _json_node(json_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(json_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == json_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="JsonParser.parse must leave the source file's bytes unchanged",
)
def test_json_parser_does_not_modify_source(json_fixture: Path) -> None:
    digest_before = _sha256_file(json_fixture)
    node, vfs = _json_node(json_fixture)

    JsonParser().parse(node, vfs)

    assert _sha256_file(json_fixture) == digest_before, "JsonParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="JsonParser.parse must not change mtime or ctime of the source file",
)
def test_json_parser_does_not_change_timestamps(json_fixture: Path) -> None:
    ts_before = _timestamps(json_fixture)
    node, vfs = _json_node(json_fixture)

    JsonParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(json_fixture), "JsonParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="JsonParser.parse must not create any sibling files next to the source",
)
def test_json_parse_creates_no_sibling_files(json_fixture: Path) -> None:
    files_before = set(json_fixture.parent.iterdir())
    node, vfs = _json_node(json_fixture)

    JsonParser().parse(node, vfs)

    new_files = set(json_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"JsonParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="JsonParser.parse must work when the source file is chmod 0o444",
)
def test_json_parser_works_on_readonly_media(json_fixture: Path) -> None:
    json_fixture.chmod(0o444)
    try:
        node, vfs = _json_node(json_fixture)
        result = JsonParser().parse(node, vfs)
        assert result.viewer_type == "tree_text"
    finally:
        json_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc='Synthetic {"application": "crush-forensics", "count": 3} must decode to exactly that dict',
)
def test_json_fixture_known_output(json_fixture: Path) -> None:
    node, vfs = _json_node(json_fixture)

    result = JsonParser().parse(node, vfs)

    assert result.viewer_type == "tree_text"
    assert result.data == {"application": "crush-forensics", "count": 3}
    assert result.metadata["Format"] == "JSON"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same JSON file twice must produce identical results",
)
def test_json_parse_is_reproducible(json_fixture: Path) -> None:
    node, vfs = _json_node(json_fixture)
    parser = JsonParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 14. PDF parser forensic tests
# ---------------------------------------------------------------------------

def _pdf_node(pdf_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(pdf_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == pdf_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="PDFParser.parse must leave the source file's bytes unchanged",
)
def test_pdf_parser_does_not_modify_source(pdf_fixture: Path) -> None:
    digest_before = _sha256_file(pdf_fixture)
    node, vfs = _pdf_node(pdf_fixture)

    PDFParser().parse(node, vfs)

    assert _sha256_file(pdf_fixture) == digest_before, "PDFParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="PDFParser.parse must not change mtime or ctime of the source file",
)
def test_pdf_parser_does_not_change_timestamps(pdf_fixture: Path) -> None:
    ts_before = _timestamps(pdf_fixture)
    node, vfs = _pdf_node(pdf_fixture)

    PDFParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(pdf_fixture), "PDFParser")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="PDFParser.parse must not create any sibling files next to the source",
)
def test_pdf_parse_creates_no_sibling_files(pdf_fixture: Path) -> None:
    files_before = set(pdf_fixture.parent.iterdir())
    node, vfs = _pdf_node(pdf_fixture)

    PDFParser().parse(node, vfs)

    new_files = set(pdf_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"PDFParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="PDFParser.parse must work when the source file is chmod 0o444",
)
def test_pdf_parser_works_on_readonly_media(pdf_fixture: Path) -> None:
    pdf_fixture.chmod(0o444)
    try:
        node, vfs = _pdf_node(pdf_fixture)
        result = PDFParser().parse(node, vfs)
        assert result.viewer_type == "pdf"
    finally:
        pdf_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic 1-page PDF with Title/Author metadata must report exactly those known fields",
)
def test_pdf_fixture_known_output(pdf_fixture: Path) -> None:
    node, vfs = _pdf_node(pdf_fixture)

    result = PDFParser().parse(node, vfs)

    assert result.viewer_type == "pdf"
    assert result.metadata["Format"] == "PDF"
    assert result.metadata["Pages"] == "1"
    assert result.metadata["Title"] == "crush-forensics evidence"
    assert result.metadata["Author"] == "crush-forensics"
    assert result.metadata["JavaScript"].code == "pdf.js_not_present"
    assert result.metadata["Signatures"].code == "pdf.signatures_none"
    assert result.metadata["Attachments"] == ParseIssue("pdf.attachments", {"count": 0})
    assert result.metadata["Revisions"] == "1"
    assert "Revision chain" not in result.metadata


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same PDF file twice must produce identical results",
)
def test_pdf_parse_is_reproducible(pdf_fixture: Path) -> None:
    node, vfs = _pdf_node(pdf_fixture)
    parser = PDFParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 15. Image / EXIF parser forensic tests
# ---------------------------------------------------------------------------

def _image_exif_node(image_exif_fixture: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(image_exif_fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == image_exif_fixture.name)
    return node, vfs


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on a JPEG with EXIF must leave the source file's bytes unchanged",
)
def test_image_exif_parser_does_not_modify_source(image_exif_fixture: Path) -> None:
    digest_before = _sha256_file(image_exif_fixture)
    node, vfs = _image_exif_node(image_exif_fixture)

    ImageParser().parse(node, vfs)

    assert _sha256_file(image_exif_fixture) == digest_before, "ImageParser modified the source file"


@pytest.mark.forensic(
    category="Source Immutability",
    desc="ImageParser.parse on a JPEG with EXIF must not change mtime or ctime of the source file",
)
def test_image_exif_parser_does_not_change_timestamps(image_exif_fixture: Path) -> None:
    ts_before = _timestamps(image_exif_fixture)
    node, vfs = _image_exif_node(image_exif_fixture)

    ImageParser().parse(node, vfs)

    _assert_timestamps_unchanged(ts_before, _timestamps(image_exif_fixture), "ImageParser (EXIF)")


@pytest.mark.forensic(
    category="No Side Effects",
    desc="ImageParser.parse on a JPEG with EXIF must not create any sibling files next to the source",
)
def test_image_exif_parse_creates_no_sibling_files(image_exif_fixture: Path) -> None:
    files_before = set(image_exif_fixture.parent.iterdir())
    node, vfs = _image_exif_node(image_exif_fixture)

    ImageParser().parse(node, vfs)

    new_files = set(image_exif_fixture.parent.iterdir()) - files_before
    assert new_files == set(), f"ImageParser left unexpected files next to the source: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="ImageParser.parse on a JPEG with EXIF must work when the source file is chmod 0o444",
)
def test_image_exif_parser_works_on_readonly_media(image_exif_fixture: Path) -> None:
    image_exif_fixture.chmod(0o444)
    try:
        node, vfs = _image_exif_node(image_exif_fixture)
        result = ImageParser().parse(node, vfs)
        assert result.metadata["Make"] == "CrushCam"
    finally:
        image_exif_fixture.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="Synthetic JPEG with Make/Model/DateTime EXIF tags must report exactly those known values",
)
def test_image_exif_fixture_known_output(image_exif_fixture: Path) -> None:
    node, vfs = _image_exif_node(image_exif_fixture)

    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "image"
    assert result.metadata["Make"] == "CrushCam"
    assert result.metadata["Model"] == "CrushModel"
    assert result.metadata["DateTime"] == "2024:01:15 10:23:45"


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Parsing the same JPEG with EXIF twice must produce identical results",
)
def test_image_exif_parse_is_reproducible(image_exif_fixture: Path) -> None:
    node, vfs = _image_exif_node(image_exif_fixture)
    parser = ImageParser()

    r1 = parser.parse(node, vfs)
    r2 = parser.parse(node, vfs)

    assert r1.data == r2.data
    assert r1.metadata == r2.metadata
    assert r1.viewer_type == r2.viewer_type


# ---------------------------------------------------------------------------
# 16. Protobuf schema-based decoder (protobuf_schema.py) forensic tests —
#     the real compile_proto -> load_descriptor_set -> decode_message_with_schema
#     pipeline, using the real protoc-compiled schema + real protobuf-library-
#     encoded message that generate_protobuf_fixtures.py built as ground
#     truth. These fixtures existed but were never exercised by any test
#     (see project memory) before this section.
# ---------------------------------------------------------------------------

@pytest.mark.forensic(
    category="Source Immutability",
    desc="compile_proto/decode_message_with_schema must leave the .proto and .pb source files unchanged",
)
def test_protobuf_schema_does_not_modify_source(protobuf_schema_fixture: dict) -> None:
    proto_path = protobuf_schema_fixture["proto_path"]
    pb_path = protobuf_schema_fixture["pb_path"]
    proto_digest_before = _sha256_file(proto_path)
    pb_digest_before = _sha256_file(pb_path)

    loaded = load_descriptor_set(proto_path)
    decode_message_with_schema(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_path.read_bytes())

    assert _sha256_file(proto_path) == proto_digest_before, "compile_proto modified the .proto source"
    assert _sha256_file(pb_path) == pb_digest_before, "decode_message_with_schema modified the .pb source"


@pytest.mark.forensic(
    category="No Side Effects",
    desc="compile_proto must not create any sibling files next to the .proto/.pb sources "
    "(its FileDescriptorSet output goes to a separate temp directory)",
)
def test_protobuf_schema_creates_no_sibling_files(protobuf_schema_fixture: dict) -> None:
    proto_path = protobuf_schema_fixture["proto_path"]
    files_before = set(proto_path.parent.iterdir())

    load_descriptor_set(proto_path)

    new_files = set(proto_path.parent.iterdir()) - files_before
    assert new_files == set(), f"compile_proto left unexpected files next to the sources: {new_files}"


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    desc="The schema-based decode pipeline must work when the .proto and .pb source files are chmod 0o444",
)
def test_protobuf_schema_works_on_readonly_media(protobuf_schema_fixture: dict) -> None:
    proto_path = protobuf_schema_fixture["proto_path"]
    pb_path = protobuf_schema_fixture["pb_path"]
    proto_path.chmod(0o444)
    pb_path.chmod(0o444)
    try:
        loaded = load_descriptor_set(proto_path)
        msg = decode_message_with_schema(
            loaded["pool"], "crush.fixtures.BasicWireTypes", pb_path.read_bytes()
        )
        assert msg.small_count == 1
    finally:
        proto_path.chmod(0o644)
        pb_path.chmod(0o644)


@pytest.mark.forensic(
    category="Known-output Verification",
    desc="protobuf_basic_wire_types.pb decoded against its real protoc-compiled schema must match "
    "the committed .expected.json ground truth field-for-field",
)
def test_protobuf_schema_fixture_known_output(protobuf_schema_fixture: dict) -> None:
    proto_path = protobuf_schema_fixture["proto_path"]
    pb_bytes = protobuf_schema_fixture["pb_path"].read_bytes()
    expected = protobuf_schema_fixture["expected"]

    loaded = load_descriptor_set(proto_path)
    assert "crush.fixtures.BasicWireTypes" in loaded["message_names"]
    msg = decode_message_with_schema(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)

    assert msg.small_count == 1
    assert msg.large_count == 300
    assert msg.enabled is True
    assert msg.unix_timestamp == 1_700_000_000
    assert msg.temperature_c == pytest.approx(36.5)
    assert msg.magic_fixed32 == 305_419_896
    assert msg.ratio == pytest.approx(6.25)
    assert msg.magic_fixed64 == 0x0102030405060708
    assert msg.note == "hello forensic protobuf"
    assert msg.binary_blob == bytes.fromhex("00ff10807f42")
    assert msg.empty_blob == b""
    assert msg.long_text == "L" * 130

    # Byte-provenance ("Locate in Hex") ranges must match the committed
    # ground truth's key/value ranges for every scalar top-level field.
    ranges = schema_byte_ranges(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)
    for field in expected["fields"]:
        path = (field["name"],)
        assert path in ranges, f"no byte range computed for field {field['name']!r}"
        assert list(ranges[path]["byte_range"]) == field["byte_range"], field["name"]
        highlights = ranges[path]["highlight_ranges"]
        assert list(highlights[0]) == field["key_range"], field["name"]
        assert list(highlights[-1]) == field["value_range"], field["name"]


@pytest.mark.forensic(
    category="Reproducibility",
    desc="Decoding the same protobuf message against the same schema twice must produce identical results",
)
def test_protobuf_schema_decode_is_reproducible(protobuf_schema_fixture: dict) -> None:
    proto_path = protobuf_schema_fixture["proto_path"]
    pb_bytes = protobuf_schema_fixture["pb_path"].read_bytes()

    loaded = load_descriptor_set(proto_path)
    msg1 = decode_message_with_schema(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)
    msg2 = decode_message_with_schema(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)

    assert msg1 == msg2
    ranges1 = schema_byte_ranges(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)
    ranges2 = schema_byte_ranges(loaded["pool"], "crush.fixtures.BasicWireTypes", pb_bytes)
    assert ranges1 == ranges2
