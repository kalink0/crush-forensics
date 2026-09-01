# SPDX-License-Identifier: Apache-2.0
"""Pytest configuration: fixture corpus integrity + forensic audit report.

Two responsibilities:
  1. Verify SHA-256 checksums of committed test-evidence files before any test
     runs.  If a fixture has been tampered with the entire session is aborted.
  2. Collect results of @pytest.mark.forensic-tagged tests and generate a
     human-readable audit report at reports/forensic_audit.html.
"""
from __future__ import annotations

import datetime
import hashlib
import html as _html
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Forensic category metadata (order + intro text shown in the report)
# ---------------------------------------------------------------------------

_CATEGORY_ORDER = [
    "Source Immutability",
    "No Side Effects",
    "Read-only Media",
    "Known-output Verification",
    "Completeness",
    "Reproducibility",
]

_CATEGORY_INTROS: dict[str, str] = {
    "Source Immutability": (
        "The tool must never modify digital evidence it reads. "
        "These tests verify that after any VFS read operation the source data is "
        "byte-identical to its pre-examination state."
    ),
    "No Side Effects": (
        "Parsing an artifact must not create additional files next to the evidence. "
        "Sibling files such as SQLite WAL or journal entries would alter the "
        "evidence directory and compromise the examination."
    ),
    "Read-only Media": (
        "The tool must operate correctly when evidence has read-only permissions "
        "(chmod 0o444 / 0o555), simulating examination of write-protected forensic media."
    ),
    "Known-output Verification": (
        "Committed reference artifacts must parse to their exact, pre-computed values. "
        "These are fixed-point checks: if parser output changes for a known input, "
        "the test fails."
    ),
    "Completeness": (
        "Every plausible interpretation of a value must always be produced — silently "
        "omitting a valid interpretation means potentially missing forensic evidence. "
        "These tests verify that no interpretation group is ever dropped."
    ),
    "Reproducibility": (
        "Parsing the same artifact twice must produce identical results. "
        "Non-deterministic output would undermine the reliability of forensic findings."
    ),
}

# Module-level state populated by the hooks below
_forensic_items: dict[str, dict[str, str]] = {}
_forensic_results: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Corpus integrity check + marker registration
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pytest_configure(config: pytest.Config) -> None:
    """Register the forensic marker and abort if any fixture file was tampered with."""
    config.addinivalue_line(
        "markers",
        "forensic(category, desc): mark test as a forensic integrity check",
    )

    checksums_path = FIXTURES_DIR / "checksums.json"
    if not checksums_path.exists():
        return

    expected: dict[str, str] = json.loads(checksums_path.read_text())
    failures: list[str] = []

    for name, digest in expected.items():
        fpath = FIXTURES_DIR / name
        if not fpath.exists():
            failures.append(f"  MISSING   {name}")
            continue
        actual = _sha256(fpath)
        if actual != digest:
            failures.append(
                f"  TAMPERED  {name}\n"
                f"    expected: {digest}\n"
                f"    actual:   {actual}"
            )

    if failures:
        pytest.exit(
            "Fixture corpus integrity check FAILED — "
            "committed test evidence has been modified:\n" + "\n".join(failures),
            returncode=3,
        )


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def realm_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.realm placed in tmp_path."""
    src = FIXTURES_DIR / "minimal.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def realm_format9_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal_format9.realm (pre-Cluster file format 9,
    BigBlobs-form class names — see issue #55) placed in tmp_path."""
    src = FIXTURES_DIR / "minimal_format9.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def sqlite_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.sqlite placed in tmp_path."""
    src = FIXTURES_DIR / "minimal.sqlite"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def plist_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal_binary.plist placed in tmp_path."""
    src = FIXTURES_DIR / "minimal_binary.plist"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def zip_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.zip placed in tmp_path."""
    src = FIXTURES_DIR / "minimal.zip"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def tar_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.tar.gz placed in tmp_path."""
    src = FIXTURES_DIR / "minimal.tar.gz"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def android_backup_fixture(tmp_path: Path) -> Path:
    """Synthetic unencrypted `adb backup` (.ab) container in tmp_path.

    Built on the fly rather than checked into fixtures/ — an .ab is just a
    header plus a deflated tar stream, and forensic tooling shouldn't ship
    even a fake device backup if a few lines of code can produce one.
    """
    import io
    import tarfile
    import zlib

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        data = b"SQLite format 3\x00"
        info = tarfile.TarInfo(name="apps/com.example.app/db/sample.db")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    dst = tmp_path / "backup.ab"
    dst.write_bytes(
        b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_buf.getvalue())
    )
    return dst


@pytest.fixture
def android_backup_encrypted_fixture(tmp_path: Path) -> Path:
    """Synthetic password-protected `adb backup` (.ab) container, password
    "hunter2" — built with the same primitives crush.core.android_backup_crypto
    uses (mirror-image of the decrypt path: PBKDF2 derive, AES-CBC encrypt
    the master-key blob and the payload) so the test exercises the real
    cryptographic pipeline, not a stub.
    """
    import io
    import os
    import tarfile
    import zlib

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from crush.core.android_backup_crypto import _key_checksum, _password_to_bytes, _pbkdf2

    password = "hunter2"
    version = 5
    rounds = 10_000

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        data = b"SQLite format 3\x00"
        info = tarfile.TarInfo(name="apps/com.example.app/db/sample.db")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    compressed_payload = zlib.compress(tar_buf.getvalue())

    user_salt = os.urandom(64)
    checksum_salt = os.urandom(64)
    user_iv = os.urandom(16)
    master_key = os.urandom(32)
    master_iv = os.urandom(16)

    user_key = _pbkdf2(_password_to_bytes(password), user_salt, rounds)
    checksum = _key_checksum(master_key, checksum_salt, rounds, use_utf8=version >= 2)
    mk_blob = (
        bytes([len(master_iv)]) + master_iv
        + bytes([len(master_key)]) + master_key
        + bytes([len(checksum)]) + checksum
    )
    mk_pad = 16 - (len(mk_blob) % 16)
    mk_blob_padded = mk_blob + bytes([mk_pad]) * mk_pad
    mk_encryptor = Cipher(algorithms.AES(user_key), modes.CBC(user_iv)).encryptor()
    master_key_blob_ct = mk_encryptor.update(mk_blob_padded) + mk_encryptor.finalize()

    payload_pad = 16 - (len(compressed_payload) % 16)
    payload_padded = compressed_payload + bytes([payload_pad]) * payload_pad
    payload_encryptor = Cipher(algorithms.AES(master_key), modes.CBC(master_iv)).encryptor()
    payload_ct = payload_encryptor.update(payload_padded) + payload_encryptor.finalize()

    header = (
        b"ANDROID BACKUP\n" + str(version).encode() + b"\n1\nAES-256\n"
        + user_salt.hex().encode() + b"\n"
        + checksum_salt.hex().encode() + b"\n"
        + str(rounds).encode() + b"\n"
        + user_iv.hex().encode() + b"\n"
        + master_key_blob_ct.hex().encode() + b"\n"
    )

    dst = tmp_path / "backup_encrypted.ab"
    dst.write_bytes(header + payload_ct)
    return dst


@pytest.fixture
def sevenzip_encrypted_content_fixture(tmp_path: Path) -> Path:
    """Password-protected 7z archive, content encrypted but the file listing
    itself is not (py7zr's `header_encryption` left at its default False).
    Password: "secret123"."""
    import py7zr

    dst = tmp_path / "content_encrypted.7z"
    with py7zr.SevenZipFile(dst, "w", password="secret123") as zf:
        zf.writestr(b"SQLite format 3\x00", "sample.db")
    return dst


@pytest.fixture
def sevenzip_encrypted_header_fixture(tmp_path: Path) -> Path:
    """Password-protected 7z archive with header encryption enabled — even
    listing file names requires the password. Password: "secret123"."""
    import py7zr

    dst = tmp_path / "header_encrypted.7z"
    with py7zr.SevenZipFile(dst, "w", password="secret123", header_encryption=True) as zf:
        zf.writestr(b"SQLite format 3\x00", "sample.db")
    return dst


@pytest.fixture
def legacy_encrypted_zip_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal_legacy_encrypted.zip (password "secret123"), placed in tmp_path.

    Checked into fixtures/ rather than built inline like the other synthetic
    fixtures in this file — legacy ZipCrypto is a write-only-by-nobody format
    among our dependencies: stdlib zipfile can only read it, and pyzipper
    refuses to write it at all (deliberately, since it's cryptographically
    weak). Built once with the system `zip -P` tool.
    """
    src = FIXTURES_DIR / "minimal_legacy_encrypted.zip"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def aes_encrypted_zip_fixture(tmp_path: Path) -> Path:
    """Synthetic WinZip-AES-encrypted ZIP (password "secret123") in tmp_path,
    built with pyzipper (our own AES-ZIP dependency, so no checked-in binary
    is needed the way legacy_encrypted_zip_fixture requires)."""
    import pyzipper

    dst = tmp_path / "aes_encrypted.zip"
    with pyzipper.AESZipFile(dst, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"secret123")
        zf.writestr("sample.db", b"SQLite format 3\x00")
    return dst


@pytest.fixture
def itunes_backup_fixture(tmp_path: Path) -> Path:
    """Synthetic unencrypted iTunes/Finder iOS backup directory in tmp_path.

    Built on the fly (Manifest.db + one sharded file) rather than checked
    into fixtures/, for the same reason as android_backup_fixture.
    """
    import plistlib
    import sqlite3

    backup_dir = tmp_path / "00008030-000A2D6E3601C01E"
    backup_dir.mkdir()

    conn = sqlite3.connect(backup_dir / "Manifest.db")
    conn.execute(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, "
        "relativePath TEXT, flags INTEGER, file BLOB)"
    )
    file_id = "3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"
    conn.execute(
        "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
        (file_id, "HomeDomain", "Library/SMS/sms.db", 1, b""),
    )
    conn.commit()
    conn.close()

    shard_dir = backup_dir / file_id[:2]
    shard_dir.mkdir()
    (shard_dir / file_id).write_bytes(b"SQLite format 3\x00")

    (backup_dir / "Info.plist").write_bytes(plistlib.dumps({"Product Name": "iPhone"}))
    (backup_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    (backup_dir / "Status.plist").write_bytes(plistlib.dumps({"BackupState": "new"}))

    return backup_dir


def _build_backup_keybag_tlv(salt: bytes, iterations: int, dpsl: bytes, dpic: int,
                              class_num: int, wrapped_class_key: bytes) -> bytes:
    """Build a minimal BackupKeyBag TLV blob (header + one class-key group)."""
    import os
    import struct

    def tlv(tag: str, value: bytes | int) -> bytes:
        if isinstance(value, int):
            value = struct.pack(">I", value)
        return tag.encode("ascii") + struct.pack(">I", len(value)) + value

    return (
        tlv("UUID", os.urandom(16))
        + tlv("WRAP", 0)
        + tlv("SALT", salt)
        + tlv("ITER", iterations)
        + tlv("DPSL", dpsl)
        + tlv("DPIC", dpic)
        + tlv("UUID", os.urandom(16))
        + tlv("CLAS", class_num)
        + tlv("WRAP", 2)  # WRAP_PASSCODE
        + tlv("KTYP", 0)
        + tlv("WPKY", wrapped_class_key)
    )


def _build_nska_file_metadata(protection_class: int, encryption_key_entry: bytes) -> bytes:
    """Build a minimal NSKeyedArchiver bplist matching `Files.file`'s real shape
    (ProtectionClass + EncryptionKey, the two fields crush.core.ios_keybag reads)."""
    import plistlib

    objects = [
        "$null",
        {"$class": plistlib.UID(3), "ProtectionClass": protection_class, "EncryptionKey": plistlib.UID(2)},
        {"$class": plistlib.UID(4), "NS.data": encryption_key_entry},
        {"$classes": ["MBFile", "NSObject"], "$classname": "MBFile"},
        {"$classes": ["NSMutableData", "NSData", "NSObject"], "$classname": "NSMutableData"},
    ]
    archive = {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": {"root": plistlib.UID(1)},
        "$objects": objects,
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


@pytest.fixture
def itunes_backup_keybag_fixture(tmp_path: Path) -> Path:
    """Synthetic iOS-10.2+-style iTunes backup: Manifest.db is KeyBag/AES
    encrypted (as real backups always are since iOS 10.2), but the backup
    itself has no password (`IsEncrypted: False` — the common, real-world
    case exercised against Josh Hickman's iOS 14.3 sample by the user).

    Built with the same primitives `crush.core.ios_keybag` uses (mirror-image
    of the decrypt path: PBKDF2 derive, AES key-wrap, AES-CBC encrypt) so the
    test exercises the real cryptographic pipeline, not a stub.
    """
    import os
    import plistlib
    import sqlite3
    import struct

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap

    from crush.core.ios_keybag import _pbkdf2

    password = ""
    class_num = 3
    class_key = os.urandom(32)
    manifest_key = os.urandom(32)
    salt, iterations = os.urandom(20), 10_000
    dpsl, dpic = os.urandom(20), 100_000

    passcode_key = _pbkdf2(password.encode(), dpsl, dpic, "sha256")
    passcode_key = _pbkdf2(passcode_key, salt, iterations, "sha1")

    keybag = _build_backup_keybag_tlv(
        salt, iterations, dpsl, dpic, class_num, aes_key_wrap(passcode_key, class_key)
    )
    manifest_key_entry = struct.pack("<I", class_num) + aes_key_wrap(class_key, manifest_key)

    backup_dir = tmp_path / "00008030-000A2D6E3601C01F"
    backup_dir.mkdir()

    file_id = "3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"

    # A second, per-file-encrypted file (real backups with IsEncrypted=False
    # still leave file contents in the clear — this shape only shows up once
    # a backup password is set — but the fixture builds it regardless so the
    # per-file decrypt path in ITunesBackupVFS.read()/ios_keybag.py is covered
    # without needing a real password-protected sample in the test suite).
    protected_file_id = "aa11bb22cc33dd44ee55ff667788990011223344"
    protected_plaintext = b"protected note content" * 4
    file_key = os.urandom(32)
    encryption_key_entry = struct.pack("<I", class_num) + aes_key_wrap(class_key, file_key)
    protected_file_blob = _build_nska_file_metadata(class_num, encryption_key_entry)

    # Built as a real on-disk WAL-mode database, then checkpointed and read back
    # as bytes — real-world Manifest.db files are WAL-mode (SQLite header format
    # version 2), which sqlite3.Connection.deserialize() can't open directly
    # (see _clear_wal_header_flag in crush.core.vfs). Using plain serialize()
    # here would produce a rollback-journal-mode header and silently skip that
    # code path, as an earlier version of this fixture did.
    plain_path = tmp_path / "_plaintext_manifest.db"
    plain = sqlite3.connect(plain_path)
    plain.execute("PRAGMA journal_mode=WAL")
    plain.execute(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, "
        "relativePath TEXT, flags INTEGER, file BLOB)"
    )
    plain.execute(
        "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
        (file_id, "HomeDomain", "Library/SMS/sms.db", 1, b""),
    )
    plain.execute(
        "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
        (protected_file_id, "HomeDomain", "Library/Notes/notes.sqlite", 1, protected_file_blob),
    )
    plain.commit()
    plain.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    plain.close()
    plaintext_manifest_db = plain_path.read_bytes()
    plain_path.unlink()
    for sidecar in (f"{plain_path}-wal", f"{plain_path}-shm"):
        Path(sidecar).unlink(missing_ok=True)

    pad_len = 16 - (len(plaintext_manifest_db) % 16)
    padded = plaintext_manifest_db + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(manifest_key), modes.CBC(b"\x00" * 16)).encryptor()
    encrypted_manifest_db = encryptor.update(padded) + encryptor.finalize()
    (backup_dir / "Manifest.db").write_bytes(encrypted_manifest_db)

    shard_dir = backup_dir / file_id[:2]
    shard_dir.mkdir()
    (shard_dir / file_id).write_bytes(b"SQLite format 3\x00")

    protected_pad_len = 16 - (len(protected_plaintext) % 16)
    protected_padded = protected_plaintext + bytes([protected_pad_len]) * protected_pad_len
    protected_encryptor = Cipher(algorithms.AES(file_key), modes.CBC(b"\x00" * 16)).encryptor()
    protected_ciphertext = protected_encryptor.update(protected_padded) + protected_encryptor.finalize()
    protected_shard_dir = backup_dir / protected_file_id[:2]
    protected_shard_dir.mkdir(exist_ok=True)
    (protected_shard_dir / protected_file_id).write_bytes(protected_ciphertext)

    (backup_dir / "Info.plist").write_bytes(plistlib.dumps({"Product Name": "iPhone"}))
    (backup_dir / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {"IsEncrypted": False, "BackupKeyBag": keybag, "ManifestKey": manifest_key_entry}
        )
    )
    (backup_dir / "Status.plist").write_bytes(plistlib.dumps({"BackupState": "new"}))

    return backup_dir


@pytest.fixture
def itunes_backup_zip_fixture(tmp_path: Path, itunes_backup_keybag_fixture: Path) -> Path:
    """The keybag-encrypted backup fixture, wrapped in a `.zip` under a single
    top-level folder — mirrors how the user's real-world sample (a zipped
    iTunes backup with one wrapper directory before Manifest.db) is shaped.
    """
    import zipfile

    zip_path = tmp_path / "backup_export.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for path in itunes_backup_keybag_fixture.rglob("*"):
            if path.is_file():
                arcname = f"wrapper/{path.relative_to(itunes_backup_keybag_fixture)}"
                zf.write(path, arcname)
    return zip_path


@pytest.fixture
def segb_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.segb2 placed in tmp_path."""
    src = FIXTURES_DIR / "minimal.segb2"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


# ---------------------------------------------------------------------------
# Forensic report: collect results during the run
# ---------------------------------------------------------------------------

def pytest_collection_finish(session: pytest.Session) -> None:
    for item in session.items:
        marker = item.get_closest_marker("forensic")
        if marker is not None:
            _forensic_items[item.nodeid] = {
                "category": str(marker.kwargs.get("category", "Uncategorized")),
                "desc": str(marker.kwargs.get("desc", item.name)),
                "name": item.name,
            }


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    nodeid = report.nodeid
    if nodeid not in _forensic_items:
        return
    # Skips are reported during setup; everything else at call time
    if report.when == "setup" and report.skipped:
        outcome, reason = "skipped", str(getattr(report, "wasxfail", "")) or "skipped"
    elif report.when == "call":
        if report.passed:
            outcome, reason = "passed", ""
        elif report.skipped:
            outcome, reason = "skipped", ""
        else:
            outcome, reason = "failed", str(report.longrepr) if report.longrepr else ""
    else:
        return

    _forensic_results.append({
        **_forensic_items[nodeid],
        "outcome": outcome,
        "reason": reason,
    })


# ---------------------------------------------------------------------------
# Forensic report: generate HTML on session finish
# ---------------------------------------------------------------------------

def pytest_sessionfinish(session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
    if not _forensic_results:
        return
    output_path = Path(str(session.config.rootdir)) / "reports" / "forensic_audit.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render_report(), encoding="utf-8")
    print(f"\n  Forensic audit report -> {output_path}")

    # Write a Markdown summary to the GitHub Actions job summary page when running in CI
    gha_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gha_summary:
        Path(gha_summary).open("a", encoding="utf-8").write(_render_gha_summary())


def _render_gha_summary() -> str:
    passed = sum(1 for r in _forensic_results if r["outcome"] == "passed")
    failed = sum(1 for r in _forensic_results if r["outcome"] == "failed")
    skipped = sum(1 for r in _forensic_results if r["outcome"] == "skipped")
    overall = "PASS" if failed == 0 else "FAIL"
    icon = "white_check_mark" if failed == 0 else "x"

    by_cat: dict[str, list[dict[str, Any]]] = {c: [] for c in _CATEGORY_ORDER}
    for r in _forensic_results:
        cat = r["category"]
        if cat not in by_cat:
            by_cat[cat] = []
        by_cat[cat].append(r)

    rows = ""
    for category in _CATEGORY_ORDER:
        results = by_cat.get(category, [])
        if not results:
            continue
        c_pass = sum(1 for r in results if r["outcome"] == "passed")
        c_fail = sum(1 for r in results if r["outcome"] == "failed")
        c_skip = sum(1 for r in results if r["outcome"] == "skipped")
        cat_icon = ":white_check_mark:" if c_fail == 0 else ":x:"
        counts = f"{c_pass} passed"
        if c_fail:
            counts += f", {c_fail} failed"
        if c_skip:
            counts += f", {c_skip} skipped"
        rows += f"| {cat_icon} {category} | {counts} |\n"

    return (
        f"\n## :{icon}: Forensic Integrity Audit &mdash; {overall}\n\n"
        f"| Category | Result |\n"
        f"|---|---|\n"
        f"{rows}\n"
        f"**{passed} passed &nbsp;·&nbsp; {failed} failed &nbsp;·&nbsp; {skipped} skipped**\n\n"
        f"> Full report available as the `forensic-test-report` CI artifact.\n"
    )


def _render_report() -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    python_ver = sys.version.split()[0]

    passed = sum(1 for r in _forensic_results if r["outcome"] == "passed")
    failed = sum(1 for r in _forensic_results if r["outcome"] == "failed")
    skipped = sum(1 for r in _forensic_results if r["outcome"] == "skipped")
    total = len(_forensic_results)
    overall = "PASS" if failed == 0 else "FAIL"
    ov_cls = "pass" if failed == 0 else "fail"

    # Group by category, preserving defined order
    by_cat: dict[str, list[dict[str, Any]]] = {c: [] for c in _CATEGORY_ORDER}
    for r in _forensic_results:
        cat = r["category"]
        if cat not in by_cat:
            by_cat[cat] = []
        by_cat[cat].append(r)

    sections = ""
    for category in _CATEGORY_ORDER:
        results = by_cat.get(category, [])
        if not results:
            continue
        c_pass = sum(1 for r in results if r["outcome"] == "passed")
        c_fail = sum(1 for r in results if r["outcome"] == "failed")
        c_skip = sum(1 for r in results if r["outcome"] == "skipped")
        badge_cls = "pass" if c_fail == 0 else "fail"
        badge_txt = "PASS" if c_fail == 0 else "FAIL"
        counter = f"{c_pass}&#10003;"
        if c_fail:
            counter += f"&nbsp; {c_fail}&#10007;"
        if c_skip:
            counter += f"&nbsp; {c_skip}&ndash;"
        intro = _html.escape(_CATEGORY_INTROS.get(category, ""))
        rows = ""
        for r in results:
            oc = r["outcome"]
            rows += (
                f'<tr class="row-{oc}">'
                f'<td class="cell-status status-{oc}">{oc.upper()}</td>'
                f'<td class="cell-desc">{_html.escape(r["desc"])}</td>'
                f'<td class="cell-fn">{_html.escape(r["name"])}</td>'
                f"</tr>\n"
            )
        sections += f"""
<section>
  <div class="cat-header">
    <h2>{_html.escape(category)}</h2>
    <span class="badge {badge_cls}">{badge_txt}</span>
    <span class="cat-count">{counter}</span>
  </div>
  <p class="cat-intro">{intro}</p>
  <table>
    <thead><tr>
      <th class="col-status">Result</th>
      <th class="col-desc">Forensic Property Verified</th>
      <th class="col-fn">Test Function</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    # Reference corpus section
    checksums_path = FIXTURES_DIR / "checksums.json"
    corpus_rows = ""
    if checksums_path.exists():
        checksums: dict[str, str] = json.loads(checksums_path.read_text())
        for name, digest in sorted(checksums.items()):
            fpath = FIXTURES_DIR / name
            size = fpath.stat().st_size if fpath.exists() else 0
            corpus_rows += (
                f"<tr>"
                f'<td class="cell-fn">{_html.escape(name)}</td>'
                f'<td class="cell-hash">{digest}</td>'
                f'<td class="cell-size">{size:,}&thinsp;B</td>'
                f"</tr>\n"
            )
    corpus = f"""
<section>
  <div class="cat-header">
    <h2>Reference Corpus</h2>
    <span class="badge pass">VERIFIED</span>
  </div>
  <p class="cat-intro">
    SHA-256 checksums of the committed test-evidence files.
    The corpus integrity check runs before the first test and aborts the session
    if any file has been modified.
  </p>
  <table>
    <thead><tr>
      <th class="col-fn">File</th>
      <th class="col-hash">SHA-256</th>
      <th class="col-size" style="text-align:right">Size</th>
    </tr></thead>
    <tbody>{corpus_rows}</tbody>
  </table>
</section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Crush &mdash; Forensic Integrity Audit</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         font-size:14px;color:#1a1a2e;background:#f0f2f5}}
    a{{color:inherit}}
    header{{background:#1a1a2e;color:#fff;padding:24px 32px 20px}}
    header h1{{font-size:20px;font-weight:600;letter-spacing:.3px}}
    .meta{{margin-top:5px;font-size:12px;opacity:.65}}
    .overall{{display:inline-flex;align-items:center;gap:12px;
              margin-top:14px;background:rgba(255,255,255,.08);
              padding:8px 16px;border-radius:6px}}
    .verdict{{font-size:18px;font-weight:700;letter-spacing:1px}}
    .verdict.pass{{color:#4ade80}}.verdict.fail{{color:#f87171}}
    .counts{{font-size:12px;opacity:.75}}
    main{{max-width:960px;margin:0 auto;padding:24px 16px 40px}}
    section{{background:#fff;border-radius:8px;padding:20px 24px;
             margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
    .cat-header{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
    .cat-header h2{{font-size:15px;font-weight:600}}
    .cat-count{{font-size:12px;color:#666}}
    .badge{{font-size:11px;font-weight:700;letter-spacing:.4px;
            padding:2px 8px;border-radius:4px}}
    .badge.pass{{background:#dcfce7;color:#166534}}
    .badge.fail{{background:#fee2e2;color:#991b1b}}
    .cat-intro{{font-size:13px;color:#555;line-height:1.55;margin-bottom:14px}}
    table{{width:100%;border-collapse:collapse}}
    th{{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;
        letter-spacing:.5px;color:#999;padding:6px 10px;
        border-bottom:2px solid #e5e7eb}}
    td{{padding:8px 10px;border-bottom:1px solid #f3f4f6;vertical-align:top}}
    tr:last-child td{{border-bottom:none}}
    .col-status{{width:68px}}.col-fn{{width:260px}}
    .cell-status{{font-weight:700;font-size:11px;letter-spacing:.5px}}
    .status-passed{{color:#16a34a}}.status-failed{{color:#dc2626}}
    .status-skipped{{color:#9ca3af}}
    .cell-fn{{font-family:"SF Mono","Fira Code",monospace;font-size:12px;color:#6366f1}}
    .cell-hash{{font-family:"SF Mono","Fira Code",monospace;font-size:11px;
               color:#888;word-break:break-all}}
    .cell-size{{text-align:right;color:#888;font-size:12px;white-space:nowrap}}
    .row-failed{{background:#fff5f5}}.row-skipped td{{opacity:.55}}
    footer{{text-align:center;font-size:11px;color:#bbb;padding:0 0 24px}}
  </style>
</head>
<body>
<header>
  <h1>Crush &mdash; Forensic Integrity Audit Report</h1>
  <div class="meta">Generated: {now}&nbsp;&nbsp;|&nbsp;&nbsp;Python {python_ver}</div>
  <div class="overall">
    <span class="verdict {ov_cls}">{overall}</span>
    <span class="counts">
      {passed} passed &nbsp;&middot;&nbsp;
      {failed} failed &nbsp;&middot;&nbsp;
      {skipped} skipped &nbsp;&middot;&nbsp;
      {total} total
    </span>
  </div>
</header>
<main>
{sections}
{corpus}
</main>
<footer>crush-forensics &nbsp;&middot;&nbsp; forensic audit report &nbsp;&middot;&nbsp; {now}</footer>
</body>
</html>"""
