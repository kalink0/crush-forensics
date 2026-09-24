# SPDX-License-Identifier: Apache-2.0
"""Pytest configuration: fixture corpus integrity + forensic audit report.

Two responsibilities:
  1. Verify SHA-256 checksums of committed test-evidence files before any test
     runs.  If a fixture has been tampered with the entire session is aborted.
  2. Collect results of @pytest.mark.forensic-tagged tests and generate a
     human-readable audit report at reports/forensic_audit.html, plus the
     same data as reports/forensic_audit.json (rendering lives in
     forensic_report.py, shared with scripts/combine_forensic_audit.py).
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from crush.tests import forensic_report

# Qt tests build real widgets (TableViewer, HexViewer, ...) against the
# pytest-qt qapp/qtbot fixtures. Left unset, PySide6 connects to whatever
# real display this machine has (X11/Wayland), so any test that calls
# .show() or relies on real on-screen visibility (isVisible()) would pop an
# actual window on the developer's live desktop. Forcing Qt's built-in
# offscreen platform plugin -- before any QApplication is constructed --
# keeps widget visibility state fully real and queryable without ever
# touching a real display; must be set here (not in a fixture) since it has
# to take effect before pytest-qt's own qapp fixture creates the
# QApplication singleton.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Module-level state populated by the hooks below
_forensic_items: dict[str, dict[str, Any]] = {}
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
# Qt safety net
# ---------------------------------------------------------------------------
#
# No test should ever launch a real external application (a file manager, a
# browser) -- that's a side effect on the developer's own desktop, not on
# anything the test controls or cleans up. This has actually happened: a
# MainWindow left open by one test (see the general Qt-widget-leak note
# below) can have a queued cross-thread "export finished" signal delivered
# arbitrarily late, during a completely unrelated later test's own Qt event
# loop -- by which point that first test's QMessageBox mock has already been
# reverted, so the real "Open location?" dialog and, if answered yes, a real
# `xdg-open` call can fire. Blocking the one real-world side effect at its
# source, for the whole session, makes that failure mode inert regardless of
# which other bug caused the stray signal.
@pytest.fixture(autouse=True)
def _no_real_external_open(monkeypatch: pytest.MonkeyPatch) -> None:
    import crush.ui as _crush_ui
    monkeypatch.setattr(_crush_ui, "open_url", lambda url: None)

# NOTE: a companion autouse fixture that force-closed every leftover
# top-level widget after each test (to plug the general MainWindow-leak
# problem described in the module docstring at the top of this section) was
# tried here and reverted -- it made the suite crash the whole pytest
# process (SIGABRT/segfault) intermittently, not consistently, which points
# to one or more tests leaving a QThread worker still running when its
# owning widget gets torn down. That's a real bug worth fixing, but a blind
# global "close everything" is the wrong way to do it: it does not know
# which threads are safe to interrupt, and papering over the crash by luck
# of timing is worse than the leak it was meant to fix. Fixing it properly
# means going test by test and making sure each worker thread is stopped
# and joined (not just the widget closed) before the test ends -- see the
# three tests fixed alongside this fixture (test_cli_focus.py,
# test_export_overwrite_confirm.py, test_send_biome_to_peach.py) for the
# pattern to extend elsewhere.


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
def realm_streaming_form_fixture(tmp_path: Path) -> Path:
    """Writable copy of streaming_form.realm placed in tmp_path -- a genuine
    Realm "streaming form" file (top_ref[0] = sentinel, real top ref in an
    end-of-file footer) produced by realm-js's own Realm.prototype.writeCopyTo(),
    not a hand-rebuilt header. See generate_streaming_form.js (kept alongside
    for provenance/reproducibility) for how it was generated: one user table
    "Item" (_id: int primary key, label: string) with two rows."""
    src = FIXTURES_DIR / "streaming_form.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def realm_ifttt_v9_fixture(tmp_path: Path) -> Path:
    """Writable copy of ifttt_v9_data.realm placed in tmp_path -- a real
    file format 9 Realm database (IFTTT iOS app, Magnet Virtual Summit CTF
    2020), donated by the issue #55 reporter for pre-Cluster row-level
    extraction testing against genuine data, not just synthetic fixtures."""
    src = FIXTURES_DIR / "ifttt_v9_data.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def realm_mcdonalds_v9_fixture(tmp_path: Path) -> Path:
    """Writable copy of mcdonalds_v9_data.realm placed in tmp_path -- a
    real file format 9 Realm database (McDonald's Android app, DFRWS 2021
    Challenge, Samsung Galaxy S10), donated by the issue #55 reporter."""
    src = FIXTURES_DIR / "mcdonalds_v9_data.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def realm_all_types_v24_fixture(tmp_path: Path) -> Path:
    """Writable copy of all_types_v24.realm placed in tmp_path -- a real
    file format 24 Realm database produced by the actual realm-js SDK
    (not hand-built bytes), covering every modern column type including
    Decimal128, UUID, ObjectId, Link, LinkList, Mixed (incl. nested
    List/Dictionary), and Dictionary. Generated for issue #55 follow-up
    testing since no real format >=10 sample with this coverage was
    available; regenerate via crush/tests/fixtures/generate_all_types_v24.js."""
    src = FIXTURES_DIR / "all_types_v24.realm"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


@pytest.fixture
def realm_format9_alltypes_fixture(tmp_path: Path) -> Path:
    """Writable copy of format9_alltypes.realm placed in tmp_path -- a real
    file format 9 Realm database written by realm-core v5.23.9's own public
    API (not hand-built bytes), donated by the issue #55 reporter
    (abrignoni). Covers every old ColumnType deliberately, including the
    two hardest-to-verify pieces (Mixed, incl. a negative int subtype, and
    a Table/subtable column with both empty and populated rows), plus
    edge-case integers (both 32-bit boundaries, beyond 2^53) and all three
    String on-disk forms (Short/Medium/BigBlobs). Expected values are in
    the sibling format9_alltypes.expected.json (same donation); the
    original generator (format9_alltypes_gen.cpp) and its README
    (format9_alltypes_README.md) are kept alongside for provenance/
    reproducibility."""
    src = FIXTURES_DIR / "format9_alltypes.realm"
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
def gzip_fixture(tmp_path: Path) -> Path:
    """Writable copy of minimal.sqlite.gz placed in tmp_path.

    A standalone gzip-compressed minimal.sqlite, with the original filename
    stored in the gzip header's FNAME field (RFC 1952), so GzipVFS should
    recover "minimal.sqlite" as the decompressed member's name.
    """
    src = FIXTURES_DIR / "minimal.sqlite.gz"
    dst = tmp_path / src.name
    dst.write_bytes(src.read_bytes())
    return dst


def _mmkv_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _mmkv_string_value(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _mmkv_varint(len(encoded)) + encoded


def _mmkv_entry(key: str, container: bytes) -> bytes:
    encoded_key = key.encode("utf-8")
    return _mmkv_varint(len(encoded_key)) + encoded_key + _mmkv_varint(len(container)) + container


@pytest.fixture
def mmkv_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic MMKV key-value store, built by hand to the
    on-disk layout rather than taken from a real store, per this project's
    synthetic-fixtures-only rule for MMKV (see test_mmkv_parser.py). Contains
    one live entry: "channel" -> "googleplay" (string).
    """
    entry = _mmkv_entry("channel", _mmkv_string_value("googleplay"))
    region = _mmkv_varint(len(entry)) + entry
    payload = struct.pack("<I", len(region)) + region + b"\x00" * 64
    dst = tmp_path / "mmkv.default"
    dst.write_bytes(payload)
    return dst


def _abx_u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _abx_utf(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return _abx_u16(len(encoded)) + encoded


def _abx_interned(s: str) -> bytes:
    return _abx_u16(0xFFFF) + _abx_utf(s)


@pytest.fixture
def abx_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic Android Binary XML (ABX) file: <root attr="value"/>."""
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _abx_utf("root")  # TYPE_STRING + START_TAG
    attr = bytes([0x2F]) + _abx_interned("attr") + _abx_utf("value")  # ATTRIBUTE token
    end_tag = bytes([0x23]) + _abx_utf("root")  # TYPE_STRING + END_TAG
    end_doc = bytes([0x01])
    data = magic + start_doc + start_tag + attr + end_tag + end_doc
    dst = tmp_path / "binary.xml"
    dst.write_bytes(data)
    return dst


def _make_atx_head_chunk(width: int = 32, height: int = 16) -> bytes:
    head = bytearray(0x54)
    struct.pack_into("<I", head, 0x18, width)
    struct.pack_into("<I", head, 0x1C, height)
    struct.pack_into("<I", head, 0x20, 1)
    struct.pack_into("<I", head, 0x28, 1)
    struct.pack_into("<I", head, 0x2C, 1)
    head[0x3C:0x4C] = bytes(range(16))
    struct.pack_into("<I", head, 0x4C, 3)
    struct.pack_into("<I", head, 0x50, 5)
    return struct.pack("<I4s", len(head), b"HEAD") + bytes(head)


@pytest.fixture
def atx_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic Apple ATX texture archive: metadata-only (no
    compressed image payload), matching the same layout used in
    test_parsers.py's ATX tests.
    """
    data = b"AAPL\r\n\x1a\n" + _make_atx_head_chunk(width=32, height=16)
    dst = tmp_path / "poster.atx"
    dst.write_bytes(data)
    return dst


_KTX_VOID_EXTENT_BLOCK = bytes.fromhex("fcfdffffffffffff") + struct.pack(
    "<4H", 0xFFFF, 0x8000, 0x0000, 0xFFFF
)


def _make_ktx_bytes(
    width: int = 4,
    height: int = 4,
    gl_internal_format: int = 0x93B0,
    little_endian: bool = True,
) -> bytes:
    """Build a KTX 1.1 file the way iOS writes them (Khronos KTX 1.1 spec)."""
    blocks = -(-width // 4) * (-(-height // 4))
    astc = _KTX_VOID_EXTENT_BLOCK * blocks
    order = "<" if little_endian else ">"
    header = (
        b"\xabKTX 11\xbb\r\n\x1a\n"
        + (b"\x01\x02\x03\x04" if little_endian else b"\x04\x03\x02\x01")
        + struct.pack(
            order + "12I",
            0,                    # glType (0 for compressed textures)
            1,                    # glTypeSize
            0,                    # glFormat
            gl_internal_format,
            0x1908,               # glBaseInternalFormat (GL_RGBA)
            width,
            height,
            0,                    # pixelDepth
            0,                    # numberOfArrayElements
            1,                    # numberOfFaces
            1,                    # numberOfMipmapLevels
            0,                    # bytesOfKeyValueData
        )
    )
    body = struct.pack(order + "I", len(astc)) + astc
    return header + body


@pytest.fixture
def ktx_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic KTX 1.1 texture with an unsupported (non-ASTC)
    glInternalFormat, so parsing stays metadata-only and needs no optional
    ASTC-decompression dependency to produce a deterministic known output.
    """
    data = _make_ktx_bytes(width=8, height=8, gl_internal_format=0x881A)
    dst = tmp_path / "texture.ktx"
    dst.write_bytes(data)
    return dst


@pytest.fixture
def xml_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic XML document: <root attr="value"><child>text</child></root>."""
    data = b'<?xml version="1.0"?>\n<root attr="value"><child>text</child></root>'
    dst = tmp_path / "evidence.xml"
    dst.write_bytes(data)
    return dst


@pytest.fixture
def json_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic JSON document: {"application": "crush-forensics", "count": 3}."""
    dst = tmp_path / "evidence.json"
    dst.write_text('{"application": "crush-forensics", "count": 3}', encoding="utf-8")
    return dst


@pytest.fixture
def pdf_fixture(tmp_path: Path) -> Path:
    """A minimal, single blank-page PDF with known /Info metadata, built with
    pypdf's own writer (a real, valid PDF, not a hand-crafted approximation).
    """
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Title": "crush-forensics evidence", "/Author": "crush-forensics"})
    dst = tmp_path / "evidence.pdf"
    with open(dst, "wb") as f:
        writer.write(f)
    return dst


@pytest.fixture
def image_exif_fixture(tmp_path: Path) -> Path:
    """A minimal 4x4 JPEG with known EXIF tags (Make/Model/DateTime), built
    with Pillow's own EXIF writer (a real, valid JPEG, not a hand-crafted
    approximation).
    """
    PIL_Image = pytest.importorskip("PIL.Image")
    im = PIL_Image.new("RGB", (4, 4), color="red")
    exif = im.getexif()
    exif[0x010F] = "CrushCam"          # Make
    exif[0x0110] = "CrushModel"        # Model
    exif[0x0132] = "2024:01:15 10:23:45"  # DateTime
    dst = tmp_path / "evidence.jpg"
    im.save(dst, "JPEG", exif=exif)
    return dst


@pytest.fixture
def protobuf_schema_fixture(tmp_path: Path) -> dict[str, Any]:
    """Writable copies of the real (previously orphaned) schema-based protobuf
    fixtures: protobuf_test_messages.proto + protobuf_basic_wire_types.pb,
    plus the parsed .expected.json ground truth (generated by
    generate_protobuf_fixtures.py from real protobuf wire primitives).
    """
    proto_src = FIXTURES_DIR / "protobuf_test_messages.proto"
    pb_src = FIXTURES_DIR / "protobuf_basic_wire_types.pb"
    expected_src = FIXTURES_DIR / "protobuf_basic_wire_types.expected.json"

    proto_dst = tmp_path / proto_src.name
    pb_dst = tmp_path / pb_src.name
    proto_dst.write_bytes(proto_src.read_bytes())
    pb_dst.write_bytes(pb_src.read_bytes())

    return {
        "proto_path": proto_dst,
        "pb_path": pb_dst,
        "expected": json.loads(expected_src.read_text()),
    }


@pytest.fixture
def protobuf_fixture(tmp_path: Path) -> Path:
    """A minimal, synthetic schema-less protobuf message: field 1 (varint) =
    42, field 2 (length-delimited) = "evidence".
    """
    data = b"\x08\x2a" + b"\x12\x08" + b"evidence"
    dst = tmp_path / "message.pb"
    dst.write_bytes(data)
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
            path, lineno, _ = item.location
            _forensic_items[item.nodeid] = {
                "nodeid": item.nodeid,
                "category": str(marker.kwargs.get("category", "Uncategorized")),
                "desc": str(marker.kwargs.get("desc", item.name)),
                "name": item.name,
                "path": path,
                # item.location is 0-based; None when pytest can't tell
                "line": lineno + 1 if lineno is not None else None,
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
    rootdir = Path(str(session.config.rootdir))
    checksums_path = FIXTURES_DIR / "checksums.json"
    corpus: dict[str, dict[str, Any]] = {}
    if checksums_path.exists():
        for name, digest in json.loads(checksums_path.read_text()).items():
            fpath = FIXTURES_DIR / name
            corpus[name] = {"sha256": digest, "size": fpath.stat().st_size if fpath.exists() else 0}

    run = forensic_report.build_run(
        _forensic_results, forensic_report.collect_environment(rootdir), corpus,
    )
    _, html_path = forensic_report.write_run(run, rootdir / "reports")
    print(f"\n  Forensic audit report -> {html_path}")

    # Write a Markdown summary to the GitHub Actions job summary page when running in CI
    gha_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gha_summary:
        with Path(gha_summary).open("a", encoding="utf-8") as f:
            f.write(forensic_report.render_markdown_summary(
                [run], "> Full report available as the `forensic-test-report` CI artifact.",
            ))
