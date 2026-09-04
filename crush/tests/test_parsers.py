# SPDX-License-Identifier: Apache-2.0
"""Tests for built-in parsers."""
from __future__ import annotations

import plistlib
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


from crush.core.vfs import DirectoryVFS
from crush.parsers.sqlite_parser import SQLiteParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.abx_parser import AbxParser
from crush.parsers.abx_decoder import decode_abx
from crush.parsers.hex_fallback import HexFallbackParser
from crush.parsers.image_parser import ImageParser
from crush.parsers.realm_parser import RealmParser
from crush.core.encodings import detect_encoding as _detect_encoding


def _make_sqlite(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)")
    conn.execute("INSERT INTO messages (text) VALUES ('hello')")
    conn.commit()
    conn.close()


def test_sqlite_parser_can_parse(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    _make_sqlite(db_path)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.db")

    parser = SQLiteParser()
    assert parser.can_parse(node.path, vfs.peek(node))


def test_sqlite_parser_parse(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    _make_sqlite(db_path)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.db")

    parser = SQLiteParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "table"
    assert "messages" in result.data
    assert result.data["messages"]["columns"][1] == "text"
    assert result.data["messages"]["rows"][0][1] == "hello"


def _make_sqlcipher(path: Path, password: str, *, wal: bool = False) -> None:
    from sqlcipher3 import dbapi2 as sqlcipher

    conn = sqlcipher.connect(str(path))
    conn.execute(f"PRAGMA key = '{password}'")
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
    conn.executemany(
        "INSERT INTO messages (sender, body) VALUES (?, ?)",
        [("alice@example.com", "Hello Bob"), ("bob@example.com", "Hi Alice")],
    )
    conn.commit()
    conn.close()


def test_sqlcipher_can_parse_returns_false_without_a_key(tmp_path: Path) -> None:
    """An encrypted file's content -- including the first 16 bytes, which
    would be the SQLite magic header on a plaintext file -- is ciphertext,
    indistinguishable from corrupt/other binary data. can_parse() must stay
    False so a normal double-click open never auto-prompts for a password;
    only the explicit "Open as -> SQLite DB (Encrypted)…" action tries."""
    db_path = tmp_path / "encrypted.db"
    _make_sqlcipher(db_path, "hunter2")

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    assert parser.can_parse(node.path, vfs.peek(node)) is False


def test_sqlcipher_wrong_password_raises_wrong_password_error(tmp_path: Path) -> None:
    from crush.core.passwords import WrongPasswordError

    db_path = tmp_path / "encrypted.db"
    _make_sqlcipher(db_path, "hunter2")

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    with pytest.raises(WrongPasswordError):
        parser.parse(node, vfs, password="wrong-password")


def test_sqlcipher_correct_password_parses_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "encrypted.db"
    _make_sqlcipher(db_path, "hunter2")

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    result = parser.parse(node, vfs, password="hunter2")

    assert result.viewer_type == "table"
    assert result.data["messages"]["columns"] == ["id", "sender", "body"]
    assert result.data["messages"]["rows"] == [
        [1, "alice@example.com", "Hello Bob"],
        [2, "bob@example.com", "Hi Alice"],
    ]
    assert result.metadata["Encrypted"] == "Yes (SQLCipher, password supplied)"


def test_sqlcipher_wal_companion_is_decrypted_and_merged(tmp_path: Path) -> None:
    """A SQLCipher database's WAL frames are encrypted the same way as
    regular pages -- unlike a plaintext SQLite WAL, they can't just be
    copied next to the decrypted main file, since there's no decrypted
    main file here at all. Relying on the real linked SQLCipher engine
    (rather than a hand-rolled decrypt) means the existing WAL-companion
    file copying (unchanged) plus the engine's own checkpoint-on-open
    already just works -- including data that only ever made it into the
    WAL, not yet checkpointed into the main file (the realistic forensic
    case: a device seized mid-session, before the app closed its DB
    connection and triggered SQLite's own auto-checkpoint-on-close)."""
    from sqlcipher3 import dbapi2 as sqlcipher

    live_path = tmp_path / "live.db"
    conn = sqlcipher.connect(str(live_path))
    conn.execute("PRAGMA key = 'hunter2'")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
    conn.execute(
        "INSERT INTO messages (sender, body) VALUES (?, ?)",
        ("alice@example.com", "Hello Bob"),
    )
    conn.commit()
    # Capture bytes with the connection still open -- committed WAL frames
    # are on disk and independently readable, but not yet checkpointed into
    # the main file (closing the connection would auto-checkpoint and merge
    # them, defeating the point of this test).
    main_bytes = live_path.read_bytes()
    wal_bytes = Path(str(live_path) + "-wal").read_bytes()
    conn.close()
    assert wal_bytes, "test setup: expected non-empty WAL bytes before checkpoint"

    db_path = tmp_path / "encrypted.db"
    db_path.write_bytes(main_bytes)
    Path(str(db_path) + "-wal").write_bytes(wal_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    result = parser.parse(node, vfs, password="hunter2")

    assert result.data["messages"]["rows"] == [[1, "alice@example.com", "Hello Bob"]]


def test_sqlcipher_raw_key_opens_via_advanced_params(tmp_path: Path) -> None:
    """Raw key mode (PRAGMA key = "x'<hex>'", skipping the passphrase KDF
    entirely) is SQLCipher's own recommended approach for a key "managed
    externally (e.g. keystore, keychain...) not via user input" -- exactly
    the case for an Android app pulling its DB key out of the Keystore.
    raw_key must stand alone (no "Advanced" cipher_params needed) since it's
    orthogonal to those tuning parameters -- deliberately NOT testing it
    bundled with cipher_params, to catch a regression where raw_key only
    took effect together with Advanced."""
    from sqlcipher3 import dbapi2 as sqlcipher

    raw_key_hex = "a1" * 32  # 32 bytes / 256 bits, a plausible Keystore-derived key
    db_path = tmp_path / "encrypted.db"
    conn = sqlcipher.connect(str(db_path))
    conn.execute(f"PRAGMA key = \"x'{raw_key_hex}'\"")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES (?)", ("secret",))
    conn.commit()
    conn.close()

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    result = parser.parse(node, vfs, password=raw_key_hex, raw_key=True)

    assert result.data["messages"]["rows"] == [[1, "secret"]]
    assert result.metadata["Encrypted"] == "Yes (SQLCipher, raw key supplied)"

    # Same raw key, but treated as a passphrase (raw_key=False, the
    # default) must NOT open the file -- proving raw_key actually changes
    # behavior rather than being a no-op.
    from crush.core.passwords import WrongPasswordError

    with pytest.raises(WrongPasswordError):
        parser.parse(node, vfs, password=raw_key_hex)


def test_sqlcipher_signal_style_custom_kdf_iter_opens(tmp_path: Path) -> None:
    """Signal and its forks (Session, Molly) manage a high-entropy key via
    the platform keystore and set kdf_iter=1 to skip the now-pointless
    passphrase-stretching cost -- a real, common combination none of the
    standard cipher_compatibility presets (1-4) cover, since it isn't one
    of SQLCipher's own bundled version defaults."""
    from sqlcipher3 import dbapi2 as sqlcipher

    from crush.parsers.sqlite_parser import SQLCipherParams

    db_path = tmp_path / "encrypted.db"
    conn = sqlcipher.connect(str(db_path))
    conn.execute("PRAGMA key = 'signal-derived-key'")
    conn.execute("PRAGMA cipher_page_size = 4096")
    conn.execute("PRAGMA kdf_iter = 1")
    conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES (?)", ("signal message",))
    conn.commit()
    conn.close()

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "encrypted.db")

    parser = SQLiteParser()
    result = parser.parse(
        node,
        vfs,
        password="signal-derived-key",
        cipher_params=SQLCipherParams(kdf_iter=1, kdf_algorithm="SHA512", hmac_algorithm="SHA512"),
    )

    assert result.data["messages"]["rows"] == [[1, "signal message"]]

    # The standard preset auto-try (no cipher_params) must NOT be able to
    # open this file -- proving the custom-params path is actually doing
    # something the default 4-preset search can't.
    from crush.core.passwords import WrongPasswordError

    with pytest.raises(WrongPasswordError):
        parser.parse(node, vfs, password="signal-derived-key")


def test_plist_parser_binary(tmp_path: Path) -> None:
    data = {"key": "value", "number": 42}
    plist_path = tmp_path / "test.plist"
    plist_path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_BINARY))

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.plist")

    parser = PlistParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "tree_text"
    assert result.data["key"] == "value"
    assert result.metadata["Format"] == "binary"


def test_hex_fallback_always_matches() -> None:
    parser = HexFallbackParser()
    assert parser.can_parse("anything.xyz", b"\x00\x01\x02\x03")


def test_hex_fallback_parse(tmp_path: Path) -> None:
    raw = bytes(range(64))
    (tmp_path / "blob.bin").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "blob.bin")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)
    assert result.viewer_type == "hex"
    assert result.data == raw


def _make_realm_header(
    top_ref0: int = 212880,
    top_ref1: int = 211736,
    fmt0: int = 24,
    fmt1: int = 24,
    reserved: int = 0,
    flag: int = 0,
) -> bytes:
    return (
        top_ref0.to_bytes(8, "little") +
        top_ref1.to_bytes(8, "little") +
        b"T-DB" +
        bytes([fmt0, fmt1, reserved, flag])
    )


def test_realm_parser_header(tmp_path: Path) -> None:
    realm_path = tmp_path / "default.realm"
    realm_path.write_bytes(_make_realm_header() + b"\x00" * 512)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "default.realm")

    parser = RealmParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "realm"
    assert "header" in result.data
    header = result.data["header"]
    assert header["Mnemonic"] == "T-DB"
    assert header["File format (top ref 0)"] == 24

    # New data structure: top_refs and schema
    assert "top_refs" in result.data
    assert "schema" in result.data
    # top_ref entries exist even when array headers are not reachable (synthetic file)
    top_refs = result.data["top_refs"]
    assert "top_ref_0" in top_refs
    assert "top_ref_1" in top_refs
    assert "active_index" in top_refs


def _make_realm_array_header(
    flags: int = 0x0E,
    size: int = 0,
) -> bytes:
    """Build an 8-byte Realm array header for tests."""
    return b"\x41\x41\x41\x41" + bytes([flags]) + size.to_bytes(3, "big")


def test_realm_array_header_decoding(tmp_path: Path) -> None:
    """_parse_array_header correctly decodes flags and computes payload size."""
    from crush.parsers.realm_parser import _parse_array_header

    # Example from PDF: flags=0x0E, size=5 → width_scheme=1, width=32 bytes → 160 bytes payload
    raw = _make_realm_array_header(flags=0x0E, size=5)
    hdr = _parse_array_header(raw, 0)
    assert hdr is not None
    assert hdr["is_inner_bptree_node"] is False
    assert hdr["has_refs"] is False
    assert hdr["width_scheme"] == 1
    assert hdr["width"] == 32
    assert hdr["Element count (size)"] == 5
    assert hdr["Payload bytes (raw)"] == 160   # 32 * 5
    assert hdr["Total array bytes"] == 168      # 8 header + 160

    # flags=0x46: has_refs=True, scheme=0, width=32 bits (4 bytes/elem), size=11 → 44 raw → 48 aligned
    raw2 = _make_realm_array_header(flags=0x46, size=11)
    hdr2 = _parse_array_header(raw2, 0)
    assert hdr2 is not None
    assert hdr2["has_refs"] is True
    assert hdr2["width_scheme"] == 0
    assert hdr2["width"] == 32
    assert hdr2["Element count (size)"] == 11
    assert hdr2["Payload bytes (raw)"] == 44    # ceil(32*11/8)
    assert hdr2["Payload bytes (aligned)"] == 48
    assert hdr2["Total array bytes"] == 56


def test_realm_schema_extraction(tmp_path: Path) -> None:
    """Schema extraction follows the B+ tree path and returns class names."""
    # Build a minimal realm file: file header + schema array + root ref array
    # Offsets (all computed to avoid overlap):
    #   0x00 (0):  24-byte file header  (top_ref1 → ROOT_OFFSET, flags=0x01)
    #   0x18 (24): schema data array    (flags=0x0E, size=2, width=32 bytes → 72 total)
    #   0x60 (96): root ref array       (flags=0x46, size=1, 4-byte ref → SCHEMA_OFFSET)

    SCHEMA_OFFSET = 24   # right after file header
    # schema array = 8-byte header + 2 × 32-byte entries = 72 bytes
    ROOT_OFFSET = SCHEMA_OFFSET + 72  # = 96

    # Two 32-byte schema entries
    # ArrayStringShort real encoding (array_string_short.hpp get()): content,
    # zero-padding, then a trailing pad-count byte (= width-1-len(content)).
    entry0 = b"metadata" + b"\x00" * 23 + bytes([23])
    entry1 = b"class_Task" + b"\x00" * 21 + bytes([21])
    schema_hdr = b"\x41\x41\x41\x41\x0E" + (2).to_bytes(3, "big")  # flags=0x0E, size=2
    schema_array = schema_hdr + entry0 + entry1  # 8 + 32 + 32 = 72 bytes

    # Root ref array: flags=0x46, size=1, width_scheme=0, width=32bits → 4-byte LE ref
    # payload_bytes = ceil(32*1/8)=4, aligned=8
    root_hdr_bytes = b"\x41\x41\x41\x41\x46" + (1).to_bytes(3, "big")
    ref_payload = SCHEMA_OFFSET.to_bytes(4, "little") + b"\x00" * 4  # padded to 8
    root_array = root_hdr_bytes + ref_payload  # 16 bytes

    # File header: top_ref1=ROOT_OFFSET, flags=0x01 (top_ref1 active)
    file_hdr = (
        (0).to_bytes(8, "little")               # top_ref0 = 0 (unused)
        + ROOT_OFFSET.to_bytes(8, "little")     # top_ref1 = 96
        + b"T-DB"                               # mnemonic
        + bytes([24, 24, 0, 0x01])              # fmt0, fmt1, reserved, flags
    )

    realm_bytes = file_hdr + schema_array + root_array

    realm_path = tmp_path / "test.realm"
    realm_path.write_bytes(realm_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "test.realm")

    parser = RealmParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "realm"
    schema = result.data["schema"]
    assert "metadata" in schema
    assert "class_Task" in schema
    assert result.metadata.get("Tables found") == "2"


def test_realm_schema_extraction_format9_big_blobs(tmp_path: Path) -> None:
    """Pre-Cluster (file format < 10) Group.m_table_names is the full
    polymorphic ArrayString (group.hpp, confirmed against tag v5.23.9 -- the
    last release that still wrote format 9), which can use the on-disk
    SmallBlobs/BigBlobs forms, not just the inline ArrayStringShort form
    modern (format 10+) files are restricted to (max_table_name_length=63
    lets them always use the inline form). Before the issue #55 fix,
    _extract_schema only decoded the inline form and silently returned zero
    classes for a BigBlobs-form file -- indistinguishable from a genuinely
    empty schema. This fixture only builds the Group-level table_names
    array (no actual Table/Spec structures), so it also verifies that when
    schema names resolve but the pre-Cluster table structure itself does
    not, that gap is explicitly flagged rather than silently shown as
    zero decoded tables.
    """
    ROOT_OFFSET = 24
    TABLE_NAMES_OFFSET = 40
    BLOB0_OFFSET = 56
    name0 = b"metadata\x00"
    BLOB1_OFFSET = BLOB0_OFFSET + 8 + len(name0)
    name1 = b"class_LegacyRecord\x00"

    # Group top array: 1 ref (flags=0x46: has_refs, scheme=0, width_ndx=6/32-bit)
    root_hdr_bytes = b"\x41\x41\x41\x41\x46" + (1).to_bytes(3, "big")
    root_payload = TABLE_NAMES_OFFSET.to_bytes(4, "little") + b"\x00" * 4
    root_array = root_hdr_bytes + root_payload  # 24..40

    # ArrayBigBlobs: has_refs=1, context_flag=1, scheme=0, width_ndx=6 (32-bit refs)
    # -> flags = 0b01100110 = 0x66 (see _read_array_string_or_binary dispatch)
    table_names_hdr = b"\x41\x41\x41\x41\x66" + (2).to_bytes(3, "big")
    table_names_payload = (
        BLOB0_OFFSET.to_bytes(4, "little") + BLOB1_OFFSET.to_bytes(4, "little")
    )
    table_names_array = table_names_hdr + table_names_payload  # 40..56

    # Each blob leaf: has_refs=0, scheme=0, width_ndx=1 (1 byte/elem) -> size == byte length
    blob0 = b"\x41\x41\x41\x41\x01" + len(name0).to_bytes(3, "big") + name0
    blob1 = b"\x41\x41\x41\x41\x01" + len(name1).to_bytes(3, "big") + name1

    file_hdr = (
        (0).to_bytes(8, "little")             # top_ref0 = 0 (unused)
        + ROOT_OFFSET.to_bytes(8, "little")   # top_ref1 = 24
        + b"T-DB"
        + bytes([9, 9, 0, 0x01])              # fmt0=fmt1=9 (pre-Cluster), top_ref1 active
    )

    realm_bytes = file_hdr + root_array + table_names_array + blob0 + blob1

    realm_path = tmp_path / "format9.realm"
    realm_path.write_bytes(realm_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "format9.realm")

    result = RealmParser().parse(node, vfs)

    assert result.viewer_type == "realm"
    assert result.data["schema"] == ["metadata", "class_LegacyRecord"]

    # This fixture has no real Table/Spec structure to decode -- the gap
    # must be explicitly flagged with the parser's own concrete reason,
    # never silently left at zero rows or a generic "could not be decoded".
    assert result.data["tables"] == []
    assert result.metadata["Row data"] == (
        "Pre-Cluster layout — Group top array has no table-refs slot (fewer than 2 children)"
    )


def _to_streaming_form(data: bytes, *, corrupt_magic: bool = False) -> bytes:
    """Rewrite a normal-form Realm file's bytes into Group::write() streaming
    form (alloc_slab.hpp/.cpp SlabAlloc::is_file_on_streaming_form /
    StreamingFooter, verified against realm-core v5.23.9 source): top_ref[0]
    becomes the sentinel 0xFFFFFFFFFFFFFFFF, top_ref[1]/flags/reserved become
    0, and the real (previously active) top ref moves into a 16-byte footer
    appended at the end of the file, followed by the magic cookie
    0x3034125237E526C8. Body bytes are untouched -- every array still lives
    at its original absolute offset, only the header's own top-ref encoding
    changes, exactly as a real streaming-form export would.
    """
    buf = bytearray(data)
    top_ref0 = int.from_bytes(buf[0:8], "little")
    top_ref1 = int.from_bytes(buf[8:16], "little")
    fmt0, fmt1, flags = buf[20], buf[21], buf[23]
    active = flags & 1
    active_ref = top_ref1 if active else top_ref0
    active_fmt = fmt1 if active else fmt0

    buf[0:8] = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    buf[8:16] = (0).to_bytes(8, "little")
    buf[20] = active_fmt
    buf[21] = 0
    buf[22] = 0
    buf[23] = 0  # select bit cleared -> slot_selector 0, matching the sentinel check

    magic = 0x3034125237E526C8
    if corrupt_magic:
        magic ^= 0xFF
    buf += active_ref.to_bytes(8, "little") + magic.to_bytes(8, "little")
    return bytes(buf)


def test_realm_streaming_form_resolves_via_footer(
    tmp_path: Path, realm_fixture: Path,
) -> None:
    """Group::write() streaming form must not decode as an empty schema.

    Reported by the issue #55 reporter (abrignoni), 2026-09-02: his own
    generator initially used Group::write() (producing the streaming form
    -- top_ref[0] a sentinel, real top ref in an end-of-file footer) rather
    than SharedGroup + WriteTransaction::commit() (the normal on-disk form
    an app actually leaves behind). Before this fix, the parser read
    top_ref[0]'s literal sentinel value as an offset, which is always out
    of bounds, so _extract_schema silently returned []  -- read by him as
    "the generator failed" when the file was in fact valid, just in a form
    this parser didn't yet resolve. Realm Studio's file-export feature can
    also produce this form, so it's a form real examiners will encounter,
    not just a generator quirk.
    """
    streaming_bytes = _to_streaming_form(realm_fixture.read_bytes())
    streaming_path = tmp_path / "streaming.realm"
    streaming_path.write_bytes(streaming_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "streaming.realm")

    result = RealmParser().parse(node, vfs)

    # minimal.realm's own known-output schema (see realm_fixture/its known-
    # output test) -- must resolve identically once routed through the
    # streaming-form footer instead of the normal two-slot header.
    assert result.data["schema"] == ["metadata", "class_Evidence"]
    assert result.data["streaming_form"] == {
        "top_ref": 96, "footer_valid": True,
    }
    assert "resolved from end-of-file footer" in result.metadata["Streaming form"]


def test_realm_streaming_form_corrupt_footer_marked_explicit(
    tmp_path: Path, realm_fixture: Path,
) -> None:
    """A streaming-form file with a missing/corrupt footer must surface an
    explicit status, never a silent empty schema indistinguishable from a
    genuinely empty database (see feedback_explicit_unsupported_marking).
    """
    corrupt_bytes = _to_streaming_form(realm_fixture.read_bytes(), corrupt_magic=True)
    corrupt_path = tmp_path / "streaming_corrupt.realm"
    corrupt_path.write_bytes(corrupt_bytes)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "streaming_corrupt.realm")

    result = RealmParser().parse(node, vfs)

    assert result.data["schema"] == []
    assert result.data["streaming_form"] == {"top_ref": None, "footer_valid": False}
    assert "could not be resolved" in result.metadata["Streaming form"]
    assert result.metadata["Tables found"] == "Unresolved (see Streaming form)"


def test_realm_pre_cluster_mixed_column(tmp_path: Path) -> None:
    """Pre-Cluster (file format < 10) Mixed column decode -- the one old
    ColumnType with zero real-file coverage (neither of the two real format
    9 samples used for this branch's other tests contains a Mixed column),
    so this is the only verification for it.

    Slot layout (MixedColumn::create(), column_mixed.cpp @ v5.23.8 -- the
    exact realm-core version realm-java 6.1.0, the last release to write
    format 9, bundled): 0=m_types, 1=m_data, 2=m_binary_data,
    3=m_timestamp_data (unused here, m_timestamp_data ref left 0).

    Exercises the trickiest verified-from-source detail: get_value()
    (column_mixed_tpl.hpp) is `uint64_t(m_data.get(ndx)) >> 1` -- plain
    64-bit modular arithmetic, no separate sign-magnitude split despite
    first appearances -- so the IntNeg/DoubleNeg rows below are encoded
    exactly as MixedColumn::set_int64 would (`(value << 1) + 1`, wrapped
    to 64 bits), not as "shifted absolute value", to prove the decode
    side's inverse operation is exactly right rather than only
    self-consistent with a wrong encoding.
    """
    U64 = (1 << 64) - 1

    def tag(v: int) -> int:
        """Mirrors MixedColumn::set_int64/set_value: (value << 1) + 1, wrapped to int64."""
        return ((v << 1) + 1) & U64

    def string_short_entry(content: bytes, width: int) -> bytes:
        pad = (width - 1) - len(content)
        return content + b"\x00" * pad + bytes([pad])

    def string_short_array(strings: list[str], width: int = 32) -> bytes:
        hdr = b"\x41\x41\x41\x41\x06" + len(strings).to_bytes(3, "big")  # has_refs=0, width_ndx=6 -> 32
        return hdr + b"".join(string_short_entry(s.encode(), width) for s in strings)

    def refs_array(refs: list[int], width_ndx: int = 6) -> bytes:
        width = [0, 1, 2, 4, 8, 16, 32, 64][width_ndx]
        flags = 0b01000000 | width_ndx  # has_refs=1
        eb = width // 8
        payload = b"".join((r & U64).to_bytes(eb, "little") for r in refs)
        payload += b"\x00" * ((-len(payload)) % 8)
        return b"\x41\x41\x41\x41" + bytes([flags]) + len(refs).to_bytes(3, "big") + payload

    def int_leaf(values: list[int], width: int = 64) -> bytes:
        width_ndx = [0, 1, 2, 4, 8, 16, 32, 64].index(width)
        n = len(values)
        buf = bytearray((width * n + 7) // 8)
        for i, v in enumerate(values):
            bitpos = i * width
            bytepos, bitoff = divmod(bitpos, 8)
            raw = v & (U64 if width == 64 else ((1 << width) - 1))
            for b in range((width + 7) // 8):
                if bytepos + b < len(buf):
                    buf[bytepos + b] |= (raw >> (b * 8)) & 0xFF
        buf += b"\x00" * ((-len(buf)) % 8)
        return b"\x41\x41\x41\x41" + bytes([width_ndx]) + n.to_bytes(3, "big") + bytes(buf)

    # 7 rows, one of each numeric/string variant that exercises a distinct
    # get_value() code path: Int, IntNeg, Bool, Float, Double, DoubleNeg, String.
    mixtypes = [0, 12, 1, 9, 10, 11, 2]
    float_bits = struct.unpack("<I", struct.pack("<f", 2.5))[0]
    double_pos_bits = struct.unpack("<Q", struct.pack("<d", 1.25))[0]
    double_neg_bits = struct.unpack("<Q", struct.pack("<d", -1.25))[0] & ((1 << 63) - 1)
    data_values = [tag(100), tag(-100), tag(1), tag(float_bits), tag(double_pos_bits), tag(double_neg_bits), tag(0)]

    types_bytes = int_leaf(mixtypes, width=8)
    data_bytes = int_leaf(data_values, width=64)

    blob_str = b"hi\x00"  # trailing NUL per array_string_long.hpp

    ROOT_OFFSET = 24
    TABLE_NAMES_OFFSET = ROOT_OFFSET + 16
    table_names_bytes = string_short_array(["TestTable"])
    TABLES_OFFSET = TABLE_NAMES_OFFSET + len(table_names_bytes)
    TABLE_OFFSET = TABLES_OFFSET + 16
    SPEC_OFFSET = TABLE_OFFSET + 16
    TYPES_OFFSET = SPEC_OFFSET + 24
    spec_types_bytes = int_leaf([6], width=8)  # 1 column, type_code=6 (Mixed)
    NAMES_OFFSET = TYPES_OFFSET + len(spec_types_bytes)
    names_bytes = string_short_array(["mixedCol"])
    ATTR_OFFSET = NAMES_OFFSET + len(names_bytes)
    attr_bytes = int_leaf([0], width=8)
    COLUMNS_OFFSET = ATTR_OFFSET + len(attr_bytes)

    MIXED_COL_OFFSET = COLUMNS_OFFSET + 16
    MIXED_TYPES_OFFSET = MIXED_COL_OFFSET + 24
    MIXED_DATA_OFFSET = MIXED_TYPES_OFFSET + len(types_bytes)
    MIXED_BINARY_OFFSET = MIXED_DATA_OFFSET + len(data_bytes)
    BLOB_ARRAY_OFFSET = MIXED_BINARY_OFFSET + 16
    offsets_bytes = int_leaf([len(blob_str)], width=64)
    BLOB_DATA_OFFSET = BLOB_ARRAY_OFFSET + len(offsets_bytes)
    blob_data_bytes = b"\x41\x41\x41\x41\x01" + len(blob_str).to_bytes(3, "big") + blob_str
    blob_data_bytes += b"\x00" * ((-len(blob_data_bytes)) % 8)

    root_array = refs_array([TABLE_NAMES_OFFSET, TABLES_OFFSET])
    tables_array = refs_array([TABLE_OFFSET])
    table_array = refs_array([SPEC_OFFSET, COLUMNS_OFFSET])
    spec_array = refs_array([TYPES_OFFSET, NAMES_OFFSET, ATTR_OFFSET])
    columns_array = refs_array([MIXED_COL_OFFSET])
    mixed_top_array = refs_array([MIXED_TYPES_OFFSET, MIXED_DATA_OFFSET, MIXED_BINARY_OFFSET, 0])
    binary_top_bytes = refs_array([BLOB_ARRAY_OFFSET, BLOB_DATA_OFFSET])

    file_hdr = (
        (0).to_bytes(8, "little")
        + ROOT_OFFSET.to_bytes(8, "little")
        + b"T-DB"
        + bytes([9, 9, 0, 0x01])
    )

    total = BLOB_DATA_OFFSET + len(blob_data_bytes)
    buf = bytearray(total)

    def place(offset: int, data: bytes) -> None:
        buf[offset : offset + len(data)] = data

    place(0, file_hdr)
    place(ROOT_OFFSET, root_array)
    place(TABLE_NAMES_OFFSET, table_names_bytes)
    place(TABLES_OFFSET, tables_array)
    place(TABLE_OFFSET, table_array)
    place(SPEC_OFFSET, spec_array)
    place(TYPES_OFFSET, spec_types_bytes)
    place(NAMES_OFFSET, names_bytes)
    place(ATTR_OFFSET, attr_bytes)
    place(COLUMNS_OFFSET, columns_array)
    place(MIXED_COL_OFFSET, mixed_top_array)
    place(MIXED_TYPES_OFFSET, types_bytes)
    place(MIXED_DATA_OFFSET, data_bytes)
    place(MIXED_BINARY_OFFSET, binary_top_bytes)
    place(BLOB_ARRAY_OFFSET, offsets_bytes)
    place(BLOB_DATA_OFFSET, blob_data_bytes)

    realm_path = tmp_path / "mixed.realm"
    realm_path.write_bytes(bytes(buf))

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "mixed.realm")
    result = RealmParser().parse(node, vfs)

    table = result.data["tables"][0]
    assert table["columns"][0] == [100, -100, True, 2.5, 1.25, -1.25, "hi"]


def test_realm_pre_cluster_string_enum_column(tmp_path: Path) -> None:
    """Pre-Cluster (file format < 10) StringEnum column decode -- the other
    old ColumnType with zero real-file coverage (neither IFTTT nor
    McDonald's uses it).

    m_enumkeys (Spec slot 4, spec.cpp Spec::get_enumkeys_ndx) is itself an
    array of refs -- one per StringEnum column, indexed by a running count
    over prior StringEnum columns only -- each pointing to that column's
    own shared keys StringColumn. A first attempt at this fixture treated
    Spec slot 4 as pointing *directly* at the keys column, skipping that
    wrapper array, and silently read the wrong bytes (a corrupted-looking
    huge ref) instead of failing loudly -- worth remembering when building
    similar fixtures: the indirection level matters even when "just a
    ref" looks obviously right.

    3 unique keys, 5 rows with repeated indices, so the dedup itself
    (not just a 1:1 index) is actually exercised.
    """
    U64 = (1 << 64) - 1

    def string_short_entry(content: bytes, width: int) -> bytes:
        pad = (width - 1) - len(content)
        return content + b"\x00" * pad + bytes([pad])

    def string_short_array(strings: list[str], width: int = 32) -> bytes:
        hdr = b"\x41\x41\x41\x41\x06" + len(strings).to_bytes(3, "big")  # has_refs=0
        return hdr + b"".join(string_short_entry(s.encode(), width) for s in strings)

    def refs_array(refs: list[int], width_ndx: int = 6) -> bytes:
        width = [0, 1, 2, 4, 8, 16, 32, 64][width_ndx]
        flags = 0b01000000 | width_ndx  # has_refs=1
        eb = width // 8
        payload = b"".join((r & U64).to_bytes(eb, "little") for r in refs)
        payload += b"\x00" * ((-len(payload)) % 8)
        return b"\x41\x41\x41\x41" + bytes([flags]) + len(refs).to_bytes(3, "big") + payload

    def int_leaf(values: list[int], width: int = 64) -> bytes:
        width_ndx = [0, 1, 2, 4, 8, 16, 32, 64].index(width)
        n = len(values)
        buf = bytearray((width * n + 7) // 8)
        for i, v in enumerate(values):
            bytepos = (i * width) // 8
            raw = v & (U64 if width == 64 else ((1 << width) - 1))
            for b in range((width + 7) // 8):
                if bytepos + b < len(buf):
                    buf[bytepos + b] |= (raw >> (b * 8)) & 0xFF
        buf += b"\x00" * ((-len(buf)) % 8)
        return b"\x41\x41\x41\x41" + bytes([width_ndx]) + n.to_bytes(3, "big") + bytes(buf)

    keys = ["active", "inactive", "pending"]
    indices = [0, 1, 0, 2, 1]
    keys_bytes = string_short_array(keys)
    indices_bytes = int_leaf(indices, width=8)

    ROOT_OFFSET = 24
    TABLE_NAMES_OFFSET = ROOT_OFFSET + 16
    table_names_bytes = string_short_array(["TestTable"])
    TABLES_OFFSET = TABLE_NAMES_OFFSET + len(table_names_bytes)
    TABLE_OFFSET = TABLES_OFFSET + 16
    SPEC_OFFSET = TABLE_OFFSET + 16
    # Spec array: 5 slots (types, names, attr, subspecs[unused=0], enumkeys)
    # -> payload 5*4=20 bytes, aligned 24 -> header(8)+24=32
    TYPES_OFFSET = SPEC_OFFSET + 32
    spec_types_bytes = int_leaf([3], width=8)  # 1 column, type_code=3 (StringEnum)
    NAMES_OFFSET = TYPES_OFFSET + len(spec_types_bytes)
    names_bytes = string_short_array(["statusCol"])
    ATTR_OFFSET = NAMES_OFFSET + len(names_bytes)
    attr_bytes = int_leaf([0], width=8)
    COLUMNS_OFFSET = ATTR_OFFSET + len(attr_bytes)

    ENUM_COL_OFFSET = COLUMNS_OFFSET + 16  # columns array: 1 ref
    ENUMKEYS_ARRAY_OFFSET = ENUM_COL_OFFSET + len(indices_bytes)  # m_enumkeys wrapper: 1 ref
    KEYS_OFFSET = ENUMKEYS_ARRAY_OFFSET + 16

    root_array = refs_array([TABLE_NAMES_OFFSET, TABLES_OFFSET])
    tables_array = refs_array([TABLE_OFFSET])
    table_array = refs_array([SPEC_OFFSET, COLUMNS_OFFSET])
    spec_array = refs_array([TYPES_OFFSET, NAMES_OFFSET, ATTR_OFFSET, 0, ENUMKEYS_ARRAY_OFFSET])
    columns_array = refs_array([ENUM_COL_OFFSET])
    enumkeys_array = refs_array([KEYS_OFFSET])

    file_hdr = (
        (0).to_bytes(8, "little")
        + ROOT_OFFSET.to_bytes(8, "little")
        + b"T-DB"
        + bytes([9, 9, 0, 0x01])
    )

    total = KEYS_OFFSET + len(keys_bytes)
    buf = bytearray(total)

    def place(offset: int, data: bytes) -> None:
        buf[offset : offset + len(data)] = data

    place(0, file_hdr)
    place(ROOT_OFFSET, root_array)
    place(TABLE_NAMES_OFFSET, table_names_bytes)
    place(TABLES_OFFSET, tables_array)
    place(TABLE_OFFSET, table_array)
    place(SPEC_OFFSET, spec_array)
    place(TYPES_OFFSET, spec_types_bytes)
    place(NAMES_OFFSET, names_bytes)
    place(ATTR_OFFSET, attr_bytes)
    place(COLUMNS_OFFSET, columns_array)
    place(ENUM_COL_OFFSET, indices_bytes)
    place(ENUMKEYS_ARRAY_OFFSET, enumkeys_array)
    place(KEYS_OFFSET, keys_bytes)

    realm_path = tmp_path / "stringenum.realm"
    realm_path.write_bytes(bytes(buf))

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "stringenum.realm")
    result = RealmParser().parse(node, vfs)

    table = result.data["tables"][0]
    assert table["column_types"] == ["string_enum"]
    assert table["columns"][0] == ["active", "inactive", "active", "pending", "inactive"]
    assert table["unsupported_columns"] == []


def test_realm_parser_decrypts_with_correct_key(tmp_path: Path) -> None:
    """RealmParser.parse(..., password=hex_key) decrypts an encrypted file
    and parses it exactly like the equivalent plaintext file -- end-to-end
    through the real parser, not just the isolated crypto module."""
    import os

    from crush.core.realm_crypto import _PAGE_SIZE
    from crush.tests.test_realm_crypto import _encrypt_realm_file

    SCHEMA_OFFSET = 24
    ROOT_OFFSET = SCHEMA_OFFSET + 72
    # ArrayStringShort real encoding (array_string_short.hpp get()): content,
    # zero-padding, then a trailing pad-count byte (= width-1-len(content)).
    entry0 = b"metadata" + b"\x00" * 23 + bytes([23])
    entry1 = b"class_Task" + b"\x00" * 21 + bytes([21])
    schema_hdr = b"\x41\x41\x41\x41\x0E" + (2).to_bytes(3, "big")
    schema_array = schema_hdr + entry0 + entry1
    root_hdr_bytes = b"\x41\x41\x41\x41\x46" + (1).to_bytes(3, "big")
    ref_payload = SCHEMA_OFFSET.to_bytes(4, "little") + b"\x00" * 4
    root_array = root_hdr_bytes + ref_payload
    file_hdr = (
        (0).to_bytes(8, "little")
        + ROOT_OFFSET.to_bytes(8, "little")
        + b"T-DB"
        + bytes([24, 24, 0, 0x01])
    )
    plaintext = file_hdr + schema_array + root_array
    plaintext += b"\x00" * (-len(plaintext) % _PAGE_SIZE)  # pad to a full page

    key = os.urandom(64)
    encrypted = _encrypt_realm_file(plaintext, key)

    realm_path = tmp_path / "encrypted.realm"
    realm_path.write_bytes(encrypted)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "encrypted.realm")

    parser = RealmParser()
    result = parser.parse(node, vfs, password=key.hex())

    assert result.viewer_type == "realm"
    assert "class_Task" in result.data["schema"]
    assert result.metadata.get("Encrypted", "").startswith("Yes")

    from crush.core.passwords import WrongPasswordError

    with pytest.raises(WrongPasswordError):
        parser.parse(node, vfs, password=os.urandom(64).hex())


def test_extract_table_data_reports_reason_when_table_refs_missing() -> None:
    """_extract_table_data (Cluster/format >=10 path) must surface a
    concrete reason when it comes back with zero tables, not just an
    unexplained empty list -- mirrors the pre-Cluster path's own
    (result, reason) contract (_extract_pre_cluster_tables_data). Same
    underlying gap as the one found on minimal_format9.realm (a Group top
    array with only 1 child, no table-refs slot at index 1), just for the
    modern path this time."""
    from crush.parsers.realm_parser import _extract_table_data

    raw = _array_hdr(0x46, 1) + _pad8((0).to_bytes(4, "little"))
    tables, reason = _extract_table_data(raw, 0, ["class_Foo"], len(raw))
    assert tables == []
    assert reason == "Group top array has no table-refs slot (fewer than 2 children)"


def test_extract_table_data_flags_estimated_row_count_on_corrupt_key_slot() -> None:
    """When a leaf's key slot (child[0]) is unreadable (e.g. corruption),
    row_count falls back to _derive_row_count and the table is flagged
    row_count_estimated=True so the UI never shows a guessed count as if it
    were authoritative — same failure shape as the original RealmDB bug
    (silently-wrong row count), just surfaced instead of hidden."""
    from crush.parsers.realm_parser import _extract_table_data

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- leaf: key slot (child[0]) is corrupt (ref=0), column has 2 rows --
    col1_ref = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (10, 20))
    ))
    cluster_root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + col1_ref.to_bytes(4, "little")
    ))

    names_ref = emit(_array_hdr(0x0C, 1) + _pad8(b"n\x00\x00\x00\x00\x00\x00\x00"))
    colkey = 0
    colkeys_ref = emit(_array_hdr(0x0C, 1) + _pad8(colkey.to_bytes(8, "little", signed=True)))
    spec_ref = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little")
        + names_ref.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + colkeys_ref.to_bytes(4, "little")
    ))

    table_ref = emit(_array_hdr(0x46, 3) + _pad8(
        spec_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") + cluster_root_ref.to_bytes(4, "little")
    ))
    table_refs_ref = emit(_array_hdr(0x46, 1) + _pad8(table_ref.to_bytes(4, "little")))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    tables, _ = _extract_table_data(data, root_ref, ["class_Foo"], len(data))

    assert len(tables) == 1
    t = tables[0]
    assert t["row_count_estimated"] is True
    assert t["row_count"] == 2  # recovered via the column-element-count vote
    assert t["columns"][0] == [10, 20]


def test_extract_table_data_decodes_dictionary_column() -> None:
    """Dictionary<String, Mixed> column, one row: {"k": 5}.

    Exercises the full chain from dictionary.cpp/spec.cpp: colkey attrs bit
    0x40 (is_dictionary) selects _read_dictionary_column; the key type
    (String=2) comes from the spec's m_types array (upper 16 bits, per
    Spec::get_dictionary_key_type), not the colkey; the per-row ref points
    directly at a 2-slot "dictionary top" array (slot 0 = keys BPlusTree
    root, slot 1 = values BPlusTree root); the single Mixed value is
    decoded via the composite-encoding inline-Int path (data_type=0,
    payload_idx_flag=0, payload_val=5).
    """
    from crush.parsers.realm_parser import _extract_table_data

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- keys leaf: ArrayStringShort, one entry "k" (width=8, content_area=7,
    #    content_len=1 -> pad=6, matching test_read_array_string_short_inline)
    key_entry = b"k" + b"\x00" * 6 + bytes([6])
    keys_leaf_ref = emit(_array_hdr(0x0C, 1) + key_entry)

    # -- values leaf: ArrayMixed, one row, inline Int(5):
    #    composite = (5 << 8) | (0 << 5) | (0 + 1) = 1281
    composite_ref = emit(_array_hdr(0x0C, 1) + _pad8((1281).to_bytes(8, "little", signed=True)))
    values_leaf_ref = emit(_array_hdr(0x46, 4) + _pad8(
        composite_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") * 3
    ))

    # -- per-row "dictionary top" array: slot 0 = keys root, slot 1 = values root
    top_ref = emit(_array_hdr(0x46, 2) + _pad8(
        keys_leaf_ref.to_bytes(4, "little") + values_leaf_ref.to_bytes(4, "little")
    ))

    # -- column-level flat ref array, one row -> top_ref
    dict_col_ref = emit(_array_hdr(0x46, 1) + _pad8(top_ref.to_bytes(4, "little")))

    # -- cluster leaf: child[0] = tagged row count (1<<1)|1 = 3 (compact form)
    cluster_root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (3).to_bytes(4, "little") + dict_col_ref.to_bytes(4, "little")
    ))

    names_ref = emit(_array_hdr(0x0C, 1) + _pad8(b"d\x00\x00\x00\x00\x00\x00\x00"))

    # colkey: col_index=0, type_code=6 (Mixed), attrs=0x40 (is_dictionary)
    colkey = (6 << 16) | (0x40 << 22)
    colkeys_ref = emit(_array_hdr(0x0C, 1) + _pad8(colkey.to_bytes(8, "little", signed=True)))

    # m_types[0]: base type (6=Mixed) in low 16 bits, key type (2=String) in high 16 bits
    types_entry = 6 | (2 << 16)
    types_ref = emit(_array_hdr(0x0C, 1) + _pad8(types_entry.to_bytes(8, "little", signed=True)))

    spec_ref = emit(_array_hdr(0x46, 6) + _pad8(
        types_ref.to_bytes(4, "little")
        + names_ref.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + colkeys_ref.to_bytes(4, "little")
    ))

    table_ref = emit(_array_hdr(0x46, 3) + _pad8(
        spec_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") + cluster_root_ref.to_bytes(4, "little")
    ))
    table_refs_ref = emit(_array_hdr(0x46, 1) + _pad8(table_ref.to_bytes(4, "little")))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    tables, _ = _extract_table_data(data, root_ref, ["class_Dict"], len(data))

    assert len(tables) == 1
    t = tables[0]
    assert t["row_count_estimated"] is False
    assert t["row_count"] == 1
    assert t["columns"][0] == [{"k": 5}]
    assert t["column_types"][0] == "dictionary<string, mixed>"


def test_read_array_mixed_decodes_nested_list() -> None:
    """A List held inside a Mixed value: composite data_type=19 (List),
    payload_idx=payload_idx_ref(4) pointing into m_refs at an ArrayMixed
    leaf (the List's own BPlusTree<Mixed> "root" -- non-inner, so
    _walk_bplustree_leaves resolves it directly) holding one inline
    Int(7) element."""
    from crush.parsers.realm_parser import _read_array_mixed

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- the List's single element: inline Int(7) -> composite = (7<<8)|(0<<5)|(0+1) = 1793
    inner_composite_ref = emit(_array_hdr(0x0C, 1) + _pad8((1793).to_bytes(8, "little", signed=True)))
    inner_mixed_ref = emit(_array_hdr(0x46, 4) + _pad8(
        inner_composite_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") * 3
    ))

    # -- outer ArrayMixed: one row, data_type=19 (List), payload_idx_ref(4), payload_val=0
    outer_composite_val = (0 << 8) | (4 << 5) | (19 + 1)
    outer_composite_ref = emit(_array_hdr(0x0C, 1) + _pad8(
        outer_composite_val.to_bytes(8, "little", signed=True)
    ))
    outer_refs_ref = emit(_array_hdr(0x0C, 1) + _pad8(
        inner_mixed_ref.to_bytes(8, "little", signed=True)
    ))
    outer_mixed_ref = emit(_array_hdr(0x46, 5) + _pad8(
        outer_composite_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") * 3
        + outer_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    assert _read_array_mixed(data, outer_mixed_ref, len(data)) == [[7]]


def test_read_array_mixed_unknown_type_is_visible_not_silent() -> None:
    """A data_type that isn't one of the known scalars or List/Set/Dictionary
    (e.g. Geospatial=22, which has no case in array_mixed.cpp's store() at
    all) must never disappear or read as a plain value -- it has to show
    up as a clearly-flagged placeholder string."""
    from crush.parsers.realm_parser import _read_array_mixed

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    composite_val = (0 << 8) | (0 << 5) | (22 + 1)  # data_type=22 (Geospatial)
    composite_ref = emit(_array_hdr(0x0C, 1) + _pad8(composite_val.to_bytes(8, "little", signed=True)))
    outer_mixed_ref = emit(_array_hdr(0x46, 4) + _pad8(
        composite_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") * 3
    ))

    data = bytes(buf)
    result = _read_array_mixed(data, outer_mixed_ref, len(data))
    assert result == ["<mixed: unsupported type_22>"]


def test_read_array_mixed_nested_collection_depth_limit_is_visible() -> None:
    """A List-in-Mixed encountered once _nest_depth already reached
    _MIXED_MAX_NEST_DEPTH must not recurse further (guards against a
    corrupt/malicious Mixed<->collection reference chain) -- and must say
    so visibly rather than silently returning an empty/truncated result."""
    from crush.parsers.realm_parser import _MIXED_MAX_NEST_DEPTH, _read_array_mixed

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    inner_mixed_ref = emit(_array_hdr(0x46, 4) + _pad8((0).to_bytes(4, "little") * 4))
    composite_val = (0 << 8) | (4 << 5) | (19 + 1)  # List, payload_idx_ref, payload_val=0
    composite_ref = emit(_array_hdr(0x0C, 1) + _pad8(composite_val.to_bytes(8, "little", signed=True)))
    refs_ref = emit(_array_hdr(0x0C, 1) + _pad8(inner_mixed_ref.to_bytes(8, "little", signed=True)))
    outer_mixed_ref = emit(_array_hdr(0x46, 5) + _pad8(
        composite_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") * 3
        + refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    result = _read_array_mixed(data, outer_mixed_ref, len(data), _nest_depth=_MIXED_MAX_NEST_DEPTH)
    assert result == [f"<mixed: nesting depth limit ({_MIXED_MAX_NEST_DEPTH}) reached>"]


def _array_hdr(flags: int, size: int) -> bytes:
    return bytes([0x41, 0x41, 0x41, 0x41, flags]) + size.to_bytes(3, "big")


def _pad8(b: bytes) -> bytes:
    rem = len(b) % 8
    return b if rem == 0 else b + b"\x00" * (8 - rem)


def test_walk_cluster_leaves_resolves_inner_node() -> None:
    """_walk_cluster_leaves recurses a ClusterNodeInner's fixed layout
    ([key_ref_or_0, tagged_depth, tagged_tree_size, child_refs...]) and
    skips the 3 bookkeeping slots, matching cluster_tree.cpp's
    ClusterNodeInner (s_key_ref_index=0, s_sub_tree_depth_index=1,
    s_sub_tree_size=2, s_first_node_index=3).
    """
    from crush.parsers.realm_parser import _walk_cluster_leaves

    def leaf_bytes() -> bytes:
        return _array_hdr(0x46, 1) + _pad8((0).to_bytes(4, "little"))

    # A ref of 0 conventionally means "null" in Realm, so no real array ever
    # sits at file offset 0 (the 24-byte file header always precedes it) —
    # an 8-byte prefix here keeps every offset below realistic and nonzero.
    PREFIX = b"\x00" * 8
    ROOT_OFFSET = len(PREFIX)
    leaf_a = leaf_bytes()
    leaf_b = leaf_bytes()
    LEAF_A_OFFSET = ROOT_OFFSET + 32
    LEAF_B_OFFSET = ROOT_OFFSET + 48

    inner_payload = _pad8(
        (0).to_bytes(4, "little")                    # child[0]: key ref = 0 (compact form)
        + (((1 << 1) | 1)).to_bytes(4, "little")      # child[1]: tagged sub_tree_depth = 1
        + (((2 << 1) | 1)).to_bytes(4, "little")      # child[2]: tagged sub_tree_size = 2
        + LEAF_A_OFFSET.to_bytes(4, "little")         # child[3]: leaf A
        + LEAF_B_OFFSET.to_bytes(4, "little")         # child[4]: leaf B
    )
    inner = _array_hdr(0xC6, 5) + inner_payload  # is_inner=1, has_refs=1

    raw = PREFIX + inner + leaf_a + leaf_b
    leaves = _walk_cluster_leaves(raw, ROOT_OFFSET, len(raw))
    assert [ref for ref, _off in leaves] == [LEAF_A_OFFSET, LEAF_B_OFFSET]
    # compact form: child_idx << (sub_tree_depth * 8) = 0<<8=0, 1<<8=256
    assert [off for _ref, off in leaves] == [0, 256]


def test_read_array_int_null_reads_sentinel_from_slot_zero() -> None:
    """_read_array_int_null: slot[0] holds the file's own null sentinel
    (not an assumed INT_MAX-style constant); value == sentinel -> NULL
    (array_integer.hpp: null_value() reads slot 0 directly)."""
    from crush.parsers.realm_parser import _read_array_int_null

    sentinel = 999
    raw = _array_hdr(0x0C, 4) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (sentinel, 10, sentinel, 30)
    )
    assert _read_array_int_null(raw, 0, len(raw)) == [10, None, 30]


def test_read_array_bool_null_is_exactly_three() -> None:
    """_read_array_bool: nullable Bool is NULL iff the stored value is
    exactly 3, not "any value >= 2" (array_bool.hpp: null_value = 3)."""
    from crush.parsers.realm_parser import _read_array_bool

    # 4 values, 2 bits each: 0, 1, 3, 1 -> byte = 0b01_11_01_00 = 0x74
    raw = _array_hdr(0x02, 4) + _pad8(bytes([0b01110100]))
    assert _read_array_bool(raw, 0, len(raw), nullable=True) == [False, True, None, True]
    assert _read_array_bool(raw, 0, len(raw), nullable=False) == [False, True, True, True]


def test_decode_column_values_int_width1_stays_int_not_bool() -> None:
    """Modern (Cluster, format >=10) Int-column dispatch must not decode a
    1-bit-wide leaf as bool. Realm sizes an array's storage width from the
    largest value it ever held, so an Int column whose values all happen to
    fit in one bit (e.g. a small counter, or plain 0/1 values) legitimately
    uses the same 1-bit encoding as a real Bool column -- confusing the two
    made such a column display as True/False instead of 0/1 (found by the
    issue #55 reporter, @abrignoni, on a real-world file; see
    test_realm_pre_cluster equivalents and _read_scalar_leaf's own
    docstring for the pre-Cluster side of this same bug class).

    Exercises the actual dispatch path a Cluster leaf goes through
    (_decode_column_values -> type_code == 0 -> _read_scalar_leaf), not
    just the shared low-level reader in isolation, and checks real `int`
    type -- not just `== 0`/`== 1`, which a Python bool would also satisfy.
    """
    from crush.parsers.realm_parser import _decode_column_values

    # 4 values, 1 bit each: 0, 1, 0, 1 -> byte = 0b0000_1010 = 0x0A
    raw = _array_hdr(0x01, 4) + _pad8(bytes([0b00001010]))
    info = {
        "is_dictionary": False, "type_code": 0, "nullable": False,
        "is_list": False, "is_set": False,
    }
    result = _decode_column_values(raw, 0, len(raw), info)
    assert result == [0, 1, 0, 1]
    assert all(type(v) is int for v in result)


def test_read_array_string_short_inline() -> None:
    """ArrayStringShort: pad byte == width -> NULL; else content length is
    (width-1)-pad (array_string_short.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    entry0 = b"hello\x00\x00" + bytes([2])   # length = 7-2 = 5
    entry1 = b"\x00" * 7 + bytes([8])        # pad == width(8) -> NULL
    raw = _array_hdr(0x0C, 2) + entry0 + entry1
    result = _read_array_string_or_binary(raw, 0, len(raw), is_string=True, nullable=True)
    assert result == ["hello", None]


def test_read_array_small_blobs_cumulative_end_offsets() -> None:
    """ArraySmallBlobs: offsets[i] is the cumulative END position (begin =
    offsets[i-1] or 0), not a start-offset scanned for a NUL terminator;
    String rows carry a trailing '\\0' in blob that is stripped
    (array_blobs_small.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    OFFS_OFF, BLOB_OFF, NULL_OFF = 0, 16, 32
    # row0="ab" (stored "ab\0", end=3), row1="" (stored "\0", end=4), row2=NULL
    offs_array = _array_hdr(0x05, 3) + _pad8(
        (3).to_bytes(2, "little") + (4).to_bytes(2, "little") + (4).to_bytes(2, "little")
    )
    blob_array = _array_hdr(0x10, 4) + _pad8(b"ab\x00\x00")
    null_array = _array_hdr(0x01, 3) + _pad8(bytes([0b100]))
    COL_OFF = 48
    col_array = _array_hdr(0x46, 3) + _pad8(
        OFFS_OFF.to_bytes(4, "little") + BLOB_OFF.to_bytes(4, "little") + NULL_OFF.to_bytes(4, "little")
    )
    raw = offs_array + blob_array + null_array + col_array
    result = _read_array_string_or_binary(raw, COL_OFF, len(raw), is_string=True, nullable=True)
    assert result == ["ab", "", None]


def test_read_array_big_blobs_per_row_ref() -> None:
    """ArrayBigBlobs: each element is a ref to a standalone blob elsewhere
    in the file, or 0 for NULL (array_blobs_big.hpp)."""
    from crush.parsers.realm_parser import _read_array_string_or_binary

    # A ref of 0 means "null" in Realm, so the target blob must not sit at
    # file offset 0 (a small prefix keeps it, and every other offset, nonzero).
    PREFIX = b"\x00" * 8
    BLOB_OFF = len(PREFIX)
    blob_array = _array_hdr(0x10, 3) + _pad8(b"XYZ")
    OUTER_OFF = BLOB_OFF + 16
    outer_array = _array_hdr(0x66, 2) + _pad8(  # has_refs=1, context_flag=1
        BLOB_OFF.to_bytes(4, "little") + (0).to_bytes(4, "little")
    )
    raw = PREFIX + blob_array + outer_array
    result = _read_array_string_or_binary(raw, OUTER_OFF, len(raw), is_string=False, nullable=True)
    assert result == [b"XYZ", None]


def test_decode_timestamp_negative_seconds_before_1970() -> None:
    """A negative Timestamp (a valid pre-1970 date, not a guessed unit) must
    still decode to a date instead of silently falling back to the raw int —
    array_timestamp.hpp's seconds field is signed and pre-1970 dates are
    ordinary data, not an edge case to special-case away."""
    from crush.parsers.realm_parser import _decode_timestamp

    # -100_000 seconds before epoch = 1969-12-30 20:13:20 UTC.
    result = _decode_timestamp(-100_000)
    assert result == "1969-12-30 20:13:20 UTC"


def test_decode_timestamp_does_not_guess_unit_from_magnitude() -> None:
    """A value that would look like plausible milliseconds under the old
    magnitude-based guess must still be decoded as whole seconds, since
    that's the only unit array_timestamp.hpp ever stores."""
    from crush.parsers.realm_parser import _decode_timestamp

    # Old code's magnitude guess would have treated this as milliseconds
    # (dividing by 1000, landing on 1971); it's actually whole seconds.
    # Expected value computed via epoch + timedelta, not fromtimestamp():
    # fromtimestamp() delegates to the platform C library, and this value
    # is beyond what Windows' CRT accepts (though within glibc's range).
    result = _decode_timestamp(50_000_000_000)
    expected = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=50_000_000_000))
    assert result == expected.strftime("%Y-%m-%d %H:%M:%S UTC")
    assert "1971" not in result


def test_read_array_timestamp_nested_int_null() -> None:
    """ArrayTimestamp: [seconds_ref, nanos_ref], seconds is itself an
    ArrayIntNull (array_timestamp.cpp)."""
    from crush.parsers.realm_parser import _decode_timestamp, _read_array_timestamp

    SECS_OFF = 0
    sentinel = 777
    secs_array = _array_hdr(0x0C, 3) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (sentinel, 1_700_000_000, sentinel)
    )
    NANOS_OFF = 32
    nanos_array = _array_hdr(0x0C, 2) + b"".join(v.to_bytes(8, "little", signed=True) for v in (0, 0))
    OUTER_OFF = 56
    outer_array = _array_hdr(0x46, 2) + _pad8(
        SECS_OFF.to_bytes(4, "little") + NANOS_OFF.to_bytes(4, "little")
    )
    raw = secs_array + nanos_array + outer_array
    result = _read_array_timestamp(raw, OUTER_OFF, len(raw))
    assert result == [_decode_timestamp(1_700_000_000), None]


def test_read_array_fixed_bytes_block_bitvector() -> None:
    """ArrayFixedBytes[Null]: elements packed in blocks of 8, with 1
    null-bitvector byte prefixing each block (array_fixed_bytes.hpp)."""
    from crush.parsers.realm_parser import _read_array_fixed_bytes

    bitvec = bytes([0b00000010])  # element index 1 is NULL
    elem0 = b"\xAA\xBB\xCC\xDD"
    elem1 = b"\x00\x00\x00\x00"
    raw = _array_hdr(0x10, 9) + bitvec + elem0 + elem1  # total_bytes=9 (scheme=2, raw bytes)
    result = _read_array_fixed_bytes(raw, 0, len(raw), elem_size=4)
    assert result == [b"\xAA\xBB\xCC\xDD", None]


def test_read_array_link_stores_target_plus_one() -> None:
    """ArrayKey (single Link column): stored value = target ObjKey + 1, so
    that 0 represents NULL (array_key.hpp: ArrayKeyBase<1>)."""
    from crush.parsers.realm_parser import _read_array_link

    raw = _array_hdr(0x0C, 3) + b"".join(v.to_bytes(8, "little", signed=True) for v in (0, 6, 1))
    assert _read_array_link(raw, 0, len(raw)) == [None, 5, 0]


def test_extract_table_data_multi_leaf_concatenates_rows() -> None:
    """End-to-end: a table whose ClusterTree spans 2 leaves has its column
    values concatenated across leaves in key order, and row_count is the
    true sum — the scenario that was silently truncated before the
    ClusterNodeInner traversal fix."""
    from crush.parsers.realm_parser import _extract_table_data

    # A ref of 0 means "null" in Realm, so no real array may sit at file
    # offset 0 — an 8-byte prefix keeps every emitted offset nonzero.
    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- leaf 1: rows [10, 20] (compact keys) --
    col1_ref = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (10, 20))
    ))
    leaf1_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((2 << 1) | 1)).to_bytes(4, "little") + col1_ref.to_bytes(4, "little")
    ))

    # -- leaf 2: rows [30, 40, 50] (compact keys) --
    col2_ref = emit(_array_hdr(0x0C, 3) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (30, 40, 50))
    ))
    leaf2_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((3 << 1) | 1)).to_bytes(4, "little") + col2_ref.to_bytes(4, "little")
    ))

    # -- ClusterNodeInner: [key_ref=0, tagged_depth=1, tagged_tree_size=5, leaf1, leaf2] --
    cluster_root_ref = emit(_array_hdr(0xC6, 5) + _pad8(
        (0).to_bytes(4, "little")
        + (((1 << 1) | 1)).to_bytes(4, "little")
        + (((5 << 1) | 1)).to_bytes(4, "little")
        + leaf1_ref.to_bytes(4, "little")
        + leaf2_ref.to_bytes(4, "little")
    ))

    # -- spec: one column "n", Int, non-nullable --
    names_ref = emit(_array_hdr(0x0C, 1) + _pad8(b"n\x00\x00\x00\x00\x00\x00\x00"))
    colkey = 0  # index=0, type=Int(0), attrs=0
    colkeys_ref = emit(_array_hdr(0x0C, 1) + _pad8(colkey.to_bytes(8, "little", signed=True)))
    spec_ref = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little")            # child[0] types: unused by dispatch (colkey carries type)
        + names_ref.to_bytes(4, "little")    # child[1] names
        + (0).to_bytes(4, "little")          # child[2] attrs: unused (colkey carries attrs)
        + (0).to_bytes(4, "little")          # child[3] vacant
        + (0).to_bytes(4, "little")          # child[4] enum keys: unused
        + colkeys_ref.to_bytes(4, "little")  # child[5] colkeys
    ))

    # -- table node: [spec_ref, 0(unused), cluster_root_ref] --
    table_ref = emit(_array_hdr(0x46, 3) + _pad8(
        spec_ref.to_bytes(4, "little") + (0).to_bytes(4, "little") + cluster_root_ref.to_bytes(4, "little")
    ))

    # -- table refs + root --
    table_refs_ref = emit(_array_hdr(0x46, 1) + _pad8(table_ref.to_bytes(4, "little")))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    tables, _ = _extract_table_data(data, root_ref, ["class_Foo"], len(data))

    assert len(tables) == 1
    t = tables[0]
    assert t["name"] == "class_Foo"
    assert t["row_count"] == 5
    assert t["column_names"] == ["n"]
    assert t["column_types"] == ["int"]
    assert t["columns"][0] == [10, 20, 30, 40, 50]


def test_walk_bplustree_leaves_compact_form() -> None:
    """_walk_bplustree_leaves: BPlusTreeInner has a *different* layout from
    ClusterNodeInner — [elem0, child_1..child_N, tagged_tree_size(last)],
    only 2 bookkeeping slots (not 3), and elem0 uses the RefOrTagged tag
    bit (not zero/nonzero) to distinguish compact vs. general form
    (bplustree.cpp: BPlusTreeInner::get_node_size/get_bp_node_ref)."""
    from crush.parsers.realm_parser import _walk_bplustree_leaves

    # Children must be emitted (and their real offsets known) before the
    # inner node that references them, since the inner node's fixed size
    # depends on its own element count, not the children's.
    buf = bytearray(b"\x00" * 8)  # ref 0 means "null" in Realm; keep offsets nonzero

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    def leaf_bytes() -> bytes:
        return _array_hdr(0x05, 1) + _pad8((0).to_bytes(2, "little"))

    leaf_a_off = emit(leaf_bytes())
    leaf_b_off = emit(leaf_bytes())

    elems_per_child = 3
    inner_payload = _pad8(
        (((elems_per_child << 1) | 1)).to_bytes(4, "little")  # elem[0]: tagged compact marker
        + leaf_a_off.to_bytes(4, "little")                    # elem[1]: child A
        + leaf_b_off.to_bytes(4, "little")                    # elem[2]: child B
        + (((5 << 1) | 1)).to_bytes(4, "little")               # elem[3] (last): tagged tree_size
    )
    root_off = emit(_array_hdr(0xC6, 4) + inner_payload)

    raw = bytes(buf)
    leaves = _walk_bplustree_leaves(raw, root_off, len(raw))
    assert [ref for ref, _off in leaves] == [leaf_a_off, leaf_b_off]
    # compact form: child_idx * elems_per_child = 0*3=0, 1*3=3
    assert [off for _ref, off in leaves] == [0, 3]


def test_read_collection_column_list_of_int() -> None:
    """_read_collection_column: each row's ref points to its own
    BPlusTree<T> root — 0 means an empty collection, a non-inner ref means
    the tree root is itself already a leaf (small lists)."""
    from crush.parsers.realm_parser import _read_collection_column

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # row0's list tree root is a single leaf holding [7, 8]; row1 is empty.
    row0_leaf = emit(_array_hdr(0x0C, 2) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in (7, 8))
    ))
    col_ref = emit(_array_hdr(0x46, 2) + _pad8(
        row0_leaf.to_bytes(4, "little") + (0).to_bytes(4, "little")
    ))

    data = bytes(buf)
    result = _read_collection_column(data, col_ref, len(data), element_type=0, nullable=False)
    assert result == [[7, 8], []]


def test_read_array_typed_link_pairs() -> None:
    """ArrayTypedLink: flat (table_key+1, obj_key+1) int64 pairs;
    table_key==0 means NULL (array_typed_link.hpp)."""
    from crush.parsers.realm_parser import _read_array_typed_link

    raw = _array_hdr(0x0C, 4) + b"".join(
        v.to_bytes(8, "little", signed=True) for v in (4, 11, 0, 0)
    )
    assert _read_array_typed_link(raw, 0, len(raw)) == ["Obj(table_key=3, key=10)", None]


def test_read_array_mixed_basic_types() -> None:
    """ArrayMixed: each composite entry packs
    (payload_or_inline_value << 8) | (payload_idx << 5) | (data_type + 1);
    Int/Bool can be stored inline, String goes through the shared
    m_strings (ArrayString-shaped) payload array (array_mixed.cpp: get())."""
    from crush.parsers.realm_parser import _read_array_mixed

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # m_strings: 1 short-inline entry "hi" (width=8, pad=5)
    strings_ref = emit(_array_hdr(0x0C, 1) + (b"hi" + b"\x00" * 5 + bytes([5])))

    DT_INT, DT_BOOL, DT_STRING = 1, 2, 3  # data_type + 1 (Int=0, Bool=1, String=2)
    composite_vals = [
        (42 << 8) | (0 << 5) | DT_INT,     # inline Int
        (1 << 8) | (0 << 5) | DT_BOOL,     # inline Bool (True)
        (0 << 8) | (3 << 5) | DT_STRING,   # String at m_strings[0]
        0,                                  # NULL
    ]
    composite_ref = emit(_array_hdr(0x0C, 4) + _pad8(
        b"".join(v.to_bytes(8, "little", signed=True) for v in composite_vals)
    ))

    # outer ArrayMixed: [composite_ref, ints_ref=0, pairs_ref=0, strings_ref]
    outer_ref = emit(_array_hdr(0x46, 4) + _pad8(
        composite_ref.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + strings_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    result = _read_array_mixed(data, outer_ref, len(data))
    assert result == [42, True, "hi", None]


def test_link_column_resolves_target_table_name() -> None:
    """A Link column's target table is resolved via table.hpp's
    top_position_for_key (=3, this table's own TableKey) and
    top_position_for_opposite_table (=7, one TableKey per column) —
    table.hpp: Table::get_key_direct / Table::get_opposite_table_key.
    TableKeys are stable IDs, not necessarily equal to the table's
    physical index, so class_B (schema index 1) deliberately gets the
    larger TableKey (9) and class_A (schema index 0) the smaller one (5)."""
    from crush.parsers.realm_parser import _build_table_key_map, _extract_table_data

    buf = bytearray(b"\x00" * 8)

    def emit(b: bytes) -> int:
        off = len(buf)
        buf.extend(b)
        return off

    # -- class_A: one Int column "x", own TableKey = 5 --
    names_ref_a = emit(_array_hdr(0x0C, 1) + (b"x" + b"\x00" * 6 + bytes([6])))
    colkeys_ref_a = emit(_array_hdr(0x0C, 1) + _pad8((0).to_bytes(8, "little", signed=True)))
    spec_ref_a = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little") + names_ref_a.to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + colkeys_ref_a.to_bytes(4, "little")
    ))
    col_a_data_ref = emit(_array_hdr(0x0C, 1) + _pad8((42).to_bytes(8, "little", signed=True)))
    leaf_a_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((1 << 1) | 1)).to_bytes(4, "little") + col_a_data_ref.to_bytes(4, "little")
    ))
    table_a_ref = emit(_array_hdr(0x46, 4) + _pad8(
        spec_ref_a.to_bytes(4, "little") + (0).to_bytes(4, "little")
        + leaf_a_ref.to_bytes(4, "little") + (((5 << 1) | 1)).to_bytes(4, "little")
    ))

    # -- class_B: one Link column "link_to_a" pointing at class_A, own TableKey = 9 --
    names_ref_b = emit(_array_hdr(0x0D, 1) + (b"link_to_a" + b"\x00" * 6 + bytes([6])))
    colkey_b = 12 << 16  # index=0, type=Link(12), attrs=0
    colkeys_ref_b = emit(_array_hdr(0x0C, 1) + _pad8(colkey_b.to_bytes(8, "little", signed=True)))
    spec_ref_b = emit(_array_hdr(0x46, 6) + _pad8(
        (0).to_bytes(4, "little") + names_ref_b.to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + colkeys_ref_b.to_bytes(4, "little")
    ))
    col_b_data_ref = emit(_array_hdr(0x0C, 1) + _pad8((1).to_bytes(8, "little", signed=True)))
    leaf_b_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (((1 << 1) | 1)).to_bytes(4, "little") + col_b_data_ref.to_bytes(4, "little")
    ))
    opposite_ref_b = emit(_array_hdr(0x0C, 1) + _pad8((5).to_bytes(8, "little", signed=True)))
    table_b_ref = emit(_array_hdr(0x46, 8) + _pad8(
        spec_ref_b.to_bytes(4, "little") + (0).to_bytes(4, "little")
        + leaf_b_ref.to_bytes(4, "little") + (((9 << 1) | 1)).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little") + opposite_ref_b.to_bytes(4, "little")
    ))

    table_refs_ref = emit(_array_hdr(0x46, 2) + _pad8(
        table_a_ref.to_bytes(4, "little") + table_b_ref.to_bytes(4, "little")
    ))
    root_ref = emit(_array_hdr(0x46, 2) + _pad8(
        (0).to_bytes(4, "little") + table_refs_ref.to_bytes(4, "little")
    ))

    data = bytes(buf)
    schema = ["class_A", "class_B"]
    table_key_map = _build_table_key_map(data, root_ref, schema, len(data))
    assert table_key_map == {5: "class_A", 9: "class_B"}

    tables, _ = _extract_table_data(data, root_ref, schema, len(data), table_key_map)
    table_b = next(t for t in tables if t["name"] == "class_B")
    assert table_b["column_names"] == ["link_to_a"]
    assert table_b["column_target_tables"] == ["class_A"]


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _utf(s: str) -> bytes:
    data = s.encode("utf-8")
    return _u16(len(data)) + data


def _interned(s: str) -> bytes:
    return _u16(0xFFFF) + _utf(s)


def _make_abx_bytes() -> bytes:
    # Minimal ABX for: <root attr="value"/>
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")  # TYPE_STRING + START_TAG
    attr = bytes([0x2F]) + _interned("attr") + _utf("value")  # ATTRIBUTE token
    end_tag = bytes([0x23]) + _utf("root")  # TYPE_STRING + END_TAG
    end_doc = bytes([0x01])
    return magic + start_doc + start_tag + attr + end_tag + end_doc


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


def _make_atx_metadata_bytes() -> bytes:
    return b"AAPL\r\n\x1a\n" + _make_atx_head_chunk()


def _make_atx_lzfs_bytes() -> bytes:
    import liblzfse
    astc_block = bytes(16)
    compressed = liblzfse.compress(astc_block)
    lzfs_inner = struct.pack("<I", len(astc_block)) + compressed
    lzfs_chunk = struct.pack("<I4s", len(lzfs_inner), b"LZFS") + lzfs_inner
    return b"AAPL\r\n\x1a\n" + _make_atx_head_chunk(width=4, height=4) + lzfs_chunk


def test_abx_decode_unknown_value_type_reports_error() -> None:
    # START_TAG with an unassigned type nibble (0xE0) instead of a real ABX type.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    bad_start_tag = bytes([0xE2])  # token=START_TAG(2), dtype=0xE0 (unassigned)
    data = magic + start_doc + bad_start_tag

    result = decode_abx(data)

    assert any("Unknown ABX value type" in w for w in result.warnings)


def test_abx_decode_invalid_string_pool_reference_reports_error() -> None:
    # ATTRIBUTE with an interned-string reference pointing past the (empty) pool,
    # rather than the reserved 0xFFFF "new string" marker.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")
    bad_attr = bytes([0x2F]) + _u16(0) + _utf("value")  # ref=0, pool is empty
    data = magic + start_doc + start_tag + bad_attr

    result = decode_abx(data)

    assert any("Invalid ABX string pool reference" in w for w in result.warnings)


def test_abx_decode_multi_root_wraps_synthetic_root() -> None:
    # Real-world Android files (e.g. settings_secure.xml) can contain more
    # than one top-level element with no enclosing root — without wrapping,
    # the downstream lxml parse in AbxParser fails with "Extra content at
    # the end of the document" and the whole tree view is lost.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    tag_a = bytes([0x22]) + _utf("a")
    end_a = bytes([0x23]) + _utf("a")
    tag_b = bytes([0x22]) + _utf("b")
    end_b = bytes([0x23]) + _utf("b")
    data = magic + start_doc + tag_a + end_a + tag_b + end_b

    result = decode_abx(data)

    assert any("Multiple root elements" in w for w in result.warnings)

    from lxml import etree

    root = etree.fromstring(result.xml.encode("utf-8"))  # must not raise
    assert root.tag == "abx-root"
    assert [c.tag for c in root] == ["a", "b"]


def test_abx_decode_sanitizes_illegal_control_chars() -> None:
    # XML 1.0 forbids raw control bytes below 0x20 (other than tab/LF/CR).
    # Silently stripping them would lose forensic byte content; silently
    # passing them through breaks the downstream XML parse entirely.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")
    attr = bytes([0x2F]) + _interned("val") + _utf("bad\x01char")
    end_tag = bytes([0x23]) + _utf("root")
    data = magic + start_doc + start_tag + attr + end_tag

    result = decode_abx(data)

    assert "\\x01" in result.xml
    assert "\x01" not in result.xml
    assert any("illegal control character" in w.lower() for w in result.warnings)

    from lxml import etree

    etree.fromstring(result.xml.encode("utf-8"))  # must not raise


def test_abx_decode_surfaces_processing_instruction_not_silently() -> None:
    # ENTITY_REF/PROCESSING_INSTRUCTION/DOCDECL used to be consumed and
    # discarded with zero warning — a silent data loss. They must now show
    # up in the output and be flagged.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")
    pi = bytes([0x28]) + _utf("mypi data")  # token=PROCESSING_INSTRUCTION(8), dtype=TYPE_STRING
    end_tag = bytes([0x23]) + _utf("root")
    data = magic + start_doc + start_tag + pi + end_tag

    result = decode_abx(data)

    assert "mypi data" in result.xml
    assert any("PROCESSING_INSTRUCTION" in w for w in result.warnings)


def test_abx_decode_reports_truncation_scope_on_error() -> None:
    # A single decode error used to silently drop every remaining byte with
    # only a generic, scope-free message. The warning and the XML itself
    # must now make clear how much was lost and from where.
    magic = b"ABX\x00"
    start_doc = bytes([0x00])
    start_tag = bytes([0x22]) + _utf("root")
    bad_start_tag = bytes([0xE2])  # unassigned dtype, raises mid-document
    tail = b"\x00" * 10
    data = magic + start_doc + start_tag + bad_start_tag + tail
    expected_offset = len(magic) + len(start_doc) + len(start_tag)
    expected_remaining = len(data) - expected_offset

    result = decode_abx(data)

    assert any(
        w.startswith("TRUNCATED:")
        and f"offset {expected_offset}" in w
        and f"{expected_remaining} of {len(data)} bytes not decoded" in w
        for w in result.warnings
    )
    assert "ABX-DECODE-TRUNCATED" in result.xml


def test_abx_parser_parse(tmp_path: Path) -> None:
    abx_path = tmp_path / "binary.xml"
    abx_path.write_bytes(_make_abx_bytes())

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "binary.xml")

    parser = AbxParser()
    assert parser.can_parse(node.path, vfs.peek(node))

    result = parser.parse(node, vfs)
    assert result.viewer_type == "abx"
    assert "<root" in result.data["xml_str"]
    assert "attr" in result.data["xml_str"]
    tree = result.data["tree"]
    assert tree["@tag"] == "root"
    assert tree["@attribs"]["attr"] == "value"


def test_image_parser_can_parse_atx_magic(tmp_path: Path) -> None:
    atx_path = tmp_path / "poster.bin"
    atx_path.write_bytes(_make_atx_metadata_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.bin")

    assert ImageParser().can_parse(node.path, vfs.peek(node))


def test_image_parser_atx_metadata(tmp_path: Path) -> None:
    atx_path = tmp_path / "poster.atx"
    atx_path.write_bytes(_make_atx_metadata_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.atx")
    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "text"
    assert result.metadata["Format"] == "ATX"
    assert result.metadata["Width"] == 32
    assert result.metadata["Height"] == 16
    assert result.metadata["Pixel format"] == "ASTC 4x4"
    assert result.metadata["Chunks"] == "HEAD"
    assert result.metadata["Decode status"] == "ATX metadata parsed; image decode unavailable"


def test_image_parser_atx_image_decode(tmp_path: Path) -> None:
    pytest.importorskip("astc_decomp_faster")
    atx_path = tmp_path / "poster.atx"
    atx_path.write_bytes(_make_atx_lzfs_bytes())

    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "poster.atx")
    result = ImageParser().parse(node, vfs)

    assert result.viewer_type == "image"
    assert result.metadata["Format"] == "ATX"
    assert result.metadata["Width"] == 4
    assert result.metadata["Height"] == 4
    assert result.metadata["Pixel format"] == "ASTC 4x4"
    assert result.metadata["Decode status"] == "Decoded ATX to PNG"

# ---------------------------------------------------------------------------
# HexFallbackParser — format identification via FormatDatabase
# ---------------------------------------------------------------------------

def test_hex_fallback_identifies_sqlite_format(tmp_path: Path) -> None:
    raw = b"SQLite format 3\x00" + b"\x00" * 512
    (tmp_path / "mystery.bin").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "mystery.bin")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "hex"
    assert "Format (identified)" in result.metadata
    assert "SQLite" in result.metadata["Format (identified)"]
    assert "Parser support" in result.metadata
    assert result.metadata["Parser support"] == "Supported"


def test_hex_fallback_unknown_has_no_format_key(tmp_path: Path) -> None:
    raw = b"\xDE\xAD\xBE\xEF" * 32
    (tmp_path / "random.xyz999").write_bytes(raw)

    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == "random.xyz999")

    parser = HexFallbackParser()
    result = parser.parse(node, vfs)

    assert result.viewer_type == "hex"
    assert "Format (identified)" not in result.metadata


# ---------------------------------------------------------------------------
# _detect_encoding — text viewer encoding detection
# ---------------------------------------------------------------------------

def test_detect_utf8_bom() -> None:
    raw = b"\xef\xbb\xbf" + "hello".encode("utf-8")
    text, label = _detect_encoding(raw)
    assert text == "hello"
    assert label == "UTF-8 BOM"


def test_detect_utf16_le_bom() -> None:
    raw = b"\xff\xfe" + "hi".encode("utf-16-le")
    text, label = _detect_encoding(raw)
    assert text == "hi"
    assert label == "UTF-16 LE"


def test_detect_utf16_be_bom() -> None:
    raw = b"\xfe\xff" + "hi".encode("utf-16-be")
    text, label = _detect_encoding(raw)
    assert text == "hi"
    assert label == "UTF-16 BE"


def test_detect_plain_utf8() -> None:
    raw = "plain ascii".encode("utf-8")
    text, label = _detect_encoding(raw)
    assert text == "plain ascii"
    assert label == "UTF-8"


def test_detect_utf16_le_no_bom() -> None:
    # UTF-16 LE without BOM — non-ASCII chars put null bytes at odd positions
    # and make the raw bytes invalid as strict UTF-8, triggering the heuristic
    raw = "héllo wörld".encode("utf-16-le")
    text, label = _detect_encoding(raw)
    assert "h" in text
    assert "UTF-16 LE" in label


def test_detect_lossy_fallback() -> None:
    # Latin-1 bytes that are not valid UTF-8
    raw = b"\xff\xfe\xfd" * 10  # matches UTF-16 LE BOM — use something else
    # Use bytes that are invalid UTF-8 and won't trigger UTF-16 LE heuristic
    raw = bytes([0x80, 0x81, 0x82, 0x83] * 20)
    text, label = _detect_encoding(raw)
    assert isinstance(text, str)
    assert "lossy" in label.lower() or "UTF-8" in label


# ---------------------------------------------------------------------------
# LevelDB parser
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    out = []
    while n > 127:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _make_log_entry(key: bytes, value: bytes | None, seq: int) -> bytes:
    """Build one LevelDB log record (Full type). CRC is zeroed — ccl_leveldb doesn't validate it."""
    batch = struct.pack("<QI", seq, 1)
    if value is not None:
        batch += b"\x01" + _varint(len(key)) + key + _varint(len(value)) + value
    else:
        batch += b"\x00" + _varint(len(key)) + key
    header = struct.pack("<IHB", 0, len(batch), 1)  # CRC=0, length, type=Full
    return header + batch


def _make_minimal_leveldb(
    path: Path,
    records: list[tuple[bytes, bytes | None]],
) -> None:
    """Write a minimal LevelDB directory with one log file containing *records*."""
    path.mkdir(parents=True, exist_ok=True)
    log_data = b"".join(
        _make_log_entry(k, v, seq=i + 1) for i, (k, v) in enumerate(records)
    )
    (path / "000001.log").write_bytes(log_data)
    (path / "MANIFEST-000001").write_bytes(b"")  # empty manifest — parser handles gracefully


def test_leveldb_can_parse_dir_ldb(tmp_path: Path) -> None:
    (tmp_path / "000001.ldb").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_log(tmp_path: Path) -> None:
    (tmp_path / "000001.log").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_sst(tmp_path: Path) -> None:
    (tmp_path / "000001.sst").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_manifest(tmp_path: Path) -> None:
    (tmp_path / "MANIFEST-000001").touch()
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert LeveldbParser().can_parse_dir(node)


def test_leveldb_can_parse_dir_negative(tmp_path: Path) -> None:
    (tmp_path / "README.txt").write_text("not a leveldb")
    from crush.parsers.leveldb_parser import LeveldbParser
    node = DirectoryVFS(tmp_path).root()
    assert not LeveldbParser().can_parse_dir(node)


def test_leveldb_parse_viewer_type(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"key1", b"value1")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    assert result.viewer_type == "leveldb"


def test_leveldb_parse_live_records(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"hello", b"world")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    live = [r for r in records if r["state"] == "Live"]
    assert len(live) == 1
    assert live[0]["user_key_bytes"] == b"hello"
    assert live[0]["value_bytes"] == b"world"
    assert live[0]["user_key_text"] == "hello"
    assert live[0]["value_text"] == "world"


def test_leveldb_parse_deleted_records(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"gone", b"data"), (b"gone", None)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    deleted = [r for r in records if r["state"] == "Deleted"]
    assert len(deleted) >= 1
    assert deleted[0]["user_key_bytes"] == b"gone"


def test_leveldb_parse_file_stats(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"k", b"v"), (b"k2", None)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    files = result.data["files"]
    assert len(files) == 1
    assert files[0]["type"] == "Log"
    assert files[0]["total"] == 2
    assert files[0]["live"] == 1
    assert files[0]["deleted"] == 1


def test_leveldb_binary_key_value(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    binary_key = b"\x80\x81\x82\x83"   # invalid UTF-8 (continuation bytes without leader)
    binary_val = b"\xff\xfe\xfd"
    _make_minimal_leveldb(db, [(binary_key, binary_val)])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    assert records[0]["user_key_bytes"] == binary_key
    assert records[0]["value_bytes"] == binary_val
    assert records[0]["user_key_text"] is None   # not valid UTF-8
    assert records[0]["value_text"] is None


def test_leveldb_parse_record_has_offset(tmp_path: Path) -> None:
    db = tmp_path / "testdb"
    _make_minimal_leveldb(db, [(b"key1", b"value1")])
    from crush.parsers.leveldb_parser import LeveldbParser
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "testdb")
    result = LeveldbParser().parse(node, vfs)
    records = result.data["records"]
    assert len(records) >= 1
    assert "offset" in records[0]
    assert isinstance(records[0]["offset"], int)
    assert records[0]["offset"] >= 0


# ---------------------------------------------------------------------------
# BlobInspector helpers: _is_image, _render_protobuf
# ---------------------------------------------------------------------------

def test_is_image_png() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)


def test_is_image_jpeg() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"\xff\xd8\xff\xe0" + b"\x00" * 100)


def test_is_image_gif87() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"GIF87a" + b"\x00" * 100)


def test_is_image_gif89() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert _is_image(b"GIF89a" + b"\x00" * 100)


def test_is_image_negative() -> None:
    from crush.viewers.blob_inspector import _is_image
    assert not _is_image(b"SQLite format 3\x00" + b"\x00" * 100)
    assert not _is_image(b"")
    assert not _is_image(b"\x00\x01\x02\x03")


def test_render_protobuf_simple() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 1, "wire_type": "varint", "value": 42},
        {"field": 2, "wire_type": "varint", "value": 0},
    ]
    result = _render_protobuf(entries)
    assert "1 [varint]: 42" in result
    assert "2 [varint]: 0" in result


def test_render_protobuf_nested() -> None:
    # wire_type is "length-delimited" (as _decode_message produces);
    # value shape is {"type": "message", "entries": [...]}
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 1, "wire_type": "length-delimited", "value": {
            "type": "message",
            "entries": [{"field": 3, "wire_type": "varint", "value": 99}],
        }},
    ]
    result = _render_protobuf(entries)
    assert "1 {" in result
    assert "3 [varint]: 99" in result
    assert "}" in result


def test_render_protobuf_string_value() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 5, "wire_type": "length-delimited", "value": {"type": "string", "text": "hello"}},
    ]
    result = _render_protobuf(entries)
    assert '5: "hello"' in result


def test_render_protobuf_bytes_dict_value() -> None:
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {"field": 3, "wire_type": "length-delimited", "value": {
            "type": "bytes", "length": 4, "hex_preview": "de ad be ef",
        }},
    ]
    result = _render_protobuf(entries)
    assert "3:" in result
    assert "de ad be ef" in result


def test_render_protobuf_bytes_value() -> None:
    """A field's full bytes value must never be truncated — hiding real evidence
    bytes behind a display cutoff would be a forensic-accuracy bug, not a cosmetic
    one. This is distinct from the 40-byte 'value' shape here (a bare bytes object,
    not the {"type": "bytes", ...} dict _decode_message() actually produces)."""
    from crush.viewers.blob_inspector import _render_protobuf
    payload = bytes(range(40))
    entries = [{"field": 2, "wire_type": "bytes", "value": payload}]
    result = _render_protobuf(entries)
    assert "2:" in result
    assert "…" not in result
    assert payload.hex() in result  # complete 40-byte hex, not just the first 32


def test_render_protobuf_bytes_dict_value_uses_full_raw_not_capped_preview() -> None:
    """The parser's hex_preview is capped at 64 bytes for the tree/text display label —
    when the entry also carries the full raw payload (as real _decode_message() output
    does), the renderer must use that instead of repeating the capped preview."""
    from crush.viewers.blob_inspector import _render_protobuf
    payload = bytes(range(256)) * 2  # 512 bytes, well past the 64-byte preview cap
    entries = [{
        "field": 3,
        "wire_type": "length-delimited",
        "value": {"type": "bytes", "length": len(payload), "hex_preview": payload[:64].hex(" ") + " …"},
        "raw": payload,
    }]
    result = _render_protobuf(entries)
    assert payload.hex(" ") in result
    assert "…" not in result


def test_render_protobuf_ambiguous_message_raw_bytes_hint_shows_full_payload() -> None:
    """The dimmed 'raw bytes' interpretation shown alongside an ambiguous message
    decode is built from the same capped hex_preview — it must also be replaced
    with the full payload when available, not just the field's own primary value."""
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    inner_payload = bytes(range(64, 64 + 80))  # 80 bytes, not itself a nested submessage
    inner = b"\x0a" + _varint(len(inner_payload)) + inner_payload  # itself valid protobuf -> ambiguous
    outer = b"\x12" + _varint(len(inner)) + inner  # field 2, length-delimited

    decoded, warning, _ = _decode_message(outer)
    assert not warning
    result = _render_protobuf(decoded["entries"])
    assert "raw bytes" in result
    assert inner.hex(" ") in result
    assert "…" not in result


def test_render_protobuf_integration_nested() -> None:
    """End-to-end: real wire bytes with a nested message render as a block, not a raw dict."""
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # inner: field 1, varint 7  →  b'\x08\x07'
    inner = b"\x08\x07"
    # outer: field 1 varint 42, field 2 length-delimited (inner)
    outer = (
        b"\x08\x2a"                                        # field 1, varint 42
        + b"\x12" + bytes([len(inner)]) + inner            # field 2, length-delimited, inner
    )
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    result = _render_protobuf(decoded["entries"])
    assert "1 [varint]: 42" in result
    assert "2 {" in result            # nested message renders as block
    assert "1 [varint]: 7" in result  # inner field present
    assert "}" in result
    assert "type" not in result       # no raw dict repr leaking through


def test_decode_message_nested_field_also_shows_raw_bytes_interpretation() -> None:
    """Wire type 2 doesn't declare whether a payload is really a submessage —
    a short blob that happens to be grammatically valid protobuf (like a hash
    prefix or opaque token) would otherwise render as a confident nested
    message with no hint it might just be bytes. The raw-bytes reading must
    always be shown alongside it, like scalar fields' interpretations."""
    from crush.parsers.protobuf_parser import _decode_message

    # inner: field 1, varint 7  →  b'\x08\x07' (also happens to parse as a message)
    inner = b"\x08\x07"
    outer = b"\x12" + bytes([len(inner)]) + inner  # field 2, length-delimited
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "message"
    labels = [i.label for i in entry["interpretations"]]
    assert "raw bytes" in labels
    raw_hint = next(i for i in entry["interpretations"] if i.label == "raw bytes")
    assert raw_hint.value == inner.hex(" ")


def test_decode_message_bytes_entry_keeps_full_raw_past_preview_cap() -> None:
    """The hex_preview shown in the tree/text output is capped at 64 bytes, but the
    full payload must still be retrievable (e.g. for "Inspect BLOB…" / expanded value
    display) — losing it past the cap would silently hide real evidence bytes."""
    from crush.parsers.protobuf_parser import _decode_message

    payload = bytes(range(256)) * 2  # 512 bytes, well past the 64-byte preview cap, non-UTF8
    outer = b"\x0a" + _varint(len(payload)) + payload  # field 1, length-delimited
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "bytes"
    assert len(entry["value"]["hex_preview"]) < len(payload.hex(" "))  # preview is truncated
    assert entry["raw"] == payload  # but the full payload is preserved


def test_decode_message_string_entry_raw_matches_utf8_bytes() -> None:
    from crush.parsers.protobuf_parser import _decode_message

    text = "hello protobuf"
    payload = text.encode("utf-8")
    outer = b"\x0a" + _varint(len(payload)) + payload
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "string"
    assert entry["raw"] == payload


def test_decode_message_nested_message_entry_keeps_raw_submessage_bytes() -> None:
    from crush.parsers.protobuf_parser import _decode_message

    inner = b"\x08\x07"  # field 1, varint 7
    outer = b"\x12" + _varint(len(inner)) + inner  # field 2, length-delimited
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "message"
    assert entry["raw"] == inner


def test_decode_message_empty_length_delimited_has_empty_raw() -> None:
    from crush.parsers.protobuf_parser import _decode_message

    outer = b"\x0a\x00"  # field 1, length-delimited, zero length
    decoded, warning, _ = _decode_message(outer)
    assert not warning
    assert decoded["entries"][0]["raw"] == b""


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def test_render_protobuf_shows_interpretations() -> None:
    """Interpretation hints appear as '# label: value' lines below the field."""
    from crush.parsers.proto_interp import Interpretation
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {
            "field": 1,
            "wire_type": "varint",
            "value": 42,
            "interpretations": [
                Interpretation("uint64", "42"),
                Interpretation("sint64 (zigzag)", "21"),
                Interpretation("bool", "false"),
            ],
        }
    ]
    result = _render_protobuf(entries)
    assert "1 [varint]: 42" in result
    assert "# sint64 (zigzag): 21" in result
    assert "# bool: false" in result
    # uint64 is redundant (same as primary value) — must be suppressed
    assert "# uint64" not in result


def test_render_protobuf_suppresses_uint32() -> None:
    """uint32 is also suppressed as it equals the primary fixed32 value."""
    from crush.parsers.proto_interp import Interpretation
    from crush.viewers.blob_inspector import _render_protobuf
    entries = [
        {
            "field": 2,
            "wire_type": "fixed32",
            "value": 99,
            "interpretations": [
                Interpretation("uint32", "99"),
                Interpretation("int32", "99"),
                Interpretation("float", "1.387e-43"),
            ],
        }
    ]
    result = _render_protobuf(entries)
    assert "# uint32" not in result
    assert "# int32: 99" in result
    assert "# float" in result


def test_render_protobuf_integration_with_interpretations() -> None:
    """End-to-end: _decode_message produces interpretations shown in text output."""
    import struct
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # field 1: fixed64 containing a Cocoa timestamp (694656000.0 = 2023-01-07 UTC)
    raw = b"\x09" + struct.pack("<d", 694_656_000.0)
    decoded, warning, _ = _decode_message(raw)
    assert not warning
    result = _render_protobuf(decoded["entries"])
    assert "# double:" in result
    assert "# Cocoa timestamp:" in result
    assert "2023" in result


def test_try_protobuf_surfaces_warning() -> None:
    """Truncated protobuf shows a Warning header in BlobInspector output."""
    from crush.parsers.protobuf_parser import _decode_message
    from crush.viewers.blob_inspector import _render_protobuf

    # field 1, wire_type 1 (64-bit) with only 4 bytes — truncated
    truncated = b"\x09\x00\x01\x02\x03"
    decoded, warning, _ = _decode_message(truncated)
    assert warning  # must have a warning

    result = _render_protobuf(decoded["entries"])
    # _try_protobuf prepends the warning — simulate that here
    if warning:
        result = f"# Warning: {warning}\n\n{result}"
    assert "# Warning:" in result
    assert "Truncated" in result


# ---------------------------------------------------------------------------
# _decode_message heuristic: nested-first, string/bytes fallback
# ---------------------------------------------------------------------------

def test_decode_message_prefers_nested_over_utf8() -> None:
    """A length-delimited payload that is valid protobuf AND printable UTF-8 is decoded
    as a nested message, not a string."""
    from crush.parsers.protobuf_parser import _decode_message, _looks_like_utf8

    # tag 0x20 = field 4, wire_type 0 (varint); 0x41 = 65 — both are printable ASCII
    inner = b"\x20\x41"
    assert _looks_like_utf8(inner), "precondition: inner passes UTF-8 heuristic"

    # wrap as field 1, length-delimited
    outer = b"\x0a" + bytes([len(inner)]) + inner
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "message", (
        "valid nested protobuf should be decoded as message, not string"
    )


def test_decode_message_falls_back_to_string() -> None:
    """When nested parse yields no entries, UTF-8 payload is decoded as string."""
    from crush.parsers.protobuf_parser import _decode_message

    # b'\x07' is BEL — not parseable as a valid protobuf field (wire_type 7 is unknown)
    # and not printable (< 0x20), so this will fall through to bytes preview.
    # Use a clean printable string that cannot parse as protobuf:
    # 0xff starts an invalid varint sequence (never terminates within 1 byte as a tag)
    # → use pure ASCII text wrapped to trigger string fallback

    # "hello" as a payload: tag attempts fail quickly on 'h'=0x68 → field 13, wire_type 0
    # then 'e'=0x65 as varint value → succeeds → gives entries → would be nested!
    # We need something that fails nested parse but passes UTF-8.
    # Best approach: a payload that has a valid tag but truncated value.
    # field 1, wire_type 1 (64-bit) needs exactly 8 bytes — give it only 4.
    # tag 0x09 (field 1, wire_type 1) + 4 bytes "aaaa" → nested fails (truncated), payload IS UTF-8.
    payload = b"\x09aaaa"  # truncated 64-bit field → nested_warn set → falls back
    outer = b"\x0a" + bytes([len(payload)]) + payload
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "string", (
        "when nested parse fails, UTF-8 payload should fall back to string"
    )


def test_decode_message_falls_back_to_bytes() -> None:
    """When nested parse fails and payload is not UTF-8, shown as bytes preview."""
    from crush.parsers.protobuf_parser import _decode_message

    # 0x09 = field 1, wire_type 1 (64-bit) — but only 3 bytes follow → truncated nested parse
    # 0x80 0x81 0x82 are non-UTF-8 bytes → not a string either
    payload = b"\x09\x80\x81\x82"
    outer = b"\x0a" + bytes([len(payload)]) + payload
    decoded, warning, _ = _decode_message(outer)

    assert not warning
    entry = decoded["entries"][0]
    assert entry["value"]["type"] == "bytes"


# ---------------------------------------------------------------------------
# proto_interp: multi-interpretation display
# ---------------------------------------------------------------------------

def test_interpret_varint_basic() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(42)}
    assert "uint64" in labels
    assert "sint64 (zigzag)" in labels


def test_interpret_varint_bool() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(1)}
    assert "bool" in labels
    val = {i.label: i.value for i in interpret_varint(1)}
    assert val["bool"] == "true"
    val0 = {i.label: i.value for i in interpret_varint(0)}
    assert val0["bool"] == "false"


def test_interpret_varint_no_bool_for_large() -> None:
    from crush.parsers.proto_interp import interpret_varint
    labels = {i.label for i in interpret_varint(999)}
    assert "bool" not in labels


def test_interpret_varint_unix_ts() -> None:
    from crush.parsers.proto_interp import interpret_varint
    # 2023-01-07 00:00:00 UTC = 1673049600
    val = {i.label: i.value for i in interpret_varint(1_673_049_600)}
    assert "Unix timestamp (s)" in val
    assert "2023" in val["Unix timestamp (s)"]


def test_interpret_varint_signed() -> None:
    from crush.parsers.proto_interp import interpret_varint
    # max uint64 would be negative as int64
    big = (1 << 63)
    val = {i.label: i.value for i in interpret_varint(big)}
    assert "int64" in val


def test_interpret_fixed64_double_cocoa() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed64
    # Cocoa timestamp 694656000.0 = 2023-01-07 00:00:00 UTC
    raw = struct.pack("<d", 694_656_000.0)
    val = {i.label: i.value for i in interpret_fixed64(raw)}
    assert "double" in val
    assert "Cocoa timestamp" in val
    assert "2023" in val["Cocoa timestamp"]


def test_interpret_fixed64_uint64() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed64
    raw = struct.pack("<Q", 12345678)
    val = {i.label: i.value for i in interpret_fixed64(raw)}
    assert "uint64" in val


def test_interpret_fixed32_float() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed32
    raw = struct.pack("<f", 3.14)
    val = {i.label: i.value for i in interpret_fixed32(raw)}
    assert "float" in val


def test_interpret_fixed32_uint32() -> None:
    import struct
    from crush.parsers.proto_interp import interpret_fixed32
    raw = struct.pack("<I", 99)
    val = {i.label: i.value for i in interpret_fixed32(raw)}
    assert "uint32" in val


def test_decode_message_adds_interpretations() -> None:
    """_decode_message entries include an 'interpretations' list for numeric fields."""
    from crush.parsers.protobuf_parser import _decode_message
    # field 1, varint 42
    data = b"\x08\x2a"
    decoded, warning, _ = _decode_message(data)
    assert not warning
    entry = decoded["entries"][0]
    assert "interpretations" in entry
    assert any(i.label == "uint64" for i in entry["interpretations"])


# ---------------------------------------------------------------------------
# SEGB protobuf decoder tests
# ---------------------------------------------------------------------------

def _varint(v: int) -> bytes:
    """Encode a single unsigned varint."""
    out = []
    while v > 127:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _proto_field(field_num: int, wire_type: int, payload: bytes) -> bytes:
    return _varint((field_num << 3) | wire_type) + payload


def test_parse_protobuf_varint_field() -> None:
    """Basic varint field is decoded correctly."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(2, 0, _varint(42))
    result = _parse_protobuf(data)
    assert result[2] == 42


def test_parse_protobuf_string_field() -> None:
    """Length-delimited UTF-8 field is decoded as str."""
    from crush.parsers.segb_parser import _parse_protobuf
    s = b"com.apple.Preferences"
    data = _proto_field(2, 2, _varint(len(s)) + s)
    result = _parse_protobuf(data)
    assert result[2] == "com.apple.Preferences"


def test_parse_protobuf_repeated_fields() -> None:
    """Same field number appearing twice is collected into a list."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(1, 0, _varint(10)) + _proto_field(1, 0, _varint(20))
    result = _parse_protobuf(data)
    assert result[1] == [10, 20]


def test_parse_protobuf_high_field_number() -> None:
    """Field numbers above 200 (old hard limit) are now parsed correctly."""
    from crush.parsers.segb_parser import _parse_protobuf
    data = _proto_field(750, 0, _varint(99))
    result = _parse_protobuf(data)
    assert 750 in result
    assert result[750] == 99


def test_parse_protobuf_multiple_fields() -> None:
    """Multiple different field numbers are all decoded."""
    from crush.parsers.segb_parser import _parse_protobuf
    s = b"hello"
    data = (
        _proto_field(1, 0, _varint(7))
        + _proto_field(2, 2, _varint(len(s)) + s)
        + _proto_field(300, 0, _varint(1))
    )
    result = _parse_protobuf(data)
    assert result[1] == 7
    assert result[2] == "hello"
    assert result[300] == 1


def test_proto_to_json_basic() -> None:
    """Simple protobuf payload serialises to valid JSON."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    s = b"com.apple.test"
    data = _proto_field(2, 2, _varint(len(s)) + s)
    j = _proto_to_json(data)
    obj = json.loads(j)
    assert obj["2"] == "com.apple.test"


def test_proto_to_json_repeated_fields_become_array() -> None:
    """Repeated fields are stored as JSON arrays."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    data = _proto_field(1, 0, _varint(10)) + _proto_field(1, 0, _varint(20))
    obj = json.loads(_proto_to_json(data))
    assert obj["1"] == [10, 20]


def test_proto_to_json_always_valid_json() -> None:
    """Garbage input always returns valid (empty) JSON, never raises."""
    import json
    from crush.parsers.segb_parser import _proto_to_json
    for bad in (b"", b"\xff\xff\xff", b"\x00" * 20):
        result = _proto_to_json(bad)
        obj = json.loads(result)   # must not raise
        assert isinstance(obj, dict)


def test_render_proto_payload_shows_undecodable_blobs_as_hex() -> None:
    """Binary blobs that cannot be sub-parsed still appear, as a size+hex preview."""
    from crush.parsers.segb_parser import _render_proto_payload
    binary = b"\xde\xad\xbe\xef"
    data = _proto_field(5, 2, _varint(len(binary)) + binary)
    result = _render_proto_payload(data)
    # field 5 must stay visible — no field silently vanishes from the rendered view.
    assert "5" in result
    assert "4 B" in result
    assert "deadbeef" in result


def test_render_proto_payload_double_field_gets_cocoa_hint_not_replaced() -> None:
    """A double in the plausible Cocoa range is shown as a labeled hint, raw value kept."""
    import struct
    from crush.parsers.segb_parser import _render_proto_payload
    # 694656000.0 = 2023-01-06 UTC as a Cocoa timestamp (2001-01-01 epoch + 8040 days).
    data = _proto_field(4, 1, struct.pack("<d", 694_656_000.0))
    result = _render_proto_payload(data)
    assert f"{694_656_000.0:.6g}" in result  # raw value still present, not replaced
    assert "possible Cocoa timestamp" in result
    assert "2023" in result


def test_proto_to_json_double_field_stays_a_json_number() -> None:
    """Payload JSON must never swap a plausible-Cocoa double for a date string,
    so json_extract() comparisons stay type-consistent regardless of value."""
    import json
    import struct
    from crush.parsers.segb_parser import _proto_to_json
    data = _proto_field(4, 1, struct.pack("<d", 694_656_000.0))
    obj = json.loads(_proto_to_json(data))
    assert isinstance(obj["4"], float)
    assert obj["4"] == pytest.approx(694_656_000.0)


def test_render_proto_payload_repeated_fields() -> None:
    """Repeated fields appear in the rendered output."""
    from crush.parsers.segb_parser import _render_proto_payload
    data = _proto_field(3, 0, _varint(1)) + _proto_field(3, 0, _varint(2))
    result = _render_proto_payload(data)
    assert result  # non-empty
    assert "3" in result


def test_render_proto_payload_nested_message_also_shows_raw_bytes() -> None:
    """A bytes field that decodes as a nested message must still show the raw
    bytes alongside it — wire type 2 doesn't declare that the payload really
    is a submessage, and a short blob can coincidentally parse as one (same
    convention as the standalone Protobuf Viewer's 'raw bytes' hint)."""
    from crush.parsers.segb_parser import _render_proto_payload
    # field 1, varint 200 -> b'\x08\xc8\x01': invalid UTF-8 (0xC8 needs a
    # continuation byte), but grammatically valid protobuf -> {1: 200}.
    inner = _proto_field(1, 0, _varint(200))
    data = _proto_field(5, 2, _varint(len(inner)) + inner)
    result = _render_proto_payload(data)
    assert "{1:200}" in result
    assert f"[raw: {len(inner)} B: {inner.hex()}]" in result


def test_create_segb_sqlite_payload_columns() -> None:
    """SQLite DB has both Payload (rendered text) and Payload JSON columns."""
    import json
    import sqlite3
    from crush.parsers.segb_parser import _create_segb_sqlite, _COLUMNS_V1
    s = b"com.apple.test"
    raw = _proto_field(2, 2, _varint(len(s)) + s)
    rendered = "2: \"com.apple.test\""
    rows = [
        [0, 0, "Current", "2024-01-01", "2024-01-01", 0, 0, True,
         len(raw), (rendered, raw)],
    ]
    path = _create_segb_sqlite(_COLUMNS_V1, rows)
    assert path is not None
    conn = sqlite3.connect(str(path))
    cols = [r[1] for r in conn.execute('PRAGMA table_info("SEGB")').fetchall()]
    assert "Payload" in cols
    assert "Payload JSON" in cols
    payload_val = conn.execute('SELECT "Payload" FROM SEGB').fetchone()[0]
    assert payload_val == rendered
    payload_json = conn.execute('SELECT "Payload JSON" FROM SEGB').fetchone()[0]
    obj = json.loads(payload_json)
    assert obj.get("2") == "com.apple.test"
    conn.close()
    path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Group wire-type (3/4) handling in _decode_message
# ---------------------------------------------------------------------------

def test_decode_message_skips_simple_group() -> None:
    """A group (wire_type=3) should be skipped; fields after it are decoded normally."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B), field 2 varint 99 inside (0x10 0x63),
    # field 1 end-group (0x0C), then field 3 varint 7 (0x18 0x07)
    raw = bytes([0x0B, 0x10, 0x63, 0x0C, 0x18, 0x07])
    decoded, warning, _ = _decode_message(raw)
    assert warning == ""
    entries = decoded["entries"]
    assert len(entries) == 1
    assert entries[0]["field"] == 3
    assert entries[0]["value"] == 7


def test_decode_message_skips_nested_group() -> None:
    """Nested groups (group inside a group) are skipped recursively."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B)
    #   field 3 start-group (0x1B)
    #     field 4 varint 5 (0x20 0x05)
    #   field 3 end-group (0x1C)
    # field 1 end-group (0x0C)
    # field 3 varint 7 (0x18 0x07)
    raw = bytes([0x0B, 0x1B, 0x20, 0x05, 0x1C, 0x0C, 0x18, 0x07])
    decoded, warning, _ = _decode_message(raw)
    assert warning == ""
    entries = decoded["entries"]
    assert len(entries) == 1
    assert entries[0]["field"] == 3
    assert entries[0]["value"] == 7


def test_decode_message_warns_on_truncated_group() -> None:
    """A group without a closing end-group tag produces a truncation warning."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 start-group (0x0B), field 2 varint 99 inside (0x10 0x63), then EOF
    raw = bytes([0x0B, 0x10, 0x63])
    decoded, warning, _ = _decode_message(raw)
    assert "Truncated" in warning or "truncated" in warning.lower()


def test_decode_message_warns_on_unexpected_end_group() -> None:
    """An end-group tag (wire_type=4) at the top level produces a warning."""
    from crush.parsers.protobuf_parser import _decode_message

    # field 1 end-group (0x0C) at top level — no matching start-group
    raw = bytes([0x0C])
    decoded, warning, _ = _decode_message(raw)
    assert "end-group" in warning.lower() or "Unexpected" in warning


# ---------------------------------------------------------------------------
# blob_inspector — intermediate decode functions and registry
# ---------------------------------------------------------------------------

def test_decode_base64_valid() -> None:
    import base64
    from crush.viewers.blob_inspector import _decode_base64
    payload = b"hello world"
    assert _decode_base64(base64.b64encode(payload)) == payload


def test_decode_base64_invalid() -> None:
    from crush.viewers.blob_inspector import _decode_base64
    assert _decode_base64(b"!!!not-base64!!!") is None


def test_decode_hex_valid() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"deadbeef") == bytes.fromhex("deadbeef")


def test_decode_hex_with_spaces() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"de ad be ef") == bytes.fromhex("deadbeef")


def test_decode_hex_with_colons() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"de:ad:be:ef") == bytes.fromhex("deadbeef")


def test_decode_hex_invalid() -> None:
    from crush.viewers.blob_inspector import _decode_hex
    assert _decode_hex(b"zzzz") is None


def test_intermediate_registry_dispatches() -> None:
    import base64
    from crush.viewers.blob_inspector import _INTERMEDIATE
    payload = b"hello"
    assert _INTERMEDIATE["Base64 (decode)"](base64.b64encode(payload)) == payload
    assert _INTERMEDIATE["Hex → Bytes"](b"deadbeef") == bytes.fromhex("deadbeef")


def test_intermediate_registry_unknown_returns_none() -> None:
    from crush.viewers.blob_inspector import _INTERMEDIATE
    assert _INTERMEDIATE.get("UTF-8 text") is None


def test_decode_base64url_valid() -> None:
    import base64
    from crush.viewers.blob_inspector import _decode_base64url
    payload = b"\xfb\xfc\xfd"
    assert _decode_base64url(base64.urlsafe_b64encode(payload)) == payload


def test_decode_base64url_url_chars_accepted() -> None:
    """URL-safe alphabet (-_) must round-trip correctly."""
    from crush.viewers.blob_inspector import _decode_base64url
    # b"\xfb\xfc\xfd" encodes to "-_z9" in URL-safe b64 (contains - and _)
    import base64
    payload = b"\xfb\xfc\xfd"
    url_encoded = base64.urlsafe_b64encode(payload)
    assert _decode_base64url(url_encoded) == payload


def test_decode_base64url_no_padding_needed() -> None:
    """urlsafe_b64decode adds padding automatically — partial input must still decode."""
    import base64
    from crush.viewers.blob_inspector import _decode_base64url
    payload = b"hello"
    # strip trailing padding; function must restore it
    stripped = base64.urlsafe_b64encode(payload).rstrip(b"=")
    assert _decode_base64url(stripped) == payload


def test_decode_lzfse_invalid_returns_none() -> None:
    from crush.viewers.blob_inspector import _decode_lzfse
    assert _decode_lzfse(b"not lzfse data at all") is None


def test_intermediate_registry_has_new_steps() -> None:
    from crush.viewers.blob_inspector import _INTERMEDIATE
    assert "Base64url (decode)" in _INTERMEDIATE
    assert "lzfse decompress" in _INTERMEDIATE


def test_intermediate_registry_base64url_dispatches() -> None:
    import base64
    from crush.viewers.blob_inspector import _INTERMEDIATE
    payload = b"hello \xfb\xfc"
    assert _INTERMEDIATE["Base64url (decode)"](base64.urlsafe_b64encode(payload)) == payload
