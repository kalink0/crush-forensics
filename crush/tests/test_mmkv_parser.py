# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the MMKV parser (crush/parsers/mmkv_parser.py).

Buffers are built by hand to the on-disk layout (verified independently against
Tencent/MMKV's own source, see CHANGELOG) rather than taken from a real store,
per this project's synthetic-fixtures-only rule for forensic tests.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from crush.core.passwords import WrongPasswordError
from crush.core.vfs import DirectoryVFS
from crush.parsers.mmkv_parser import MMKVParser


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _string_value(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _varint(len(encoded)) + encoded


def _entry(key: str, container: bytes) -> bytes:
    encoded_key = key.encode("utf-8")
    return _varint(len(encoded_key)) + encoded_key + _varint(len(container)) + container


def _store(*entries: bytes, holder: bytes | None = None) -> bytes:
    """A real MMKV file: [u32 actual_size][items-size varint][entries][padding]."""
    data = b"".join(entries)
    items = holder if holder is not None else _varint(len(data))
    region = items + data
    return struct.pack("<I", len(region)) + region + b"\x00" * 64


def _write_store(tmp_path: Path, payload: bytes, name: str = "mmkv.default", crc: bytes | None = None):
    path = tmp_path / name
    path.write_bytes(payload)
    if crc is not None:
        (tmp_path / (name + ".crc")).write_bytes(crc)
    vfs = DirectoryVFS(tmp_path)
    root = vfs.root()
    node = next(c for c in root.children if c.name == name)
    return node, vfs


# ---------------------------------------------------------------------------
# Explicit-only detection
# ---------------------------------------------------------------------------

def test_can_parse_is_always_false() -> None:
    parser = MMKVParser()
    assert parser.can_parse("/x/mmkv.default", b"anything") is False
    assert parser.can_parse("/x/random.bin", b"") is False


# ---------------------------------------------------------------------------
# Basic decode
# ---------------------------------------------------------------------------

def test_reads_strings_and_scalars(tmp_path: Path) -> None:
    payload = _store(
        _entry("channel", _string_value("googleplay")),
        _entry("version", _varint(33)),
    )
    node, vfs = _write_store(tmp_path, payload)
    result = MMKVParser().parse(node, vfs)

    assert result.viewer_type == "mmkv"
    records = {r["key"]: r for r in result.data["records"]}
    assert records["channel"]["decoded"] == "googleplay"
    assert records["channel"]["type"] == "string"
    assert records["channel"]["state"] == "Live"
    assert records["version"]["decoded"] == 33
    assert records["version"]["type"] == "int"


def test_first_key_follows_items_size_varint_at_every_width(tmp_path: Path) -> None:
    """Regression test for the exact bug class #68 warns about: a reader that
    assumes a fixed items-size width starts the first key at the wrong offset
    and silently returns zero entries. All four on-disk widths are exercised."""
    append_holder = b"\xff\xff\xff\x07"  # Tencent's 4-byte ItemSizeHolder constant
    entries = (_entry("alpha", _string_value("one")), _entry("beta", _string_value("two")))
    for holder, width in (
        (append_holder, 4),
        (_varint(2**20), 3),
        (_varint(2**12), 2),
        (_varint(3), 1),
    ):
        payload = _store(*entries, holder=holder)
        node, vfs = _write_store(tmp_path, payload, name=f"store_{width}")
        result = MMKVParser().parse(node, vfs)
        records = {r["key"]: r["decoded"] for r in result.data["records"]}
        assert records == {"alpha": "one", "beta": "two"}, f"holder width {width}"


def test_last_write_is_live_earlier_ones_are_superseded(tmp_path: Path) -> None:
    payload = _store(
        _entry("checked", _string_value("")),
        _entry("checked", _string_value("8.11.4")),
    )
    node, vfs = _write_store(tmp_path, payload)
    result = MMKVParser().parse(node, vfs)
    records = result.data["records"]
    assert [r["state"] for r in records] == ["Superseded", "Live"]
    assert records[0]["decoded"] == ""
    assert records[1]["decoded"] == "8.11.4"


def test_zero_length_value_marks_removal(tmp_path: Path) -> None:
    payload = _store(
        _entry("token", _string_value("abc")),
        _entry("token", b""),
    )
    node, vfs = _write_store(tmp_path, payload)
    result = MMKVParser().parse(node, vfs)
    records = result.data["records"]
    assert [r["state"] for r in records] == ["Superseded", "Removed"]
    assert records[1]["decoded"] is None
    assert result.metadata["Removed"] == "1"
    assert result.metadata["Live"] == "0"


def test_removed_key_reset_later_is_superseded_not_removed(tmp_path: Path) -> None:
    """A key can be removed and then set again — the removal write is then just
    a superseded write, not the final state, and must be labelled accordingly."""
    payload = _store(
        _entry("x", _string_value("a")),
        _entry("x", b""),               # removed here, but not the last write
        _entry("x", _string_value("b")),
    )
    node, vfs = _write_store(tmp_path, payload)
    result = MMKVParser().parse(node, vfs)
    records = result.data["records"]
    assert [r["state"] for r in records] == ["Superseded", "Superseded", "Live"]
    assert records[1]["decoded"] is None  # still shows the empty container it recorded
    assert records[2]["decoded"] == "b"


def test_empty_store_reads_as_no_entries(tmp_path: Path) -> None:
    payload = struct.pack("<I", 0)
    node, vfs = _write_store(tmp_path, payload)
    result = MMKVParser().parse(node, vfs)
    assert result.data["records"] == []


# ---------------------------------------------------------------------------
# .crc meta file
# ---------------------------------------------------------------------------

def test_missing_crc_file_is_reported_not_hidden(tmp_path: Path) -> None:
    payload = _store(_entry("a", _string_value("b")))
    node, vfs = _write_store(tmp_path, payload, crc=None)
    result = MMKVParser().parse(node, vfs)
    assert result.data["meta_info"] is None
    assert "not found" in result.metadata["Meta file"]
    # Still readable as plaintext — a missing .crc doesn't block parsing.
    assert result.data["records"][0]["decoded"] == "b"


def test_zero_vector_meta_is_not_treated_as_encrypted(tmp_path: Path) -> None:
    payload = _store(_entry("a", _string_value("b")))
    crc = bytes(32)  # all-zero: version 0, zero vector
    node, vfs = _write_store(tmp_path, payload, crc=crc)
    result = MMKVParser().parse(node, vfs)
    assert result.data["meta_info"]["encrypted"] is False
    assert result.data["records"][0]["decoded"] == "b"


def _meta_bytes(*, version: int, sequence: int, vector: bytes = b"\x00" * 16, actual_size: int = 0) -> bytes:
    return struct.pack("<III", 0, version, sequence) + vector.ljust(16, b"\x00") + struct.pack("<I", actual_size)


def test_meta_version_and_sequence_surfaced_in_overview(tmp_path: Path) -> None:
    payload = _store(_entry("a", _string_value("b")))
    crc = _meta_bytes(version=1, sequence=42)
    node, vfs = _write_store(tmp_path, payload, crc=crc)
    result = MMKVParser().parse(node, vfs)
    assert result.data["meta_info"]["version"] == 1
    assert result.data["meta_info"]["sequence"] == 42


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _aes_cfb128_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    encryptor = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def test_encrypted_store_without_key_reports_encrypted_not_empty(tmp_path: Path) -> None:
    key = b"correct horse battery staple 12"[:16]
    iv = bytes(range(16))
    plaintext = _store(_entry("a", _string_value("secret")))
    header, region = plaintext[:4], plaintext[4:]
    ciphertext = header + _aes_cfb128_encrypt(region, key, iv)

    crc = _meta_bytes(version=1, sequence=0, vector=iv)
    node, vfs = _write_store(tmp_path, ciphertext, crc=crc)

    result = MMKVParser().parse(node, vfs)  # no password
    assert result.viewer_type == "tree"
    assert result.metadata["Encrypted"] == "yes"
    assert "records" not in result.data


def test_high_meta_version_false_positive_encrypted_flag_does_not_block_plaintext_read(
    tmp_path: Path,
) -> None:
    """Regression: a real react-native-mmkv store's .crc file had a non-zero
    vector (meta version 61, far outside the 1-4 range this struct layout
    has been verified against) even though the store's own data was
    demonstrably plaintext (readable JSON, hundreds of correctly-decoded
    entries). Crush must not take the vector-nonzero flag at face value when
    the store reads cleanly as plaintext anyway -- confirm before refusing."""
    payload = _store(_entry("a", _string_value("b")), _entry("c", _string_value("d")))
    vector = bytes(range(1, 17))  # non-zero, would normally mean "encrypted"
    crc = _meta_bytes(version=61, sequence=0, vector=vector)
    node, vfs = _write_store(tmp_path, payload, crc=crc)

    result = MMKVParser().parse(node, vfs)  # no password
    assert result.data["records"][0]["decoded"] == "b"
    assert result.data["records"][1]["decoded"] == "d"
    assert "false positive" in result.metadata["Encrypted"]


def test_encrypted_store_with_correct_key_decrypts(tmp_path: Path) -> None:
    key = b"correct horse battery staple 12"[:16]
    iv = bytes(range(16))
    plaintext = _store(_entry("a", _string_value("secret")))
    header, region = plaintext[:4], plaintext[4:]
    ciphertext = header + _aes_cfb128_encrypt(region, key, iv)

    crc = _meta_bytes(version=1, sequence=0, vector=iv)
    node, vfs = _write_store(tmp_path, ciphertext, crc=crc)

    result = MMKVParser().parse(node, vfs, password=key)
    assert result.data["records"][0]["decoded"] == "secret"
    assert result.metadata["Encrypted"] == "yes (decrypted)"


def test_encrypted_store_with_wrong_key_raises_wrong_password(tmp_path: Path) -> None:
    key = b"correct horse battery staple 12"[:16]
    wrong_key = b"nope nope nope nope nope nope!!"[:16]
    iv = bytes(range(16))
    plaintext = _store(_entry("a", _string_value("secret")))
    header, region = plaintext[:4], plaintext[4:]
    ciphertext = header + _aes_cfb128_encrypt(region, key, iv)

    crc = _meta_bytes(version=1, sequence=0, vector=iv)
    node, vfs = _write_store(tmp_path, ciphertext, crc=crc)

    with pytest.raises(WrongPasswordError):
        MMKVParser().parse(node, vfs, password=wrong_key)


# ---------------------------------------------------------------------------
# raw value bytes must exclude MMKV's own internal length-prefix
# ---------------------------------------------------------------------------

def test_raw_stays_complete_while_value_bytes_excludes_length_prefix(tmp_path: Path) -> None:
    """A string value's on-disk container is [length-prefix varint][UTF-8 bytes]
    — that prefix is MMKV's own internal way of telling a string apart from a
    bare scalar, not part of the value. rec["raw"] must always stay the
    complete, untouched container (nothing is ever removed from raw); a
    separate rec["value_bytes"] holds just the value's own bytes, for anything
    that tries to actually use them (e.g. re-parsing a JSON value, which
    breaks on the stray leading byte if the prefix is left in)."""
    import json

    payload = {"type": "PERSISTED_CACHE_V3", "recordMap": {"client:root": {"id": "root"}}}
    text = json.dumps(payload)
    container = _string_value(text)
    node, vfs = _write_store(tmp_path, _store(_entry("cache", container)))
    result = MMKVParser().parse(node, vfs)
    rec = result.data["records"][0]

    assert rec["decoded"] == text
    assert rec["raw"] == container  # complete container, length-prefix included
    assert rec["value_bytes"] == text.encode("utf-8")  # stripped, value only
    assert json.loads(rec["value_bytes"]) == payload  # the whole point: must parse as JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(rec["raw"])  # raw still has the prefix — this is expected, not a bug


def test_raw_bytes_for_scalar_values_are_the_bare_container() -> None:
    """A scalar (bare varint) container has no length-prefix to strip — it IS
    the value, so it must be returned unchanged."""
    from crush.parsers.mmkv_parser import _content_bytes

    container = _varint(42)
    assert _content_bytes(container) == container


def test_content_bytes_agrees_with_decode_value_on_shape() -> None:
    """_content_bytes()'s shape check must always match decode_value()'s own —
    otherwise the displayed "decoded" value and the "value_bytes" exposed for
    Inspect Value could disagree about what kind of container this even is."""
    from crush.third_party.mmkv_parser import decode_value
    from crush.parsers.mmkv_parser import _content_bytes

    for container in (
        _string_value("hello"),
        _string_value(""),
        _varint(0),
        _varint(1_785_482_702_086),
        b"",
    ):
        decoded = decode_value(container)
        content = _content_bytes(container)
        if isinstance(decoded, str):
            assert content == decoded.encode("utf-8")
        elif decoded is None:
            assert content == b""
        else:
            # scalar (int) or the true undecodable fallback — no prefix to strip
            assert content == container
