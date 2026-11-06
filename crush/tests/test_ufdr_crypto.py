# SPDX-License-Identifier: Apache-2.0
"""Tests for UFDR file-level Protection crypto (crush/core/ufdr_crypto.py).

Self-contained: ciphertext is produced here with the inverse of the reader's
own chunk model, so no checked-in or multi-GB fixture is needed. The absolute
constants (PBKDF2 rounds, default passwords, verifier plaintext, the IV/chunk
layout) were verified separately against a real protected UFDR 10.x sample --
the known-answer vectors below pin them so a change is caught.
"""
from __future__ import annotations

import io
import struct

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crush.core import ufdr_crypto as c

_CHUNK = 8192


def _encrypt_member(key: bytes, name: str, plaintext: bytes) -> bytes:
    """Inverse of ufdr_crypto.decrypt_member, for building test ciphertext."""
    nonce8 = c._nonce8(name)
    nonlast = len(plaintext) // _CHUNK
    out = bytearray()
    for i in range(nonlast):
        iv = struct.pack("<q", i) + nonce8
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        out += enc.update(plaintext[i * _CHUNK : (i + 1) * _CHUNK]) + enc.finalize()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext[nonlast * _CHUNK :]) + padder.finalize()
    iv = struct.pack("<q", nonlast) + nonce8
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    out += enc.update(padded) + enc.finalize()
    return bytes(out)


def _footer(
    salt: bytes,
    verifier_ct: bytes,
    *,
    is_encrypted: int = 1,
    is_default: int = 1,
    enc_major: int = 1,
    enc_minor: int = 1,
) -> bytes:
    blob = bytearray(c._FOOTER_SIZE)
    struct.pack_into("<IIII", blob, 0, 10, 0, 11, 3022)
    blob[16] = is_encrypted
    blob[17] = is_default
    struct.pack_into("<III", blob, 18, enc_major, enc_minor, len(verifier_ct))
    blob[30 : 30 + len(verifier_ct)] = verifier_ct
    blob[30 + len(verifier_ct) : 46 + len(verifier_ct)] = salt
    struct.pack_into("<I", blob, c._MAGIC_OFFSET, 0x12345678)
    return bytes(blob)


def test_derive_key_known_answer() -> None:
    salt = bytes(range(16))
    assert (
        c.derive_key("123456", salt).hex()
        == "0d3caf1d102f759d0b412e20894132dd4b057cf34b5a52080c36e9bd3aaa52e2"
    )


def test_short_password_is_padded_with_aaaa() -> None:
    salt = bytes(range(16))
    # A password under four characters is right-extended with "aaaa".
    assert c.derive_key("ab", salt) == c.derive_key("abaaaa", salt)


def test_default_passwords() -> None:
    assert c.default_password("1.1") == "Cellebrite 1.0 password"
    assert c.default_password("1.0") == "aaaa"
    # Unknown version falls back to the newest known.
    assert c.default_password("9.9") == "Cellebrite 1.0 password"


@pytest.mark.parametrize(
    "size",
    [0, 1, 15, 16, 17, 8191, 8192, 8193, 16384, 40960, 40976, 100003],
)
def test_decrypt_member_roundtrip(size: int) -> None:
    key = c.derive_key("pw", bytes(range(16)))
    name = "files/Image/a/b.png"
    plain = bytes((i * 7) % 256 for i in range(size))
    ct = _encrypt_member(key, name, plain)
    # Ciphertext grows by its PKCS#7 padding only: 1..16 bytes.
    assert 1 <= len(ct) - size <= 16
    assert c.decrypt_member(key, name, ct) == plain


def test_decrypting_reader_matches_whole_and_seeks() -> None:
    key = c.derive_key("pw", bytes(range(16)))
    name = "files/Database/x.db"
    plain = bytes((i * 13 + 5) % 256 for i in range(50000))
    ct = _encrypt_member(key, name, plain)
    reader = c.DecryptingReader(io.BytesIO(ct), key, name, len(ct))
    assert reader.read() == plain
    reader.seek(12345)
    assert reader.read(9000) == plain[12345:21345]
    reader.seek(-10, io.SEEK_END)
    assert reader.read() == plain[-10:]


def test_verify_key_accepts_right_and_rejects_wrong() -> None:
    salt = bytes(range(16))
    key = c.derive_key("Cellebrite 1.0 password", salt)
    verifier_ct = _encrypt_member(key, "UFDR footer unique path", c.VERIFIER_PLAINTEXT)
    footer = c.parse_footer(_pad_to_eocd(_footer(salt, verifier_ct)))
    assert footer is not None
    assert c.verify_key(key, footer) is True
    assert c.verify_key(c.derive_key("nope", salt), footer) is False


def _pad_to_eocd(footer_bytes: bytes) -> bytes:
    """Prepend a minimal empty-ZIP EOCD so parse_footer can locate the footer
    the same way it does in a real container."""
    eocd = b"PK\x05\x06" + b"\x00" * 18  # disk/entries/size/offset/comment-len all zero
    return eocd + footer_bytes


def test_parse_footer_reads_flags() -> None:
    salt = bytes(range(16, 32))
    verifier_ct = _encrypt_member(c.derive_key("x", salt), "UFDR footer unique path", c.VERIFIER_PLAINTEXT)
    data = _pad_to_eocd(_footer(salt, verifier_ct, is_encrypted=1, is_default=0))
    footer = c.parse_footer(data)
    assert footer is not None
    assert footer.is_encrypted is True
    assert footer.is_default_password is False
    assert footer.enc_version == "1.1"
    assert footer.salt == salt


def test_parse_footer_none_without_magic() -> None:
    # A plain ZIP EOCD with no encryption footer behind it.
    assert c.parse_footer(b"PK\x05\x06" + b"\x00" * 18) is None
