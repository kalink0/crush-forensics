# SPDX-License-Identifier: Apache-2.0
"""Realm database encryption (AES-256-CBC + HMAC-SHA224 per page).

Reference: Realm Core (github.com/realm/realm-core, Apache-2.0) —
src/realm/util/aes_cryptor.hpp and encrypted_file_mapping.cpp. The 64-byte
key is a raw key the app itself generates and stores (e.g. Keychain/
Keystore), not a password — there is no PBKDF2/KDF step here, unlike
Android backup or 7z passwords elsewhere in this codebase.

On-disk layout: logical (plaintext) data is split into 4096-byte pages.
Every 64 data pages are preceded by one 4096-byte metadata page holding 64
64-byte IVTable entries (one per following data page):
    iv1 (4B) | hmac1 (28B) | iv2 (4B) | hmac2 (28B)
— two generations per page for crash-safety across writes (cluster.cpp's
top_ref0/top_ref1 alternation is the same idea, one layer up). A block is
therefore (64 + 1) * 4096 = 266240 bytes: one metadata page + 64 data pages.

Per page: AES key = key[0:32], HMAC key = key[32:64] (confirmed from
AESCryptor::crypt's EVP_CipherInit_ex(..., m_key.data(), ...) and
calculate_hmac's Span(m_key).sub_span<32>() — i.e. key bytes [32:64), not
[0:32) as an earlier read of a summarized excerpt of this same function
briefly suggested; the actual sub_span<32>() call settles it). HMAC is
computed over the ciphertext only. The 16-byte CBC IV is stored_iv1 (4B) +
data_pos (8B, little-endian) + 4 zero bytes; padding is explicitly disabled
(EVP_CIPHER_CTX_set_padding(ctx, 0)) since every page is already an exact
multiple of the AES block size.

Generation selection on read (AESCryptor::attempt_read): compute the
page's HMAC and compare to hmac1; if it matches, decrypt with iv1. If not,
and it matches hmac2, decrypt with iv2 instead (a write landed mid-way
through updating generation 1). If neither matches: an all-zero page is
"never actually written" (StaleHmac in Realm's own terms) and decodes to
plaintext zeros, not an error; anything else is either the wrong key or
real corruption.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_mod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crush.core.issues import ParseIssue
from crush.core.passwords import WrongPasswordError

KEY_SIZE_BYTES = 64
_PAGE_SIZE = 4096
_IVTABLE_ENTRY_SIZE = 64
_PAGES_PER_BLOCK = _PAGE_SIZE // _IVTABLE_ENTRY_SIZE  # 64
_BLOCK_SIZE = (_PAGES_PER_BLOCK + 1) * _PAGE_SIZE  # 266240: 1 metadata page + 64 data pages


def _hmac_sha224(data: bytes, key: bytes) -> bytes:
    return _hmac_mod.new(key, data, hashlib.sha224).digest()


def _aes_cbc_decrypt_page(ciphertext: bytes, aes_key: bytes, iv1: int, data_pos: int) -> bytes:
    iv = iv1.to_bytes(4, "little") + data_pos.to_bytes(8, "little") + b"\x00" * 4
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def parse_hex_key(text: str) -> bytes:
    """Parse a user-supplied hex string into the raw 64-byte encryption key.

    Realm's key is a raw binary key an app generates itself (Keychain/
    Keystore), not a memorable password — examiners typically have it as a
    hex dump from an extraction tool, sometimes with separators (spaces,
    colons, a "0x" prefix) copied along from however the tool displayed it.
    """
    cleaned = text.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "").replace(":", "").replace("-", "")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise WrongPasswordError(ParseIssue("password.realm_not_hex", detail=str(exc))) from exc
    if len(key) != KEY_SIZE_BYTES:
        raise WrongPasswordError(ParseIssue("password.realm_key_length", {
            "size": KEY_SIZE_BYTES, "hex_chars": KEY_SIZE_BYTES * 2, "got": len(key),
        }))
    return key


def decrypt_realm_file(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt an encrypted .realm file's full contents into a plaintext
    buffer laid out exactly like an unencrypted .realm file, so every
    existing offset-based reader in realm_parser.py works unchanged.

    Raises WrongPasswordError if the key is the wrong length, or if a
    page's HMAC matches neither generation and the page isn't plausibly
    just a never-written all-zero page (i.e. genuinely wrong key or
    corruption a right key wouldn't produce).
    """
    if len(key) != KEY_SIZE_BYTES:
        raise WrongPasswordError(ParseIssue("password.realm_key_size", {"size": KEY_SIZE_BYTES}))
    aes_key, hmac_key = key[:32], key[32:64]

    out = bytearray()
    pos = 0  # physical (on-disk) read position
    data_pos = 0  # logical (plaintext) position, mirrors out's length
    total = len(encrypted)

    while pos + _PAGE_SIZE <= total:
        iv_table_raw = encrypted[pos : pos + _PAGE_SIZE]
        pos += _PAGE_SIZE

        for entry_idx in range(_PAGES_PER_BLOCK):
            if pos + _PAGE_SIZE > total:
                break
            off = entry_idx * _IVTABLE_ENTRY_SIZE
            iv1 = int.from_bytes(iv_table_raw[off : off + 4], "little")
            hmac1 = iv_table_raw[off + 4 : off + 32]
            iv2 = int.from_bytes(iv_table_raw[off + 32 : off + 36], "little")
            hmac2 = iv_table_raw[off + 36 : off + 64]

            if iv1 == 0:
                # Never written (IVTable entry still at its zero default) --
                # a real, sparse "no data here yet" state, not corruption.
                out += b"\x00" * _PAGE_SIZE
                pos += _PAGE_SIZE
                data_pos += _PAGE_SIZE
                continue

            ciphertext = encrypted[pos : pos + _PAGE_SIZE]
            pos += _PAGE_SIZE
            computed = _hmac_sha224(ciphertext, hmac_key)

            use_iv = iv1
            if not _hmac_mod.compare_digest(computed, hmac1):
                if iv2 != 0 and _hmac_mod.compare_digest(computed, hmac2):
                    use_iv = iv2
                elif not any(ciphertext):
                    out += b"\x00" * _PAGE_SIZE
                    data_pos += _PAGE_SIZE
                    continue
                else:
                    raise WrongPasswordError(ParseIssue("password.realm_hmac"))

            out += _aes_cbc_decrypt_page(ciphertext, aes_key, use_iv, data_pos)
            data_pos += _PAGE_SIZE

    return bytes(out)
