# SPDX-License-Identifier: Apache-2.0
"""Android `adb backup` (.ab) encryption: unwraps the master key needed to
decrypt the tar payload.

An encrypted .ab has a "master key" that's random per backup and actually
decrypts the payload, itself wrapped under a "user key" derived from the
backup password via PBKDF2 — so the password never touches the payload
cipher directly. A checksum of the master key (a second PBKDF2 run over the
key bytes themselves) lets the password be verified without decrypting the
(potentially large) payload first.

Reference: org.nick.abe.AndroidBackup in the Android Backup Extractor (ABE,
github.com/nelenkov/android-backup-extractor — already linked from this
format's entry in build_formats_db.py), itself derived from AOSP's
BackupManagerService. Verified against that source, including the
historical Android version quirk where the master-key-checksum step encodes
the key bytes as ASCII on some versions and UTF-8 on others (KitKat) — ABE
tries both, so this does too. The read/decrypt path only; backup creation
is out of scope.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crush.core.passwords import WrongPasswordError

_KEY_SIZE_BYTES = 32  # 256-bit keys throughout (user key, master key, checksum)


def _pbkdf2(password_bytes: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password_bytes, salt, rounds, dklen=_KEY_SIZE_BYTES)


def _password_to_bytes(password: str) -> bytes:
    """Mirrors BouncyCastle's PBEParametersGenerator.PKCS5PasswordToBytes:
    each char truncated to its low 8 bits (not UTF-8) — what Android's own
    user-password-to-key derivation always uses, regardless of backup version."""
    return bytes(ord(c) & 0xFF for c in password)


def _bytes_to_java_chars(data: bytes) -> str:
    """Mirrors `(char) someByte` in Java: the byte is sign-extended to an int
    then truncated to an unsigned 16-bit char, so bytes >= 0x80 become
    0xFF80-0xFFFF rather than their own value. Needed to reproduce the
    master-key-checksum step exactly."""
    chars = []
    for b in data:
        signed = b if b < 128 else b - 256
        chars.append(signed & 0xFFFF)
    return "".join(chr(c) for c in chars)


def _key_checksum(master_key: bytes, salt: bytes, rounds: int, use_utf8: bool) -> bytes:
    chars = _bytes_to_java_chars(master_key)
    pw_bytes = chars.encode("utf-8") if use_utf8 else bytes(ord(c) & 0xFF for c in chars)
    return _pbkdf2(pw_bytes, salt, rounds)


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1] if data else 0
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise WrongPasswordError("Payload padding invalid after decryption (wrong password?)")
    return data[:-pad_len]


def unwrap_master_key(
    password: str,
    user_salt: bytes,
    checksum_salt: bytes,
    rounds: int,
    user_iv: bytes,
    master_key_blob: bytes,
    version: int,
) -> tuple[bytes, bytes]:
    """Decrypt the master-key blob and verify it against its checksum.

    Returns (master_key, master_iv) for decrypting the payload. Raises
    WrongPasswordError if the password doesn't check out (tried both known
    master-key-checksum encodings, matching ABE's fallback behaviour).
    """
    user_key = _pbkdf2(_password_to_bytes(password), user_salt, rounds)
    try:
        mk_blob = _aes_cbc_decrypt(user_key, user_iv, master_key_blob)
        offset = 0
        iv_len = mk_blob[offset]
        offset += 1
        master_iv = mk_blob[offset:offset + iv_len]
        offset += iv_len
        mk_len = mk_blob[offset]
        offset += 1
        master_key = mk_blob[offset:offset + mk_len]
        offset += mk_len
        ck_len = mk_blob[offset]
        offset += 1
        checksum = mk_blob[offset:offset + ck_len]
    except (IndexError, ValueError) as exc:
        raise WrongPasswordError("Incorrect Android backup password") from exc

    use_utf8 = version >= 2
    if _key_checksum(master_key, checksum_salt, rounds, use_utf8) != checksum:
        use_utf8 = not use_utf8
        if _key_checksum(master_key, checksum_salt, rounds, use_utf8) != checksum:
            raise WrongPasswordError("Incorrect Android backup password")
    return master_key, master_iv


def decrypt_payload(master_key: bytes, master_iv: bytes, ciphertext: bytes) -> bytes:
    return _unpad_pkcs7(_aes_cbc_decrypt(master_key, master_iv, ciphertext))
