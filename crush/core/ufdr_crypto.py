# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Cellebrite UFDR file-level Protection (member payload encryption).

A protected UFDR is **not** a password-protected ZIP. The outer ZIP, its
central directory, the member names and the stored (uncompressed) sizes all
stay readable, and ZIP general-purpose bit 0 is not set. Only each member's
*payload bytes* are AES-256-CBC ciphertext, and a 256-byte encryption footer
sits immediately after the ZIP end-of-central-directory record describing how
to derive the key. Detection is therefore by that footer's structure, never by
the file name or the GP bit (see parse_footer).

Footer v1.1 (little-endian, from the first byte after the EOCD record and its
comment):

    0   uint32 x4  writer product version (informational)
    16  uint8      isEncrypted (0/1)
    17  uint8      isDefaultPassword (1 = built-in password, 0 = user password)
    18  int32      encryption-format major
    22  int32      encryption-format minor
    26  int32      verifier ciphertext length C (96 in samples)
    30  C bytes    AES-CBC ciphertext of the key-check plaintext
    30+C 16 bytes  PBKDF2 salt
    240 int32 x3   reserved
    252 uint32     magic 0x12345678

Key: PBKDF2-HMAC-SHA1(password, salt, 2184 rounds, 32 bytes). A password
shorter than four characters is right-extended with ``aaaa`` before PBKDF2.
The same 32-byte key encrypts every member and the footer verifier.

Per member, the CBC IV is derived, not stored. ``nonce8`` is the first eight
bytes of SHA-1 over the member name with ``/`` turned into ``\\``. The payload
is cut into 8192-byte chunks; chunk index ``c`` (counted from the member start)
uses ``IV = int64_le(c) || nonce8``. Every chunk but the last is decrypted
without padding; the last chunk (the one that contains the payload's final
byte) carries PKCS#7 padding. This matches the maintainer's reference reader,
which was verified against real protected samples (every member of a 23 GB
Android 14 export decrypting to its recorded content and MD5).

The verifier is decrypted as if it were a member named ``UFDR footer unique
path``; its plaintext must equal VERIFIER_PLAINTEXT, which is how a wrong
password is told from a correct one before any member is touched.

A separate, older scheme encrypts individual XML field values
(``EncryptedValue=`` / ``IsEncrypted="true"``) and is unrelated to the
Protection checkbox handled here; it is not implemented.
"""
from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Footer magic, at offset 252 of the 256-byte v1.1 record.
_MAGIC = 0x12345678
# The record this reader understands is 256 bytes; a signature blob may follow.
_FOOTER_SIZE = 256
# The reserved/magic block sits at a fixed offset regardless of verifier length
# (30 + C + 16 + (194 - C) == 240).
_MAGIC_OFFSET = 252
_CHUNK = 8192
_PBKDF2_ROUNDS = 2184
_KEY_LEN = 32
_EOCD_SIG = b"PK\x05\x06"

# The verifier's member name and its expected plaintext, both fixed by the
# writer. Decrypting the footer verifier to exactly this string is the
# password check.
_VERIFIER_NAME = "UFDR footer unique path"
VERIFIER_PLAINTEXT = (
    b"Cellebrite is a global company known for its "
    b"breakthroughs in mobile data technology"
)

# Built-in password per encryption-format version, used when the footer says
# the archive is protected without a user password (isDefaultPassword == 1).
_DEFAULT_PASSWORDS = {
    "1.1": "Cellebrite 1.0 password",
    "1.0": "aaaa",
}


@dataclass(frozen=True)
class EncryptionFooter:
    """The parsed UFDR encryption footer (one per container)."""

    is_encrypted: bool
    is_default_password: bool
    enc_version: str
    salt: bytes
    verifier: bytes
    product_version: tuple[int, int, int, int]


def parse_footer(tail: bytes) -> EncryptionFooter | None:
    """Parse the encryption footer from the container's trailing bytes, or
    None when there is no v1.1 footer (an older/plain UFDR). *tail* must
    cover from the EOCD record to the end of the file."""
    eocd = tail.rfind(_EOCD_SIG)
    if eocd < 0 or len(tail) < eocd + 22:
        return None
    comment_len = struct.unpack_from("<H", tail, eocd + 20)[0]
    start = eocd + 22 + comment_len
    blob = tail[start:]
    if len(blob) < _FOOTER_SIZE:
        return None
    if struct.unpack_from("<I", blob, _MAGIC_OFFSET)[0] != _MAGIC:
        return None
    product = struct.unpack_from("<IIII", blob, 0)
    is_enc = blob[16]
    is_def = blob[17]
    enc_maj, enc_min, const_len = struct.unpack_from("<III", blob, 18)
    if const_len > 194:
        return None
    verifier = blob[30 : 30 + const_len]
    salt = blob[30 + const_len : 46 + const_len]
    return EncryptionFooter(
        is_encrypted=bool(is_enc),
        is_default_password=bool(is_def),
        enc_version=f"{enc_maj}.{enc_min}",
        salt=salt,
        verifier=verifier,
        product_version=(product[0], product[1], product[2], product[3]),
    )


def read_footer(path: str | Path) -> EncryptionFooter | None:
    """Read and parse the encryption footer of the UFDR at *path*, or None
    when it has none. Reads only the file's tail, never the whole archive."""
    p = Path(path)
    size = p.stat().st_size
    span = min(size, 1 << 20)
    with p.open("rb") as fh:
        fh.seek(size - span)
        tail = fh.read(span)
    return parse_footer(tail)


def default_password(enc_version: str) -> str:
    """The built-in password for a protected-without-user-password archive of
    this encryption version (falls back to the 1.1 password for an unknown
    version, the newest format this reader knows)."""
    return _DEFAULT_PASSWORDS.get(enc_version, _DEFAULT_PASSWORDS["1.1"])


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the AES-256 key from *password* and the footer *salt*."""
    if len(password) < 4:
        password = password + "aaaa"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(), length=_KEY_LEN, salt=salt, iterations=_PBKDF2_ROUNDS
    )
    return kdf.derive(password.encode("utf-8"))


def verify_key(key: bytes, footer: EncryptionFooter) -> bool:
    """True when *key* decrypts the footer verifier to the expected plaintext
    -- i.e. the password behind *key* is the right one."""
    try:
        plain = decrypt_member(key, _VERIFIER_NAME, footer.verifier)
    except ValueError:
        return False
    return plain == VERIFIER_PLAINTEXT


def _nonce8(member_name: str) -> bytes:
    return hashlib.sha1(member_name.replace("/", "\\").encode("utf-8")).digest()[:8]


def _decrypt_chunk(key: bytes, nonce8: bytes, index: int, data: bytes, last: bool) -> bytes:
    iv = struct.pack("<q", index) + nonce8
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = dec.update(data) + dec.finalize()
    if last:
        unpadder = padding.PKCS7(128).unpadder()
        out = unpadder.update(out) + unpadder.finalize()
    return out


def decrypt_member(key: bytes, member_name: str, ciphertext: bytes) -> bytes:
    """Decrypt a whole member payload. The member name sets the IV nonce, so
    it must be the exact ZIP entry name (``/`` is normalised internally)."""
    nonce8 = _nonce8(member_name)
    n = len(ciphertext)
    if n == 0:
        return b""
    last_index = (n - 1) // _CHUNK
    out = bytearray()
    for index in range(last_index + 1):
        chunk = ciphertext[index * _CHUNK : (index + 1) * _CHUNK]
        out.extend(_decrypt_chunk(key, nonce8, index, chunk, index == last_index))
    return bytes(out)


class DecryptingReader(io.RawIOBase):
    """A seekable, read-only plaintext view over one encrypted member.

    Wraps the member's raw (ciphertext) ZIP stream, which for a UFDR is stored
    uncompressed and therefore seekable. Only the chunks a read touches are
    decrypted, so a hex/strings viewer can seek into a multi-GB member without
    decrypting the whole thing or holding it in memory. Not thread-safe on its
    own; the VFS serialises access through LockedStream, exactly as for a plain
    member stream.
    """

    def __init__(self, raw: Any, key: bytes, member_name: str, cipher_size: int) -> None:
        super().__init__()
        self._raw = raw
        self._key = key
        self._nonce8 = _nonce8(member_name)
        self._cipher_size = cipher_size
        self._last_index = (cipher_size - 1) // _CHUNK if cipher_size else 0
        # The last ciphertext chunk carries PKCS#7 padding, so the plaintext
        # size is learnt from it -- from the real bytes, not a recorded size.
        self._last_plain = self._decrypt_index(self._last_index) if cipher_size else b""
        self._plain_size = self._last_index * _CHUNK + len(self._last_plain)
        self._pos = 0

    def _decrypt_index(self, index: int) -> bytes:
        self._raw.seek(index * _CHUNK)
        data = self._raw.read(_CHUNK)
        return _decrypt_chunk(self._key, self._nonce8, index, data, index == self._last_index)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._plain_size + offset
        else:  # pragma: no cover - io contract
            raise ValueError(f"invalid whence: {whence}")
        self._pos = max(0, self._pos)
        return self._pos

    def readinto(self, b: Any) -> int:
        want = len(b)
        if want == 0 or self._pos >= self._plain_size:
            return 0
        end = min(self._pos + want, self._plain_size)
        out = bytearray()
        pos = self._pos
        while pos < end:
            index = pos // _CHUNK
            plain = self._last_plain if index == self._last_index else self._decrypt_index(index)
            within = pos % _CHUNK
            take = min(len(plain) - within, end - pos)
            out.extend(plain[within : within + take])
            pos += take
        b[: len(out)] = out
        self._pos = pos
        return len(out)

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            finally:
                super().close()
