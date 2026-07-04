# SPDX-License-Identifier: Apache-2.0
"""Apple iOS backup KeyBag: unwraps keys needed to decrypt Manifest.db and,
for password-protected backups, individual file contents.

Since iOS 10.2, `Manifest.db` inside an iTunes/Finder backup is always AES
encrypted, regardless of whether the user set a backup password. The wrapping
key comes from the backup's KeyBag (`BackupKeyBag` in `Manifest.plist`), which
is itself unlocked with a key derived from the backup password (an empty
string for backups without a password — the same derivation, just no secret).
When a backup password IS set (`IsEncrypted=True`), individual files are
additionally encrypted with their own per-file key, wrapped under one of the
KeyBag's protection classes (`Files.file`'s `ProtectionClass`/`EncryptionKey`,
an NSKeyedArchiver blob).

Reference: `python_scripts/keystore/keybag.py` and
`python_scripts/backups/backup10.py` in github.com/dinosec/iphone-dataprotection
(verified against that source, and against a real password-protected iOS 14.3
sample). Only the backup-keybag, passcode-unlock path is implemented here —
system/escrow keybags, Curve25519 class keys, HMAC signature checks and the
device-key path are on-device-keybag concerns that don't apply to backups.
"""
from __future__ import annotations

import hashlib
import struct
from io import BytesIO
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

from crush.core.passwords import WrongPasswordError
from crush.third_party.ccl_bplist import (
    NSKeyedArchiver_common_objects_convertor,
    deserialise_NsKeyedArchiver,
    load as bplist_load,
    set_object_converter,
)

_WRAP_PASSCODE = 2
_CLASSKEY_TAGS = {"CLAS", "WRAP", "WPKY", "KTYP"}

_TlvValue = bytes | int
_TlvAttrs = dict[str, _TlvValue]


def _parse_tlv(data: bytes) -> list[tuple[str, _TlvValue]]:
    """Split a KeyBag TLV blob into (tag, value) pairs.

    4-byte values are auto-converted to a big-endian uint32, matching the
    reference implementation (TYPE/CLAS/WRAP/KTYP/ITER/DPIC are all 4 bytes).
    """
    entries: list[tuple[str, _TlvValue]] = []
    offset = 0
    while offset < len(data):
        tag = data[offset:offset + 4].decode("ascii")
        length = struct.unpack(">I", data[offset + 4:offset + 8])[0]
        raw_value = data[offset + 8:offset + 8 + length]
        value: _TlvValue = struct.unpack(">I", raw_value)[0] if length == 4 else raw_value
        entries.append((tag, value))
        offset += 8 + length
    return entries


def _parse_backup_keybag(data: bytes) -> tuple[_TlvAttrs, dict[int, _TlvAttrs]]:
    """Parse a BackupKeyBag blob into header attrs and per-class-key dicts.

    The first UUID/WRAP tags belong to the keybag header; every later UUID
    tag starts a new class-key group (CLAS/WRAP/KTYP/WPKY), keyed by class
    number (masked to the low nibble, as the reference does).
    """
    attrs: _TlvAttrs = {}
    class_keys: dict[int, _TlvAttrs] = {}
    current: _TlvAttrs | None = None
    seen_uuid = False
    seen_wrap = False

    for tag, value in _parse_tlv(data):
        if tag == "UUID" and not seen_uuid:
            seen_uuid = True
            attrs["UUID"] = value
        elif tag == "WRAP" and not seen_wrap:
            seen_wrap = True
            attrs["WRAP"] = value
        elif tag == "UUID":
            if current is not None:
                class_keys[cast(int, current["CLAS"]) & 0xF] = current
            current = {"UUID": value}
        elif tag in _CLASSKEY_TAGS and current is not None:
            current[tag] = value
        else:
            attrs[tag] = value
    if current is not None:
        class_keys[cast(int, current["CLAS"]) & 0xF] = current
    return attrs, class_keys


def _pbkdf2(password: bytes, salt: bytes, iterations: int, digest: str) -> bytes:
    return hashlib.pbkdf2_hmac(digest, password, salt, iterations, dklen=32)


def _derive_passcode_key(attrs: _TlvAttrs, password: str) -> bytes:
    passcode_key = password.encode("utf-8")
    if "DPSL" in attrs and "DPIC" in attrs:
        # Extra round introduced in iOS 10.2. DPIC is commonly ~10 million on
        # real backups (~1s), so the caller must derive this at most once per
        # backup, never per file — see BackupKeyBag below.
        passcode_key = _pbkdf2(
            passcode_key, cast(bytes, attrs["DPSL"]), cast(int, attrs["DPIC"]), "sha256"
        )
    return _pbkdf2(passcode_key, cast(bytes, attrs["SALT"]), cast(int, attrs["ITER"]), "sha1")


def aes_cbc_decrypt_and_unpad(key: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC decrypt with a zero IV and strip PKCS7 padding — the scheme
    used for both Manifest.db and individual file contents."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded[-1] if padded else 0
    if pad_len < 1 or pad_len > 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise WrongPasswordError("Padding invalid after decryption (wrong password?)")
    return padded[:-pad_len]


def _nsdata_converter(obj: object) -> object:
    result = cast(Any, NSKeyedArchiver_common_objects_convertor)(obj)
    if result is not obj or not isinstance(obj, dict):
        return result
    class_meta = obj.get("$class")
    classname = class_meta.get("$classname", "") if isinstance(class_meta, dict) else ""
    if classname in ("NSData", "NSMutableData"):
        return obj.get("NS.data", b"")
    return result


def extract_file_protection(file_blob: bytes) -> tuple[int, bytes] | None:
    """Parse a `Files.file` NSKeyedArchiver blob for (ProtectionClass, EncryptionKey).

    Returns None if the file has no per-file encryption key (most files in a
    backup without a password — `IsEncrypted=False` never encrypts file
    contents, only Manifest.db).
    """
    cast(Any, set_object_converter)(_nsdata_converter)
    metadata = cast(Any, deserialise_NsKeyedArchiver)(cast(Any, bplist_load)(BytesIO(file_blob)))
    encryption_key = metadata.get("EncryptionKey") if isinstance(metadata, dict) else None
    if not isinstance(encryption_key, (bytes, bytearray)):
        return None
    return int(metadata.get("ProtectionClass", 0)), bytes(encryption_key)


class BackupKeyBag:
    """A parsed, password-unlocked backup KeyBag.

    Parsing the TLV and deriving the passcode key (PBKDF2, possibly ~10
    million iterations on a real backup, ~1s) happens once per instance.
    Unwrapping a given protection class's key is cached too, since a
    backup's files typically only use a handful of distinct classes.
    """

    def __init__(self, backup_keybag: bytes, password: str) -> None:
        self._attrs, self._class_keys = _parse_backup_keybag(backup_keybag)
        self._passcode_key = _derive_passcode_key(self._attrs, password)
        self._unwrapped_classes: dict[int, bytes] = {}

    def _class_key(self, class_num: int) -> bytes:
        class_num &= 0xF
        if class_num not in self._unwrapped_classes:
            entry = self._class_keys.get(class_num)
            if (
                entry is None
                or "WPKY" not in entry
                or not (cast(int, entry.get("WRAP", 0)) & _WRAP_PASSCODE)
            ):
                raise WrongPasswordError(
                    f"Backup keybag has no usable class key for class {class_num}"
                )
            try:
                self._unwrapped_classes[class_num] = aes_key_unwrap(
                    self._passcode_key, cast(bytes, entry["WPKY"])
                )
            except InvalidUnwrap as exc:
                raise WrongPasswordError("Incorrect backup password") from exc
        return self._unwrapped_classes[class_num]

    def _unwrap(self, class_num: int, wrapped_key: bytes) -> bytes:
        try:
            return aes_key_unwrap(self._class_key(class_num), wrapped_key)
        except InvalidUnwrap as exc:
            raise WrongPasswordError("Incorrect backup password") from exc

    def unwrap_manifest_key(self, manifest_key_entry: bytes) -> bytes:
        """`ManifestKey` = 4-byte little-endian class number + 40-byte wrapped key."""
        manifest_class = struct.unpack("<I", manifest_key_entry[:4])[0]
        return self._unwrap(manifest_class, manifest_key_entry[4:])

    def unwrap_file_key(self, protection_class: int, encryption_key_entry: bytes) -> bytes:
        """`EncryptionKey` = 4-byte little-endian class number (ignored — the
        file's own `ProtectionClass` metadata field is authoritative, matching
        the reference implementation) + 40-byte wrapped key."""
        return self._unwrap(protection_class, encryption_key_entry[4:])
