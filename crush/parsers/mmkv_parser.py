# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""MMKV key-value store parser (wraps vendored crush/third_party/mmkv_parser, MIT).

Explicit-only: MMKV has no magic bytes to auto-detect from, so this parser is
never picked up during type indexing — reachable only via the filesystem
panel's "Open as" -> MMKV / MMKV (Encrypted)... actions, same as Protobuf.

The vendored reader operates on real filesystem paths (it opens the file and
its ".crc" companion directly), not in-memory bytes, so this wrapper writes
both to a temp directory before calling it and cleans up afterward — the same
pattern SQLiteParser already uses for its -wal/-shm companions, for the same
reason (the underlying library needs a real path).
"""
from __future__ import annotations

import os
import struct
import tempfile
from typing import Any, cast

from crush.core.passwords import WrongPasswordError
from crush.core.vfs import VFS, VFSNode, find_sibling
from crush.parsers.base import AbstractParser, ParseResult
from crush.third_party.mmkv_parser import MMKVError, decode_value, read_entries
from crush.third_party.mmkv_parser.mmkv_parser import (
    _HEADER_LENGTH,
    _read_varint,
    _region_size,
    _walk,
)

# MMKVMetaInfo (.crc file) layout, independently verified against Tencent/MMKV's
# MMKVMetaInfo.hpp: crc u32, version u32, sequence u32, aesVector[16], actualSize u32.
_META_MIN_LEN = 28   # crc + version + sequence + vector — enough to detect encryption
_META_FULL_LEN = 32  # + actualSize
_META_VECTOR = slice(12, 28)
_META_VERSION_ACTUAL_SIZE = 3  # from this meta version, actualSize is meaningful


def _read_meta_info(crc_bytes: bytes | None) -> dict[str, Any] | None:
    """Decode the fixed-offset MMKVMetaInfo fields directly.

    This does not call the vendored reader's own (private) meta parsing — these
    are all fixed-offset struct fields with no variable-width tricks involved,
    so re-reading them here is low-risk and keeps this wrapper decoupled from
    the vendored module's internals.
    """
    if crc_bytes is None or len(crc_bytes) < _META_MIN_LEN:
        return None
    crc, version, sequence = struct.unpack_from("<III", crc_bytes, 0)
    vector = crc_bytes[_META_VECTOR]
    actual_size = (
        struct.unpack_from("<I", crc_bytes, 28)[0] if len(crc_bytes) >= _META_FULL_LEN else None
    )
    return {
        "crc": crc,
        "version": version,
        "sequence": sequence,
        "encrypted": any(vector),
        "actual_size": actual_size if version >= _META_VERSION_ACTUAL_SIZE else None,
    }


def _try_plain_walk(raw: bytes) -> list[tuple[str, bytes]] | None:
    """Attempt to read *raw* as an unencrypted MMKV store, ignoring the .crc
    meta file's encryption flag entirely.

    The .crc file's "non-zero vector means AES-encrypted" heuristic is only
    as good as the MMKVMetaInfo layout it's read against — seen false-
    positive in the field on a real react-native-mmkv store whose meta
    "version" field was far higher than anything this layout has been
    verified against (61, vs. the 1-4 range the known struct evolution
    covers), producing a non-zero vector for a demonstrably plaintext store.
    Rather than trust the flag blindly, confirm it: a genuinely encrypted
    store fed through here as if it weren't will, per read_entries()'s own
    documented invariant, either yield nothing or leave a tail unread.
    """
    if len(raw) < _HEADER_LENGTH:
        return None
    region_size = _region_size(raw, None)  # type: ignore[no-untyped-call]
    if region_size == 0 or _HEADER_LENGTH + region_size > len(raw):
        return None
    region = raw[_HEADER_LENGTH:_HEADER_LENGTH + region_size]
    entries, unread = _walk(region)  # type: ignore[no-untyped-call]
    if not entries or unread:
        return None
    return cast(list[tuple[str, bytes]], entries)


_TYPE_LABELS: dict[type, str] = {str: "string", int: "int", bytes: "bytes"}


def _content_bytes(container: bytes) -> bytes:
    """Return the value's own bytes, with MMKV's internal string length-prefix
    varint removed when the container has that shape — a length-prefix is not
    part of the value, it's MMKV's own on-disk way of telling a string value
    apart from a bare scalar varint (untyped on disk otherwise). Left in, it
    breaks anything that tries to actually use the bytes (e.g. a value that's
    JSON text no longer parses as JSON with a stray leading byte).

    This is deliberately kept as a *separate* field from the entry's own
    "raw" — raw must always stay the complete, untouched value container
    (nothing is ever removed from it); this stripped form exists only for
    "Inspect Value", where inspecting the value itself — not MMKV's on-disk
    framing around it — is the whole point.

    Mirrors decode_value()'s own shape check exactly (read a varint at offset
    0, string-shaped iff it exactly accounts for the rest of the container),
    so this always agrees with whatever decode_value() decided — a bare
    scalar's container is returned unchanged, since it has no such prefix.
    """
    if not container:
        return container
    try:
        length, offset = _read_varint(container, 0)  # type: ignore[no-untyped-call]
    except MMKVError:
        return container
    if offset + length == len(container):
        return container[offset:offset + length]
    return container


def _classify_entries(entries: list[tuple[str, bytes]]) -> list[dict[str, Any]]:
    """Tag every entry, in file order, as Live / Superseded / Removed.

    MMKV is append-only between rewrites: setting a key appends a new entry
    rather than editing the old one, and the last occurrence of a key is the
    one the app reads. A zero-length value container marks a removal, not an
    empty value — read_entries() already keeps every occurrence in file order,
    so classifying them is just tracking each key's last index.
    """
    last_index: dict[str, int] = {}
    for i, (key, _container) in enumerate(entries):
        last_index[key] = i

    records: list[dict[str, Any]] = []
    for i, (key, container) in enumerate(entries):
        if i == last_index[key]:
            state = "Removed" if not container else "Live"
        else:
            state = "Superseded"
        decoded = decode_value(container)  # type: ignore[no-untyped-call]
        records.append({
            "index": i,
            "key": key,
            "state": state,
            "type": _TYPE_LABELS.get(type(decoded), "empty"),
            "decoded": decoded,
            "raw": container,  # complete, untouched value container — never stripped
            "value_bytes": _content_bytes(container),  # for Inspect Value only
        })
    return records


class MMKVParser(AbstractParser):
    """Tencent MMKV key-value store — same family as the LevelDB viewer.

    Reference: https://github.com/abrignoni/mmkv-parser (MIT), format verified
    independently against Tencent/MMKV's own source (see CHANGELOG).
    """

    DISPLAY_NAME = "MMKV Key-Value Store"
    SUPPORTED_EXTENSIONS: list[str] = []
    SUPPORTS_PASSWORD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False  # Explicit-only — see module docstring.

    def parse(
        self,
        node: VFSNode,
        vfs: VFS,
        password: str | bytes | None = None,
        aes256: bool = False,
    ) -> ParseResult:
        raw = vfs.read(node)
        crc_bytes: bytes | None = None
        sibling = find_sibling(node, vfs, ".crc")
        if sibling is not None:
            try:
                crc_bytes = vfs.read(sibling)
            except Exception:
                crc_bytes = None

        meta_info = _read_meta_info(crc_bytes)
        meta_flagged_encrypted = meta_info is not None and meta_info["encrypted"]
        false_positive_encrypted_flag = False

        if meta_flagged_encrypted and password is None:
            plain_entries = _try_plain_walk(raw)
            if plain_entries is None:
                return ParseResult(
                    viewer_type="tree",
                    data={
                        "error": "This MMKV store is AES-encrypted.",
                        "hint": 'Use "Open as -> MMKV (Encrypted)..." and supply the key.',
                    },
                    metadata={
                        "Format": "MMKV Key-Value Store (encrypted)",
                        "File size": f"{node.size:,} B",
                        "Encrypted": "yes",
                    },
                )
            # The .crc file's vector-nonzero flag said "encrypted", but the
            # store just read cleanly as plaintext -- trust the successful
            # read over the flag, and say so explicitly rather than silently
            # overriding it.
            entries = plain_entries
            false_positive_encrypted_flag = True
        else:
            tmp_dir = tempfile.mkdtemp(prefix="crush_mmkv_")
            tmp_path = os.path.join(tmp_dir, node.name)
            try:
                with open(tmp_path, "wb") as f:
                    f.write(raw)
                if crc_bytes is not None:
                    with open(tmp_path + ".crc", "wb") as f:
                        f.write(crc_bytes)
                try:
                    entries = read_entries(  # type: ignore[no-untyped-call]
                        tmp_path, key=password, aes256=aes256
                    )
                except MMKVError as exc:
                    msg = str(exc)
                    if password is not None and "did not decrypt" in msg:
                        raise WrongPasswordError(msg) from exc
                    return ParseResult(
                        viewer_type="tree",
                        data={"error": msg, "hint": "MMKV store could not be read"},
                        metadata={
                            "Format": "MMKV Key-Value Store (parse failed)",
                            "File size": f"{node.size:,} B",
                            "Parse error": msg,
                        },
                    )
            finally:
                for p in (tmp_path, tmp_path + ".crc"):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                try:
                    os.rmdir(tmp_dir)
                except OSError:
                    pass

        records = _classify_entries(entries)
        live = sum(1 for r in records if r["state"] == "Live")
        superseded = sum(1 for r in records if r["state"] == "Superseded")
        removed = sum(1 for r in records if r["state"] == "Removed")

        meta: dict[str, Any] = {
            "Format": "MMKV Key-Value Store",
            "File size": f"{node.size:,} B",
            "Entries": f"{len(records):,}",
            "Live": f"{live:,}",
            "Superseded": f"{superseded:,}",
            "Removed": f"{removed:,}",
        }
        if meta_info is not None:
            meta["Meta version"] = str(meta_info["version"])
            meta["Sequence"] = str(meta_info["sequence"])
        else:
            # No sibling .crc file — encryption status and the recorded region
            # size (vs. the header's own copy) could not be cross-checked.
            meta["Meta file"] = "not found (.crc companion missing) — encryption status unverified"
        if password is not None:
            meta["Encrypted"] = "yes (decrypted)"
        elif false_positive_encrypted_flag:
            meta["Encrypted"] = (
                "no — .crc meta file's vector field is non-zero, which normally "
                "flags AES encryption, but the store read cleanly as plaintext "
                "anyway, so that flag is treated as a false positive here"
            )

        text_parts: list[str] = []
        for r in records:
            text_parts.append(r["key"])
            if isinstance(r["decoded"], str):
                text_parts.append(r["decoded"][:256])
            if len(text_parts) >= 2000:
                break

        return ParseResult(
            viewer_type="mmkv",
            data={"records": records, "meta_info": meta_info},
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )
