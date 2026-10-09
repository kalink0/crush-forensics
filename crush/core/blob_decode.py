# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Strict byte→byte decoders for the BLOB Inspector's decode pipeline — no Qt.

Every decoder either returns all of its input's meaning or raises
:class:`DecodeError` with the reason. Nothing is dropped silently: input
characters outside the encoding's alphabet are an error, and bytes after the
end of a compressed stream are reported in :attr:`Decoded.trailing_offset` /
:attr:`Decoded.trailing_size` instead of being discarded.
"""
from __future__ import annotations

import base64
import binascii
import struct
import zlib
from dataclasses import dataclass


class DecodeError(ValueError):
    """The input is not valid for the decoder; ``str()`` is the reason."""


@dataclass(frozen=True)
class Decoded:
    data: bytes
    # Bytes of the input after the end of the decoded stream, not decoded.
    trailing_offset: int | None = None
    trailing_size: int = 0
    # Why decoding stopped before the trailing bytes, when it wasn't the
    # end of the stream (e.g. a following gzip member that doesn't decode).
    trailing_reason: str = ""
    # LZFSE only: the stream has no end-of-stream block (bvx$).
    end_marker_missing: bool = False


def _char(b: int) -> str:
    shown = chr(b) if 0x20 <= b < 0x7F else ""
    return f"0x{b:02x} ({shown!r})" if shown else f"0x{b:02x}"


# Line breaks are layout (MIME wraps Base64 at 76 characters), not data.
_LINE_BREAKS = b"\r\n"
_B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def _strict_b64(data: bytes, extra: bytes) -> bytes:
    """Base64 with the alphabet's two extra characters *extra* (``+/`` or ``-_``).

    Line breaks are ignored; any other character outside the alphabet, data
    after padding, or a length no Base64 text can have is an error. Missing
    padding is restored (it carries no data)."""
    alphabet = _B64_ALPHABET | frozenset(extra)
    body = bytearray()
    padding = 0
    for offset, b in enumerate(data):
        if b in _LINE_BREAKS:
            continue
        if b == 0x3D:  # "="
            padding += 1
            if padding > 2:
                raise DecodeError(f"more than two padding characters (offset {offset})")
            continue
        if padding:
            raise DecodeError(f"data after padding at offset {offset}")
        if b not in alphabet:
            raise DecodeError(f"invalid character {_char(b)} at offset {offset}")
        body.append(b)
    if len(body) % 4 == 1:
        raise DecodeError(
            f"{len(body)} Base64 characters: one character left over, which no data encodes to"
        )
    needed = -len(body) % 4
    if padding and padding != needed:
        raise DecodeError(f"{padding} padding character(s) where {needed} belong")
    try:
        return base64.b64decode(bytes(body) + b"=" * needed, altchars=extra, validate=True)
    except binascii.Error as exc:  # pragma: no cover -- checked above
        raise DecodeError(str(exc)) from exc


def decode_base64(data: bytes) -> Decoded:
    """Standard Base64 (``+``/``/``)."""
    return Decoded(_strict_b64(data, b"+/"))


def decode_base64url(data: bytes) -> Decoded:
    """URL-safe Base64 (``-``/``_``); padding optional."""
    return Decoded(_strict_b64(data, b"-_"))


# Separators between hex digits: whitespace, ":" (MAC-address / hexdump
# style), "_" and "-".
HEX_SEPARATORS = frozenset(b" \t\r\n\v\f:_-")
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


def decode_hex(data: bytes) -> Decoded:
    """Hex digits with any of :data:`HEX_SEPARATORS` between them."""
    digits = bytearray()
    for offset, b in enumerate(data):
        if b in HEX_SEPARATORS:
            continue
        if b not in _HEX_DIGITS:
            raise DecodeError(f"invalid character {_char(b)} at offset {offset}")
        digits.append(b)
    if len(digits) % 2:
        raise DecodeError(f"odd number of hex digits ({len(digits):,})")
    return Decoded(bytes.fromhex(digits.decode("ascii")))


def _inflate(data: bytes, wbits: int) -> tuple[bytes, int]:
    """One zlib/gzip stream from the start of *data*: (output, bytes consumed)."""
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data)
    except zlib.error as exc:
        raise DecodeError(str(exc)) from exc
    if not d.eof:
        raise DecodeError("incomplete or truncated stream")
    return out, len(data) - len(d.unused_data)


def _with_trailing(out: bytes, data: bytes, end: int, reason: str = "") -> Decoded:
    if end >= len(data):
        return Decoded(out)
    return Decoded(out, trailing_offset=end, trailing_size=len(data) - end, trailing_reason=reason)


def decompress_zlib(data: bytes) -> Decoded:
    """A zlib stream (RFC 1950)."""
    out, end = _inflate(data, zlib.MAX_WBITS)
    return _with_trailing(out, data, end)


_GZIP_MAGIC = b"\x1f\x8b"


def decompress_gzip(data: bytes) -> Decoded:
    """gzip (RFC 1952): every member, concatenated, as gzip itself does."""
    out, end = _inflate(data, 16 + zlib.MAX_WBITS)
    parts = [out]
    member = 1
    reason = ""
    while end < len(data) and data[end:end + 2] == _GZIP_MAGIC:
        member += 1
        try:
            out, used = _inflate(data[end:], 16 + zlib.MAX_WBITS)
        except DecodeError as exc:
            reason = f"member {member}: {exc}"
            break
        parts.append(out)
        end += used
    return _with_trailing(b"".join(parts), data, end, reason)


# LZFSE block magics (lzfse_internal.h).
_LZFSE_END = b"bvx$"
_LZFSE_RAW = b"bvx-"
_LZFSE_V1 = b"bvx1"
_LZFSE_V2 = b"bvx2"
_LZFSE_LZVN = b"bvxn"
# sizeof(lzfse_compressed_block_header_v1): 7 uint32 + int32 literal_bits +
# 4 uint16 literal_state + int32 lmd_bits + 3 uint16 states + uint16
# l/m/d/literal freq[20 + 20 + 64 + 256], padded to the struct's 4-byte
# alignment.
_LZFSE_V1_HEADER_SIZE = 772


def _lzfse_stream_end(data: bytes) -> tuple[int, bool]:
    """Offset after the LZFSE stream's last block, from the block headers
    (lzfse_internal.h), and whether that block is the end-of-stream block.
    Called on data liblzfse decoded, so the headers are valid."""
    pos = 0
    while pos + 4 <= len(data):
        magic = data[pos:pos + 4]
        if magic == _LZFSE_END:
            return pos + 4, True
        if magic == _LZFSE_RAW and pos + 8 <= len(data):
            (n_raw,) = struct.unpack_from("<I", data, pos + 4)
            pos += 8 + n_raw
        elif magic == _LZFSE_LZVN and pos + 12 <= len(data):
            (n_payload,) = struct.unpack_from("<I", data, pos + 8)
            pos += 12 + n_payload
        elif magic == _LZFSE_V1 and pos + 28 <= len(data):
            n_lit, n_lmd = struct.unpack_from("<II", data, pos + 20)
            pos += _LZFSE_V1_HEADER_SIZE + n_lit + n_lmd
        elif magic == _LZFSE_V2 and pos + 32 <= len(data):
            f0, f1, f2 = struct.unpack_from("<QQQ", data, pos + 8)
            header_size = f2 & 0xFFFFFFFF
            n_lit = (f0 >> 20) & 0xFFFFF
            n_lmd = (f1 >> 40) & 0xFFFFF
            pos += header_size + n_lit + n_lmd
        else:
            break
    return min(pos, len(data)), False


def decompress_lzfse(data: bytes) -> Decoded:
    """Apple LZFSE (also LZVN and uncompressed blocks)."""
    try:
        import liblzfse  # type: ignore[import-not-found]
        out = liblzfse.decompress(data)
    except ImportError as exc:
        raise DecodeError("lzfse decoder not installed") from exc
    except Exception as exc:
        # liblzfse gives no reason (an empty liblzfse.error or MemoryError).
        raise DecodeError(
            str(exc) if str(exc) and not isinstance(exc, MemoryError)
            else "the LZFSE decoder rejected the data (not LZFSE, or a damaged or truncated stream)"
        ) from exc
    end, has_end = _lzfse_stream_end(data)
    result = _with_trailing(out, data, end)
    if not has_end:
        return Decoded(
            result.data, result.trailing_offset, result.trailing_size, end_marker_missing=True
        )
    return result
