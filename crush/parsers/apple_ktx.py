# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Parser and decoder for Apple-flavoured KTX 1.1 textures.

iOS writes application snapshots and Safari tab thumbnails as Khronos KTX 1.1
files whose payload is ASTC 4x4, optionally wrapped in LZFSE. The container is
the standard Khronos layout; what is Apple-specific is the `Compression_APPLE`
key in the key/value block and the LZFSE block that follows it.

The same `.ktx` extension is also used for Apple's own AAPL/ATX container, which
`apple_atx.py` handles. Which of the two a snapshot uses varies by release, so
both readers are needed to cover a device.

The Apple-specific handling here follows `ios_ktx2png.py`
(Copyright (c) 2020 Yogesh Khatri, MIT License), the reference implementation
used by iLEAPP.

A KTX file can hold PVRTC or other ASTC block sizes; only ASTC 4x4
(`glInternalFormat` 0x93B0) is decoded. Anything else is reported as parsed
metadata with a warning rather than a wrong image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from crush.parsers.apple_atx import decode_astc_4x4

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

KTX11_MAGIC = b"\xabKTX 11\xbb\r\n\x1a\n"
KTX_HEADER_SIZE = 64
# The endianness field holds 0x04030201 written in the file's own byte order,
# so a little-endian file carries these bytes in this order on disk.
_LITTLE_ENDIAN_MARKER = b"\x01\x02\x03\x04"
GL_COMPRESSED_RGBA_ASTC_4X4_KHR = 0x93B0
_APPLE_COMPRESSION_KEY = b"Compression_APPLE"
_APPLE_LZFS_MARKER = b"LZFS"
_LZFSE_BLOCK_MAGIC_PREFIX = b"bvx"
# imageSize (4) + "LZFS" (4) + compressed block length (4)
_LZFSE_PAYLOAD_OFFSET = 12
MAX_IMAGE_PIXELS = 100_000_000


@dataclass(frozen=True)
class KtxHeader:
    """Metadata from the KTX 1.1 file header."""

    gl_type: int
    gl_type_size: int
    gl_format: int
    gl_internal_format: int
    gl_base_internal_format: int
    width: int
    height: int
    depth: int
    array_layers: int
    faces: int
    mipmap_count: int
    key_value_bytes: int
    little_endian: bool

    @property
    def pixel_format(self) -> str:
        if self.gl_internal_format == GL_COMPRESSED_RGBA_ASTC_4X4_KHR:
            return "ASTC 4x4 (GL_COMPRESSED_RGBA_ASTC_4x4_KHR)"
        return f"Unsupported (glInternalFormat 0x{self.gl_internal_format:04X})"


@dataclass(frozen=True)
class KtxPayload:
    """Texture payload bytes found in a KTX file."""

    data: bytes
    declared_size: int
    compressed: bool


@dataclass(frozen=True)
class DecodedImage:
    """RGBA8 image produced from a KTX texture."""

    width: int
    height: int
    pixels: bytes

    def to_pil(self) -> "PILImage":
        from PIL import Image

        return Image.frombytes("RGBA", (self.width, self.height), self.pixels)


@dataclass(frozen=True)
class KtxDecodeResult:
    """Parsed KTX metadata plus optional decoded RGBA image."""

    header: KtxHeader | None
    key_values: tuple[str, ...]
    payload: KtxPayload | None
    image: DecodedImage | None
    warnings: tuple[str, ...]


def is_ktx(data: bytes) -> bool:
    return data.startswith(KTX11_MAGIC)


def parse_ktx(data: bytes) -> KtxDecodeResult:
    """Parse KTX container metadata without attempting image decode."""

    return decode_ktx(data, decode_image=False)


def decode_ktx(data: bytes, decode_image: bool = True) -> KtxDecodeResult:
    """Parse a KTX 1.1 file and optionally decode a supported ASTC 4x4 texture."""

    warnings: list[str] = []
    if not is_ktx(data):
        if data[:4] == b"\xabKTX":
            return KtxDecodeResult(None, (), None, None, ("Unsupported KTX version",))
        return KtxDecodeResult(None, (), None, None, ("Not a KTX 1.1 file",))

    header = _parse_header(data, warnings)
    if header is None:
        return KtxDecodeResult(None, (), None, None, tuple(warnings))

    key_values = _parse_key_values(data, header, warnings)
    payload = _parse_payload(data, header, warnings)
    image = None

    if decode_image and payload:
        try:
            image = _decode_image(header, payload, warnings)
        except (ImportError, OSError, ValueError, struct.error) as ex:
            warnings.append(f"KTX image decode failed: {ex}")

    return KtxDecodeResult(header, key_values, payload, image, tuple(warnings))


def _parse_header(data: bytes, warnings: list[str]) -> KtxHeader | None:
    if len(data) < KTX_HEADER_SIZE:
        warnings.append(f"File is {len(data)} bytes; a KTX header needs {KTX_HEADER_SIZE}")
        return None

    little_endian = data[12:16] == _LITTLE_ENDIAN_MARKER
    fmt = "<12I" if little_endian else ">12I"
    (
        gl_type,
        gl_type_size,
        gl_format,
        gl_internal_format,
        gl_base_internal_format,
        width,
        height,
        depth,
        array_layers,
        faces,
        mipmap_count,
        key_value_bytes,
    ) = struct.unpack(fmt, data[16:KTX_HEADER_SIZE])
    return KtxHeader(
        gl_type=gl_type,
        gl_type_size=gl_type_size,
        gl_format=gl_format,
        gl_internal_format=gl_internal_format,
        gl_base_internal_format=gl_base_internal_format,
        width=width,
        height=height,
        depth=depth,
        array_layers=array_layers,
        faces=faces,
        mipmap_count=mipmap_count,
        key_value_bytes=key_value_bytes,
        little_endian=little_endian,
    )


def _parse_key_values(data: bytes, header: KtxHeader, warnings: list[str]) -> tuple[str, ...]:
    end = KTX_HEADER_SIZE + header.key_value_bytes
    if end > len(data):
        warnings.append(
            f"Key/value block claims {header.key_value_bytes} bytes but the file ends first"
        )
        return ()

    block = data[KTX_HEADER_SIZE:end]
    keys: list[str] = []
    offset = 0
    while offset + 4 <= len(block):
        size = struct.unpack_from("<I" if header.little_endian else ">I", block, offset)[0]
        offset += 4
        entry = block[offset:offset + size]
        if len(entry) < size:
            warnings.append("Key/value entry extends beyond the key/value block")
            break
        key = entry.split(b"\x00", 1)[0]
        if key:
            keys.append(key.decode("utf-8", errors="replace"))
        offset += size
        offset += (-size) % 4  # entries are padded to a 4-byte boundary
    return tuple(keys)


def _parse_payload(data: bytes, header: KtxHeader, warnings: list[str]) -> KtxPayload | None:
    start = KTX_HEADER_SIZE + header.key_value_bytes
    if start + 4 > len(data):
        warnings.append("No texture payload after the key/value block")
        return None

    order = "<I" if header.little_endian else ">I"
    key_value_block = data[KTX_HEADER_SIZE:start]
    body = data[start:]
    declared_size = struct.unpack_from(order, body, 0)[0]

    if _APPLE_COMPRESSION_KEY not in key_value_block:
        return KtxPayload(body[4:], declared_size, False)

    # Apple's LZFSE variant: imageSize, an "LZFS" marker, the compressed block
    # length, then the LZFSE block itself.
    if body[4:8] != _APPLE_LZFS_MARKER:
        warnings.append(
            "Key/value block declares Compression_APPLE but no LZFS marker follows imageSize"
        )
        return None
    if body[_LZFSE_PAYLOAD_OFFSET:_LZFSE_PAYLOAD_OFFSET + 3] != _LZFSE_BLOCK_MAGIC_PREFIX:
        warnings.append("LZFS marker is present but the block that follows is not LZFSE")
        return None

    block_length = struct.unpack_from(order, body, 8)[0]
    block = body[_LZFSE_PAYLOAD_OFFSET:]
    if len(block) < block_length:
        warnings.append(
            f"LZFSE block declares {block_length:,} bytes but only {len(block):,} are present"
        )
    return KtxPayload(block[:block_length] if block_length else block, declared_size, True)


def _decode_image(header: KtxHeader, payload: KtxPayload, warnings: list[str]) -> DecodedImage:
    if header.gl_internal_format != GL_COMPRESSED_RGBA_ASTC_4X4_KHR:
        raise ValueError(f"unsupported KTX pixel format {header.pixel_format}")
    if header.width <= 0 or header.height <= 0:
        raise ValueError(f"invalid KTX dimensions: {header.width}x{header.height}")
    if header.width * header.height > MAX_IMAGE_PIXELS:
        raise ValueError(f"KTX image dimensions are too large: {header.width}x{header.height}")
    if header.depth not in (0, 1):
        warnings.append(f"Unexpected KTX depth {header.depth}; attempting 2D decode")
    if header.array_layers not in (0, 1):
        warnings.append(f"Unexpected KTX array layer count {header.array_layers}; decoding first")
    if header.faces not in (0, 1):
        warnings.append(f"Unexpected KTX face count {header.faces}; decoding first face")
    if header.mipmap_count not in (0, 1):
        warnings.append(f"Unexpected KTX mipmap count {header.mipmap_count}; decoding first level")

    astc_data = payload.data
    if payload.compressed:
        import liblzfse  # type: ignore[import-not-found]

        try:
            astc_data = liblzfse.decompress(astc_data)
        except liblzfse.error as ex:
            raise ValueError(f"LZFSE decompression failed: {ex}") from ex

    image = decode_astc_4x4(astc_data, header.width, header.height)
    return DecodedImage(header.width, header.height, image.convert("RGBA").tobytes())
