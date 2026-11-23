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

Textures shipped inside system frameworks and apps use the same container
with other pixel formats. Decoded are: every ASTC block size (via
`astc_decomp_faster`), ETC1/ETC2/EAC, PVRTC 1 and BC1/BC3/BC4/BC5/BC7 (via
`texture2ddecoder`), and uncompressed 8-bit-per-channel data. Anything else
(e.g. half-float or packed 16-bit formats) is reported as parsed metadata with
a warning rather than a wrong image.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from crush.core.issues import ParseIssue, ParseIssueError, issue_from_exception
from crush.parsers.apple_atx import decode_astc_4x4

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

KTX11_MAGIC = b"\xabKTX 11\xbb\r\n\x1a\n"
KTX_HEADER_SIZE = 64
# The endianness field holds 0x04030201 written in the file's own byte order,
# so a little-endian file carries these bytes in this order on disk.
_LITTLE_ENDIAN_MARKER = b"\x01\x02\x03\x04"
GL_COMPRESSED_RGBA_ASTC_4X4_KHR = 0x93B0
GL_UNSIGNED_BYTE = 0x1401
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
    def pixel_format(self) -> str | ParseIssue:
        block = _BLOCK_FORMATS.get(self.gl_internal_format)
        if block is not None:
            return f"{block.label} ({block.gl_name})"
        raw = self.raw_format
        if raw is not None:
            return raw.label
        return ParseIssue("ktx.pixel_format_unsupported_label", {"fmt": self.gl_internal_format})

    @property
    def pixel_family(self) -> str | None:
        """Short name of the pixel encoding ("ASTC", "ETC2", "RGBA8" …), or
        None when it is not one this module decodes."""
        block = _BLOCK_FORMATS.get(self.gl_internal_format)
        if block is not None:
            return block.family
        raw = self.raw_format
        return raw.family if raw is not None else None

    @property
    def raw_format(self) -> "_RawFormat | None":
        """The uncompressed layout, when glType/glFormat name one decoded here.
        Compressed textures carry glType 0 and never match."""
        if self.gl_type != GL_UNSIGNED_BYTE:
            return None
        return _RAW_FORMATS.get(self.gl_format)

    @property
    def display_note(self) -> ParseIssue | None:
        """How the decoded image represents the stored values, when it
        doesn't show them as the colours they are (e.g. alpha as greyscale)."""
        raw = self.raw_format
        return ParseIssue(raw.display_note) if raw is not None and raw.display_note else None


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
    warnings: tuple[ParseIssue, ...]


def is_ktx(data: bytes) -> bool:
    return data.startswith(KTX11_MAGIC)


def parse_ktx(data: bytes) -> KtxDecodeResult:
    """Parse KTX container metadata without attempting image decode."""

    return decode_ktx(data, decode_image=False)


def decode_ktx(data: bytes, decode_image: bool = True) -> KtxDecodeResult:
    """Parse a KTX 1.1 file and optionally decode a supported ASTC 4x4 texture."""

    warnings: list[ParseIssue] = []
    if not is_ktx(data):
        if data[:4] == b"\xabKTX":
            return KtxDecodeResult(None, (), None, None, (ParseIssue("ktx.unsupported_version"),))
        return KtxDecodeResult(None, (), None, None, (ParseIssue("ktx.not_ktx"),))

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
            warnings.append(ParseIssue("ktx.decode_failed", {"reason": issue_from_exception(ex)}))

    return KtxDecodeResult(header, key_values, payload, image, tuple(warnings))


def _parse_header(data: bytes, warnings: list[ParseIssue]) -> KtxHeader | None:
    if len(data) < KTX_HEADER_SIZE:
        warnings.append(ParseIssue("ktx.header_too_short", {"size": len(data), "needed": KTX_HEADER_SIZE}))
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


def _parse_key_values(data: bytes, header: KtxHeader, warnings: list[ParseIssue]) -> tuple[str, ...]:
    end = KTX_HEADER_SIZE + header.key_value_bytes
    if end > len(data):
        warnings.append(ParseIssue("ktx.kv_beyond_eof", {"size": header.key_value_bytes}))
        return ()

    block = data[KTX_HEADER_SIZE:end]
    keys: list[str] = []
    offset = 0
    while offset + 4 <= len(block):
        size = struct.unpack_from("<I" if header.little_endian else ">I", block, offset)[0]
        offset += 4
        entry = block[offset:offset + size]
        if len(entry) < size:
            warnings.append(ParseIssue("ktx.kv_entry_overflow"))
            break
        key = entry.split(b"\x00", 1)[0]
        if key:
            keys.append(key.decode("utf-8", errors="replace"))
        offset += size
        offset += (-size) % 4  # entries are padded to a 4-byte boundary
    return tuple(keys)


def _parse_payload(data: bytes, header: KtxHeader, warnings: list[ParseIssue]) -> KtxPayload | None:
    start = KTX_HEADER_SIZE + header.key_value_bytes
    if start + 4 > len(data):
        warnings.append(ParseIssue("ktx.no_payload"))
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
        warnings.append(ParseIssue("ktx.no_lzfs_marker"))
        return None
    if body[_LZFSE_PAYLOAD_OFFSET:_LZFSE_PAYLOAD_OFFSET + 3] != _LZFSE_BLOCK_MAGIC_PREFIX:
        warnings.append(ParseIssue("ktx.not_lzfse"))
        return None

    block_length = struct.unpack_from(order, body, 8)[0]
    block = body[_LZFSE_PAYLOAD_OFFSET:]
    if len(block) < block_length:
        warnings.append(ParseIssue(
            "ktx.lzfse_short", {"declared": block_length, "present": len(block)},
        ))
    return KtxPayload(block[:block_length] if block_length else block, declared_size, True)


def _decode_image(header: KtxHeader, payload: KtxPayload, warnings: list[ParseIssue]) -> DecodedImage:
    dims = {"width": header.width, "height": header.height}
    block = _BLOCK_FORMATS.get(header.gl_internal_format)
    raw = header.raw_format
    if block is None and raw is None:
        raise ParseIssueError(
            ParseIssue("ktx.unsupported_pixel_format", {"format": header.pixel_format})
        )
    if header.width <= 0 or header.height <= 0:
        raise ParseIssueError(ParseIssue("ktx.invalid_dimensions", dims))
    if header.width * header.height > MAX_IMAGE_PIXELS:
        raise ParseIssueError(ParseIssue("ktx.too_large", dims))
    if header.depth not in (0, 1):
        warnings.append(ParseIssue("ktx.unexpected_depth", {"depth": header.depth}))
    if header.array_layers not in (0, 1):
        warnings.append(ParseIssue("ktx.unexpected_layers", {"count": header.array_layers}))
    if header.faces not in (0, 1):
        warnings.append(ParseIssue("ktx.unexpected_faces", {"count": header.faces}))
    if header.mipmap_count not in (0, 1):
        warnings.append(ParseIssue("ktx.unexpected_mipmaps", {"count": header.mipmap_count}))

    pixel_data = payload.data
    if payload.compressed:
        import liblzfse  # type: ignore[import-not-found]

        try:
            pixel_data = liblzfse.decompress(pixel_data)
        except liblzfse.error as ex:
            raise ParseIssueError(ParseIssue("ktx.lzfse_failed", detail=str(ex))) from ex

    width, height = header.width, header.height
    if block is not None:
        needed = block.data_size(width, height)
    else:
        assert raw is not None
        needed = _raw_row_stride(raw, width) * height
    # Neither the ASTC decoder nor texture2ddecoder checks its input length:
    # a short buffer would be read past its end. Refuse it instead.
    if len(pixel_data) < needed:
        raise ParseIssueError(ParseIssue("ktx.payload_short", {
            "present": len(pixel_data), "needed": needed, **dims,
        }))

    if block is not None:
        # The blocks cover whole block rows and columns past a width or
        # height that isn't a multiple of the block size: decoded at that
        # padded size, so each block lands where it is stored, then cut to
        # the texture's own size (as apple_atx does). The ASTC decoder lays
        # blocks out wrongly when given the unpadded size, and PVRTC's below
        # its minimum block count.
        padded_width, padded_height = block.padded_size(width, height)
        image = block.decode(pixel_data[:needed], padded_width, padded_height)
        if (padded_width, padded_height) != (width, height):
            image = image.crop((0, 0, width, height))
    else:
        assert raw is not None
        image = _decode_raw(raw, pixel_data[:needed], width, height)
    return DecodedImage(width, height, image.convert("RGBA").tobytes())


# -- Pixel formats ----------------------------------------------------------


@dataclass(frozen=True)
class _BlockFormat:
    """A block-compressed glInternalFormat and how to decode it."""

    gl_name: str
    label: str
    family: str
    block_width: int
    block_height: int
    block_bytes: int
    decode: Callable[[bytes, int, int], "PILImage"]
    # PVRTC 1 textures are never smaller than this many blocks per side.
    min_blocks: tuple[int, int] = (1, 1)

    def padded_size(self, width: int, height: int) -> tuple[int, int]:
        """The pixels the stored blocks cover: *width* x *height* rounded up
        to whole blocks, and to the format's minimum block count."""
        blocks_x = max(-(-width // self.block_width), self.min_blocks[0])
        blocks_y = max(-(-height // self.block_height), self.min_blocks[1])
        return blocks_x * self.block_width, blocks_y * self.block_height

    def data_size(self, width: int, height: int) -> int:
        padded_width, padded_height = self.padded_size(width, height)
        return (
            (padded_width // self.block_width) * (padded_height // self.block_height)
            * self.block_bytes
        )


@dataclass(frozen=True)
class _RawFormat:
    """An uncompressed glFormat with GL_UNSIGNED_BYTE components."""

    label: str
    family: str
    channels: int
    mode: str
    rawmode: str
    # ParseIssue code saying how the decoded image represents the stored
    # values, when it doesn't show them as the colours they are.
    display_note: str | None = None


def _astc_decoder(block_width: int, block_height: int) -> Callable[[bytes, int, int], "PILImage"]:
    if (block_width, block_height) == (4, 4):
        return decode_astc_4x4

    def decode(data: bytes, width: int, height: int) -> "PILImage":
        import astc_decomp_faster  # type: ignore[import-not-found]  # noqa: F401  # registers PIL ASTC decoder on import
        from PIL import Image

        return Image.frombytes(
            "RGBA", (width, height), data, "astc", (block_width, block_height, False),
        )

    return decode


def _t2d_decoder(name: str, *extra: object) -> Callable[[bytes, int, int], "PILImage"]:
    """A decoder from texture2ddecoder, which returns BGRA8 pixels."""

    def decode(data: bytes, width: int, height: int) -> "PILImage":
        import texture2ddecoder
        from PIL import Image

        try:
            bgra = getattr(texture2ddecoder, name)(data, width, height, *extra)
        except (RuntimeError, SystemError) as ex:
            # texture2ddecoder signals a texture it can't decode (e.g. PVRTC
            # with non-power-of-two block counts) with RuntimeError, older
            # releases with SystemError (NULL returned without an exception).
            raise ParseIssueError(ParseIssue(
                "ktx.decoder_rejected", {"format": name.removeprefix("decode_")}, detail=str(ex),
            )) from ex
        return Image.frombytes("RGBA", (width, height), bgra, "raw", "BGRA")

    return decode


def _pillow_bcn_decoder(n: int) -> Callable[[bytes, int, int], "PILImage"]:
    """Pillow's own BCn decoder (the one its DDS plugin uses) for BC*n*."""

    def decode(data: bytes, width: int, height: int) -> "PILImage":
        from PIL import Image

        return Image.frombytes("RGBA", (width, height), data, "bcn", (n,))

    return decode


# In glInternalFormat order, from 0x93B0 (RGBA) and 0x93D0 (sRGB) upwards.
_ASTC_BLOCK_SIZES = (
    (4, 4), (5, 4), (5, 5), (6, 5), (6, 6), (8, 5), (8, 6), (8, 8),
    (10, 5), (10, 6), (10, 8), (10, 10), (12, 10), (12, 12),
)


def _build_block_formats() -> dict[int, _BlockFormat]:
    formats: dict[int, _BlockFormat] = {}
    for index, (bw, bh) in enumerate(_ASTC_BLOCK_SIZES):
        decode = _astc_decoder(bw, bh)
        formats[0x93B0 + index] = _BlockFormat(
            f"GL_COMPRESSED_RGBA_ASTC_{bw}x{bh}_KHR", f"ASTC {bw}x{bh}", "ASTC",
            bw, bh, 16, decode,
        )
        formats[0x93D0 + index] = _BlockFormat(
            f"GL_COMPRESSED_SRGB8_ALPHA8_ASTC_{bw}x{bh}_KHR", f"ASTC {bw}x{bh} sRGB", "ASTC",
            bw, bh, 16, decode,
        )

    def add(
        code: int, gl_name: str, label: str, family: str, size: int, decoder: str,
        *extra: object, bw: int = 4, min_blocks: tuple[int, int] = (1, 1),
    ) -> None:
        formats[code] = _BlockFormat(
            gl_name, label, family, bw, 4, size, _t2d_decoder(decoder, *extra), min_blocks,
        )

    add(0x8D64, "GL_ETC1_RGB8_OES", "ETC1 RGB", "ETC1", 8, "decode_etc1")
    add(0x9274, "GL_COMPRESSED_RGB8_ETC2", "ETC2 RGB", "ETC2", 8, "decode_etc2")
    add(0x9275, "GL_COMPRESSED_SRGB8_ETC2", "ETC2 RGB sRGB", "ETC2", 8, "decode_etc2")
    add(0x9276, "GL_COMPRESSED_RGB8_PUNCHTHROUGH_ALPHA1_ETC2", "ETC2 RGB A1", "ETC2", 8,
        "decode_etc2a1")
    add(0x9277, "GL_COMPRESSED_SRGB8_PUNCHTHROUGH_ALPHA1_ETC2", "ETC2 RGB A1 sRGB", "ETC2", 8,
        "decode_etc2a1")
    add(0x9278, "GL_COMPRESSED_RGBA8_ETC2_EAC", "ETC2 RGBA", "ETC2", 16, "decode_etc2a8")
    add(0x9279, "GL_COMPRESSED_SRGB8_ALPHA8_ETC2_EAC", "ETC2 RGBA sRGB", "ETC2", 16,
        "decode_etc2a8")
    add(0x9270, "GL_COMPRESSED_R11_EAC", "EAC R11", "EAC", 8, "decode_eacr")
    add(0x9271, "GL_COMPRESSED_SIGNED_R11_EAC", "EAC R11 signed", "EAC", 8, "decode_eacr_signed")
    add(0x9272, "GL_COMPRESSED_RG11_EAC", "EAC RG11", "EAC", 16, "decode_eacrg")
    add(0x9273, "GL_COMPRESSED_SIGNED_RG11_EAC", "EAC RG11 signed", "EAC", 16,
        "decode_eacrg_signed")
    # PVRTC 1: 4bpp packs 4x4 pixels and 2bpp 8x4 pixels into each 8-byte
    # block, and a texture is never smaller than 2x2 blocks.
    for code, gl_name, label, two_bpp in (
        (0x8C00, "GL_COMPRESSED_RGB_PVRTC_4BPPV1_IMG", "PVRTC RGB 4bpp", False),
        (0x8C01, "GL_COMPRESSED_RGB_PVRTC_2BPPV1_IMG", "PVRTC RGB 2bpp", True),
        (0x8C02, "GL_COMPRESSED_RGBA_PVRTC_4BPPV1_IMG", "PVRTC RGBA 4bpp", False),
        (0x8C03, "GL_COMPRESSED_RGBA_PVRTC_2BPPV1_IMG", "PVRTC RGBA 2bpp", True),
    ):
        add(code, gl_name, label, "PVRTC", 8, "decode_pvrtc", two_bpp,
            bw=8 if two_bpp else 4, min_blocks=(2, 2))
    add(0x83F0, "GL_COMPRESSED_RGB_S3TC_DXT1_EXT", "BC1 (DXT1) RGB", "BC1", 8, "decode_bc1")
    # BC1 RGBA through Pillow's BCn decoder: texture2ddecoder's decode_bc1
    # always writes alpha 255, so 1-bit transparency would show as opaque
    # black. (For BC1 RGB that opaque black is what the spec says.)
    formats[0x83F1] = _BlockFormat(
        "GL_COMPRESSED_RGBA_S3TC_DXT1_EXT", "BC1 (DXT1) RGBA", "BC1", 4, 4, 8, _pillow_bcn_decoder(1),
    )
    add(0x83F3, "GL_COMPRESSED_RGBA_S3TC_DXT5_EXT", "BC3 (DXT5) RGBA", "BC3", 16, "decode_bc3")
    add(0x8DBB, "GL_COMPRESSED_RED_RGTC1", "BC4 R", "BC4", 8, "decode_bc4")
    add(0x8DBD, "GL_COMPRESSED_RG_RGTC2", "BC5 RG", "BC5", 16, "decode_bc5")
    add(0x8E8C, "GL_COMPRESSED_RGBA_BPTC_UNORM", "BC7 RGBA", "BC7", 16, "decode_bc7")
    add(0x8E8D, "GL_COMPRESSED_SRGB_ALPHA_BPTC_UNORM", "BC7 RGBA sRGB", "BC7", 16, "decode_bc7")
    return formats


_BLOCK_FORMATS: dict[int, _BlockFormat] = _build_block_formats()

# Keyed by glFormat; the component type (glType) must be GL_UNSIGNED_BYTE.
_RAW_FORMATS: dict[int, _RawFormat] = {
    0x1908: _RawFormat("RGBA8 (GL_RGBA, GL_UNSIGNED_BYTE)", "RGBA8", 4, "RGBA", "RGBA"),
    0x80E1: _RawFormat("BGRA8 (GL_BGRA, GL_UNSIGNED_BYTE)", "BGRA8", 4, "RGBA", "BGRA"),
    0x1907: _RawFormat("RGB8 (GL_RGB, GL_UNSIGNED_BYTE)", "RGB8", 3, "RGB", "RGB"),
    0x80E0: _RawFormat("BGR8 (GL_BGR, GL_UNSIGNED_BYTE)", "BGR8", 3, "RGB", "BGR"),
    0x190A: _RawFormat("LA8 (GL_LUMINANCE_ALPHA, GL_UNSIGNED_BYTE)", "LA8", 2, "LA", "LA"),
    0x1909: _RawFormat("L8 (GL_LUMINANCE, GL_UNSIGNED_BYTE)", "L8", 1, "L", "L"),
    # GL reads a red-only texel as (r, 0, 0, 1): shown red, as BC4 and EAC R11
    # are (texture2ddecoder returns them that way).
    0x1903: _RawFormat("R8 (GL_RED, GL_UNSIGNED_BYTE)", "R8", 1, "RGB", "R"),
    # Alpha only, no colour: shown as greyscale so the mask's shape is
    # visible, and labelled, so it isn't taken for image content.
    0x1906: _RawFormat(
        "A8 (GL_ALPHA, GL_UNSIGNED_BYTE)", "A8", 1, "L", "L", display_note="ktx.alpha_as_greyscale",
    ),
}


def _raw_row_stride(raw: _RawFormat, width: int) -> int:
    # KTX 1.1 pads each row of uncompressed data to a 4-byte boundary
    # (GL_UNPACK_ALIGNMENT 4).
    row = width * raw.channels
    return row + (-row) % 4


def _decode_raw(raw: _RawFormat, data: bytes, width: int, height: int) -> "PILImage":
    from PIL import Image

    stride = _raw_row_stride(raw, width)
    return Image.frombytes(raw.mode, (width, height), data, "raw", raw.rawmode, stride)
