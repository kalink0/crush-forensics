"""Parser and best-effort decoder for Apple ATX texture archives.

The public API is intentionally small and result-oriented so artifacts can use
it similarly to Crush parser helpers: feed bytes in, receive parsed metadata,
decoded output when possible, and warnings instead of surprise exceptions for
expected format drift.

Some ATX files store ASTC blocks in the same 32x32-block macro tiles but differ
in how the Morton-order X/Y bits are interpreted inside each tile. When decoding
raw `astc` chunks, this parser tries both plausible X/Y orientations, decodes
both images, and scores the visible boundaries between 128-pixel macro tiles.
The orientation with the smaller brightness jump at those boundaries is used.
In simpler terms: if one block order leaves a checkerboard/grid artifact and the
other looks smooth, the smoother one wins. This is a heuristic based on observed
iOS PosterBoard samples, not a fully documented Apple format flag.
"""

from __future__ import annotations

import math
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from crush.core.issues import ParseIssue, ParseIssueError, issue_from_exception

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

AAPL_MAGIC = b"AAPL\r\n\x1a\n"
HEAD_TAG = b"HEAD"
FILL_TAG = b"FILL"
ASTC_TAG = b"astc"
ASTC_UPPER_TAG = b"ASTC"
LZFS_TAG = b"LZFS"
ASTC_4X4_FORMAT = (3, 5)
INFERRED_ASTC_4X4_FORMATS = {(1, 1), (3, 1)}
ASTC_BLOCK_BYTES = 16
ASTC_BLOCK_WIDTH = 4
ASTC_BLOCK_HEIGHT = 4
DEFAULT_MACRO_BLOCKS = 32
MAX_IMAGE_PIXELS = 100_000_000


@dataclass(frozen=True)
class AtxChunk:
    """A parsed AAPL container chunk."""

    tag: str
    offset: int
    size: int
    payload_offset: int


@dataclass(frozen=True)
class AtxHeader:
    """Metadata from the ATX HEAD chunk."""

    flags: int
    width: int
    height: int
    depth: int
    array_layers: int
    mipmap_count: int
    texture_uuid: str
    pixel_format_a: int
    pixel_format_b: int

    @property
    def pixel_format(self) -> str | ParseIssue:
        pair = {"a": self.pixel_format_a, "b": self.pixel_format_b}
        if (self.pixel_format_a, self.pixel_format_b) == ASTC_4X4_FORMAT:
            return "ASTC 4x4"
        if (self.pixel_format_a, self.pixel_format_b) in INFERRED_ASTC_4X4_FORMATS:
            return ParseIssue("atx.pixel_format_inferred_label", pair)
        return ParseIssue("atx.pixel_format_unknown", pair)


@dataclass(frozen=True)
class TexturePayload:
    """Texture payload bytes found in an ATX container."""

    kind: str
    data: bytes
    declared_size: int
    compressed: bool


@dataclass(frozen=True)
class DecodedImage:
    """RGBA8 image produced from an ATX texture."""

    width: int
    height: int
    pixels: bytes

    def to_pil(self) -> "PILImage":
        from PIL import Image

        return Image.frombytes("RGBA", (self.width, self.height), self.pixels)


@dataclass(frozen=True)
class AtxDecodeResult:
    """Parsed ATX metadata plus optional decoded RGBA image.

    *block_order* is set when the macro-tile block order was chosen by the
    seam-score heuristic (see module docstring); it names both candidates
    and their scores.
    """

    header: AtxHeader | None
    chunks: tuple[AtxChunk, ...]
    payload: TexturePayload | None
    image: DecodedImage | None
    warnings: tuple[ParseIssue, ...]
    block_order: ParseIssue | None = None


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def u32(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            raise ParseIssueError(ParseIssue("atx.unexpected_eof"))
        return int(struct.unpack_from("<I", self.data, offset)[0])

    def slice(self, offset: int, size: int) -> bytes:
        if offset + size > len(self.data):
            raise ParseIssueError(ParseIssue("atx.unexpected_eof"))
        return self.data[offset:offset + size]


def is_atx(data: bytes) -> bool:
    return data.startswith(AAPL_MAGIC)


def parse_atx(data: bytes) -> AtxDecodeResult:
    """Parse ATX container metadata without attempting image decode."""

    return decode_atx(data, decode_image=False)


def decode_atx_file(path: str | Path, decode_image: bool = True) -> AtxDecodeResult:
    return decode_atx(Path(path).read_bytes(), decode_image=decode_image)


def decode_atx(data: bytes, decode_image: bool = True) -> AtxDecodeResult:
    """Parse an ATX file and optionally decode supported ASTC 4x4 textures."""

    warnings: list[ParseIssue] = []
    if not is_atx(data):
        return AtxDecodeResult(None, tuple(), None, None, (ParseIssue("atx.not_atx"),))

    reader = _Reader(data)
    chunks = tuple(_iter_chunks(reader, warnings))
    header = _parse_header(reader, chunks, warnings)
    payload = _parse_payload(reader, chunks, warnings)
    image = None
    block_order = None

    if decode_image and header and payload:
        try:
            image, block_order = _decode_image(header, payload, warnings)
        except (ImportError, OSError, ValueError, struct.error) as ex:
            warnings.append(ParseIssue("atx.decode_failed", {"reason": issue_from_exception(ex)}))

    return AtxDecodeResult(header, chunks, payload, image, tuple(warnings), block_order)


def _iter_chunks(reader: _Reader, warnings: list[ParseIssue]) -> Iterable[AtxChunk]:
    offset = len(AAPL_MAGIC)
    while offset + 8 <= len(reader.data):
        try:
            size = reader.u32(offset)
            tag_bytes = reader.slice(offset + 4, 4)
        except ValueError as ex:
            warnings.append(issue_from_exception(ex))
            return

        payload_offset = offset + 8
        end = payload_offset + size
        tag = tag_bytes.decode("ascii", errors="replace")
        if end > len(reader.data):
            warnings.append(ParseIssue("atx.chunk_beyond_eof", {"tag": tag, "offset": offset}))
            return

        yield AtxChunk(tag, offset, size, payload_offset)
        offset = end

    if offset != len(reader.data):
        warnings.append(ParseIssue("atx.trailing_bytes", {"count": len(reader.data) - offset}))


def _parse_header(reader: _Reader, chunks: tuple[AtxChunk, ...], warnings: list[ParseIssue]) -> AtxHeader | None:
    head = next((chunk for chunk in chunks if chunk.tag == HEAD_TAG.decode("ascii")), None)
    if not head:
        warnings.append(ParseIssue("atx.no_head"))
        return None

    if head.size < 0x54:
        warnings.append(ParseIssue("atx.head_too_small", {"size": head.size}))
        return None

    payload = reader.slice(head.payload_offset, head.size)
    texture_uuid = str(uuid.UUID(bytes=payload[0x3C:0x4C]))
    return AtxHeader(
        flags=struct.unpack_from("<I", payload, 0x00)[0],
        width=struct.unpack_from("<I", payload, 0x18)[0],
        height=struct.unpack_from("<I", payload, 0x1C)[0],
        depth=struct.unpack_from("<I", payload, 0x20)[0],
        array_layers=struct.unpack_from("<I", payload, 0x28)[0],
        mipmap_count=struct.unpack_from("<I", payload, 0x2C)[0],
        texture_uuid=texture_uuid,
        pixel_format_a=struct.unpack_from("<I", payload, 0x4C)[0],
        pixel_format_b=struct.unpack_from("<I", payload, 0x50)[0],
    )


def _parse_payload(reader: _Reader, chunks: tuple[AtxChunk, ...], warnings: list[ParseIssue]) -> TexturePayload | None:
    payload_chunk = next((chunk for chunk in chunks if chunk.tag in ("astc", "ASTC", "LZFS")), None)
    if not payload_chunk:
        warnings.append(ParseIssue("atx.no_payload"))
        return None

    if payload_chunk.size < 4:
        warnings.append(ParseIssue("atx.payload_no_inner_size", {"tag": payload_chunk.tag}))
        return None

    declared_size = reader.u32(payload_chunk.payload_offset)
    payload_data = reader.slice(payload_chunk.payload_offset + 4, payload_chunk.size - 4)
    return TexturePayload(
        kind=payload_chunk.tag,
        data=payload_data,
        declared_size=declared_size,
        compressed=payload_chunk.tag == "LZFS",
    )


def _decode_image(
    header: AtxHeader, payload: TexturePayload, warnings: list[ParseIssue],
) -> tuple[DecodedImage, ParseIssue | None]:
    dims = {"width": header.width, "height": header.height}
    if header.width <= 0 or header.height <= 0:
        raise ParseIssueError(ParseIssue("atx.invalid_dimensions", dims))
    if header.width * header.height > MAX_IMAGE_PIXELS:
        raise ParseIssueError(ParseIssue("atx.too_large", dims))
    if header.depth not in (0, 1):
        warnings.append(ParseIssue("atx.unexpected_depth", {"depth": header.depth}))
    if header.array_layers not in (0, 1):
        warnings.append(ParseIssue("atx.unexpected_layers", {"count": header.array_layers}))
    if header.mipmap_count not in (0, 1):
        warnings.append(ParseIssue("atx.unexpected_mipmaps", {"count": header.mipmap_count}))
    pixel_format = (header.pixel_format_a, header.pixel_format_b)
    if pixel_format not in {ASTC_4X4_FORMAT, *INFERRED_ASTC_4X4_FORMATS}:
        raise ParseIssueError(
            ParseIssue("atx.unsupported_pixel_format", {"format": header.pixel_format})
        )
    if pixel_format in INFERRED_ASTC_4X4_FORMATS:
        warnings.append(ParseIssue("atx.pixel_format_inferred", {"format": str(pixel_format)}))

    block_order = None
    if payload.compressed:
        astc_data, padded_width, padded_height = _linear_lzfs_payload(header, payload)
        image = decode_astc_4x4(astc_data, padded_width, padded_height)
    else:
        image, padded_width, padded_height, block_order = _decode_macro_tiled_payload(
            header, payload,
        )

    if (padded_width, padded_height) != (header.width, header.height):
        image = image.crop((0, 0, header.width, header.height))
    decoded = DecodedImage(header.width, header.height, image.convert("RGBA").tobytes())
    return decoded, block_order


def _linear_lzfs_payload(header: AtxHeader, payload: TexturePayload) -> tuple[bytes, int, int]:
    import liblzfse  # type: ignore[import-not-found]

    astc_data = liblzfse.decompress(payload.data)
    padded_width = _round_up(header.width, ASTC_BLOCK_WIDTH)
    padded_height = _round_up(header.height, ASTC_BLOCK_HEIGHT)
    expected = _astc_byte_count(padded_width, padded_height)
    if len(astc_data) < expected:
        raise ParseIssueError(ParseIssue(
            "atx.lzfs_too_short", {"size": len(astc_data), "expected": expected},
        ))
    return astc_data[:expected], padded_width, padded_height


def _macro_tiled_payload(
    header: AtxHeader,
    payload: TexturePayload,
    swap_morton_xy: bool = True,
) -> tuple[bytes, int, int]:
    padded_width = _round_up(header.width, DEFAULT_MACRO_BLOCKS * ASTC_BLOCK_WIDTH)
    padded_height = _round_up(header.height, DEFAULT_MACRO_BLOCKS * ASTC_BLOCK_HEIGHT)
    blocks_w = padded_width // ASTC_BLOCK_WIDTH
    blocks_h = padded_height // ASTC_BLOCK_HEIGHT
    expected = blocks_w * blocks_h * ASTC_BLOCK_BYTES
    if len(payload.data) < expected:
        raise ParseIssueError(ParseIssue(
            "atx.astc_too_short", {"size": len(payload.data), "expected": expected},
        ))

    linear = bytearray(expected)
    src_offset = 0
    for macro_y in range(0, blocks_h, DEFAULT_MACRO_BLOCKS):
        for macro_x in range(0, blocks_w, DEFAULT_MACRO_BLOCKS):
            for morton_index in range(DEFAULT_MACRO_BLOCKS * DEFAULT_MACRO_BLOCKS):
                local_x, local_y = _decode_morton_5bit(morton_index)
                if swap_morton_xy:
                    local_x, local_y = local_y, local_x
                block_x = macro_x + local_x
                block_y = macro_y + local_y
                dst_offset = (block_y * blocks_w + block_x) * ASTC_BLOCK_BYTES
                linear[dst_offset:dst_offset + ASTC_BLOCK_BYTES] = (
                    payload.data[src_offset:src_offset + ASTC_BLOCK_BYTES]
                )
                src_offset += ASTC_BLOCK_BYTES

    return bytes(linear), padded_width, padded_height


def _decode_macro_tiled_payload(
    header: AtxHeader, payload: TexturePayload,
) -> tuple["PILImage", int, int, ParseIssue]:
    """Decode both Morton X/Y orientations and keep the one with the
    smaller seam score. The returned issue marks the choice as heuristic
    and names both candidates with their scores."""
    candidates = []
    for swap_morton_xy in (False, True):
        astc_data, padded_width, padded_height = _macro_tiled_payload(
            header,
            payload,
            swap_morton_xy=swap_morton_xy,
        )
        image = decode_astc_4x4(astc_data, padded_width, padded_height)
        cropped = image.crop((0, 0, header.width, header.height)).convert("RGB")
        candidates.append((
            _grid_seam_score(cropped, DEFAULT_MACRO_BLOCKS * ASTC_BLOCK_WIDTH),
            image,
            padded_width,
            padded_height,
            ParseIssue("atx.morton_swapped" if swap_morton_xy else "atx.morton_as_stored"),
        ))

    chosen = min(candidates, key=lambda item: item[0])
    other = next(c for c in candidates if c is not chosen)
    score, image, padded_width, padded_height, label = chosen
    block_order = ParseIssue("atx.block_order_heuristic", {
        "chosen": label, "chosen_score": score,
        "other": other[4], "other_score": other[0],
    })
    return image, padded_width, padded_height, block_order


def decode_astc_4x4(astc_data: bytes, width: int, height: int) -> "PILImage":
    import astc_decomp_faster  # type: ignore[import-not-found]  # noqa: F401  # registers PIL ASTC decoder on import
    from PIL import Image

    return Image.frombytes("RGBA", (width, height), astc_data, "astc", (4, 4, False))


def _grid_seam_score(image: "PILImage", step: int) -> float:
    gray = image.convert("L")
    pixels = gray.load()
    assert pixels is not None
    width, height = gray.size
    total = 0
    count = 0

    for x in range(step, width, step):
        for y in range(height):
            total += abs(pixels[x, y] - pixels[x - 1, y])  # type: ignore[operator]
            count += 1

    for y in range(step, height, step):
        for x in range(width):
            total += abs(pixels[x, y] - pixels[x, y - 1])  # type: ignore[operator]
            count += 1

    return total / count if count else 0


def _decode_morton_5bit(index: int) -> tuple[int, int]:
    x = 0
    y = 0
    for bit in range(5):
        x |= ((index >> (bit * 2)) & 1) << bit
        y |= ((index >> (bit * 2 + 1)) & 1) << bit
    return x, y


def _round_up(value: int, multiple: int) -> int:
    return int(math.ceil(value / multiple) * multiple)


def _astc_byte_count(width: int, height: int) -> int:
    blocks_w = _round_up(width, ASTC_BLOCK_WIDTH) // ASTC_BLOCK_WIDTH
    blocks_h = _round_up(height, ASTC_BLOCK_HEIGHT) // ASTC_BLOCK_HEIGHT
    return blocks_w * blocks_h * ASTC_BLOCK_BYTES
