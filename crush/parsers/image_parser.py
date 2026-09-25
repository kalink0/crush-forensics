# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Image parser — routes image files to the image viewer."""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.apple_atx import AAPL_MAGIC, decode_atx, is_atx
from crush.parsers.apple_ktx import KTX11_MAGIC, decode_ktx, is_ktx
from crush.parsers.base import AbstractParser, ParseResult

# ISOBMFF brands that identify HEIF/HEIC/AVIF containers
_ISOBMFF_IMAGE_BRANDS: frozenset[bytes] = frozenset({
    b"heic", b"heix", b"hevc", b"hevx",  # HEIC (HEVC-based)
    b"heim", b"heis", b"hevm", b"hevs",  # HEIF multi-picture / tiled
    b"mif1", b"msf1",                    # HEIF (generic)
    b"avif", b"avis",                    # AVIF
})

# JPEG XL ISOBMFF container signature (12 bytes)
_JXL_CONTAINER_SIG = b"\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A"


class ImageParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".tif", ".tiff",
        ".heic", ".heif", ".avif",
        ".jxl",
        ".atx",
        ".ktx",
    ]
    DISPLAY_NAME = "Image"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        ext = Path(path).suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return True
        return _looks_like_image(peek_bytes)

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        meta: dict[str, Any] = {
            "Format": _format_by_content(raw, Path(node.path).suffix),
            "File size": f"{node.size:,} B",
        }
        if is_ktx(raw):
            return self._parse_ktx(raw, meta)
        if is_atx(raw):
            result = decode_atx(raw)
            if result.header:
                meta.update({
                    "Format": "ATX",
                    "Width": result.header.width,
                    "Height": result.header.height,
                    "Depth": result.header.depth,
                    "Array layers": result.header.array_layers,
                    "Mipmaps": result.header.mipmap_count,
                    "Pixel format": result.header.pixel_format,
                    "Texture UUID": result.header.texture_uuid,
                })
            if result.payload:
                meta.update({
                    "Payload": result.payload.kind,
                    "Payload bytes": f"{len(result.payload.data):,} B",
                    "Declared payload bytes": f"{result.payload.declared_size:,} B",
                })
            if result.chunks:
                meta["Chunks"] = ", ".join(chunk.tag for chunk in result.chunks)
            if result.block_order:
                meta["Block order"] = result.block_order
            if result.warnings:
                meta["ATX warnings"] = list(result.warnings)
            if result.image:
                out = io.BytesIO()
                result.image.to_pil().save(out, "PNG")
                meta["Decode status"] = ParseIssue("atx.decoded")
                return ParseResult(
                    viewer_type="image",
                    data=out.getvalue(),
                    metadata=meta,
                )
            meta["Decode status"] = ParseIssue("atx.decode_unavailable")
            return ParseResult(
                viewer_type="text",
                data=_undecoded_text(meta["Decode status"], result.warnings),
                metadata=meta,
            )

        from crush.parsers.c2pa_reader import summarize_c2pa
        from crush.parsers.exif_reader import exif_metadata
        from crush.parsers.xmp_provenance import extract_xmp_provenance

        frames = _frame_count(raw)
        if frames > 1:
            meta["Frames"] = ParseIssue("image.frames_first_only", {"count": frames})
        meta.update(exif_metadata(raw))
        try:
            meta.update(summarize_c2pa(raw))
        except Exception as exc:
            meta["C2PA"] = ParseIssue("image.c2pa_detection_failed", detail=str(exc))
        meta.update(extract_xmp_provenance(raw))
        return ParseResult(viewer_type="image", data=raw, metadata=meta)


    def _parse_ktx(self, raw: bytes, meta: dict[str, Any]) -> ParseResult:
        result = decode_ktx(raw)
        if result.header:
            meta.update({
                "Format": "KTX",
                "Width": result.header.width,
                "Height": result.header.height,
                "Depth": result.header.depth,
                "Array layers": result.header.array_layers,
                "Faces": result.header.faces,
                "Mipmaps": result.header.mipmap_count,
                "Pixel format": result.header.pixel_format,
                "Byte order": "little-endian" if result.header.little_endian else "big-endian",
            })
        if result.key_values:
            meta["Key/value entries"] = ", ".join(result.key_values)
        if result.payload:
            meta.update({
                "Payload": "LZFSE-compressed ASTC" if result.payload.compressed else "ASTC",
                "Payload bytes": f"{len(result.payload.data):,} B",
                "Declared payload bytes": f"{result.payload.declared_size:,} B",
            })
        if result.warnings:
            meta["KTX warnings"] = list(result.warnings)
        if result.image:
            out = io.BytesIO()
            result.image.to_pil().save(out, "PNG")
            meta["Decode status"] = ParseIssue("ktx.decoded")
            return ParseResult(viewer_type="image", data=out.getvalue(), metadata=meta)
        meta["Decode status"] = ParseIssue("ktx.decode_unavailable")
        return ParseResult(
            viewer_type="text",
            data=_undecoded_text(meta["Decode status"], result.warnings),
            metadata=meta,
        )


def _undecoded_text(status: ParseIssue, warnings: tuple[ParseIssue, ...]) -> str:
    """Text shown in place of a texture that could not be decoded."""
    text = str(status)
    if warnings:
        text = f"{text}\n\n" + "\n".join(str(w) for w in warnings)
    return text


# ISOBMFF major brand -> image format name.
_ISOBMFF_FORMAT_NAMES: dict[bytes, str] = {
    **dict.fromkeys(
        (b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs"), "HEIC",
    ),
    b"mif1": "HEIF", b"msf1": "HEIF",
    b"avif": "AVIF", b"avis": "AVIF",
}


def _format_by_content(raw: bytes, suffix: str) -> str | ParseIssue:
    """The image format named by the file's signature bytes (the same
    signatures _looks_like_image accepts). A file routed here by its
    extension alone says so instead of echoing the extension."""
    if raw.startswith(AAPL_MAGIC):
        return "ATX"
    if raw.startswith(KTX11_MAGIC):
        return "KTX"
    if raw.startswith(b"\xFF\xD8\xFF"):
        return "JPEG"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if raw.startswith(b"BM"):
        return "BMP"
    if raw.startswith((b"II*\x00", b"MM\x00*")):
        return "TIFF"
    if len(raw) >= 12 and raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
        return "WebP"
    if len(raw) >= 12 and raw[4:8] == b"ftyp" and raw[8:12] in _ISOBMFF_FORMAT_NAMES:
        return f"{_ISOBMFF_FORMAT_NAMES[raw[8:12]]} (brand {raw[8:12].decode('ascii')})"
    if raw[:2] == b"\xFF\x0A" or raw[:12] == _JXL_CONTAINER_SIG:
        return "JPEG XL"
    return ParseIssue("image.format_unrecognised", {"ext": suffix or "—"})


def _frame_count(raw: bytes) -> int:
    """Number of frames/pages/top-level images Pillow sees (animated GIF,
    multi-page TIFF, HEIC sequences). 1 when Pillow can't open the file --
    the viewer then reports its own decode failure."""
    try:
        import PIL.Image

        from crush.core.pil_plugins import ensure_pil_plugins

        ensure_pil_plugins()
        with PIL.Image.open(io.BytesIO(raw)) as img:
            return int(getattr(img, "n_frames", 1))
    except Exception:
        return 1


def _looks_like_image(peek: bytes) -> bool:
    if len(peek) < 4:
        return False
    if peek.startswith(AAPL_MAGIC):
        return True  # Apple ATX texture archive
    if peek.startswith(KTX11_MAGIC):
        return True  # Khronos KTX 1.1 texture
    if peek.startswith(b"\xFF\xD8\xFF"):
        return True  # JPEG
    if peek.startswith(b"\x89PNG\r\n\x1a\n"):
        return True  # PNG
    if peek.startswith(b"GIF87a") or peek.startswith(b"GIF89a"):
        return True  # GIF
    if peek.startswith(b"BM"):
        return True  # BMP
    if peek.startswith(b"II*\x00") or peek.startswith(b"MM\x00*"):
        return True  # TIFF
    if len(peek) >= 12 and peek.startswith(b"RIFF") and peek[8:12] == b"WEBP":
        return True  # WebP
    # HEIC / HEIF / AVIF: ISO Base Media File Format — ftyp box at offset 4
    if len(peek) >= 12 and peek[4:8] == b"ftyp" and peek[8:12] in _ISOBMFF_IMAGE_BRANDS:
        return True
    # JPEG XL: bare codestream
    if peek[:2] == b"\xFF\x0A":
        return True
    # JPEG XL: ISOBMFF container
    if len(peek) >= 12 and peek[:12] == _JXL_CONTAINER_SIG:
        return True
    return False
