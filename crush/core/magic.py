# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Magic-byte helpers for fast file type detection."""
from __future__ import annotations

from typing import Final

try:
    import filetype  # type: ignore
except Exception:
    filetype = None

SQLITE_MAGIC: Final = b"SQLite format 3\x00"
BPLIST_MAGIC: Final = b"bplist"
XML_PLIST_SIG: Final = b"<?xml"
ABX_MAGIC: Final = b"ABX\x00"
SEGB_MAGIC: Final = b"SEGB"
AAPL_ATX_MAGIC: Final = b"AAPL\r\n\x1a\n"
KTX11_MAGIC: Final = b"\xabKTX 11\xbb\r\n\x1a\n"
# SEGB v1 header is 56 bytes; magic sits at the last 4 bytes (offset 52 = 0x34)
_SEGB_V1_MAGIC_OFFSET: Final = 52
# Realm: 24-byte file header, mnemonic "T-DB" at offset 16
REALM_MNEMONIC: Final = b"T-DB"
_REALM_MNEMONIC_OFFSET: Final = 16


_ISOBMFF_HEIC_BRANDS: Final[frozenset[bytes]] = frozenset({
    b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs",
})
_ISOBMFF_HEIF_BRANDS: Final[frozenset[bytes]] = frozenset({b"mif1", b"msf1"})
_ISOBMFF_AVIF_BRANDS: Final[frozenset[bytes]] = frozenset({b"avif", b"avis"})
_JXL_CONTAINER_SIG: Final = b"\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A"

# Ogg page header is 27 bytes + 1-byte segment table (for single-segment first pages)
# → codec identification payload starts at byte 28.
_OGG_MAGIC: Final = b"OggS"
_OPUS_HEAD: Final = b"OpusHead"   # RFC 7845 §5.1
_VORBIS_HEAD: Final = b"\x01vorbis"  # Vorbis I spec §5.2.1
_AMR_MAGIC: Final = b"#!AMR"
# ASF header object GUID 75B22630-668E-11CF-A6D9-00AA0062CE6C (WMA, WMV),
# as stored (little-endian fields).
_ASF_HEADER_GUID: Final = bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")
_ISOBMFF_IMAGE_BRANDS: Final = _ISOBMFF_HEIC_BRANDS | _ISOBMFF_HEIF_BRANDS | _ISOBMFF_AVIF_BRANDS


def looks_like_media(peek: bytes) -> bool:
    """Audio or video by its first bytes (20 are enough), each from its
    format's spec: an ISO base media file (MP4, MOV, M4A, 3GP ...) by its
    ftyp box unless the brand is an image's (HEIC, HEIF, AVIF), RIFF WAVE
    and AVI, FLAC, EBML (Matroska, WebM), ASF (WMA, WMV), Ogg, AMR, and MP3
    with an ID3v2 tag. MPEG audio without ID3v2 and AAC in ADTS begin with a
    bare frame sync of 11/12 bits that much other data matches too, so they
    are left to the file name."""
    if len(peek) < 4:
        return False
    if peek[:4] == _OGG_MAGIC or peek[:5] == _AMR_MAGIC:
        return True
    if len(peek) >= 12 and peek[4:8] == b"ftyp":  # ISO/IEC 14496-12
        return peek[8:12] not in _ISOBMFF_IMAGE_BRANDS
    if len(peek) >= 12 and peek[:4] == b"RIFF" and peek[8:12] in (b"WAVE", b"AVI "):
        return True
    if peek[:4] in (b"fLaC", b"\x1a\x45\xdf\xa3"):  # FLAC stream marker, EBML (RFC 8794)
        return True
    if peek[:16] == _ASF_HEADER_GUID:
        return True
    # ID3v2 tag (id3v2.4.0-structure 3.1): "ID3", two version bytes below
    # 0xFF, flags, and a size of four bytes below 0x80 each.
    return (
        len(peek) >= 10 and peek[:3] == b"ID3" and peek[3] < 0xFF and peek[4] < 0xFF
        and all(b < 0x80 for b in peek[6:10])
    )


def detect_fast_label(peek_bytes: bytes, path: str) -> str:
    """Return a fast type label using lightweight magic checks.

    Returns empty string when no fast label applies.
    """
    # Check ISOBMFF image containers before filetype — filetype lumps all HEIF
    # variants under a generic "heif" extension and returns no label for JXL.
    if len(peek_bytes) >= 12:
        if peek_bytes[4:8] == b"ftyp":
            brand = peek_bytes[8:12]
            if brand in _ISOBMFF_HEIC_BRANDS:
                return "HEIC"
            if brand in _ISOBMFF_HEIF_BRANDS:
                return "HEIF"
            if brand in _ISOBMFF_AVIF_BRANDS:
                return "AVIF"
        if peek_bytes[:12] == _JXL_CONTAINER_SIG:
            return "JXL"
    if len(peek_bytes) >= 2 and peek_bytes[:2] == b"\xFF\x0A":
        return "JXL"
    if peek_bytes.startswith(AAPL_ATX_MAGIC):
        return "ATX"
    if peek_bytes.startswith(KTX11_MAGIC):
        return "KTX"

    # Ogg-container codecs — check before filetype (which only returns "Media").
    # First page payload sits at offset 28 for the standard single-segment first page.
    if len(peek_bytes) >= 4 and peek_bytes[:4] == _OGG_MAGIC:
        if len(peek_bytes) >= 36 and peek_bytes[28:36] == _OPUS_HEAD:
            return "Opus"
        if len(peek_bytes) >= 35 and peek_bytes[28:35] == _VORBIS_HEAD:
            return "OGG"
        return "OGG"

    if filetype is not None:
        kind = filetype.guess(peek_bytes)
        if kind is not None:
            mime = getattr(kind, "mime", "")
            if isinstance(mime, str):
                if mime.startswith("image/"):
                    return "Image"
                if mime.startswith("audio/") or mime.startswith("video/"):
                    return "Media"
            ext = getattr(kind, "extension", "")
            if isinstance(ext, str) and ext:
                return ext.upper()

    if peek_bytes[_REALM_MNEMONIC_OFFSET : _REALM_MNEMONIC_OFFSET + 4] == REALM_MNEMONIC:
        return "Realm"
    if peek_bytes.startswith(SQLITE_MAGIC):
        return "SQLite"
    if peek_bytes.startswith(BPLIST_MAGIC):
        return "bplist"
    if peek_bytes.startswith(ABX_MAGIC):
        return "ABX"
    if peek_bytes.startswith(SEGB_MAGIC):
        return "SEGB"
    end = _SEGB_V1_MAGIC_OFFSET + len(SEGB_MAGIC)
    if len(peek_bytes) >= end and peek_bytes[_SEGB_V1_MAGIC_OFFSET:end] == SEGB_MAGIC:
        return "SEGB"
    if looks_like_plist_xml(peek_bytes):
        return "plist"
    return ""


_UTF8_BOM: Final = b"\xef\xbb\xbf"
# What an XML plist starts with once a UTF-8 BOM and whitespace are skipped:
# the XML declaration, or -- without one -- the plist DOCTYPE or the <plist>
# element itself (both well-formed XML; Apple's own files carry all three).
_XML_PLIST_STARTS: Final = (XML_PLIST_SIG, b"<!doctype plist", b"<plist")


def _xml_plist_offset(data: bytes) -> int:
    """Where the XML in *data* starts: after a UTF-8 BOM and whitespace."""
    start = len(_UTF8_BOM) if data.startswith(_UTF8_BOM) else 0
    return len(data) - len(data[start:].lstrip())


def looks_like_plist_xml(peek_bytes: bytes) -> bool:
    """Whether *peek_bytes* begin an XML plist: after an optional UTF-8 BOM
    and whitespace, an XML declaration, the plist DOCTYPE or a <plist>
    element, with a <plist> element within the first 2 KiB. The one check
    every detector (fast label, format DB, plist and XML parser) uses."""
    head = peek_bytes[_xml_plist_offset(peek_bytes):][:2048]
    if not head[:15].lower().startswith(_XML_PLIST_STARTS):
        return False
    return b"<plist" in head.lower()


def xml_plist_body(data: bytes) -> bytes:
    """*data* from where its XML starts, for loading only: plistlib takes
    neither a leading BOM + whitespace before the declaration nor a file
    without one. The stored bytes stay as they are everywhere else."""
    return data[_xml_plist_offset(data):]
