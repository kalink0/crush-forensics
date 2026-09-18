# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""JUMBF (JPEG Universal Metadata Box Format, ISO/IEC 19566-5) box reader.

Generic box-walking only -- decoding what's inside a box (CBOR, JSON, ...)
is the caller's job. Used to locate the C2PA Manifest Store embedded in an
image (see crush/parsers/c2pa_reader.py); the byte-level box layout and the
JPEG APP11 fragmentation scheme below were verified against real,
C2PA-org-published sample files, not just the written spec.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

# JUMBF Description box (TBox 'jumd') toggle bits (ISO/IEC 19566-5, Annex A.3.1)
_TOGGLE_LABEL_PRESENT = 0x02


@dataclass
class JumbfBox:
    box_type: bytes
    content_start: int
    content_end: int
    box_start: int


def read_box_header(data: bytes, pos: int) -> JumbfBox | None:
    """Read one JUMBF box header (LBox/TBox, with XLBox for 64-bit lengths)."""
    if pos + 8 > len(data):
        return None
    lbox = int.from_bytes(data[pos:pos + 4], "big")
    tbox = data[pos + 4:pos + 8]
    header_len = 8
    if lbox == 1:
        if pos + 16 > len(data):
            return None
        lbox = int.from_bytes(data[pos + 8:pos + 16], "big")
        header_len = 16
    box_len = (len(data) - pos) if lbox == 0 else lbox
    if box_len < header_len or pos + box_len > len(data):
        return None
    return JumbfBox(tbox, pos + header_len, pos + box_len, pos)


def read_description(data: bytes, jumd_content_start: int) -> tuple[bytes, str]:
    """Read a Description box's (type UUID, label) from its own content start."""
    uuid = data[jumd_content_start:jumd_content_start + 16]
    toggles = data[jumd_content_start + 16] if len(data) > jumd_content_start + 16 else 0
    label = ""
    if toggles & _TOGGLE_LABEL_PRESENT:
        start = jumd_content_start + 17
        end = data.find(b"\x00", start)
        if end >= 0:
            label = data[start:end].decode("utf-8", errors="replace")
    return uuid, label


def find_superbox_by_label(
    data: bytes, start: int, end: int, label: str,
) -> JumbfBox | None:
    """Depth-first search for a 'jumb' superbox whose Description box has *label*."""
    pos = start
    while pos < end:
        box = read_box_header(data, pos)
        if box is None:
            return None
        if box.box_type == b"jumb":
            jumd = read_box_header(data, box.content_start)
            if jumd is not None and jumd.box_type == b"jumd":
                _uuid, box_label = read_description(data, jumd.content_start)
                if box_label == label:
                    return box
                found = find_superbox_by_label(data, jumd.content_end, box.content_end, label)
                if found is not None:
                    return found
        pos = box.content_end
    return None


def iter_children(data: bytes, start: int, end: int) -> list[JumbfBox]:
    """List every top-level box in [start, end) without descending into them."""
    boxes: list[JumbfBox] = []
    pos = start
    while pos < end:
        box = read_box_header(data, pos)
        if box is None:
            break
        boxes.append(box)
        pos = box.content_end
    return boxes


def first_content_box(data: bytes, superbox: JumbfBox) -> JumbfBox | None:
    """Return a 'jumb' superbox's own content box (the sibling right after its
    Description box), e.g. the 'cbor' box holding a Claim's actual payload."""
    jumd = read_box_header(data, superbox.content_start)
    if jumd is None:
        return None
    return read_box_header(data, jumd.content_end)


# ---------------------------------------------------------------------------
# Manifest-store extraction (per-container embedding rules, C2PA spec Annex A.3)
# ---------------------------------------------------------------------------

def extract_from_jpeg(raw: bytes) -> bytes | None:
    """Reassemble the C2PA JUMBF stream from JPEG APP11 marker segments.

    Each APP11 payload is prefixed with CI (2B, "JP"), En (2B, Box Instance
    Number) and Z (4B, big-endian packet sequence number, 1-based); segments
    after the first duplicate the outer box's own 8-byte LBox+TBox, which
    must be stripped when reassembling (verified against real C2PA-org
    sample files, not just the ISO 19566-5 D.2 text).
    """
    segments: dict[bytes, list[tuple[int, bytes]]] = {}
    pos = 2
    while pos + 4 <= len(raw):
        if raw[pos] != 0xFF:
            break
        marker = raw[pos + 1]
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            pos += 2
            continue
        if marker == 0xDA:  # Start of Scan -- entropy-coded data follows
            break
        if pos + 4 > len(raw):
            break
        seg_len = int.from_bytes(raw[pos + 2:pos + 4], "big")
        if marker == 0xEB and pos + 2 + seg_len <= len(raw):
            payload = raw[pos + 4:pos + 2 + seg_len]
            if len(payload) >= 8 and payload[0:2] == b"JP":
                en = payload[2:4]
                z = int.from_bytes(payload[4:8], "big")
                segments.setdefault(en, []).append((z, payload[8:]))
        pos += 2 + seg_len

    for en, parts in segments.items():
        parts.sort(key=lambda p: p[0])
        stream = bytearray()
        for i, (z, body) in enumerate(parts):
            if z != i + 1:
                break  # non-contiguous sequence -- can't trust reassembly
            stream += body[8:] if i > 0 else body
        if stream:
            box = read_box_header(bytes(stream), 0)
            if box is not None and box.box_type == b"jumb":
                return bytes(stream)
    return None


def extract_from_png(raw: bytes) -> bytes | None:
    """Return the raw 'caBX' ancillary chunk's data (the JUMBF stream directly)."""
    pos = 8
    while pos + 8 <= len(raw):
        clen = int.from_bytes(raw[pos:pos + 4], "big")
        ctype = raw[pos + 4:pos + 8]
        if pos + 8 + clen > len(raw):
            break
        if ctype == b"caBX":
            data = raw[pos + 8:pos + 8 + clen]
            box = read_box_header(data, 0)
            if box is not None and box.box_type == b"jumb":
                return data
        elif ctype == b"IEND":
            break
        pos += 8 + clen + 4  # length + type + data + CRC
    return None


def extract_from_riff(raw: bytes) -> bytes | None:
    """Return a RIFF file's 'C2PA' chunk data directly (WebP, WAV, AVI containers
    all use the same top-level chunk convention, C2PA spec Annex A.3.7)."""
    if len(raw) < 12 or raw[:4] != b"RIFF":
        return None
    pos = 12
    while pos + 8 <= len(raw):
        chunk_id = raw[pos:pos + 4]
        size = int.from_bytes(raw[pos + 4:pos + 8], "little")
        if pos + 8 + size > len(raw):
            break
        if chunk_id == b"C2PA":
            data = raw[pos + 8:pos + 8 + size]
            box = read_box_header(data, 0)
            if box is not None and box.box_type == b"jumb":
                return data
        pos += 8 + size + (size & 1)  # chunks are padded to an even length
    return None


def _read_gif_subblocks(raw: bytes, pos: int) -> tuple[bytes, int]:
    """Read GIF length-prefixed sub-blocks up to the 0-length terminator."""
    out = bytearray()
    while pos < len(raw):
        n = raw[pos]
        pos += 1
        if n == 0:
            return bytes(out), pos
        out += raw[pos:pos + n]
        pos += n
    return bytes(out), pos


_GIF_C2PA_APP_ID = b"C2PA_GIF" + bytes([0x01, 0x00, 0x00])  # ID + block-version toggles


def extract_from_gif(raw: bytes) -> bytes | None:
    """Return the payload of a GIF's C2PA Application Extension block, per
    C2PA spec Annex A.3.8 (verified byte-for-byte against contentauth/c2pa-rs)."""
    if len(raw) < 13 or raw[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    pos = 13
    flags = raw[10]
    if flags & 0x80:  # global color table present
        pos += 3 * (2 ** ((flags & 0x07) + 1))

    while pos < len(raw):
        marker = raw[pos]
        if marker == 0x21:  # Extension Introducer
            if pos + 2 > len(raw):
                break
            label = raw[pos + 1]
            body, pos = _read_gif_subblocks(raw, pos + 2)
            if label == 0xFF and body[:11] == _GIF_C2PA_APP_ID:
                manifest_bytes = body[11:]
                box = read_box_header(manifest_bytes, 0)
                if box is not None and box.box_type == b"jumb":
                    return manifest_bytes
        elif marker == 0x2C:  # Image Descriptor
            if pos + 10 > len(raw):
                break
            local_flags = raw[pos + 9]
            pos += 10
            if local_flags & 0x80:  # local color table
                pos += 3 * (2 ** ((local_flags & 0x07) + 1))
            pos += 1  # LZW minimum code size
            _, pos = _read_gif_subblocks(raw, pos)  # compressed image data
        else:  # 0x3B trailer, or malformed -- nothing more to find
            break
    return None


_TIFF_C2PA_TAG = 0xCD41  # decimal 52545, ISO/IEC and C2PA spec Annex A.3.6


def extract_from_tiff(raw: bytes) -> bytes | None:
    """Return the C2PA Manifest Store from a TIFF-based (or DNG/TIFF-EP RAW)
    file's tag 0xCD41, located in the last IFD of the main-IFD chain."""
    if len(raw) < 8 or raw[:2] not in (b"II", b"MM"):
        return None
    endian = "<" if raw[:2] == b"II" else ">"
    if struct.unpack_from(f"{endian}H", raw, 2)[0] != 42:
        return None

    ifd_offset = struct.unpack_from(f"{endian}I", raw, 4)[0]
    last_ifd = None
    seen: set[int] = set()
    while ifd_offset and ifd_offset not in seen and ifd_offset + 2 <= len(raw):
        seen.add(ifd_offset)
        last_ifd = ifd_offset
        count = struct.unpack_from(f"{endian}H", raw, ifd_offset)[0]
        next_pos = ifd_offset + 2 + count * 12
        if next_pos + 4 > len(raw):
            break
        ifd_offset = struct.unpack_from(f"{endian}I", raw, next_pos)[0]
    if last_ifd is None:
        return None

    count = struct.unpack_from(f"{endian}H", raw, last_ifd)[0]
    pos = last_ifd + 2
    for _ in range(min(count, 512)):
        if pos + 12 > len(raw):
            break
        tag, _dtype, dcount = struct.unpack_from(f"{endian}HHI", raw, pos)
        val_raw = raw[pos + 8:pos + 12]
        pos += 12
        if tag != _TIFF_C2PA_TAG:
            continue
        if dcount <= 4:
            data = val_raw[:dcount]
        else:
            voff = struct.unpack_from(f"{endian}I", val_raw)[0]
            if voff + dcount > len(raw):
                return None
            data = raw[voff:voff + dcount]
        box = read_box_header(data, 0)
        return data if box is not None and box.box_type == b"jumb" else None
    return None


# 16-byte ISOBMFF 'uuid' box extended-type for a C2PA box (C2PA spec Annex
# A.5.1.1), verified against contentauth/c2pa-rs's C2PA_UUID constant.
_BMFF_C2PA_EXTENDED_TYPE = bytes([
    0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
    0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
])


def extract_from_bmff(raw: bytes) -> bytes | None:
    """Return the C2PA Manifest Store from a BMFF-based file's top-level
    'uuid' box (HEIF/HEIC/AVIF; also MP4/M4A, not currently opened by Crush
    as images). Only the box_purpose == "manifest" case is handled --
    "original"/"update" (update-manifest chains) and "merkle" (auxiliary
    hash-tree boxes) are out of scope for a presence/summary check."""
    pos = 0
    while pos < len(raw):
        box = read_box_header(raw, pos)
        if box is None:
            break
        if box.box_type == b"uuid":
            content = raw[box.content_start:box.content_end]
            # extended_type (16B) + FullBox version/flags (4B) precede box_purpose
            if len(content) >= 20 and content[:16] == _BMFF_C2PA_EXTENDED_TYPE:
                rest = content[20:]
                nul = rest.find(b"\x00")
                if nul >= 0:
                    purpose = rest[:nul].decode("ascii", errors="replace")
                    payload = rest[nul + 1:]
                    if purpose == "manifest" and len(payload) >= 8:
                        manifest_bytes = payload[8:]  # skip the merkle-offset field
                        inner = read_box_header(manifest_bytes, 0)
                        if inner is not None and inner.box_type == b"jumb":
                            return manifest_bytes
        pos = box.content_end
    return None


_JXL_BOX_CONTAINER_SIG = bytes.fromhex("0000000c4a584c200d0a870a")  # ISO/IEC 18181-2


def extract_from_jpeg_xl(raw: bytes) -> bytes | None:
    """Return a box-form JPEG XL file's top-level JUMBF superbox, if present
    (C2PA spec Annex A.3.9). A bare JPEG XL codestream -- no box container --
    cannot carry a manifest at all, per spec, and is not handled here."""
    if raw[:12] != _JXL_BOX_CONTAINER_SIG:
        return None
    pos = 12
    while pos < len(raw):
        box = read_box_header(raw, pos)
        if box is None:
            break
        if box.box_type == b"jumb":
            return raw[box.box_start:box.content_end]
        pos = box.content_end
    return None
