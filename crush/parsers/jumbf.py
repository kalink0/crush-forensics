# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""JUMBF (JPEG Universal Metadata Box Format, ISO/IEC 19566-5) box reader.

Generic box-walking only -- decoding what's inside a box (CBOR, JSON, ...)
is the caller's job. Used to locate the C2PA Manifest Store embedded in an
image, audio or video file (see crush/parsers/c2pa_reader.py); the
byte-level box layout and the JPEG APP11 fragmentation scheme below were
verified against real, C2PA-org-published sample files, not just the
written spec.

Every container extractor returns a ScanResult: each Manifest Store found
(with the file offset of the element carrying it), notes on C2PA data that
was found but not evaluated, and where the scan stopped when the structure
ended early -- so "no store found" is only ever reported for a structure
that was read to its end.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from crush.core.issues import ParseIssue
from crush.parsers import id3v2

# JUMBF Description box (TBox 'jumd') toggle bits (ISO/IEC 19566-5, Annex A.3.1)
_TOGGLE_LABEL_PRESENT = 0x02

MANIFEST_STORE_LABEL = "c2pa"


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


def box_runs_past_end(data: bytes, pos: int) -> bool:
    """For a box read_box_header() rejected: True when its header or
    declared length runs past the end of *data*, False when the declared
    length is smaller than the header itself (invalid, not cut off)."""
    if pos + 8 > len(data):
        return True
    lbox = int.from_bytes(data[pos:pos + 4], "big")
    header_len = 8
    if lbox == 1:
        if pos + 16 > len(data):
            return True
        lbox = int.from_bytes(data[pos + 8:pos + 16], "big")
        header_len = 16
    return lbox >= header_len


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


def _superbox_label(data: bytes, pos: int) -> str | None:
    """Label of the 'jumb' superbox starting at *pos* (read from its first
    child, the Description box), even when the superbox's own declared
    length runs past the data. None when *pos* holds no 'jumb' + 'jumd'."""
    if data[pos + 4:pos + 8] != b"jumb":
        return None
    header_len = 16 if data[pos:pos + 4] == b"\x00\x00\x00\x01" else 8
    jumd = read_box_header(data, pos + header_len)
    if jumd is None or jumd.box_type != b"jumd":
        return None
    return read_description(data, jumd.content_start)[1]


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StoreHit:
    data: bytes  # the JUMBF Manifest Store (plus any padding the container allows after it)
    offset: int  # file offset of the element carrying it (segment, chunk, box, frame, IFD entry, page)
    purpose: str = ""  # BMFF box_purpose ("manifest", "original", "update"); empty elsewhere


@dataclass
class ScanResult:
    stores: list[StoreHit] = field(default_factory=list)
    notes: list[ParseIssue] = field(default_factory=list)  # C2PA data found, not evaluated
    merkle_offsets: list[int] = field(default_factory=list)  # BMFF C2PA 'merkle' boxes
    stopped_at: int | None = None  # file offset where the structure ended early
    truncated: bool = False  # True: ran past the end of the data; False: invalid structure

    def stop(self, offset: int, truncated: bool) -> None:
        self.stopped_at = offset
        self.truncated = truncated

    def accept(self, payload: bytes, offset: int, item: str, purpose: str = "") -> None:
        """Record *payload* as a Manifest Store if it starts with a complete
        'jumb' superbox, otherwise note why it was not evaluated."""
        box = read_box_header(payload, 0)
        if box is not None and box.box_type == b"jumb":
            self.stores.append(StoreHit(payload, offset, purpose))
        elif payload[4:8] == b"jumb" and box_runs_past_end(payload, 0):
            self.notes.append(ParseIssue("c2pa.store_exceeds_item", {"item": item, "offset": offset}))
        else:
            self.notes.append(ParseIssue("c2pa.item_not_jumbf", {"item": item, "offset": offset}))


# ---------------------------------------------------------------------------
# Manifest-store extraction (per-container embedding rules, C2PA spec Annex A)
# ---------------------------------------------------------------------------

def extract_from_jpeg(raw: bytes) -> ScanResult:
    """Reassemble C2PA JUMBF streams from JPEG APP11 marker segments (A.3.1).

    Each APP11 payload is prefixed with CI (2B, "JP"), En (2B, Box Instance
    Number) and Z (4B, big-endian packet sequence number, 1-based); segments
    after the first duplicate the outer box's own 8-byte LBox+TBox, which
    must be stripped when reassembling (verified against real C2PA-org
    sample files, not just the ISO 19566-5 D.2 text). APP11 also carries
    JUMBF boxes that are not C2PA; only superboxes labelled "c2pa" count.
    """
    result = ScanResult()
    segments: dict[bytes, list[tuple[int, bytes, int]]] = {}
    pos = 2
    while pos < len(raw):
        if raw[pos] != 0xFF:
            result.stop(pos, False)
            break
        if pos + 2 > len(raw):
            result.stop(pos, True)
            break
        marker = raw[pos + 1]
        if marker == 0xFF:  # fill byte before a marker (ITU T.81 B.1.1.2)
            pos += 1
            continue
        if marker == 0xD9:  # End of Image
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue
        if marker == 0xDA:  # Start of Scan -- entropy-coded data follows
            break
        if pos + 4 > len(raw):
            result.stop(pos, True)
            break
        seg_len = int.from_bytes(raw[pos + 2:pos + 4], "big")
        if seg_len < 2:
            result.stop(pos, False)
            break
        if pos + 2 + seg_len > len(raw):
            result.stop(pos, True)
            break
        if marker == 0xEB:
            payload = raw[pos + 4:pos + 2 + seg_len]
            if len(payload) >= 8 and payload[0:2] == b"JP":
                en = payload[2:4]
                z = int.from_bytes(payload[4:8], "big")
                segments.setdefault(en, []).append((z, payload[8:], pos))
        pos += 2 + seg_len

    for parts in segments.values():
        parts.sort(key=lambda p: p[0])
        first_offset = min(p[2] for p in parts)
        if [z for z, _, _ in parts] != list(range(1, len(parts) + 1)):
            # Without a complete sequence the box (and its label) can't be
            # read, so whether it is C2PA stays open.
            result.notes.append(ParseIssue("c2pa.jpeg_sequence_gap", {"offset": first_offset}))
            continue
        stream = b"".join(body[8:] if i > 0 else body for i, (_, body, _) in enumerate(parts))
        if _superbox_label(stream, 0) != MANIFEST_STORE_LABEL:
            continue  # JUMBF, but not a C2PA Manifest Store
        result.accept(stream, first_offset, "JPEG APP11 segments")
    return result


def extract_from_png(raw: bytes) -> ScanResult:
    """Every 'caBX' ancillary chunk's data, the JUMBF stream directly (A.3.2)."""
    result = ScanResult()
    pos = 8
    while pos < len(raw):
        if pos + 8 > len(raw):
            result.stop(pos, True)
            break
        clen = int.from_bytes(raw[pos:pos + 4], "big")
        ctype = raw[pos + 4:pos + 8]
        if pos + 12 + clen > len(raw):  # length + type + data + CRC
            result.stop(pos, True)
            break
        if ctype == b"caBX":
            result.accept(raw[pos + 8:pos + 8 + clen], pos, "PNG 'caBX' chunk")
        elif ctype == b"IEND":
            break
        pos += 12 + clen
    return result


def extract_from_riff(raw: bytes) -> ScanResult:
    """Every 'C2PA' sub-chunk of the first RIFF chunk (A.3.7: WAV, AVI, WebP
    and other RIFF-based formats all use the same convention)."""
    result = ScanResult()
    if len(raw) < 12 or raw[:4] != b"RIFF":
        result.stop(0, len(raw) < 12)
        return result
    riff_end = 8 + int.from_bytes(raw[4:8], "little")
    if riff_end < 12:
        result.stop(0, False)
        return result
    pos = 12
    while pos < riff_end:
        if pos + 8 > len(raw):
            result.stop(pos, True)
            break
        if pos + 8 > riff_end:
            result.stop(pos, False)
            break
        chunk_id = raw[pos:pos + 4]
        size = int.from_bytes(raw[pos + 4:pos + 8], "little")
        if pos + 8 + size > len(raw):
            result.stop(pos, True)
            break
        if pos + 8 + size > riff_end:
            result.stop(pos, False)
            break
        if chunk_id == b"C2PA":
            result.accept(raw[pos + 8:pos + 8 + size], pos, "RIFF 'C2PA' chunk")
        pos += 8 + size + (size & 1)  # chunks are padded to an even length
    return result


def _read_gif_subblocks(raw: bytes, pos: int) -> tuple[bytes, int, bool]:
    """Read GIF length-prefixed sub-blocks up to the 0-length terminator.
    The flag is False when the data ends before the terminator."""
    out = bytearray()
    while pos < len(raw):
        n = raw[pos]
        pos += 1
        if n == 0:
            return bytes(out), pos, True
        if pos + n > len(raw):
            break
        out += raw[pos:pos + n]
        pos += n
    return bytes(out), pos, False


_GIF_C2PA_APP_ID = b"C2PA_GIF"
_GIF_C2PA_BLOCK_VERSION = bytes([0x01, 0x00, 0x00])  # 0x[Major][Minor]00, version 1.0


def extract_from_gif(raw: bytes) -> ScanResult:
    """Every C2PA Application Extension block's payload, per C2PA spec Annex
    A.3.8 (verified byte-for-byte against contentauth/c2pa-rs)."""
    result = ScanResult()
    if len(raw) < 13 or raw[:6] not in (b"GIF87a", b"GIF89a"):
        result.stop(0, len(raw) < 13)
        return result
    pos = 13
    flags = raw[10]
    if flags & 0x80:  # global color table present
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    if pos > len(raw):
        result.stop(13, True)
        return result

    while pos < len(raw):
        marker = raw[pos]
        if marker == 0x21:  # Extension Introducer
            if pos + 2 > len(raw):
                result.stop(pos, True)
                break
            label = raw[pos + 1]
            body, end, complete = _read_gif_subblocks(raw, pos + 2)
            if not complete:
                result.stop(pos, True)
                break
            if label == 0xFF and body[:8] == _GIF_C2PA_APP_ID:
                if body[8:11] == _GIF_C2PA_BLOCK_VERSION:
                    result.accept(body[11:], pos, "GIF C2PA Application Extension")
                else:
                    version = f"{body[8]}.{body[9]}" if len(body) >= 10 else body[8:].hex()
                    result.notes.append(ParseIssue(
                        "c2pa.gif_block_version", {"version": version, "offset": pos},
                    ))
            pos = end
        elif marker == 0x2C:  # Image Descriptor
            if pos + 10 > len(raw):
                result.stop(pos, True)
                break
            local_flags = raw[pos + 9]
            start = pos
            pos += 10
            if local_flags & 0x80:  # local color table
                pos += 3 * (2 ** ((local_flags & 0x07) + 1))
            pos += 1  # LZW minimum code size
            if pos > len(raw):
                result.stop(start, True)
                break
            _, pos, complete = _read_gif_subblocks(raw, pos)  # compressed image data
            if not complete:
                result.stop(start, True)
                break
        elif marker == 0x3B:  # Trailer
            break
        else:
            result.stop(pos, False)
            break
    return result


_TIFF_C2PA_TAG = 0xCD41  # decimal 52545, C2PA spec Annex A.3.6
_TIFF_BYTE, _TIFF_UNDEFINED = 1, 7  # one-byte field types


def extract_from_tiff(raw: bytes) -> ScanResult:
    """Every tag 0xCD41 in the main-IFD chain of a TIFF-based (or DNG/TIFF-EP
    RAW) file, classic TIFF or BigTIFF. The spec places it in the last IFD;
    earlier spec versions placed it in IFD 0, so every IFD of the chain is
    checked."""
    result = ScanResult()
    endian = "<" if raw[:2] == b"II" else ">"
    magic = struct.unpack_from(f"{endian}H", raw, 2)[0] if len(raw) >= 4 else 0
    if magic == 42 and len(raw) >= 8:
        count_fmt, entry_fmt, off_fmt = "H", "HHI", "I"
        ifd_offset = struct.unpack_from(f"{endian}I", raw, 4)[0]
    elif magic == 43 and len(raw) >= 16:  # BigTIFF: 8-byte offsets and counts
        count_fmt, entry_fmt, off_fmt = "Q", "HHQ", "Q"
        ifd_offset = struct.unpack_from(f"{endian}Q", raw, 8)[0]
    else:
        result.stop(0, len(raw) < 16)
        return result
    count_size = struct.calcsize(count_fmt)
    off_size = struct.calcsize(off_fmt)
    entry_size = 4 + 2 * off_size

    seen: set[int] = set()
    while ifd_offset:
        if ifd_offset in seen:  # the chain loops back
            result.stop(ifd_offset, False)
            break
        seen.add(ifd_offset)
        if ifd_offset + count_size > len(raw):
            result.stop(ifd_offset, True)
            break
        count = struct.unpack_from(f"{endian}{count_fmt}", raw, ifd_offset)[0]
        pos = ifd_offset + count_size
        for _ in range(count):
            if pos + entry_size > len(raw):
                break
            tag, dtype, dcount = struct.unpack_from(f"{endian}{entry_fmt}", raw, pos)
            if tag == _TIFF_C2PA_TAG:
                _tiff_c2pa_entry(raw, pos, dtype, dcount, endian, off_fmt, result)
            pos += entry_size
        next_pos = ifd_offset + count_size + count * entry_size
        if next_pos + off_size > len(raw):
            result.stop(ifd_offset, True)
            break
        ifd_offset = struct.unpack_from(f"{endian}{off_fmt}", raw, next_pos)[0]
    return result


def _tiff_c2pa_entry(
    raw: bytes, pos: int, dtype: int, dcount: int, endian: str, off_fmt: str,
    result: ScanResult,
) -> None:
    item = "TIFF tag 0xCD41"
    if dtype not in (_TIFF_UNDEFINED, _TIFF_BYTE):
        result.notes.append(ParseIssue("c2pa.tiff_tag_type", {"type": dtype, "offset": pos}))
        return
    off_size = struct.calcsize(off_fmt)
    value_pos = pos + 4 + off_size
    if dcount <= off_size:
        data = raw[value_pos:value_pos + dcount]
    else:
        voff = struct.unpack_from(f"{endian}{off_fmt}", raw, value_pos)[0]
        if voff + dcount > len(raw):
            result.notes.append(ParseIssue("c2pa.item_truncated", {"item": item, "offset": pos}))
            return
        data = raw[voff:voff + dcount]
    result.accept(data, pos, item)


# 16-byte ISOBMFF 'uuid' box extended-type for a C2PA box (C2PA spec Annex
# A.5.1.1), verified against contentauth/c2pa-rs's C2PA_UUID constant.
_BMFF_C2PA_EXTENDED_TYPE = bytes([
    0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
    0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
])
_BMFF_STORE_PURPOSES = ("manifest", "original", "update")


def extract_from_bmff(raw: bytes) -> ScanResult:
    """Every top-level C2PA 'uuid' box of a BMFF-based file (A.5: MP4, MOV,
    M4A, 3GP, HEIF/HEIC/AVIF, ...). box_purpose "manifest" and "original"
    carry an 8-byte merkle offset before the store; "update" is read the
    same way, as contentauth/c2pa-rs writes and reads it. "merkle" boxes
    hold hash data, not a store, and are listed by offset."""
    result = ScanResult()
    pos = 0
    while pos < len(raw):
        box = read_box_header(raw, pos)
        if box is None:
            result.stop(pos, box_runs_past_end(raw, pos))
            break
        if box.box_type == b"uuid" and raw[box.content_start:box.content_start + 16] == _BMFF_C2PA_EXTENDED_TYPE:
            _bmff_c2pa_box(raw[box.content_start + 16:box.content_end], pos, result)
        pos = box.content_end
    return result


def _bmff_c2pa_box(content: bytes, offset: int, result: ScanResult) -> None:
    rest = content[4:]  # FullBox version/flags precede box_purpose
    nul = rest.find(b"\x00")
    if len(content) < 4 or nul < 0:
        result.notes.append(ParseIssue("c2pa.bmff_no_purpose", {"offset": offset}))
        return
    purpose = rest[:nul].decode("utf-8", errors="replace")
    payload = rest[nul + 1:]
    if purpose in _BMFF_STORE_PURPOSES:
        item = f"BMFF C2PA 'uuid' box (box_purpose '{purpose}')"
        if len(payload) < 8:
            result.notes.append(ParseIssue("c2pa.item_not_jumbf", {"item": item, "offset": offset}))
            return
        result.accept(payload[8:], offset, item, purpose)  # skip the merkle-offset field
    elif purpose == "merkle":
        result.merkle_offsets.append(offset)
    else:
        result.notes.append(ParseIssue(
            "c2pa.bmff_unknown_purpose", {"purpose": purpose, "offset": offset},
        ))


_JXL_BOX_CONTAINER_SIG = bytes.fromhex("0000000c4a584c200d0a870a")  # ISO/IEC 18181-2


def extract_from_jpeg_xl(raw: bytes) -> ScanResult:
    """Every top-level JUMBF superbox labelled "c2pa" of a box-form JPEG XL
    file (A.3.9). A bare JPEG XL codestream -- no box container -- cannot
    carry a manifest at all, per spec, and is not handled here. A 'brob'
    box holding a Brotli-compressed 'jumb' is noted, not decompressed."""
    result = ScanResult()
    if raw[:12] != _JXL_BOX_CONTAINER_SIG:
        result.stop(0, len(raw) < 12)
        return result
    pos = 12
    while pos < len(raw):
        box = read_box_header(raw, pos)
        if box is None:
            result.stop(pos, box_runs_past_end(raw, pos))
            break
        if box.box_type == b"jumb":
            if _superbox_label(raw, pos) == MANIFEST_STORE_LABEL:
                result.accept(raw[box.box_start:box.content_end], pos, "JPEG XL 'jumb' box")
        elif box.box_type == b"brob" and raw[box.content_start:box.content_start + 4] == b"jumb":
            result.notes.append(ParseIssue(
                "c2pa.item_compressed",
                {"item": "JPEG XL 'brob' box (Brotli-compressed 'jumb')", "offset": pos},
            ))
        pos = box.content_end
    return result


# JUMBF media type (C2PA spec 11.4) and its deprecated predecessor, which
# contentauth/c2pa-rs still reads.
_C2PA_MIME_TYPES = ("application/c2pa", "application/x-c2pa-manifest-store")


def extract_from_id3(raw: bytes) -> ScanResult:
    """Every GEOB frame with the C2PA media type in the ID3v2 tag at the
    start of the file (A.3.4: MP3, and FLAC with a prepended ID3v2 tag)."""
    result = ScanResult()
    tag = id3v2.read_id3v2(raw)
    if tag is None:
        result.stop(0, len(raw) < 10)
        return result
    if tag.unsupported_version:
        result.notes.append(ParseIssue("c2pa.id3_version_unsupported", {"version": tag.version}))
        return result
    if tag.tag_compressed:
        result.notes.append(ParseIssue("c2pa.id3_tag_compressed"))
        return result
    for frame in tag.frames:
        if frame.frame_id not in ("GEOB", "GEO"):
            continue
        item = f"ID3 {frame.frame_id} frame"
        if frame.compressed or frame.encrypted:
            code = "c2pa.item_compressed" if frame.compressed else "c2pa.item_encrypted"
            result.notes.append(ParseIssue(code, {"item": item, "offset": frame.offset}))
            continue
        geob = id3v2.parse_geob(frame.data or b"")
        if geob is None:
            result.notes.append(ParseIssue("c2pa.id3_geob_malformed", {"item": item, "offset": frame.offset}))
            continue
        if geob.mime_type.lower() in _C2PA_MIME_TYPES:  # media types are case-insensitive (RFC 2045)
            result.accept(geob.data, frame.offset, f"{item} ({geob.mime_type})")
    if tag.stopped_at is not None:
        result.stop(tag.stopped_at, tag.truncated)
    return result


_OGG_C2PA_PREFIX = b"\x00c2pa"


@dataclass
class _OggStream:
    offset: int  # file offset of the stream's first (BOS) page
    packet: bytearray = field(default_factory=bytearray)
    complete: bool = False


def extract_from_ogg(raw: bytes) -> ScanResult:
    """Every logical bitstream whose first packet starts with \\x00c2pa
    (A.3.5, C2PA spec 2.4); the Manifest Store is the rest of that packet.
    Pages follow RFC 3533: 27-byte header, segment table, body; a packet
    ends with the first lacing value below 255 and may continue on the
    stream's next page."""
    result = ScanResult()
    streams: dict[int, _OggStream] = {}
    earlier: list[_OggStream] = []  # streams of earlier links in a chained file
    pos = 0
    while pos < len(raw):
        if pos + 27 > len(raw):
            result.stop(pos, True)
            break
        if raw[pos:pos + 4] != b"OggS" or raw[pos + 4] != 0:
            result.stop(pos, False)
            break
        header_type = raw[pos + 5]
        serial = int.from_bytes(raw[pos + 14:pos + 18], "little")
        nseg = raw[pos + 26]
        body = pos + 27 + nseg
        if body > len(raw):
            result.stop(pos, True)
            break
        lacing = raw[pos + 27:body]
        end = body + sum(lacing)
        if end > len(raw):
            result.stop(pos, True)
            break
        if header_type & 0x02:  # beginning of stream: its first packet starts here
            if serial in streams:
                earlier.append(streams[serial])
            streams[serial] = _OggStream(pos)
        stream = streams.get(serial)
        if stream is not None and not stream.complete:
            seg = body
            for value in lacing:
                stream.packet += raw[seg:seg + value]
                seg += value
                if value < 255:
                    stream.complete = True
                    break
            if len(stream.packet) >= len(_OGG_C2PA_PREFIX) and not stream.packet.startswith(_OGG_C2PA_PREFIX):
                del streams[serial]  # not a C2PA stream; its packets are not needed
        pos = end

    for stream in sorted([*earlier, *streams.values()], key=lambda s: s.offset):
        if not stream.packet.startswith(_OGG_C2PA_PREFIX):
            continue
        if not stream.complete:
            if result.stopped_at is None:
                result.stop(stream.offset, True)
            continue
        result.accept(bytes(stream.packet[len(_OGG_C2PA_PREFIX):]), stream.offset, "Ogg C2PA logical bitstream")
    return result
