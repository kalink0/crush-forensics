# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ID3v2 tag reader: walks the frames of an ID3v2.2, 2.3 or 2.4 tag at the
start of a file and decodes GEOB (General Encapsulated Object) frames.

Frame walking only -- what a frame means is the caller's job. Layouts follow
the ID3 informal standards (id3v2-00 for 2.2, id3v2.3.0, id3v2.4.0-structure
and id3v2.4.0-frames):

- 2.2: 3-character frame IDs, 3-byte frame sizes, no frame flags.
- 2.3: 4-character IDs, plain 32-bit sizes, frame flags (compression adds a
  4-byte decompressed size, encryption a method byte, grouping a group byte).
- 2.4: 4-character IDs, syncsafe sizes, frame flags (grouping byte, then
  encryption method byte, then a 4-byte data length indicator).

Unsynchronisation (every 0xFF 0x00 stands for 0xFF) covers the whole tag
after its header in 2.2/2.3 and each frame's data in 2.4. Offsets reported
here are always file offsets, also inside an unsynchronised 2.2/2.3 tag.
Compressed or encrypted frames are reported as such, their data is not
decoded.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field

_HEADER_LEN = 10


@dataclass(frozen=True)
class Id3Frame:
    frame_id: str
    offset: int  # file offset of the frame header
    data: bytes | None  # frame content; None when compressed or encrypted
    compressed: bool = False
    encrypted: bool = False


@dataclass
class Id3Tag:
    version: int  # major version: 2, 3 or 4 (anything else: unsupported)
    frames: list[Id3Frame] = field(default_factory=list)
    unsupported_version: bool = False
    tag_compressed: bool = False  # ID3v2.2 header flag: no compression scheme was ever defined
    stopped_at: int | None = None  # file offset where frame walking stopped early
    truncated: bool = False  # True: ran past the end of the data; False: invalid structure


def _syncsafe(b: bytes) -> int | None:
    if any(x & 0x80 for x in b):
        return None
    value = 0
    for x in b:
        value = (value << 7) | x
    return value


def _unsync_decode(data: bytes) -> tuple[bytes, list[int]]:
    """Undo unsynchronisation. Also returns, for every removed 0x00, the
    decoded index of the 0xFF before it, to map positions back."""
    if b"\xff\x00" not in data:
        return data, []
    parts = data.split(b"\xff\x00")
    marks: list[int] = []
    pos = 0
    for part in parts[:-1]:
        pos += len(part)
        marks.append(pos)
        pos += 1
    return b"\xff".join(parts), marks


def _is_frame_id(raw: bytes) -> bool:
    return all(0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A for c in raw)


def has_id3v2_header(raw: bytes) -> bool:
    """"ID3", two version bytes below 0xFF, flags, and a syncsafe size
    (id3v2.4.0-structure 3.1)."""
    return (
        len(raw) >= _HEADER_LEN and raw[:3] == b"ID3" and raw[3] < 0xFF and raw[4] < 0xFF
        and all(b < 0x80 for b in raw[6:10])
    )


def read_id3v2(raw: bytes) -> Id3Tag | None:
    """The frames of the ID3v2 tag at offset 0, or None without one."""
    if not has_id3v2_header(raw):
        return None
    major, flags = raw[3], raw[5]
    tag = Id3Tag(version=major)
    if major not in (2, 3, 4):
        tag.unsupported_version = True
        return tag
    size = _syncsafe(raw[6:10]) or 0
    tag_end = _HEADER_LEN + size
    tag_cut = tag_end > len(raw)  # the tag declares more bytes than the data holds

    if major == 2 and flags & 0x40:
        tag.tag_compressed = True
        return tag

    whole_unsync = bool(flags & 0x80) and major in (2, 3)
    body = raw[_HEADER_LEN:min(tag_end, len(raw))]
    marks: list[int] = []
    if whole_unsync:
        body, marks = _unsync_decode(body)

    def file_offset(pos: int) -> int:
        return _HEADER_LEN + pos + bisect_left(marks, pos)

    def stop(pos: int, past_end: bool) -> Id3Tag:
        tag.stopped_at = file_offset(pos)
        tag.truncated = past_end and tag_cut
        return tag

    pos = 0
    if flags & 0x40 and major in (3, 4):  # extended header
        if len(body) < 4:
            return stop(0, True)
        if major == 3:
            ext_len = 4 + int.from_bytes(body[0:4], "big")  # size excludes itself
        else:
            ext_size = _syncsafe(body[0:4])
            if ext_size is None or ext_size < 6:
                return stop(0, False)
            ext_len = ext_size  # size includes itself
        if ext_len > len(body):
            return stop(0, True)
        pos = ext_len

    id_len, hdr_len = (3, 6) if major == 2 else (4, 10)
    while pos < len(body):
        if body[pos] == 0:
            break  # padding
        if pos + hdr_len > len(body):
            return stop(pos, True)
        frame_id = body[pos:pos + id_len]
        if not _is_frame_id(frame_id):
            return stop(pos, False)
        if major == 2:
            frame_size = int.from_bytes(body[pos + 3:pos + 6], "big")
            fmt = 0
        elif major == 3:
            frame_size = int.from_bytes(body[pos + 4:pos + 8], "big")
            fmt = body[pos + 9]
        else:
            synced = _syncsafe(body[pos + 4:pos + 8])
            if synced is None:
                return stop(pos, False)
            frame_size = synced
            fmt = body[pos + 9]
        start = pos + hdr_len
        end = start + frame_size
        if end > len(body):
            return stop(pos, True)
        frame = _frame(major, frame_id.decode("ascii"), file_offset(pos), fmt,
                       body[start:end], bool(flags & 0x80))
        if frame is None:
            return stop(pos, False)
        tag.frames.append(frame)
        pos = end
    return tag


def _frame(
    major: int, frame_id: str, offset: int, fmt: int, content: bytes, tag_unsync: bool,
) -> Id3Frame | None:
    """One frame's content with the flag-added header bytes removed; None
    when those bytes don't fit into the frame."""
    if major == 3:
        compressed, encrypted = bool(fmt & 0x80), bool(fmt & 0x40)
        skip = (4 if compressed else 0) + (1 if encrypted else 0) + (1 if fmt & 0x20 else 0)
        unsync = False  # 2.3: the whole tag was already decoded
    elif major == 4:
        compressed, encrypted = bool(fmt & 0x08), bool(fmt & 0x04)
        skip = (1 if fmt & 0x40 else 0) + (1 if encrypted else 0) + (4 if fmt & 0x01 else 0)
        unsync = bool(fmt & 0x02) or tag_unsync
    else:
        compressed = encrypted = False
        skip, unsync = 0, False
    if skip > len(content):
        return None
    if compressed or encrypted:
        return Id3Frame(frame_id, offset, None, compressed, encrypted)
    data = content[skip:]
    if unsync:
        data, _ = _unsync_decode(data)
    return Id3Frame(frame_id, offset, data)


@dataclass(frozen=True)
class Geob:
    mime_type: str
    filename: bytes
    description: bytes
    data: bytes


_TERMINATORS = {0: b"\x00", 1: b"\x00\x00", 2: b"\x00\x00", 3: b"\x00"}


def _terminated(data: bytes, start: int, term: bytes) -> int:
    """Index of *term* at or after *start*, aligned to its width; -1 if none."""
    if len(term) == 1:
        return data.find(term, start)
    pos = start
    while pos + 1 < len(data):
        if data[pos] == 0 and data[pos + 1] == 0:
            return pos
        pos += 2
    return -1


def parse_geob(data: bytes) -> Geob | None:
    """A GEOB/GEO frame's fields: text encoding byte, MIME type
    (ISO-8859-1, 0x00-terminated), filename and description (in the frame's
    encoding: ISO-8859-1 / UTF-8 end with 0x00, UTF-16 with BOM / UTF-16BE
    with 0x00 0x00), then the object. None when the encoding byte is not
    one of those four or a field is not terminated."""
    if not data or data[0] not in _TERMINATORS:
        return None
    term = _TERMINATORS[data[0]]
    mime_end = data.find(b"\x00", 1)
    if mime_end < 0:
        return None
    name_end = _terminated(data, mime_end + 1, term)
    if name_end < 0:
        return None
    desc_end = _terminated(data, name_end + len(term), term)
    if desc_end < 0:
        return None
    return Geob(
        mime_type=data[1:mime_end].decode("latin-1"),
        filename=data[mime_end + 1:name_end],
        description=data[name_end + len(term):desc_end],
        data=data[desc_end + len(term):],
    )
