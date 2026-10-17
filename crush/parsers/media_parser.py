# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Media parser — routes audio/video files to the media viewer."""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

_OGG_MAGIC = b"OggS"
_AMR_MAGIC = b"#!AMR"
# ASF header object GUID 75B22630-668E-11CF-A6D9-00AA0062CE6C (WMA, WMV),
# as stored (little-endian fields).
_ASF_HEADER_GUID = bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")


def _looks_like_media(peek: bytes) -> bool:
    """Audio or video by its first bytes, each from its format's spec. An
    MPEG audio stream without an ID3v2 tag (and AAC in ADTS) begins with a
    bare frame sync of 11/12 bits, which plenty of other data matches too,
    so it is left to the file name."""
    from crush.parsers.image_parser import _looks_like_image

    if len(peek) < 4:
        return False
    if peek[:4] == _OGG_MAGIC or peek[:5] == _AMR_MAGIC:
        return True
    # ISO/IEC 14496-12: the file opens with its ftyp box (MP4, MOV, M4A,
    # 3GP ...). An image brand (HEIC, AVIF ...) is the ImageParser's.
    if len(peek) >= 12 and peek[4:8] == b"ftyp":
        return not _looks_like_image(peek)
    # RIFF: WAVE audio, AVI video (WebP, also RIFF, is an image).
    if len(peek) >= 12 and peek[:4] == b"RIFF" and peek[8:12] in (b"WAVE", b"AVI "):
        return True
    if peek[:4] == b"fLaC":  # FLAC stream marker
        return True
    if peek[:4] == b"\x1a\x45\xdf\xa3":  # EBML header (RFC 8794): Matroska, WebM
        return True
    if peek[:16] == _ASF_HEADER_GUID:
        return True
    # ID3v2 tag (id3v2.4.0-structure 3.1): "ID3", two version bytes below
    # 0xFF, flags, and a size of four bytes below 0x80 each.
    return (
        len(peek) >= 10 and peek[:3] == b"ID3" and peek[3] < 0xFF and peek[4] < 0xFF
        and all(b < 0x80 for b in peek[6:10])
    )


def _extract_audio_metadata(data: bytes) -> dict[str, Any]:
    """Extract codec info and Vorbis/Opus tags from OGG/Opus/AMR via PyAV.
    When nothing can be read, a "Metadata" row says why."""
    try:
        import av
        import av.container
    except ImportError:
        return {"Metadata": ParseIssue("media.pyav_missing")}
    try:
        container = av.open(io.BytesIO(data))
        if not isinstance(container, av.container.InputContainer):
            return {"Metadata": ParseIssue("media.metadata_failed", detail="not an input container")}
        if not container.streams.audio:
            return {"Metadata": ParseIssue("media.no_audio_stream")}
        stream = container.streams.audio[0]
        meta: dict[str, Any] = {}

        codec = stream.codec_context.name if stream.codec_context else ""
        if codec:
            meta["Codec"] = codec.upper()
        if stream.rate:
            meta["Sample rate"] = f"{stream.rate:,} Hz"
        if stream.channels:
            ch = stream.channels
            meta["Channels"] = "Mono" if ch == 1 else "Stereo" if ch == 2 else f"{ch}"
        dur = container.duration
        if dur and dur > 0:
            s = dur // 1_000_000
            meta["Duration"] = f"{s // 60}:{s % 60:02d}"

        # Vorbis comments / Opus tags — forensically: encoder reveals origin app
        tags: dict[str, str] = {}
        tags.update({k.lower(): v for k, v in container.metadata.items()})
        tags.update({k.lower(): v for k, v in stream.metadata.items()})

        _WANTED = {
            "encoder": "Encoder",
            "title": "Title",
            "artist": "Artist",
            "album": "Album",
            "date": "Date",
            "comment": "Comment",
            "creation_time": "Creation time",
        }
        for src, label in _WANTED.items():
            val = tags.get(src)
            if val:
                meta[label] = val

        return meta
    except Exception as exc:
        return {"Metadata": ParseIssue("media.metadata_failed", detail=str(exc))}


class MediaParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [
        # Audio
        ".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wma", ".amr",
        # Video
        ".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm", ".3gp", ".3g2",
    ]
    DISPLAY_NAME = "Media (Audio/Video)"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        ext = Path(path).suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return True
        # Renamed, carved or exported without an extension (a voice note
        # saved as .bin, a video named by its hash).
        return _looks_like_media(peek_bytes)

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        meta: dict[str, Any] = {
            "Format": "Media",
            "File size": f"{node.size:,} B",
        }
        if raw[:4] == _OGG_MAGIC or raw[:5] == _AMR_MAGIC:
            meta.update(_extract_audio_metadata(raw))
        else:
            meta["Metadata"] = ParseIssue("media.metadata_not_checked")
        return ParseResult(viewer_type="media", data=raw, metadata=meta)
