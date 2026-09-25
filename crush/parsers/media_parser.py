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
        # Catch renamed audio files (e.g. voice notes saved as .bin)
        if peek_bytes[:4] == _OGG_MAGIC:
            return True
        if peek_bytes[:5] == _AMR_MAGIC:
            return True
        return False

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
