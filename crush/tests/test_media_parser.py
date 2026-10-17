# SPDX-License-Identifier: Apache-2.0
"""Tests for MediaParser."""
from __future__ import annotations

from pathlib import Path

import pytest

from crush.core.vfs import DirectoryVFS
from crush.parsers.media_parser import MediaParser

_OGG_STUB = b"OggS" + b"\x00" * 60
_AMR_NB_STUB = b"#!AMR\n" + b"\x00" * 60
_AMR_WB_STUB = b"#!AMR-WB\n" + b"\x00" * 60

_AUDIO_EXTENSIONS = [".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wma", ".amr"]
_VIDEO_EXTENSIONS = [".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm", ".3gp", ".3g2"]


def _make_node(tmp_path: Path, name: str, data: bytes):
    (tmp_path / name).write_bytes(data)
    vfs = DirectoryVFS(tmp_path)
    return next(c for c in vfs.root().children if c.name == name), vfs


# ---------------------------------------------------------------------------
# can_parse — extension matching
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ext", _AUDIO_EXTENSIONS)
def test_can_parse_audio_by_extension(tmp_path: Path, ext: str) -> None:
    name = f"test{ext}"
    (tmp_path / name).write_bytes(b"\x00" * 32)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    assert MediaParser().can_parse(node.path, vfs.peek(node))


@pytest.mark.parametrize("ext", _VIDEO_EXTENSIONS)
def test_can_parse_video_by_extension(tmp_path: Path, ext: str) -> None:
    name = f"test{ext}"
    (tmp_path / name).write_bytes(b"\x00" * 32)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    assert MediaParser().can_parse(node.path, vfs.peek(node))


# ---------------------------------------------------------------------------
# can_parse — magic byte fallback (renamed / extensionless files)
# ---------------------------------------------------------------------------

def test_can_parse_ogg_magic_renamed_to_bin(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "voice_note.bin", _OGG_STUB)
    assert MediaParser().can_parse(node.path, vfs.peek(node))


def test_can_parse_amr_nb_magic_renamed_to_bin(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "recording.bin", _AMR_NB_STUB)
    assert MediaParser().can_parse(node.path, vfs.peek(node))


def test_can_parse_amr_wb_magic_renamed_to_bin(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "recording.bin", _AMR_WB_STUB)
    assert MediaParser().can_parse(node.path, vfs.peek(node))


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Audio/video",
    desc="Audio and video files renamed without their extension are recognised by their "
    "content: ISO base media (MP4/MOV/M4A/3GP), WAV, AVI, FLAC, Matroska/WebM, ASF, MP3 with ID3v2",
)
@pytest.mark.parametrize(("label", "head"), [
    ("MP4", b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"),
    ("MOV", b"\x00\x00\x00\x14ftypqt  \x00\x00\x02\x00"),
    ("M4A", b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00"),
    ("3GP", b"\x00\x00\x00\x18ftyp3gp4\x00\x00\x00\x00"),
    ("WAV", b"RIFF\x24\x00\x00\x00WAVEfmt "),
    ("AVI", b"RIFF\x24\x00\x00\x00AVI LIST"),
    ("FLAC", b"fLaC\x00\x00\x00\x22"),
    ("Matroska/WebM", b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81"),
    ("ASF", bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")),
    ("MP3 with ID3v2", b"ID3\x04\x00\x00\x00\x00\x0f\x76"),
])
def test_can_parse_media_by_content(tmp_path: Path, label: str, head: bytes) -> None:
    from crush.core.registry import ParserRegistry

    node, vfs = _make_node(tmp_path, "evidence.bin", head + b"\x00" * 64)
    assert MediaParser().can_parse(node.path, vfs.peek(node)), label
    assert isinstance(ParserRegistry.best(node, vfs), MediaParser), label


@pytest.mark.parametrize(("label", "head"), [
    # An image brand is the Image Viewer's.
    ("HEIC", b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00"),
    ("WebP", b"RIFF\x24\x00\x00\x00WEBPVP8 "),
    # A bare MPEG audio frame sync: 11 bits that much other data has too.
    ("MP3 frame sync", b"\xff\xfb\x90\x64\x00\x00\x00\x00"),
    # "ID3" whose size bytes break the syncsafe rule is no ID3v2 tag.
    ("not ID3v2", b"ID3\x04\x00\x00\xff\x00\x00\x00"),
])
def test_not_claimed_by_content(tmp_path: Path, label: str, head: bytes) -> None:
    node, vfs = _make_node(tmp_path, "evidence.bin", head + b"\x00" * 64)
    assert not MediaParser().can_parse(node.path, vfs.peek(node)), label


def test_cannot_parse_unknown_extension_no_magic(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "data.xyz", b"\x00" * 32)
    assert not MediaParser().can_parse(node.path, vfs.peek(node))


# ---------------------------------------------------------------------------
# parse — viewer type and raw data integrity
# ---------------------------------------------------------------------------

def test_parse_viewer_type_is_media(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "test.mp3", b"\xff\xfb" + b"\x00" * 100)
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"


def test_parse_preserves_raw_data(tmp_path: Path) -> None:
    payload = b"\xff\xfb" + b"\xAA\xBB\xCC\xDD" * 25
    node, vfs = _make_node(tmp_path, "test.mp3", payload)
    result = MediaParser().parse(node, vfs)
    assert result.data == payload


def test_parse_metadata_contains_file_size(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "test.mp4", b"\x00\x00\x00\x20ftyp" + b"\x00" * 100)
    result = MediaParser().parse(node, vfs)
    assert "File size" in result.metadata


@pytest.mark.parametrize("ext,data", [
    (".mp3", b"\xff\xfb" + b"\x00" * 32),
    (".wav", b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 32),
    (".flac", b"fLaC" + b"\x00" * 32),
    (".mp4", b"\x00\x00\x00\x20ftyp" + b"\x00" * 32),
    (".mkv", b"\x1a\x45\xdf\xa3" + b"\x00" * 32),
    (".avi", b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 32),
])
def test_parse_various_formats_return_media_viewer(tmp_path: Path, ext: str, data: bytes) -> None:
    node, vfs = _make_node(tmp_path, f"test{ext}", data)
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"
    assert result.data == data


# ---------------------------------------------------------------------------
# parse — OGG/AMR metadata extraction (PyAV path)
# ---------------------------------------------------------------------------

def test_parse_ogg_stub_does_not_crash(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "voice.ogg", _OGG_STUB)
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"
    assert isinstance(result.metadata, dict)
    assert "File size" in result.metadata


def test_parse_amr_stub_does_not_crash(tmp_path: Path) -> None:
    node, vfs = _make_node(tmp_path, "recording.amr", _AMR_NB_STUB)
    result = MediaParser().parse(node, vfs)
    assert result.viewer_type == "media"
    assert isinstance(result.metadata, dict)
