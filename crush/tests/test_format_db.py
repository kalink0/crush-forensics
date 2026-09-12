# SPDX-License-Identifier: Apache-2.0
"""Tests for FormatDatabase and encoding detection."""
from __future__ import annotations

import pytest

from crush.core.format_db import FormatDatabase, FormatMatch

# ---------------------------------------------------------------------------
# FormatDatabase — singleton
# ---------------------------------------------------------------------------

def test_format_db_singleton() -> None:
    a = FormatDatabase.get()
    b = FormatDatabase.get()
    assert a is b


def test_format_db_all_formats_nonempty() -> None:
    formats = FormatDatabase.get().all_formats()
    assert len(formats) > 0
    assert all(isinstance(f, FormatMatch) for f in formats)


def test_format_db_all_formats_have_names() -> None:
    for fmt in FormatDatabase.get().all_formats():
        assert fmt.name, f"Format with empty name: {fmt}"


# ---------------------------------------------------------------------------
# FormatDatabase.identify() — magic bytes
# ---------------------------------------------------------------------------

_SQLITE_MAGIC = b"SQLite format 3\x00" + b"\x00" * 512

def test_identify_sqlite_by_magic() -> None:
    fmt = FormatDatabase.get().identify(_SQLITE_MAGIC, "unknown_file")
    assert fmt is not None
    assert "SQLite" in fmt.name


def test_identify_sqlite_has_parser_class() -> None:
    fmt = FormatDatabase.get().identify(_SQLITE_MAGIC, "unknown_file")
    assert fmt is not None
    assert fmt.parser_class == "SQLiteParser"


def test_identify_sqlite_has_platforms() -> None:
    fmt = FormatDatabase.get().identify(_SQLITE_MAGIC, "unknown_file")
    assert fmt is not None
    assert fmt.platforms  # non-empty


def test_identify_sqlite_links_is_list() -> None:
    fmt = FormatDatabase.get().identify(_SQLITE_MAGIC, "unknown_file")
    assert fmt is not None
    assert isinstance(fmt.links, list)


# ---------------------------------------------------------------------------
# FormatDatabase.identify() — no extension fallback
# ---------------------------------------------------------------------------

def test_identify_extension_only_returns_none() -> None:
    # Random bytes that won't match any magic pattern
    junk = b"\x00\x00\x00\x00" * 128
    fmt = FormatDatabase.get().identify(junk, "com.apple.test.plist")
    assert fmt is None


def test_identify_no_match_returns_none() -> None:
    junk = b"\x00\x00\x00\x00" * 128
    fmt = FormatDatabase.get().identify(junk, "totally_unknown.xyz999")
    assert fmt is None


def test_identify_empty_bytes_no_crash() -> None:
    result = FormatDatabase.get().identify(b"", "empty_file")
    # Either None or a valid match — must not raise
    assert result is None or isinstance(result, FormatMatch)


# ---------------------------------------------------------------------------
# FormatDatabase.by_parser_class()
# ---------------------------------------------------------------------------

def test_by_parser_class_sqlite() -> None:
    fmt = FormatDatabase.get().by_parser_class("SQLiteParser")
    assert fmt is not None
    assert fmt.parser_class == "SQLiteParser"


def test_by_parser_class_plist() -> None:
    fmt = FormatDatabase.get().by_parser_class("PlistParser")
    assert fmt is not None
    assert fmt.parser_class == "PlistParser"


def test_by_parser_class_unknown_returns_none() -> None:
    fmt = FormatDatabase.get().by_parser_class("NonExistentParser")
    assert fmt is None


def test_by_parser_class_media() -> None:
    fmt = FormatDatabase.get().by_parser_class("MediaParser")
    assert fmt is not None
    assert fmt.parser_class == "MediaParser"


# ---------------------------------------------------------------------------
# FormatDatabase.identify() — media magic bytes
# ---------------------------------------------------------------------------

_MP3_ID3_MAGIC    = b"\x49\x44\x33" + b"\x00" * 125         # ID3v2 header
_MP3_SYNC_MAGIC   = b"\xff\xfb" + b"\x00" * 126             # MPEG-1 Layer 3 sync
_WAV_MAGIC        = b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 116
_FLAC_MAGIC       = b"fLaC" + b"\x00" * 124
_OGG_MAGIC        = b"OggS" + b"\x00" * 124
_AMR_NB_MAGIC     = b"#!AMR\n" + b"\x00" * 122
_WMA_GUID         = (
    b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"
    b"\xa6\xd9\x00\xaa\x00\x62\xce\x6c"
    + b"\x00" * 112
)
_MP4_FTYP_MAGIC   = b"\x00\x00\x00\x20" + b"ftyp" + b"\x00" * 120
_MKV_EBML_MAGIC   = b"\x1a\x45\xdf\xa3" + b"\x00" * 124
_AVI_MAGIC        = b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 116
_AAC_ADTS_MAGIC   = b"\xff\xf1" + b"\x00" * 126
_ATX_MAGIC        = b"AAPL\r\n\x1a\n" + b"\x00" * 120
_KTX_MAGIC        = b"\xabKTX 11\xbb\r\n\x1a\n" + b"\x00" * 120


@pytest.mark.parametrize("magic,expected_short_name", [
    (_MP3_ID3_MAGIC,  "MP3"),
    (_MP3_SYNC_MAGIC, "MP3"),
    (_WAV_MAGIC,      "WAV"),
    (_FLAC_MAGIC,     "FLAC"),
    (_OGG_MAGIC,      "OGG"),
    (_AMR_NB_MAGIC,   "AMR"),
    (_WMA_GUID,       "WMA"),
    (_MP4_FTYP_MAGIC, "MP4"),
    (_MKV_EBML_MAGIC, "MKV"),
    (_AVI_MAGIC,      "AVI"),
    (_AAC_ADTS_MAGIC, "AAC"),
])
def test_identify_media_by_magic(magic: bytes, expected_short_name: str) -> None:
    fmt = FormatDatabase.get().identify(magic, "unknown_file")
    assert fmt is not None, f"Expected {expected_short_name}, got None"
    assert fmt.short_name == expected_short_name


@pytest.mark.parametrize("magic,expected_short_name", [
    (_MP3_ID3_MAGIC,  "MP3"),
    (_WAV_MAGIC,      "WAV"),
    (_FLAC_MAGIC,     "FLAC"),
    (_OGG_MAGIC,      "OGG"),
    (_AMR_NB_MAGIC,   "AMR"),
    (_WMA_GUID,       "WMA"),
    (_MP4_FTYP_MAGIC, "MP4"),
    (_MKV_EBML_MAGIC, "MKV"),
    (_AVI_MAGIC,      "AVI"),
    (_AAC_ADTS_MAGIC, "AAC"),
])
def test_media_format_has_media_parser_class(magic: bytes, expected_short_name: str) -> None:
    fmt = FormatDatabase.get().identify(magic, "unknown_file")
    assert fmt is not None, f"No match for {expected_short_name}"
    assert fmt.parser_class == "MediaParser", (
        f"{expected_short_name}: expected parser_class='MediaParser', got {fmt.parser_class!r}"
    )


def test_identify_atx_by_magic() -> None:
    fmt = FormatDatabase.get().identify(_ATX_MAGIC, "unknown_file")
    assert fmt is not None
    assert fmt.short_name == "ATX"
    assert fmt.parser_class == "ImageParser"


def test_identify_ktx_by_magic() -> None:
    fmt = FormatDatabase.get().identify(_KTX_MAGIC, "unknown_file")
    assert fmt is not None
    assert fmt.short_name == "KTX"
    assert fmt.parser_class == "ImageParser"


# ---------------------------------------------------------------------------
# Completeness: all MediaParser extensions appear in the DB
# ---------------------------------------------------------------------------

_MEDIA_PARSER_EXTENSIONS = [
    ".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wma", ".amr",
    ".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm", ".3gp", ".3g2",
]


def test_all_media_extensions_covered_in_db() -> None:
    db = FormatDatabase.get()
    if db._conn is None:
        pytest.skip("formats.db not available")
    rows = db._conn.execute(
        "SELECT e.extension FROM formats f "
        "JOIN extensions e ON e.format_id = f.id "
        "WHERE f.parser_class = 'MediaParser'"
    )
    all_exts = {row[0] for row in rows}
    missing = [e for e in _MEDIA_PARSER_EXTENSIONS if e not in all_exts]
    assert not missing, f"Extensions not covered in formats.db: {missing}"


# ---------------------------------------------------------------------------
# FormatMatch structure
# ---------------------------------------------------------------------------

def test_format_match_fields() -> None:
    fmt = FormatDatabase.get().by_parser_class("SQLiteParser")
    assert fmt is not None
    # Check all fields exist and have expected types
    assert isinstance(fmt.name, str)
    assert isinstance(fmt.short_name, str)
    assert isinstance(fmt.category, str)
    assert isinstance(fmt.forensic_relevance, str)
    assert isinstance(fmt.platforms, str)
    assert isinstance(fmt.links, list)
    for label, url in fmt.links:
        assert isinstance(label, str)
        assert isinstance(url, str)
