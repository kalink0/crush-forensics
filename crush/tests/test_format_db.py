# SPDX-License-Identifier: Apache-2.0
"""Tests for FormatDatabase and encoding detection."""
from __future__ import annotations

import pytest

from crush.core.format_db import FORMAT_CATEGORIES, FormatDatabase, FormatMatch

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


# One spelling per category (so the Format Reference never lists the same
# category twice), and each one in the translation catalog.
def test_format_db_categories_are_documented_values() -> None:
    for fmt in FormatDatabase.get().all_formats():
        assert fmt.category in FORMAT_CATEGORIES, f"{fmt.name}: category {fmt.category!r}"


def test_format_db_platforms_in_declared_order() -> None:
    from crush.data.build_formats_db import PLATFORMS
    for fmt in FormatDatabase.get().all_formats():
        values = fmt.platforms.split(",") if fmt.platforms else []
        assert values == [p for p in PLATFORMS if p in values], f"{fmt.name}: {values}"


def test_format_db_last_reviewed_matches_build_script() -> None:
    from crush.data.build_formats_db import FORMATS
    expected = {f["name"]: f["last_reviewed"] for f in FORMATS if f["status"] == "reviewed"}
    for fmt in FormatDatabase.get().all_formats():
        assert fmt.last_reviewed == expected[fmt.name], fmt.name


@pytest.mark.parametrize("field,value", [
    ("platforms", ["MacOS"]),
    ("platforms", "Windows"),
    ("last_reviewed", "04.10.2026"),
    ("last_reviewed", "2026-13-01"),
])
def test_build_rejects_undeclared_values(field: str, value: object) -> None:
    from crush.data.build_formats_db import _check_entry
    entry = {"name": "X", "platforms": ["Windows"], "last_reviewed": None, field: value}
    with pytest.raises(ValueError):
        _check_entry(entry)


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


_PLAIN_XML = b'<?xml version="1.0" encoding="utf-8"?>\n<manifest package="a.b"/>\n'
_PLIST_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0"><dict/></plist>\n'
)


@pytest.mark.parametrize("data,expected_parser", [
    (_PLAIN_XML, "XmlParser"),
    (_PLIST_XML, "PlistParser"),
])
def test_identify_xml_vs_xml_plist(data: bytes, expected_parser: str) -> None:
    # Both entries share the "<?xml" magic; a plist is the plist entry,
    # any other XML document the generic XML entry.
    fmt = FormatDatabase.get().identify(data, "unknown_file")
    assert fmt is not None
    assert fmt.parser_class == expected_parser


def test_identify_tie_is_not_resolved_by_table_order() -> None:
    # "RIFF" alone is the WebP, AVI and WAV signature alike: no format is
    # singled out, and every tied one is reported.
    data = b"RIFF" + b"\x00" * 64
    db = FormatDatabase.get()
    assert db.identify(data, "unknown_file") is None
    assert {m.name for m in db.top_matches(data)} == {"WebP Image", "AVI Video", "WAV Audio"}


# Content a format's signatures alone don't make: an XML plist is told from
# any other XML document by its DOCTYPE / root element.
_SELF_IDENTIFY_SAMPLES = {"Property List (XML plist)": _PLIST_XML}

# Formats that share a signature by spec, with nothing at a fixed offset to
# tell them apart: they tie, and the tie is reported with all of them.
_SHARED_SIGNATURES = [
    # ASF header GUID; audio vs. video is decided by the stream types.
    {"WMA Audio", "WMV Video (ASF)"},
]


def test_every_format_identifies_itself() -> None:
    # Each signature, together with the format's other signatures, must
    # single out its own format -- a signature shared with another entry, or
    # one that ties with it, would show the analyst the other format.
    from crush.data.build_formats_db import FORMATS

    db = FormatDatabase.get()
    wrong = []
    for entry in FORMATS:
        if entry["status"] != "reviewed":
            continue
        name = entry["name"]
        magics = [(m["offset"], m["value"]) for m in entry["magic"] if m["offset"] is not None]
        for offset, value in magics:
            if name in _SELF_IDENTIFY_SAMPLES:
                data = _SELF_IDENTIFY_SAMPLES[name]
            else:
                buf = bytearray(max(o + len(v) for o, v in magics))
                for o, v in [*magics, (offset, value)]:
                    buf[o:o + len(v)] = v
                data = bytes(buf)
            found = [m.name for m in db.top_matches(data)]
            shared = next((g for g in _SHARED_SIGNATURES if name in g), {name})
            if set(found) != shared:
                wrong.append(f"{name} @{offset} {value!r} -> {found}")
    assert not wrong, "\n".join(wrong)


# ---------------------------------------------------------------------------
# FormatDatabase.for_parser()
# ---------------------------------------------------------------------------

def test_for_parser_single_entry() -> None:
    # A parser with one entry gets that one, whatever the bytes.
    matches = FormatDatabase.get().for_parser("MMKVParser", b"")
    assert [m.name for m in matches] == ["MMKV Key-Value Store"]


def test_for_parser_unknown_returns_empty() -> None:
    assert FormatDatabase.get().for_parser("NonExistentParser", _SQLITE_MAGIC) == []


@pytest.mark.parametrize("parser,data,expected", [
    ("ImageParser", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "PNG Image"),
    ("ImageParser", b"\xff\xd8\xff\xe0" + b"\x00" * 64, "JPEG Image"),
    ("MediaParser", b"\x00\x00\x00\x14ftypqt  " + b"\x00" * 64, "MOV Video (QuickTime)"),
    ("MediaParser", b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 64, "WAV Audio"),
    ("PlistParser", _PLIST_XML, "Property List (XML plist)"),
    ("SQLiteParser", _SQLITE_MAGIC, "SQLite Database"),
])
def test_for_parser_picks_the_files_own_format(parser: str, data: bytes, expected: str) -> None:
    # A parser that reads several formats: the bytes pick the entry, never
    # the parser's first one by table order.
    matches = FormatDatabase.get().for_parser(parser, data)
    assert [m.name for m in matches] == [expected]


def test_for_parser_undetermined_lists_every_candidate() -> None:
    # Neither text-log entry has a signature: both stay candidates.
    matches = FormatDatabase.get().for_parser("LogParser", b"plain text line\n" * 8)
    assert len(matches) == 2
    assert all(m.parser_class == "LogParser" for m in matches)


def _enriched(tmp_path, qapp, parser: object, name: str, raw: bytes) -> dict:  # type: ignore[no-untyped-def]
    from crush.core.vfs import DirectoryVFS
    from crush.parsers.base import ParseResult
    from crush.ui.main_window import MainWindow

    (tmp_path / name).write_bytes(raw)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    win = MainWindow()
    try:
        result = win._enrich_with_format_info(parser, node, vfs, ParseResult("hex", b""))
        return dict(result.metadata)
    finally:
        win.close()


def test_properties_show_the_parsed_files_own_format_knowledge(tmp_path, qapp) -> None:  # type: ignore[no-untyped-def]
    # A PNG read by ImageParser shows PNG's knowledge, not the first
    # ImageParser entry's (JPEG).
    from crush.parsers.image_parser import ImageParser

    meta = _enriched(tmp_path, qapp, ImageParser(), "img.bin", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    png = FormatDatabase.get().identify(b"\x89PNG\r\n\x1a\n", "x")
    assert png is not None
    assert meta["Format"] == "PNG Image"
    assert str(meta["Forensic relevance"]) == png.forensic_relevance


def test_properties_say_when_the_format_is_not_singled_out(tmp_path, qapp) -> None:  # type: ignore[no-untyped-def]
    from crush.parsers.log_parser import LogParser

    meta = _enriched(tmp_path, qapp, LogParser(), "app.log", b"plain text line\n" * 8)
    status = meta["Format (identified)"]
    assert status.code == "entry.format_not_singled_out"
    assert "Android logcat (text)" in status.params["candidates"]
    assert "Forensic relevance" not in meta
    assert "Format" not in meta


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


def test_asf_guid_names_both_asf_formats() -> None:
    # WMA and WMV share the ASF header GUID (the stream types tell them
    # apart): from the bytes alone both are named, neither is picked.
    db = FormatDatabase.get()
    assert db.identify(_WMA_GUID, "unknown_file") is None
    assert {m.name for m in db.top_matches(_WMA_GUID)} == {"WMA Audio", "WMV Video (ASF)"}
    # A file MediaParser read is one of its formats: WMA.
    assert [m.name for m in db.for_parser("MediaParser", _WMA_GUID)] == ["WMA Audio"]


def _ftyp(brand: bytes) -> bytes:
    return b"\x00\x00\x00\x18ftyp" + brand + b"\x00\x00\x00\x00isom" + b"\x00" * 104


def _riff(kind: bytes) -> bytes:
    return b"RIFF\xe8\x03\x00\x00" + kind + b"\x00" * 116


@pytest.mark.parametrize("data,expected_short_name", [
    (_ftyp(b"heic"), "HEIC/HEIF"),
    (_ftyp(b"mif1"), "HEIC/HEIF"),
    (_ftyp(b"hevc"), "HEIC/HEIF"),
    (_ftyp(b"avif"), "AVIF"),
    (_ftyp(b"isom"), "MP4"),
    (_ftyp(b"mp42"), "MP4"),
    (_ftyp(b"qt  "), "MOV"),
    (_ftyp(b"3gp4"), "3GP"),
    (_ftyp(b"3g2a"), "3GP"),
    (_ftyp(b"M4A "), "M4A"),
    (_ftyp(b"M4B "), "M4A"),
    (_riff(b"WEBP"), "WebP"),
    (_riff(b"WAVE"), "WAV"),
    (_riff(b"AVI "), "AVI"),
])
def test_identify_container_brand(data: bytes, expected_short_name: str) -> None:
    # ISOBMFF and RIFF formats share their container signature; the major
    # brand / RIFF form type decides.
    fmt = FormatDatabase.get().identify(data, "unknown_file")
    assert fmt is not None
    assert fmt.short_name == expected_short_name


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
    fmt = FormatDatabase.get().identify(_SQLITE_MAGIC, "unknown_file")
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
