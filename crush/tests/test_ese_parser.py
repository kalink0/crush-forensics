# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the ESE database parser (crush/parsers/ese_parser.py, ese_reader.py)
and the block decompressors it uses (crush/core/block_compression.py).

The fixtures were written by Windows' own ESE engine (esent.dll) from known
values (crush/tests/fixtures/generate_ese_fixtures.py); the values put in are
in ese_alltypes.expected.json, which the decoded tables are checked against.
Deleted records, a dirty shutdown and damaged pages are made by changing
single bytes of a copy of a fixture.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import struct
import sys
from typing import Any

import pytest

from crush.core.block_compression import (
    BlockCompressionError,
    lz4_block_decompress,
    lz77_decompress,
)
from crush.core.registry import ParserRegistry
from crush.core.vfs import BytesVFS
from crush.parsers import ese_reader
from crush.parsers.ese_parser import SCHEMA_TABLE, EseParser
from crush.tests.conftest import FIXTURES_DIR

sys.path.insert(0, str(FIXTURES_DIR))
from generate_ese_fixtures import rows_digest_text  # noqa: E402

EXPECTED = json.loads((FIXTURES_DIR / "ese_alltypes.expected.json").read_text(encoding="utf-8"))
FIXTURES = ["ese_alltypes_8k.edb.gz", "ese_alltypes_32k.edb.gz"]
PAGE_SIZES = {"ese_alltypes_8k.edb.gz": 8192, "ese_alltypes_32k.edb.gz": 32768}


def _load(name: str) -> bytes:
    return gzip.decompress((FIXTURES_DIR / name).read_bytes())


def _parse(data: bytes, name: str = "test.edb") -> Any:
    vfs = BytesVFS(data, name=name)
    return EseParser().parse(vfs.root(), vfs)


def _normalize(value: Any) -> Any:
    """A decoded cell in the form the expected JSON records values."""
    if isinstance(value, tuple):
        return value[0]
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, str) and len(value) > 256:
        return {"sha256_utf8": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _rows_as_dicts(table: dict[str, Any]) -> list[dict[str, Any]]:
    cols = table["columns"][2:]
    return [
        {c: _normalize(v) for c, v in zip(cols, row[2:])}
        for row in table["rows"]
    ]


# -- Detection ---------------------------------------------------------------

@pytest.mark.parametrize("fixture", FIXTURES)
def test_registry_picks_ese_parser(fixture: str) -> None:
    vfs = BytesVFS(_load(fixture), name="SRUDB.dat")
    assert isinstance(ParserRegistry.best(vfs.root(), vfs), EseParser)


def test_detection_needs_database_header() -> None:
    data = bytearray(_load(FIXTURES[0])[:4096])
    parser = EseParser()
    assert parser.can_parse("x.edb", bytes(data[:256]))
    log_like = bytearray(data)
    struct.pack_into("<I", log_like, 12, 1)  # file type: streaming file
    assert not parser.can_parse("x.edb", bytes(log_like[:256]))
    bad_page = bytearray(data)
    struct.pack_into("<I", bad_page, 236, 12345)
    assert not parser.can_parse("x.edb", bytes(bad_page[:256]))
    assert not parser.can_parse("x.edb", b"\x00" * 256)


# -- Known output ---------------------------------------------------------------

@pytest.mark.parametrize("fixture", FIXTURES)
def test_header_metadata(fixture: str) -> None:
    result = _parse(_load(fixture))
    assert result.viewer_type == "table"
    assert result.format_short_name == "ESE"
    meta = result.metadata
    assert meta["Format"] == "ESE database"
    assert meta["Page size"] == f"{PAGE_SIZES[fixture]:,} B"
    assert meta["Database state"] == "Clean shutdown"
    assert "Status" not in meta
    assert "Not decoded" not in meta, [str(i) for i in meta["Not decoded"]]
    assert "Parse warning" not in meta, [str(i) for i in meta["Parse warning"]]
    assert "Deleted" not in meta


@pytest.mark.parametrize("fixture", FIXTURES)
def test_tables_listed(fixture: str) -> None:
    data = _parse(_load(fixture)).data
    for name in (SCHEMA_TABLE, "MSysObjects", "MSysObjectsShadow", "AllTypes", "ManyRows"):
        assert name in data


@pytest.mark.parametrize("fixture", FIXTURES)
def test_alltypes_values_match_what_was_written(fixture: str) -> None:
    table = _parse(_load(fixture)).data["AllTypes"]
    expected = EXPECTED["AllTypes"]
    assert table["columns"] == ["Record state", "Page", *expected["columns"]]
    assert [row[0] for row in table["rows"]] == ["Live"] * len(expected["rows"])
    assert _rows_as_dicts(table) == expected["rows"]


@pytest.mark.parametrize("fixture", FIXTURES)
def test_value_types(fixture: str) -> None:
    table = _parse(_load(fixture)).data["AllTypes"]
    row = dict(zip(table["columns"], table["rows"][0]))
    # DateTime and GUID keep their raw bytes next to the shown text.
    assert isinstance(row["DateTimeCol"], tuple) and len(row["DateTimeCol"][1]) == 8
    assert isinstance(row["GuidCol"], tuple) and len(row["GuidCol"][1]) == 16
    assert row["BitCol"] is True
    # Multi-valued columns are lists, also with a single value.
    assert row["MultiLongCol"] == [10, 20, 30]
    row2 = dict(zip(table["columns"], table["rows"][1]))
    assert row2["MultiLongCol"] == [7]


@pytest.mark.parametrize("fixture", FIXTURES)
def test_many_rows_across_pages(fixture: str) -> None:
    table = _parse(_load(fixture)).data["ManyRows"]
    expected = EXPECTED["ManyRows"]
    assert len(table["rows"]) == expected["row_count"]
    rows = _rows_as_dicts(table)
    assert hashlib.sha256(rows_digest_text(rows).encode()).hexdigest() == expected["rows_sha256"]
    # More than one leaf page: the walk went through a branch (root) page.
    assert len({row[1] for row in table["rows"]}) > 1


@pytest.mark.parametrize("fixture", FIXTURES)
def test_schema_table(fixture: str) -> None:
    schema = _parse(_load(fixture)).data[SCHEMA_TABLE]
    rows = {(r[0], r[1]): r for r in schema["rows"]}
    assert rows[("AllTypes", "DateTimeCol")][3] == "DateTime"
    assert rows[("AllTypes", "TextUnicodeCol")][4] == 1200
    assert rows[("AllTypes", "TextAnsiCol")][4] == 1252


@pytest.mark.parametrize("fixture", FIXTURES)
def test_sql_copy_has_every_row(fixture: str) -> None:
    data = _parse(_load(fixture)).data
    conn = sqlite3.connect(data["__db_path"])
    try:
        n, total = conn.execute('SELECT COUNT(*), SUM("Id") FROM "ManyRows"').fetchone()
        assert (n, total) == (600, sum(range(1, 601)))
        multi, dt = conn.execute(
            'SELECT "MultiTextCol", "DateTimeCol" FROM "AllTypes" WHERE "Id" = 1'
        ).fetchone()
        assert json.loads(multi) == ["alpha", "beta"]
        assert dt == "2024-02-29T13:37:42"
    finally:
        conn.close()


# -- Record and header states ---------------------------------------------------

def _first_record_tag(data: bytearray, page_size: int, pgno: int, itag: int) -> int:
    """File offset of the node data of tag *itag* on page *pgno*."""
    base = (pgno + 1) * page_size
    tag_off = base + page_size - 4 * (itag + 1)
    mask = 0x1FFF if page_size <= 8192 else 0x7FFF
    ib = struct.unpack_from("<H", data, tag_off + 2)[0] & mask
    return base + (40 if page_size <= 8192 else 80) + ib


@pytest.mark.parametrize("fixture", FIXTURES)
def test_deleted_flag_shown(fixture: str) -> None:
    data = bytearray(_load(fixture))
    page_size = PAGE_SIZES[fixture]
    with __import__("io").BytesIO(bytes(data)) as f:
        db = ese_reader.EseDatabase(f, len(data))
        fdp = next(t.fdp for t in db.tables if t.name == "AllTypes")
    # Set the node's "deleted" flag (node.hxx fNDDeleted) on the second record.
    if page_size <= 8192:
        base = (fdp + 1) * page_size
        tag_off = base + page_size - 4 * 3
        ib = struct.unpack_from("<H", data, tag_off + 2)[0]
        struct.pack_into("<H", data, tag_off + 2, ib | (ese_reader.NODE_DELETED << 13))
    else:
        off = _first_record_tag(data, page_size, fdp, 2)
        word = struct.unpack_from("<H", data, off)[0]
        struct.pack_into("<H", data, off, word | (ese_reader.NODE_DELETED << 13))
    result = _parse(bytes(data))
    rows = result.data["AllTypes"]["rows"]
    assert [r[0] for r in rows] == ["Live", "Deleted", "Live"]
    assert rows[1][2] == 2  # the deleted record's values are still decoded
    assert result.metadata["Deleted"].code == "ese.deleted_records"


def test_dirty_shutdown_reported() -> None:
    data = bytearray(_load(FIXTURES[0]))
    struct.pack_into("<I", data, 52, 2)
    meta = _parse(bytes(data)).metadata
    assert meta["Database state"] == "Dirty shutdown"
    assert meta["Status"].code == "ese.dirty_shutdown"


# -- Text cut inside its last character ----------------------------------------

def _text_col(coltyp: int, codepage: int, size: int = 0) -> ese_reader.Column:
    return ese_reader.Column(
        id=1, name="T", coltyp=coltyp, size=size, flags=0, codepage=codepage, record_offset=0,
    )


def test_odd_sized_fixed_unicode_text_shown_up_to_last_byte() -> None:
    # A fixed Unicode column of an odd size (255 bytes): space-padded, the
    # last byte is half a UTF-16 code unit.
    raw = "Fixed".encode("utf-16-le") + " ".encode("utf-16-le") * 122 + b"\x20"
    assert len(raw) == 255
    value = ese_reader._decode_typed(_text_col(ese_reader.COLTYP_TEXT, 1200, 255), raw)
    assert ese_reader.is_partial_text(value)
    (text, stored), issue = ese_reader.partial_text_parts(value)
    assert text == "Fixed" + " " * 122 and stored == raw
    assert issue.code == "ese.text_cut"
    assert issue.params == {"codepage": 1200, "count": 1, "hex": "20"}


def test_text_cut_inside_surrogate_pair_shown_up_to_it() -> None:
    # Windows Search cuts System_Search_AutoSummary at 2048 bytes, which can
    # leave the high half of a surrogate pair at the end.
    raw = "a".encode("utf-16-le") * 1021 + "\U0001F600".encode("utf-16-le")[:2]
    value = ese_reader._decode_typed(_text_col(ese_reader.COLTYP_LONG_TEXT, 1200), raw)
    (text, stored), issue = ese_reader.partial_text_parts(value)
    assert text == "a" * 1021 and stored == raw
    assert issue.params["count"] == 2 and issue.params["hex"] == "3d d8"


def test_utf8_text_cut_inside_last_character() -> None:
    raw = "café €".encode("utf-8")[:-1]
    value = ese_reader._decode_typed(_text_col(ese_reader.COLTYP_TEXT, 65001), raw)
    (text, _), issue = ese_reader.partial_text_parts(value)
    assert text == "café " and issue.params["count"] == 2


@pytest.mark.parametrize("codepage, raw", [
    (1200, "ab".encode("utf-16-le") + b"\x3d\xd8" + "cd".encode("utf-16-le")),  # lone surrogate mid-text
    (65001, b"ab\xffcd"),       # invalid byte mid-text
    (65001, b"abc\xff"),        # invalid (not incomplete) last byte
    (20127, b"abc\x80"),        # ASCII: a byte that is never valid
])
def test_invalid_text_stays_undecoded(codepage: int, raw: bytes) -> None:
    value = ese_reader._decode_typed(_text_col(ese_reader.COLTYP_TEXT, codepage), raw)
    assert ese_reader.is_undecoded(value)
    stored, issue = ese_reader.undecoded_parts(value)
    assert stored == raw and issue.code == "ese.text_decode_failed"


@pytest.mark.parametrize("fixture", FIXTURES)
def test_cut_text_shown_and_listed(fixture: str) -> None:
    data = bytearray(_load(fixture))
    stored = "Grüße, 世界".encode("utf-16-le")
    at = data.index(stored)
    # Same length, so the record layout stays valid: the last character
    # becomes the high half of a surrogate pair.
    data[at + len(stored) - 2:at + len(stored)] = b"\x3d\xd8"
    result = _parse(bytes(data))
    table = result.data["AllTypes"]
    row = dict(zip(table["columns"], table["rows"][0]))
    text, raw = row["TextUnicodeCol"]
    assert text == "Grüße, 世" and raw == bytes(data[at:at + len(stored)])
    [summary] = result.metadata["Partly decoded"]
    assert summary.code == "ese.partly_decoded"
    assert summary.params["table"] == "AllTypes" and summary.params["count"] == 1
    assert summary.params["reason"].code == "ese.text_cut"
    assert "Not decoded" not in result.metadata
    assert "Grüße, 世" in result.text_index
    with sqlite3.connect(result.data["__db_path"]) as conn:
        [(sql_text,)] = conn.execute('SELECT "TextUnicodeCol" FROM "AllTypes" WHERE "Id" = 1')
    assert sql_text == "Grüße, 世"


# -- Damage ---------------------------------------------------------------------

@pytest.mark.parametrize("fixture", FIXTURES)
def test_missing_long_value_tree_is_reported_not_dropped(fixture: str) -> None:
    data = bytearray(_load(fixture))
    page_size = PAGE_SIZES[fixture]
    with __import__("io").BytesIO(bytes(data)) as f:
        db = ese_reader.EseDatabase(f, len(data))
        lv_fdp = next(t.lv_fdp for t in db.tables if t.name == "AllTypes")
    assert lv_fdp
    start = (lv_fdp + 1) * page_size
    data[start:start + page_size] = b"\x00" * page_size
    result = _parse(bytes(data))
    table = result.data["AllTypes"]
    row = dict(zip(table["columns"], table["rows"][0]))
    # The 20 000-byte value lives in the long-value tree: now its 4/8-byte
    # reference is shown instead, and why is listed.
    assert isinstance(row["LongBinCol"], bytes) and len(row["LongBinCol"]) in (4, 8)
    codes = [i.params["reason"].code for i in result.metadata["Not decoded"]]
    assert "ese.lv_missing" in codes
    # Everything else is still there.
    assert row["Id"] == 1 and row["TextAnsiCol"] == "café"


def test_truncated_file_says_why_tables_are_missing() -> None:
    data = _load(FIXTURES[0])[:8192 * 3]
    result = _parse(data)
    # The catalog's root (page 4) lies past the end: no tables, and the
    # warning says which page is missing -- not an empty-looking database.
    assert result.viewer_type == "table"
    assert result.metadata["Tables"] == "0"
    [warning] = result.metadata["Parse warning"]
    assert warning.code == "ese.page_out_of_range"
    assert warning.params == {"page": ese_reader.CATALOG_FDP_PAGE}


def test_not_ese_falls_back_to_hex() -> None:
    result = _parse(b"\x00" * 8192)
    assert result.viewer_type == "hex"
    assert result.metadata["Parse error"].code == "ese.not_ese"


# -- Decompressors ----------------------------------------------------------------

def test_lz77_ms_xca_example() -> None:
    # [MS-XCA] 3.1: "abc" repeated 100 times.
    compressed = bytes.fromhex("ffffff1f6162631700 0fff2601".replace(" ", ""))
    assert lz77_decompress(compressed, 300) == b"abc" * 100


def test_lz77_rejects_bad_data() -> None:
    with pytest.raises(BlockCompressionError):
        lz77_decompress(b"\xff\xff\xff\xff\x10\x00", 10)  # match before output start


@pytest.mark.skipif(sys.platform != "win32", reason="uses ntdll's own Xpress compressor")
def test_lz77_matches_windows_xpress() -> None:
    import ctypes

    ntdll = ctypes.WinDLL("ntdll")
    fmt = 3  # COMPRESSION_FORMAT_XPRESS: plain LZ77
    ws_size, frag = ctypes.c_ulong(), ctypes.c_ulong()
    ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(fmt), ctypes.byref(ws_size),
                                         ctypes.byref(frag))
    work = ctypes.create_string_buffer(ws_size.value)
    plain = (b"Extensible Storage Engine " * 50) + bytes(range(256)) * 4
    out = ctypes.create_string_buffer(len(plain) * 2)
    size = ctypes.c_ulong()
    status = ntdll.RtlCompressBuffer(
        ctypes.c_ushort(fmt), plain, ctypes.c_ulong(len(plain)), out,
        ctypes.c_ulong(len(out)), ctypes.c_ulong(4096), ctypes.byref(size), work,
    )
    assert status == 0
    assert lz77_decompress(out.raw[:size.value], len(plain)) == plain


def test_lz4_block() -> None:
    # Literals "abcd", then a match of 8 bytes at offset 4, then literals "xy".
    block = bytes([0x44]) + b"abcd" + struct.pack("<H", 4) + bytes([0x20]) + b"xy"
    assert lz4_block_decompress(block, 14) == b"abcdabcdabcdxy"
    with pytest.raises(BlockCompressionError):
        lz4_block_decompress(block, 20)


def test_seven_bit_decompress() -> None:
    text = b"seven bit"
    bits = 0
    for i, c in enumerate(text):
        bits |= c << (7 * i)
    total = 7 * len(text)
    payload = bits.to_bytes((total + 7) // 8, "little")
    header = (ese_reader.COMPRESS_7BIT_ASCII << 3) | ((total - 1) % 8)
    assert ese_reader.decompress(bytes([header]) + payload) == text
    uni_header = (ese_reader.COMPRESS_7BIT_UNICODE << 3) | ((total - 1) % 8)
    assert ese_reader.decompress(bytes([uni_header]) + payload) == text.decode().encode("utf-16-le")


def test_unsupported_compression_named() -> None:
    with pytest.raises(ese_reader.EseError) as info:
        ese_reader.decompress(bytes([5 << 3]) + b"\x00" * 8)
    assert info.value.issue.code == "ese.compression_unsupported"
    assert info.value.issue.params["scheme"] == "Xpress9"
