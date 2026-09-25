"""plist, XML, ABX, Protobuf, LevelDB, MMKV, SEGB and the hex fallback
report why something is missing or could not be read (parser-reason
audit, part 2e)."""
from __future__ import annotations

import plistlib
import struct
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue
from crush.core.vfs import DirectoryVFS, VFSNode
from crush.parsers.abx_decoder import AbxDecodeResult
from crush.parsers.hex_fallback import HexFallbackParser, _parser_support
from crush.parsers.leveldb_parser import LeveldbParser, _decode_internal_key
from crush.parsers.mmkv_parser import MMKVParser
from crush.parsers.plist_parser import PlistParser
from crush.parsers.protobuf_parser import MAX_DEPTH, ProtobufParser, _decode_message
from crush.parsers.segb_parser import (
    SegbParser,
    _create_segb_sqlite,
    _render_proto_payload,
    discover_segb_nodes,
)
from crush.parsers.xml_parser import XmlParser
from crush.tests.conftest import FIXTURES_DIR
from crush.tests.test_parsers import _make_minimal_leveldb


def _node(tmp_path: Path, name: str, content: bytes) -> tuple[VFSNode, DirectoryVFS]:
    (tmp_path / name).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return node, vfs


def _varint(n: int) -> bytes:
    out = bytearray()
    while n > 127:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


# -- XML ----------------------------------------------------------------------

def test_xml_syntax_error_shows_excerpt_around_error_position(tmp_path: Path) -> None:
    body = "<root>" + "".join(f"<i>{n}</i>" for n in range(500)) + "<broken></root>"
    node, vfs = _node(tmp_path, "doc.xml", body.encode())
    result = XmlParser().parse(node, vfs)

    status = result.metadata["Status"]
    assert status.code == "xml.syntax_error"
    assert "line 1" in status.detail
    assert "raw" not in result.data
    excerpt_key = next(k for k in result.data if k.startswith("excerpt (chars "))
    assert "<broken>" in result.data[excerpt_key]  # the error region, not the file start
    assert not result.data[excerpt_key].startswith("<root>")


# -- plist --------------------------------------------------------------------

def test_plist_nskeyedarchiver_failure_reason_is_shown(tmp_path: Path) -> None:
    broken = {"$archiver": "NSKeyedArchiver", "$version": 100000, "$objects": ["$null"]}
    node, vfs = _node(tmp_path, "a.plist", plistlib.dumps(broken, fmt=plistlib.FMT_BINARY))
    meta = PlistParser().parse(node, vfs).metadata
    assert meta["Format"].code == "plist.format_nska_failed"
    assert meta["Status"].code == "plist.nska_failed"
    assert meta["Status"].detail


# -- ABX ----------------------------------------------------------------------

def test_abx_shows_every_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import crush.parsers.abx_parser as abx_parser

    warnings = [ParseIssue("abx.unknown_token", {"token": n}) for n in range(5)]
    monkeypatch.setattr(
        abx_parser, "decode_abx", lambda _raw: AbxDecodeResult("<a/>", list(warnings)),
    )
    node, vfs = _node(tmp_path, "settings.xml", b"ABX\x00")
    meta = abx_parser.AbxParser().parse(node, vfs).metadata
    assert meta["Warnings"] == warnings  # all five, no "(+N more)"


# -- Protobuf -------------------------------------------------------------------

def test_protobuf_has_no_entry_limit() -> None:
    raw = b"\x08\x01" * 60_000
    decoded, warning, _ = _decode_message(raw)
    assert warning is None
    assert len(decoded["entries"]) == 60_000


def test_protobuf_depth_limit_is_reported(tmp_path: Path) -> None:
    payload = b"\x08\x01"
    for _ in range(MAX_DEPTH + 5):
        payload = b"\x0a" + _varint(len(payload)) + payload
    node, vfs = _node(tmp_path, "deep.pb", payload)
    meta = ProtobufParser().parse(node, vfs).metadata
    assert meta["Nesting"] == ParseIssue("protobuf.depth_limit", {"count": 1, "limit": MAX_DEPTH})


def test_protobuf_shallow_message_has_no_nesting_row(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "flat.pb", b"\x08\x01\x12\x02hi")
    assert "Nesting" not in ProtobufParser().parse(node, vfs).metadata


# -- LevelDB --------------------------------------------------------------------

def test_leveldb_manifest_keys_are_not_truncated() -> None:
    long_key = "k" * 600
    assert _decode_internal_key(long_key.encode() + bytes(8)) == long_key
    binary_key = bytes(range(128, 228))
    assert _decode_internal_key(binary_key + bytes(8)) == binary_key.hex()


def test_leveldb_unreadable_file_is_listed_with_reason(tmp_path: Path) -> None:
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    (db / "LOG").mkdir()  # exists, but can't be read as a file
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "db")
    result = LeveldbParser().parse(node, vfs)
    unreadable = result.data["manifests"]["Unreadable files"]
    assert unreadable["LOG"].code == "leveldb.file_unreadable"


# -- MMKV -----------------------------------------------------------------------

def _mmkv_store() -> bytes:
    key, value = b"channel", b"\x0agoogleplay"
    entry = _varint(len(key)) + key + _varint(len(value)) + value
    region = _varint(len(entry)) + entry
    return struct.pack("<I", len(region)) + region + bytes(64)


def test_mmkv_crc_too_short_is_not_reported_as_missing(tmp_path: Path) -> None:
    (tmp_path / "mmkv.default.crc").write_bytes(bytes(10))
    node, vfs = _node(tmp_path, "mmkv.default", _mmkv_store())
    result = MMKVParser().parse(node, vfs)
    assert result.metadata["Meta file"].code == "mmkv.meta_too_short"
    assert result.data["meta_status"].code == "mmkv.meta_too_short_short"


def test_mmkv_unreadable_crc_is_not_reported_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "mmkv.default.crc").write_bytes(bytes(32))
    node, vfs = _node(tmp_path, "mmkv.default", _mmkv_store())
    real_read = vfs.read

    def _read(n: VFSNode) -> bytes:
        if n.name.endswith(".crc"):
            raise PermissionError("denied")
        return real_read(n)

    monkeypatch.setattr(vfs, "read", _read)
    meta = MMKVParser().parse(node, vfs).metadata
    assert meta["Meta file"] == ParseIssue("mmkv.meta_unreadable", detail="denied")


def test_mmkv_missing_crc_wording_unchanged(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "mmkv.default", _mmkv_store())
    meta = MMKVParser().parse(node, vfs).metadata
    assert str(meta["Meta file"]) == (
        "not found (.crc companion missing) — encryption status unverified"
    )


# -- SEGB -----------------------------------------------------------------------

def test_segb_payload_decode_stop_is_marked() -> None:
    text, complete = _render_proto_payload(b"\x08\x01\x12\x09hi")
    assert not complete
    assert text.endswith("[not decoded from byte 2 on]")
    assert _render_proto_payload(b"\x08\x01") == ("1: 1", True)


def test_segb_marks_rendering_as_heuristic(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "minimal.segb2", (FIXTURES_DIR / "minimal.segb2").read_bytes())
    meta = SegbParser().parse(node, vfs).metadata
    assert meta["Payload rendering"].code == "segb.payload_heuristic"


def test_segb_sql_failure_has_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    import crush.parsers.segb_parser as segb_parser

    def _boom(**_kwargs: Any) -> Any:
        raise OSError("disk full")

    monkeypatch.setattr(segb_parser.tempdir, "mkstemp", _boom)
    path, issue = _create_segb_sqlite(["Payload"], [])
    assert path is None
    assert issue == ParseIssue("segb.sql_failed", detail="disk full")


def test_segb_discovery_only_peeks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "big.bin").write_bytes(bytes(1024))
    vfs = DirectoryVFS(tmp_path)

    def _no_full_read(_node: VFSNode) -> bytes:
        raise AssertionError("discovery must not read whole files")

    monkeypatch.setattr(vfs, "read", _no_full_read)
    assert discover_segb_nodes(vfs.root(), vfs) == []


# -- Hex fallback ---------------------------------------------------------------

def test_hex_fallback_identification_failure_has_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from crush.core import format_db

    def _boom() -> Any:
        raise RuntimeError("formats.db missing")

    monkeypatch.setattr(format_db.FormatDatabase, "get", staticmethod(_boom))
    node, vfs = _node(tmp_path, "x.bin", b"\x00\x01")
    meta = HexFallbackParser().parse(node, vfs).metadata
    assert meta["Format (identified)"] == ParseIssue(
        "hexfallback.identify_failed", detail="formats.db missing",
    )


@pytest.mark.parametrize(
    ("parser_class", "code"),
    [
        (None, "hexfallback.parser_none"),
        ("MMKVParser", "hexfallback.parser_open_as"),
        ("ProtobufParser", "hexfallback.parser_open_as"),
        ("ZipVFS", "hexfallback.parser_source"),
        ("LeveldbParser", "hexfallback.parser_folder"),
        ("UnifiedLogConverter", "hexfallback.parser_logs"),
        ("SQLiteParser", "hexfallback.parser_mismatch"),
    ],
)
def test_hex_fallback_parser_support_says_how(parser_class: str | None, code: str) -> None:
    assert _parser_support(parser_class).code == code


def test_hex_fallback_lists_every_reference_link(tmp_path: Path) -> None:
    # SQLite has several reference links in the format database.
    node, vfs = _node(tmp_path, "db.bin", (FIXTURES_DIR / "minimal.sqlite").read_bytes())
    meta = HexFallbackParser().parse(node, vfs).metadata
    from crush.core.format_db import FormatDatabase

    fmt = FormatDatabase.get().identify((FIXTURES_DIR / "minimal.sqlite").read_bytes()[:512], "db.bin")
    assert fmt is not None and len(fmt.links) > 1
    assert meta["Reference"].split("\n") == [url for _label, url in fmt.links]
