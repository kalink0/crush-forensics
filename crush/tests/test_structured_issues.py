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


def _leveldb(tmp_path: Path) -> tuple[VFSNode, DirectoryVFS]:
    vfs = DirectoryVFS(tmp_path)
    return next(c for c in vfs.root().children if c.name == "db"), vfs


@pytest.mark.forensic(
    category="Completeness",
    subject="LevelDB",
    desc="A data file that can't be opened must be listed with its reason and must not hide the other files' records",
)
def test_leveldb_table_file_without_magic_keeps_the_other_files(tmp_path: Path) -> None:
    """Regression: one .ldb without the SSTable magic made the whole database
    "could not be opened", with none of the other files' records shown and
    the reader's temporary copy named instead of the evidence path."""
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    (db / "000005.ldb").write_bytes(bytes(64))
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    assert result.viewer_type == "leveldb"
    assert [(r["user_key_bytes"], r["value_bytes"]) for r in result.data["records"]] == [
        (b"k", b"v")
    ]
    issue = result.data["manifests"]["Unreadable files"]["000005.ldb"]
    assert issue.code == "leveldb.file_unreadable"
    assert "crush-leveldb-" not in issue.detail
    assert node.path.rstrip("/") in issue.detail
    assert result.metadata["Parse warning"] == ParseIssue(
        "leveldb.data_files_not_read", {"count": 1, "total": 2}
    )


@pytest.mark.forensic(
    category="Completeness",
    subject="LevelDB",
    desc="A data file that fails partway must keep the records read before it, say where it stopped, and not stop the files after it",
)
def test_leveldb_file_failing_midway_keeps_its_records_and_the_others(tmp_path: Path) -> None:
    """A file that fails partway keeps the records read before the failure,
    says after how many it stopped, and the files after it are still read."""
    from crush.tests.test_parsers import _make_log_entry

    db = tmp_path / "db"
    db.mkdir()
    middle_without_first = struct.pack("<IHB", 0, 0, 3)
    (db / "000001.log").write_bytes(_make_log_entry(b"a", b"1", seq=1) + middle_without_first)
    (db / "000002.log").write_bytes(_make_log_entry(b"b", b"2", seq=2))
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    assert [r["user_key_bytes"] for r in result.data["records"]] == [b"a", b"b"]
    issue = result.data["manifests"]["Unreadable files"]["000001.log"]
    assert issue.code == "leveldb.read_stopped"
    assert issue.params["count"] == 1
    assert "000002.log" not in result.data["manifests"]["Unreadable files"]
    assert result.metadata["Parse warning"] == ParseIssue(
        "leveldb.data_files_not_read", {"count": 1, "total": 2}
    )


def test_leveldb_copies_beside_the_files_are_not_read_as_its_files(tmp_path: Path) -> None:
    """Regression: "000005.ldb.bak" matched the unanchored data-file pattern
    and made the whole parse fail; "MANIFEST-000002.bak" was taken as the
    current MANIFEST."""
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    (db / "000005.ldb.bak").write_bytes(bytes(64))
    (db / "MANIFEST-000001").write_bytes(_manifest_with_new_file(0, 1, 10))
    (db / "MANIFEST-000002.bak").write_bytes(_manifest_with_new_file(3, 1, 20))
    (db / "CURRENT").write_bytes(b"MANIFEST-000001\n")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    assert [r["user_key_bytes"] for r in result.data["records"]] == [b"k"]
    assert "Parse warning" not in result.metadata
    manifests = result.data["manifests"]
    assert "MANIFEST-000001 (current)" in manifests
    assert "MANIFEST-000002.bak" in manifests  # shown, never current
    assert result.data["files"][0]["level"] == 0


def test_leveldb_upper_case_log_extension_is_read(tmp_path: Path) -> None:
    """Regression: a directory with "000007.LOG" was recognised as LevelDB,
    but the file itself was never read and nothing said so."""
    from crush.tests.test_parsers import _make_log_entry

    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"a", b"1")])
    (db / "000007.LOG").write_bytes(_make_log_entry(b"b", b"2", seq=2))
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    assert [r["user_key_bytes"] for r in result.data["records"]] == [b"a", b"b"]


def _manifest_with_new_file(level: int, file_no: int, size: int) -> bytes:
    """A MANIFEST log record holding one VersionEdit that adds *file_no*."""
    edit = (
        b"\x07" + _varint(level) + _varint(file_no) + _varint(size)
        + _varint(9) + b"a" + bytes(8) + _varint(9) + b"z" + bytes(8)
    )
    return struct.pack("<IHB", 0, len(edit), 1) + edit


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="LevelDB",
    desc="File numbers must be read as LevelDB writes them (decimal), so a file's level, size and key range are its own",
)
def test_leveldb_file_numbers_are_decimal(tmp_path: Path) -> None:
    """Regression: file numbers were read as hex, so 000010.log looked up
    file 16 in the MANIFEST and the Overview listed it as "00000a"."""
    from crush.tests.test_parsers import _make_log_entry

    db = tmp_path / "db"
    db.mkdir()
    (db / "000010.log").write_bytes(_make_log_entry(b"k", b"v", seq=1))
    (db / "MANIFEST-000011").write_bytes(_manifest_with_new_file(2, 10, 999))
    (db / "CURRENT").write_bytes(b"MANIFEST-000011\n")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    (row,) = result.data["files"]
    assert (row["name"], row["level"], row["size"]) == ("000010.log", 2, 999)
    assert (row["smallest_key"], row["largest_key"]) == ("a", "z")
    manifest = result.data["manifests"]["MANIFEST-000011 (current)"]
    assert manifest["Files by level"] == {"Level 2": "000010"}
    assert manifest["Compaction history"][0]["new"][0]["file"] == "000010"


def test_leveldb_file_numbers_past_six_digits(tmp_path: Path) -> None:
    """LevelDB pads file numbers to at least six digits; a long-lived
    database has longer names, read like any other."""
    from crush.tests.test_parsers import _make_log_entry

    db = tmp_path / "db"
    db.mkdir()
    (db / "1000001.log").write_bytes(_make_log_entry(b"k", b"v", seq=1))
    (db / "MANIFEST-1000000").write_bytes(_manifest_with_new_file(0, 1000001, 64))
    (db / "CURRENT").write_bytes(b"MANIFEST-1000000\n")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    assert [r["user_key_bytes"] for r in result.data["records"]] == [b"k"]
    (row,) = result.data["files"]
    assert (row["name"], row["level"], row["size"]) == ("1000001.log", 0, 64)
    assert "MANIFEST-1000000 (current)" in result.data["manifests"]


def _db_with_two_manifests(tmp_path: Path, current: bytes | None) -> Path:
    """000001.log on level 1 per MANIFEST-000001 and on level 4 per the
    higher-numbered MANIFEST-000002; CURRENT holds *current* (None: no
    CURRENT file)."""
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    (db / "MANIFEST-000001").write_bytes(_manifest_with_new_file(1, 1, 10))
    (db / "MANIFEST-000002").write_bytes(_manifest_with_new_file(4, 1, 20))
    if current is not None:
        (db / "CURRENT").write_bytes(current)
    return db


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="LevelDB",
    desc="The current MANIFEST must be the one CURRENT names, not the highest-numbered; a higher-numbered one is shown and marked",
)
def test_leveldb_current_names_the_manifest(tmp_path: Path) -> None:
    """Regression: the highest-numbered MANIFEST was taken as current, e.g.
    one LevelDB created but never switched CURRENT to."""
    _db_with_two_manifests(tmp_path, b"MANIFEST-000001\n")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    manifests = result.data["manifests"]
    assert "MANIFEST-000001 (current)" in manifests
    assert manifests["MANIFEST-000002"]["Status"] == ParseIssue("leveldb.manifest_after_current")
    assert manifests["CURRENT"] == {"Active MANIFEST": "MANIFEST-000001"}
    assert (result.data["files"][0]["level"], result.data["files"][0]["size"]) == (1, 10)


@pytest.mark.parametrize(("current", "issue"), [
    (None, ParseIssue("leveldb.current_missing")),
    (b"MANIFEST-000009\n", ParseIssue("leveldb.current_target_missing", {"name": "MANIFEST-000009"})),
    (b"not a manifest\n", ParseIssue("leveldb.current_invalid")),
])
def test_leveldb_unusable_current_takes_no_manifest_as_current(
    tmp_path: Path, current: bytes | None, issue: ParseIssue
) -> None:
    """Without a usable CURRENT nothing is guessed: no MANIFEST is labelled
    current, files have no level, and every MANIFEST is still shown."""
    _db_with_two_manifests(tmp_path, current)
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    manifests = result.data["manifests"]
    assert manifests["CURRENT"]["Status"] == issue
    assert not any(label.endswith("(current)") for label in manifests)
    assert {"MANIFEST-000001", "MANIFEST-000002"} <= set(manifests)
    assert (result.data["files"][0]["level"], result.data["files"][0]["size"]) == (-1, None)


def test_leveldb_current_without_line_break_is_noted(tmp_path: Path) -> None:
    """LevelDB requires CURRENT to end with a line break; one without it is
    shown as it is, with a note, and still names the MANIFEST."""
    _db_with_two_manifests(tmp_path, b"MANIFEST-000001")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    manifests = result.data["manifests"]
    assert manifests["CURRENT"] == {
        "Active MANIFEST": "MANIFEST-000001",
        "Status": ParseIssue("leveldb.current_no_newline"),
    }
    assert "MANIFEST-000001 (current)" in manifests


def test_leveldb_empty_data_file_has_a_files_row(tmp_path: Path) -> None:
    """A data file that opens but holds no records is listed with zero
    records, not left out of the Files tab."""
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    (db / "000003.log").write_bytes(b"")
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)

    rows = {f["name"]: f for f in result.data["files"]}
    assert set(rows) == {"000001.log", "000003.log"}
    assert (rows["000003.log"]["type"], rows["000003.log"]["total"]) == ("Log", 0)
    assert "Parse warning" not in result.metadata


def test_leveldb_with_every_file_readable_has_no_warning(tmp_path: Path) -> None:
    db = tmp_path / "db"
    _make_minimal_leveldb(db, [(b"k", b"v")])
    node, vfs = _leveldb(tmp_path)
    result = LeveldbParser().parse(node, vfs)
    assert "Parse warning" not in result.metadata
    assert "Unreadable files" not in result.data["manifests"]


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
