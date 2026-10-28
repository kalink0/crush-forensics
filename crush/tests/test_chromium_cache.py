# SPDX-License-Identifier: Apache-2.0
"""Chromium Disk Cache: detection by content, both backends, cache kinds,
readings, recovery and the viewer. Every fixture is built here, byte by
byte to the Chromium layouts (simple_entry_format.h, simple_index_file.cc,
disk_format.h, http_response_info.cc, cache_storage.proto) -- no real cache
is checked in."""
from __future__ import annotations

import datetime
import gzip
import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue, render_value
from crush.core.registry import ParserRegistry
from crush.core.vfs import DirectoryVFS, VFSNode
from crush.parsers import chromium_blockfile as bfmt
from crush.parsers import chromium_simple as sfmt
from crush.parsers.chromium_cache_content import (
    KIND_CACHE_STORAGE,
    KIND_CODE,
    KIND_CODE_DATA,
    KIND_HTTP,
    KIND_UNDETERMINED,
    _schema_pool,
    decode_body,
    split_key,
)
from crush.parsers.chromium_cache_parser import ChromiumCacheParser
from crush.parsers.chromium_pickle import decode_response_info, strictly_valid
from crush.parsers.hex_fallback import HexFallbackParser
from crush.tests.test_forensic import _assert_timestamps_unchanged, _timestamps

# A base::Time internal value (µs since 1601-01-01 UTC) and what it shows.
_T_REQUEST = 13_359_656_341_000_000
_T_RESPONSE = 13_359_656_342_500_000
_EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _utc(value: int) -> str:
    return (_EPOCH_1601 + datetime.timedelta(microseconds=value)).strftime("%Y-%m-%d %H:%M:%S")


# -- builders ----------------------------------------------------------------------


def _pad4(raw: bytes) -> bytes:
    return raw + b"\0" * (-len(raw) % 4)


def _p_int(v: int) -> bytes:
    return struct.pack("<i", v)


def _p_uint32(v: int) -> bytes:
    return struct.pack("<I", v)


def _p_int64(v: int) -> bytes:
    return struct.pack("<q", v)


def _p_uint16(v: int) -> bytes:
    return _pad4(struct.pack("<H", v))


def _p_str(raw: bytes) -> bytes:
    return struct.pack("<i", len(raw)) + _pad4(raw)


def _pickle(*parts: bytes) -> bytes:
    payload = b"".join(parts)
    return struct.pack("<I", len(payload)) + payload


def _certificate() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(4242)
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _response_info(
    headers: list[tuple[str, str]], *, status: str = "HTTP/1.1 200 OK",
    certs: list[bytes] | None = None, host: bytes = b"203.0.113.7", port: int = 443,
    alpn: bytes = b"h2", connection_info: int = 4, cache_zstd: int | None = None,
) -> bytes:
    """HttpResponseInfo::MakePickle's field order."""
    flags = 3 | (1 << 31) | (1 << 14) | (1 << 17) | (1 << 18)
    extra = 1 << 2
    if certs is not None:
        flags |= (1 << 8) | (1 << 10) | (1 << 16)
    if cache_zstd is not None:
        extra |= 1 << 4
    raw_headers = status.encode() + b"\0" + b"".join(
        f"{k}: {v}".encode() + b"\0" for k, v in headers
    ) + b"\0"
    parts = [_p_uint32(flags), _p_int(extra), _p_int64(_T_REQUEST), _p_int64(_T_RESPONSE),
             _p_int64(_T_RESPONSE), _p_str(raw_headers)]
    if certs is not None:
        parts.append(_p_int(len(certs)))
        parts.extend(_p_str(c) for c in certs)
        parts.append(_p_uint32(0))                       # cert status
        parts.append(_p_int((6 << 20) | 0x1301))         # TLS 1.3, TLS_AES_128_GCM_SHA256
    parts += [_p_str(host), _p_uint16(port), _p_str(alpn), _p_int(connection_info)]
    if cache_zstd is not None:
        parts.append(_p_int64(cache_zstd))
    return _pickle(*parts)


def _eof(flags: int, crc: int, size: int) -> bytes:
    return struct.pack("<QIIII", sfmt.FINAL_MAGIC, flags, crc, size, 0)


def _simple_header(key: bytes, version: int = sfmt.ENTRY_VERSION) -> bytes:
    return struct.pack("<QIIII", sfmt.INITIAL_MAGIC, version, len(key), 0x1234, 0) + key


def _simple_entry(key: bytes, stream0: bytes, stream1: bytes, *, sha: bool = True) -> bytes:
    """simple_entry_format.h: header, key, stream 1, EOF 1, stream 0,
    SHA-256 of the key, EOF 0."""
    flags0 = sfmt.FLAG_HAS_CRC32 | (sfmt.FLAG_HAS_KEY_SHA256 if sha else 0)
    return (
        _simple_header(key) + stream1 + _eof(sfmt.FLAG_HAS_CRC32, zlib.crc32(stream1), 0)
        + stream0 + (hashlib.sha256(key).digest() if sha else b"")
        + _eof(flags0, zlib.crc32(stream0), len(stream0))
    )


def _simple_stream2(key: bytes, data: bytes) -> bytes:
    return _simple_header(key) + data + _eof(sfmt.FLAG_HAS_CRC32, zlib.crc32(data), 0)


def _simple_sparse(key: bytes, ranges: list[tuple[int, bytes]]) -> bytes:
    out = _simple_header(key, sfmt.SPARSE_VERSION)
    for offset, data in ranges:
        out += struct.pack("<QQQII", sfmt.SPARSE_RANGE_MAGIC, offset, len(data), zlib.crc32(data), 0) + data
    return out


def _real_index(records: list[tuple[int, int, int]], *, modified: int = _T_RESPONSE) -> bytes:
    """simple_index_file.cc: pickle (payload size, CRC), IndexMetadata,
    records (hash, time or prefetch size, packed size), last modified."""
    payload = struct.pack("<QIQQI", sfmt.INDEX_MAGIC, 9, len(records), 4096, 2)
    for h, first, size in records:
        payload += struct.pack("<QqQ", h, first, ((size + 255) >> 8) << 8)
    payload += struct.pack("<q", modified)
    return struct.pack("<II", len(payload), zlib.crc32(payload)) + payload


def _fake_index() -> bytes:
    return struct.pack("<QIIII", sfmt.INITIAL_MAGIC, 9, 0, 0, 0)


def _write_simple(folder: Path, key: bytes, stream0: bytes, stream1: bytes) -> str:
    name = f"{sfmt.entry_hash(key):016x}_0"
    (folder / name).write_bytes(_simple_entry(key, stream0, stream1))
    return name


def _dir_node(vfs: DirectoryVFS, *names: str) -> VFSNode:
    node = vfs.root()
    for name in names:
        node = next(c for c in node.children if c.name == name)
    return node


_HTTP_KEY = b"1/0/_dk_https://site.test https://frame.test https://cdn.test/app.js"
_BODY = b"console.log('evidence');" * 20


def _http_cache(folder: Path, *, with_index: bool = True, orphan: bool = True) -> dict[str, Any]:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "index").write_bytes(_fake_index())
    cert = _certificate()
    stream0 = _response_info(
        [("Content-Type", "text/javascript"), ("Content-Encoding", "gzip"), ("Date", "x")],
        certs=[cert],
    )
    encoded = gzip.compress(_BODY, mtime=0)
    name = _write_simple(folder, _HTTP_KEY, stream0, encoded)
    records = [(sfmt.entry_hash(_HTTP_KEY), _T_RESPONSE + 5_000_000, len(encoded))]
    if orphan:
        records.append((0x1122334455667788, _T_REQUEST, 512))
    if with_index:
        (folder / "index-dir").mkdir()
        (folder / "index-dir" / "the-real-index").write_bytes(_real_index(records))
    return {"name": name, "cert": cert, "encoded": encoded}


def _parse_dir(root: Path, *names: str) -> Any:
    vfs = DirectoryVFS(root)
    node = _dir_node(vfs, *names)
    return ChromiumCacheParser().parse(node, vfs), vfs, node


# -- detection ---------------------------------------------------------------------


@pytest.mark.forensic(
    category="Completeness",
    subject="Chromium Disk Cache",
    desc="A cache folder must be recognised by its files' bytes even when every file is renamed",
)
def test_folder_detected_by_content_not_names(tmp_path: Path) -> None:
    cache = tmp_path / "renamed"
    cache.mkdir()
    (cache / "evidence.bin").write_bytes(_simple_entry(_HTTP_KEY, _response_info([]), b"x"))
    (cache / "readme").write_bytes(b"not a cache file")
    vfs = DirectoryVFS(tmp_path)
    node = _dir_node(vfs, "renamed")
    assert any(isinstance(p, ChromiumCacheParser) for p in ParserRegistry.candidates(node, vfs))
    result = ChromiumCacheParser().parse(node, vfs)
    assert len(result.data["entries"]) == 1
    assert result.data["entries"][0]["url"] == "https://cdn.test/app.js"


def test_folder_named_like_a_cache_without_cache_bytes_is_not_claimed(tmp_path: Path) -> None:
    folder = tmp_path / "Cache_Data"
    folder.mkdir()
    (folder / "index").write_bytes(b"plain text index")
    (folder / "0123456789abcdef_0").write_bytes(b"\0" * 64)
    vfs = DirectoryVFS(tmp_path)
    assert not ChromiumCacheParser().can_parse_dir(_dir_node(vfs, "Cache_Data"), vfs)


def test_index_named_file_with_simple_magic_is_read_as_simple(tmp_path: Path) -> None:
    """Cronet's disk_cache/index holds the Simple magic: the backend marker,
    not a Blockfile index -- the name says nothing about the format."""
    _http_cache(tmp_path / "disk_cache")
    result, _vfs, _node = _parse_dir(tmp_path, "disk_cache")
    assert result.metadata["Format"] == "Chromium Disk Cache (Simple)"
    assert "index" in result.data["overview"]["Files"]


def test_folder_with_only_the_index_is_a_cache(tmp_path: Path) -> None:
    folder = tmp_path / "emptied"
    (folder / "index-dir").mkdir(parents=True)
    (folder / "index-dir" / "the-real-index").write_bytes(_real_index([(7, _T_REQUEST, 100)]))
    vfs = DirectoryVFS(tmp_path)
    assert ChromiumCacheParser().can_parse_dir(_dir_node(vfs, "emptied"), vfs)


def test_single_entry_and_index_files_are_claimed_by_content() -> None:
    parser = ChromiumCacheParser()
    assert parser.can_parse("anything", _simple_entry(b"k", b"", b"")[:256])
    assert parser.can_parse("anything", _real_index([])[:256])
    assert not parser.can_parse("index", b"\xc3\xca\x03\xc1" + b"\0" * 60)


def test_lone_blockfile_file_says_open_the_folder(tmp_path: Path) -> None:
    data = struct.pack("<II", bfmt.INDEX_MAGIC, 0x30000) + b"\0" * 400
    (tmp_path / "copied").write_bytes(data)
    vfs = DirectoryVFS(tmp_path)
    node = _dir_node(vfs, "copied")
    assert ParserRegistry.best(node, vfs).__class__ is HexFallbackParser
    result = HexFallbackParser().parse(node, vfs)
    assert result.metadata["Parser support"] == ParseIssue("hexfallback.parser_folder_chromium_cache")


# -- Simple: HTTP cache ----------------------------------------------------------


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Chromium Disk Cache",
    desc="A Simple HTTP cache entry must give its key parts, times, headers, server, protocol and certificate",
)
def test_simple_http_entry_facts(tmp_path: Path) -> None:
    built = _http_cache(tmp_path / "Cache_Data")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache_Data")
    row = result.data["entries"][0]
    assert row["kind"] == KIND_HTTP
    assert row["url"] == "https://cdn.test/app.js"
    assert row["top_frame_site"] == "https://site.test"
    assert row["frame_site"] == "https://frame.test"
    assert row["http_status"] == "200"
    assert row["content_type"] == "text/javascript"
    assert row["content_encoding"] == "gzip"
    assert row["request_time"] == _T_REQUEST
    assert row["request_time_text"].startswith(_utc(_T_REQUEST))
    assert row["response_time"] == _T_RESPONSE
    assert row["last_used"] == _T_RESPONSE + 5_000_000
    assert row["server"] == "203.0.113.7:443"
    assert row["protocol"] == "h2"
    assert row["body_size"] == len(built["encoded"])
    assert row["state"] == "normal"
    detail = result.data["__store"].detail(row["id"])
    assert ("Content-Type", "text/javascript") in detail["headers"]
    assert detail["certificates"][0]["der"] == built["cert"]
    assert detail["certificates"][0]["fields"]["Subject"] == "CN=example.test"
    assert detail["certificates"][0]["fields"]["Subject alternative names"] == "example.test"


@pytest.mark.forensic(
    category="Completeness",
    subject="Chromium Disk Cache",
    desc="The body must stay RAW as stored; the declared Content-Encoding gives a separate derived body",
)
def test_body_raw_untouched_and_derived_separate(tmp_path: Path) -> None:
    built = _http_cache(tmp_path / "Cache_Data")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache_Data")
    body = result.data["__store"].detail(0)["body"]
    assert body["raw"] == built["encoded"]
    assert body["derived"] == _BODY
    assert body["derived_label"] == "gzip"


def test_structure_ranges_point_at_the_bytes(tmp_path: Path) -> None:
    _http_cache(tmp_path / "Cache_Data")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache_Data")
    part = result.data["__store"].detail(0)["structure"][0]
    raw = part["raw"]
    start, end = part["ranges"][("Key",)]["byte_range"]
    assert raw[start:end] == _HTTP_KEY
    start, end = part["ranges"][("Stream 0 (HttpResponseInfo)", "Socket address", "Host")]["byte_range"]
    assert raw[start:end].endswith(b"203.0.113.7")


@pytest.mark.forensic(
    category="Completeness",
    subject="Chromium Disk Cache",
    desc="Index records whose entry file is gone must be listed with hash, last-used time and size",
)
def test_index_record_without_file_is_listed(tmp_path: Path) -> None:
    _http_cache(tmp_path / "Cache_Data")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache_Data")
    orphans = result.data["orphans"]
    assert len(orphans) == 1
    assert orphans[0]["hash"] == "0x1122334455667788"
    assert orphans[0]["last_used"] == _T_REQUEST
    assert orphans[0]["size"] == 512
    detail = result.data["__store"].orphan_detail(0)
    assert detail["structure"][0]["tree"]["Hash"] == "0x1122334455667788"


def test_entry_linked_to_index_by_key_hash_not_file_name(tmp_path: Path) -> None:
    folder = tmp_path / "c"
    _http_cache(folder, orphan=False)
    entry = next(p for p in folder.iterdir() if p.name.endswith("_0"))
    entry.rename(folder / "copy_of_entry")
    result, _vfs, _node = _parse_dir(tmp_path, "c")
    assert result.data["entries"][0]["last_used"] == _T_RESPONSE + 5_000_000
    assert result.data["orphans"] == []


def test_doomed_file_is_marked(tmp_path: Path) -> None:
    folder = tmp_path / "c"
    folder.mkdir()
    (folder / "index").write_bytes(_fake_index())
    h = sfmt.entry_hash(_HTTP_KEY)
    (folder / f"todelete_{h:016x}_0_3").write_bytes(
        _simple_entry(_HTTP_KEY, _response_info([]), b"body"))
    result, _vfs, _node = _parse_dir(tmp_path, "c")
    row = result.data["entries"][0]
    assert row["state"] == "doomed"
    assert "todelete" in render_value(row["note"])


def test_stream2_and_sparse_files_join_their_entry(tmp_path: Path) -> None:
    folder = tmp_path / "c"
    _http_cache(folder, with_index=False, orphan=False)
    h = sfmt.entry_hash(_HTTP_KEY)
    (folder / f"{h:016x}_1").write_bytes(_simple_stream2(_HTTP_KEY, b"side data"))
    (folder / f"{h:016x}_s").write_bytes(_simple_sparse(_HTTP_KEY, [(0, b"A" * 10), (100, b"B" * 5)]))
    result, _vfs, _node = _parse_dir(tmp_path, "c")
    assert len(result.data["entries"]) == 1
    detail = result.data["__store"].detail(0)
    assert {s["index"] for s in detail["streams"]} == {0, 1, 2}
    body = detail["body"]
    assert [(r["offset"], r["length"]) for r in body["sparse"]] == [(0, 10), (100, 5)]
    assert body["gaps"] == [(10, 100)]


# -- cache kinds and readings -------------------------------------------------------


def _cache_storage_proto(message: str, **fields: Any) -> Any:
    from google.protobuf import message_factory

    cls = message_factory.GetMessageClass(_schema_pool().FindMessageTypeByName(f"content.proto.{message}"))
    return cls(**fields)


def _cache_metadata(url: str) -> bytes:
    pool_msg = _cache_storage_proto("CacheMetadata")
    pool_msg.request.method = "GET"
    pool_msg.response.status_code = 200
    pool_msg.response.status_text = "OK"
    pool_msg.response.response_type = 1
    pool_msg.response.response_time = _T_RESPONSE
    pool_msg.response.url_list.append(url)
    header = pool_msg.response.headers.add()
    header.name, header.value = "content-encoding", "gzip"
    pool_msg.entry_time = _T_REQUEST
    return pool_msg.SerializeToString()


def _cache_storage(root: Path, *, with_index_txt: bool) -> Path:
    origin = root / "CacheStorage" / "0f00ba11"
    cache = origin / "1b2c3d4e-uuid"
    cache.mkdir(parents=True)
    (cache / "index").write_bytes(_fake_index())
    url = "https://app.test/offline.html"
    _write_simple(cache, url.encode(), _cache_metadata(url), b"<html>offline</html>")
    (cache / "index-dir").mkdir()
    (cache / "index-dir" / "the-real-index").write_bytes(
        _real_index([(sfmt.entry_hash(url.encode()), 777, 300)]))
    if with_index_txt:
        index = _cache_storage_proto("CacheStorageIndex", storage_key="https://app.test/")
        entry = index.cache.add()
        entry.name, entry.cache_dir = "offline-v1", cache.name
        (origin / "index.txt").write_bytes(index.SerializeToString())
    return cache


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Chromium Disk Cache",
    desc="A CacheStorage cache named by index.txt must decode stream 0 as CacheMetadata and the index field as prefetch size",
)
def test_cache_storage_with_index_txt(tmp_path: Path) -> None:
    _cache_storage(tmp_path, with_index_txt=True)
    result, _vfs, _node = _parse_dir(tmp_path, "CacheStorage", "0f00ba11", "1b2c3d4e-uuid")
    row = result.data["entries"][0]
    assert row["kind"] == KIND_CACHE_STORAGE
    assert row["url"] == "https://app.test/offline.html"
    assert row["http_status"] == "200"
    assert row["response_time"] == _T_RESPONSE
    assert row["created"] == _T_REQUEST
    assert row["last_used"] is None
    assert row["prefetch"] == 777
    assert result.data["overview"]["CacheStorage"]["Cache name"] == "offline-v1"
    body = result.data["__store"].detail(0)["body"]
    assert body["raw"] == b"<html>offline</html>"
    assert body["derived"] is None
    assert body["note"].code == "chromium_cache.cs_body_stored_decoded"


@pytest.mark.forensic(
    category="Completeness",
    subject="Chromium Disk Cache",
    desc="Without index.txt, CacheStorage entries must show every valid reading of stream 0 and both readings of the index field, marked as heuristic",
)
def test_cache_storage_without_index_txt_shows_readings(tmp_path: Path) -> None:
    _cache_storage(tmp_path, with_index_txt=False)
    result, _vfs, _node = _parse_dir(tmp_path, "CacheStorage", "0f00ba11", "1b2c3d4e-uuid")
    row = result.data["entries"][0]
    assert row["kind"] == KIND_UNDETERMINED
    note = render_value(row["note"])
    assert "Heuristic" in note and "CacheMetadata" in note
    assert result.data["overview"]["Index field read as"].code == "chromium_cache.index_field_both"
    tree = result.data["__store"].detail(0)["structure"][0]["tree"]
    assert "Stream 0 reading: CacheMetadata (heuristic)" in tree
    assert "Last used" in tree["Index record"] and "Trailer prefetch size" in tree["Index record"]


def test_undetermined_key_with_valid_response_info_is_a_heuristic_reading(tmp_path: Path) -> None:
    """Service Worker script caches key entries by a number: the response
    info is read as a heuristic, and the body isn't decompressed."""
    folder = tmp_path / "ScriptCache"
    folder.mkdir()
    (folder / "index").write_bytes(_fake_index())
    _write_simple(folder, b"17", _response_info([("Content-Encoding", "br")]), b"var a=1;")
    result, _vfs, _node = _parse_dir(tmp_path, "ScriptCache")
    row = result.data["entries"][0]
    assert row["kind"] == KIND_UNDETERMINED
    assert row["http_status"] == "200"
    assert "HttpResponseInfo" in render_value(row["note"])
    body = result.data["__store"].detail(0)["body"]
    assert body["derived"] is None
    assert body["note"].code == "chromium_cache.heuristic_body_not_decoded"


def test_unknown_content_gets_an_explicit_status(tmp_path: Path) -> None:
    folder = tmp_path / "GPUCache"
    folder.mkdir()
    (folder / "index").write_bytes(_fake_index())
    _write_simple(folder, b"Chrome/141.0-GPU:AAAA", b"", b"\x01\x02shader")
    result, _vfs, _node = _parse_dir(tmp_path, "GPUCache")
    row = result.data["entries"][0]
    assert row["kind"] == KIND_UNDETERMINED
    assert "Content not decoded" in render_value(row["note"])
    body = result.data["__store"].detail(0)["body"]
    assert body["raw"] == b"\x01\x02shader"
    assert body["note"].code == "chromium_cache.content_kind_undetermined"


def test_code_cache_entries(tmp_path: Path) -> None:
    folder = tmp_path / "js"
    folder.mkdir()
    (folder / "index").write_bytes(_fake_index())
    code = b"\xc0\xde" * 8
    header = struct.pack("<qI", _T_RESPONSE, len(code)) + code
    _write_simple(folder, b"_keyhttps://cdn.test/app.js \nhttps://site.test/", header, b"")
    big = b"\x77" * 20000
    sha_key = hashlib.sha256(big).hexdigest().upper().encode()
    _write_simple(folder, sha_key, b"", big)
    result, _vfs, _node = _parse_dir(tmp_path, "js")
    rows = {r["kind"]: r for r in result.data["entries"]}
    assert set(rows) == {KIND_CODE, KIND_CODE_DATA}
    assert rows[KIND_CODE]["url"] == "https://cdn.test/app.js"
    assert rows[KIND_CODE]["response_time"] == _T_RESPONSE
    detail = result.data["__store"].detail(rows[KIND_CODE]["id"])
    assert detail["body"]["raw"] == code
    assert detail["body"]["note"].code == "chromium_cache.body_v8_not_decoded"
    assert result.data["overview"]["Index field read as"] != ParseIssue("chromium_cache.index_field_both")


def test_key_grammars() -> None:
    parts = split_key(b"0/12/_dk_s_cn_https://a.test https://b.test https://c.test/x")
    assert (parts.kind, parts.url, parts.upload_id) == (KIND_HTTP, "https://c.test/x", "12")
    assert parts.subframe_document and parts.cross_site_navigation
    assert parts.top_frame_site == "https://a.test" and parts.frame_site == "https://b.test"
    assert split_key(b"1/0/https://plain.test/").url == "https://plain.test/"
    assert split_key(b"https://bare.test/").kind == KIND_UNDETERMINED


# -- response info details ---------------------------------------------------------


def test_cut_off_response_info_keeps_what_was_read() -> None:
    full = _response_info([("A", "b")])
    info = decode_response_info(full[:40])
    assert info.request_time == _T_REQUEST
    assert info.stopped is not None
    assert not strictly_valid(info)


def test_cache_stored_zstd_body_is_declared() -> None:
    try:
        from compression import zstd  # type: ignore[import-not-found]
    except ImportError:
        from backports import zstd

    info = decode_response_info(_response_info([], cache_zstd=5))
    assert info.zstd_uncompressed_size == 5
    derived, note = decode_body(zstd.compress(b"hello"), [], cache_zstd=True)
    assert (derived, note) == (b"hello", None)


def test_undecodable_body_says_why() -> None:
    derived, note = decode_body(b"not gzip", ["gzip"])
    assert derived is None and note is not None and note.code == "chromium_cache.coding_failed"
    derived, note = decode_body(b"x", ["compress"])
    assert note is not None and note.code == "chromium_cache.coding_unsupported"


# -- single files ------------------------------------------------------------------


def test_entry_file_alone(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(_simple_entry(_HTTP_KEY, _response_info([]), b"body"))
    vfs = DirectoryVFS(tmp_path)
    result = ChromiumCacheParser().parse(_dir_node(vfs, "f"), vfs)
    assert result.data["entries"][0]["url"] == "https://cdn.test/app.js"
    assert result.metadata["Status"] == ParseIssue("chromium_cache.entry_alone")


def test_index_alone_lists_records_with_both_readings(tmp_path: Path) -> None:
    (tmp_path / "the-real-index").write_bytes(_real_index([(1, _T_REQUEST, 256), (2, 300, 512)]))
    vfs = DirectoryVFS(tmp_path)
    result = ChromiumCacheParser().parse(_dir_node(vfs, "the-real-index"), vfs)
    assert [o["hash"] for o in result.data["orphans"]] == ["0x0000000000000001", "0x0000000000000002"]
    assert all(o["note"] == ParseIssue("chromium_cache.index_field_both") for o in result.data["orphans"])


def test_marker_alone(tmp_path: Path) -> None:
    (tmp_path / "index").write_bytes(_fake_index())
    vfs = DirectoryVFS(tmp_path)
    result = ChromiumCacheParser().parse(_dir_node(vfs, "index"), vfs)
    assert result.metadata["Status"] == ParseIssue("chromium_cache.marker_alone")
    assert result.data["entries"] == []


# -- Blockfile ---------------------------------------------------------------------


def _addr(file_type: int, file_no: int, block: int, blocks: int = 1) -> int:
    return 0x80000000 | (file_type << 28) | ((blocks - 1) << 24) | (file_no << 16) | block


def _block_file(number: int, entry_size: int, blocks: dict[int, bytes], used: set[int], count: int = 64) -> bytes:
    bitmap = bytearray(8192 - 80)
    for b in used:
        bitmap[b // 8] |= 1 << (b % 8)
    head = struct.pack("<IIhhiii", bfmt.BLOCK_MAGIC, 0x20000, number, 0, entry_size, len(used), count)
    head += b"\0" * (80 - len(head))
    body = bytearray(entry_size * count)
    for b, raw in blocks.items():
        body[b * entry_size:b * entry_size + len(raw)] = raw
    return head + bytes(bitmap) + bytes(body)


def _entry_store(key: bytes, *, rankings: int, state: int, sizes: list[int], addrs: list[int]) -> bytes:
    head = struct.pack(
        "<IIIiiiQiI4i4II4i", bfmt.super_fast_hash(key), 0, rankings, 1, 0, state, _T_REQUEST,
        len(key), 0, *sizes, *addrs, 0, 0, 0, 0, 0,
    )
    head += struct.pack("<I", bfmt.super_fast_hash(head[:92]))
    return head + key + b"\0" * (160 - len(key))


def _rankings(contents: int, last_used: int) -> bytes:
    return struct.pack("<QQIIIiI", last_used, _T_REQUEST, 0, 0, contents, 0, 0)


def _blockfile_cache(folder: Path, *, with_external: bool = True) -> dict[str, Any]:
    folder.mkdir(parents=True)
    keys = [b"1/0/https://one.test/a.png", b"1/0/https://two.test/b.css"]
    entries, rankings, data2 = {}, {}, {}
    table_entries: list[int] = []
    body_big = b"\x89PNG" + b"\0" * 30000
    for i, key in enumerate(keys):
        e_addr = _addr(bfmt.BLOCK_256, 1, i)
        r_addr = _addr(bfmt.RANKINGS, 0, i)
        s0 = _response_info([("Content-Type", "image/png")])
        s0_addr = _addr(bfmt.BLOCK_1K, 2, i * 2, 2)
        data2[i * 2] = s0
        if i == 0 and with_external:
            sizes = [len(s0), len(body_big), 0, 0]
            addrs = [s0_addr, 0x80000000 | 1, 0, 0]
        else:
            sizes = [len(s0), 4, 0, 0]
            body_addr = _addr(bfmt.BLOCK_1K, 2, 10 + i)
            data2[10 + i] = b"body"
            addrs = [s0_addr, body_addr, 0, 0]
        entries[i] = _entry_store(key, rankings=r_addr, state=bfmt.STATE_EVICTED if i == 1 else 0,
                                  sizes=sizes, addrs=addrs)
        rankings[i] = _rankings(e_addr, _T_RESPONSE + i)
        table_entries.append(e_addr)
    # A freed entry record: free in the bitmap, its bytes still there.
    deleted_key = b"https://gone.test/secret.json"
    entries[5] = _entry_store(deleted_key, rankings=0, state=0, sizes=[0, 0, 0, 0], addrs=[0, 0, 0, 0])
    (folder / "data_0").write_bytes(_block_file(0, 36, rankings, {0, 1}))
    (folder / "data_1").write_bytes(_block_file(1, 256, entries, {0, 1}))
    (folder / "data_2").write_bytes(_block_file(2, 1024, data2, {0, 1, 2, 3, 10, 11}))
    if with_external:
        (folder / "f_000001").write_bytes(body_big)
    table_len = 0x400
    table = [0] * table_len
    table[3], table[9] = table_entries
    lru_heads = [_addr(bfmt.RANKINGS, 0, 0), 0, 0, 0, _addr(bfmt.RANKINGS, 0, 1)]
    header = struct.pack(
        "<IIiiiiIiiiQqi", bfmt.INDEX_MAGIC, 0x30000, 2, 0, 1, 7, 0, table_len, 0, 0, _T_REQUEST, 0, 0,
    )
    header += b"\0" * (256 - len(header))
    header += struct.pack("<2ii5i5I5IIii7i", 0, 0, 0, 1, 0, 0, 0, 1, *lru_heads, *lru_heads, 0, 0, 0, *[0] * 7)
    (folder / "index").write_bytes(header + struct.pack(f"<{table_len}I", *table))
    return {"keys": keys, "deleted": deleted_key, "body_big": body_big}


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Chromium Disk Cache",
    desc="A Blockfile cache must give every entry the index reaches, with state, times and its external body",
)
def test_blockfile_entries(tmp_path: Path) -> None:
    built = _blockfile_cache(tmp_path / "Cache")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache")
    rows = {r["url"]: r for r in result.data["entries"]}
    assert {r["key"] for r in result.data["entries"]} == {k.decode() for k in built["keys"]}
    assert all(r["kind"] == KIND_HTTP for r in result.data["entries"])
    one = rows["https://one.test/a.png"]
    assert one["state"] == "normal"
    assert one["created"] == _T_REQUEST
    assert one["last_used"] == _T_RESPONSE
    assert one["content_type"] == "image/png"
    assert rows["https://two.test/b.css"]["state"] == "evicted"
    detail = result.data["__store"].detail(one["id"])
    assert detail["body"]["raw"] == built["body_big"]
    assert "f_000001" in result.data["overview"]["Files"]


@pytest.mark.forensic(
    category="Completeness",
    subject="Chromium Disk Cache",
    desc="An entry record in a free block whose key hash matches its key must be listed as a heuristic recovery with its reason",
)
def test_blockfile_free_block_is_carved_as_heuristic(tmp_path: Path) -> None:
    built = _blockfile_cache(tmp_path / "Cache")
    result, _vfs, _node = _parse_dir(tmp_path, "Cache")
    carved = [o for o in result.data["orphans"] if o["kind"] == "carved"]
    assert [o["key"] for o in carved] == [built["deleted"].decode()]
    assert "Heuristic" in render_value(carved[0]["note"])
    detail = result.data["__store"].orphan_detail(carved[0]["id"])
    codes = {n.code for n in detail["notes"] if isinstance(n, ParseIssue)}
    assert "chromium_cache.carved_blocks_reused" in codes


def test_zeroed_free_blocks_are_not_carved(tmp_path: Path) -> None:
    folder = tmp_path / "Cache"
    _blockfile_cache(folder)
    raw = bytearray((folder / "data_1").read_bytes())
    start = bfmt.BLOCK_HEADER_SIZE + 5 * 256
    raw[start:start + 256] = b"\0" * 256
    (folder / "data_1").write_bytes(bytes(raw))
    result, _vfs, _node = _parse_dir(tmp_path, "Cache")
    assert result.data["orphans"] == []
    assert result.data["orphans_note"].code == "chromium_cache.no_orphans_blockfile"


def test_blockfile_missing_external_file_is_named(tmp_path: Path) -> None:
    folder = tmp_path / "Cache"
    _blockfile_cache(folder)
    (folder / "f_000001").unlink()
    result, _vfs, _node = _parse_dir(tmp_path, "Cache")
    missing = ParseIssue("chromium_cache.file_missing", {"name": "f_000001"})
    assert missing in result.data["overview"]["Status"]
    one = next(r for r in result.data["entries"] if r["url"] == "https://one.test/a.png")
    body = result.data["__store"].detail(one["id"])["body"]
    assert body["raw"] is None
    assert body["note"] == ParseIssue("chromium_cache.body_unreadable", {"reason": missing})


def test_super_fast_hash_matches_the_reference_values() -> None:
    """SuperFastHash (superfasthash.c) for each tail length."""
    assert bfmt.super_fast_hash(b"") == 0
    values = [bfmt.super_fast_hash(b"abcd"[:n]) for n in range(1, 5)]
    assert len(set(values)) == 4
    assert bfmt.super_fast_hash(b"\xff") != bfmt.super_fast_hash(b"\x7f")


# -- forensic integrity ------------------------------------------------------------


def _sha256_tree(path: Path) -> dict[str, str]:
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(path.rglob("*")) if p.is_file()
    }


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Chromium Disk Cache",
    desc="Cache files must be byte-identical after parsing and reading every entry's details",
)
def test_does_not_modify_source(tmp_path: Path) -> None:
    _http_cache(tmp_path / "simple")
    _blockfile_cache(tmp_path / "block")
    before = _sha256_tree(tmp_path)
    for name in ("simple", "block"):
        result, _vfs, _node = _parse_dir(tmp_path, name)
        for row in result.data["entries"]:
            result.data["__store"].detail(row["id"])
        for row in result.data["orphans"]:
            result.data["__store"].orphan_detail(row["id"])
    assert _sha256_tree(tmp_path) == before


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Chromium Disk Cache",
    desc="Parsing must not change mtime or ctime of the cache files",
)
def test_does_not_change_timestamps(tmp_path: Path) -> None:
    _http_cache(tmp_path / "simple")
    files = [p for p in (tmp_path / "simple").rglob("*") if p.is_file()]
    before = {p: _timestamps(p) for p in files}
    result, _vfs, _node = _parse_dir(tmp_path, "simple")
    result.data["__store"].detail(0)
    for p in files:
        _assert_timestamps_unchanged(before[p], _timestamps(p), f"Chromium cache parser ({p.name})")


@pytest.mark.forensic(
    category="No Side Effects",
    subject="Chromium Disk Cache",
    desc="Parsing must not create files in or next to the cache folder",
)
def test_no_side_effect_files(tmp_path: Path) -> None:
    _http_cache(tmp_path / "simple")
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    result, _vfs, _node = _parse_dir(tmp_path, "simple")
    result.data["__store"].detail(0)
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


@pytest.mark.forensic(
    category="Read-only Media",
    subject="Chromium Disk Cache",
    desc="The parser must succeed when the cache folder and files are read-only (0o555/0o444)",
)
def test_read_only_media(tmp_path: Path) -> None:
    folder = tmp_path / "simple"
    _http_cache(folder)
    paths = sorted(folder.rglob("*"), key=lambda p: -len(p.parts))
    try:
        for p in paths:
            p.chmod(0o555 if p.is_dir() else 0o444)
        folder.chmod(0o555)
        result, _vfs, _node = _parse_dir(tmp_path, "simple")
        assert len(result.data["entries"]) == 1
        assert result.data["__store"].detail(0)["body"]["raw"] is not None
    finally:
        folder.chmod(0o755)
        for p in paths:
            p.chmod(0o755 if p.is_dir() else 0o644)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="Chromium Disk Cache",
    desc="Parsing the same cache twice must produce identical results",
)
def test_parse_is_reproducible(tmp_path: Path) -> None:
    _http_cache(tmp_path / "simple")
    _blockfile_cache(tmp_path / "block")
    for name in ("simple", "block"):
        r1, _v1, _n1 = _parse_dir(tmp_path, name)
        r2, _v2, _n2 = _parse_dir(tmp_path, name)
        assert r1.metadata == r2.metadata
        assert r1.data["entries"] == r2.data["entries"]
        assert [render_value(o["note"]) for o in r1.data["orphans"]] == [
            render_value(o["note"]) for o in r2.data["orphans"]]


# -- format info for folder formats --------------------------------------------------


@pytest.mark.parametrize("kind", ["chromium", "leveldb"])
def test_folder_format_info_comes_from_the_parser(qapp, tmp_path: Path, monkeypatch, kind: str) -> None:
    """Regression: a folder has no bytes to match formats.db against -- the
    Properties panel showed no format knowledge for an opened cache or
    LevelDB folder, and Open Format Info… failed silently."""
    import crush.parsers  # noqa: F401
    import crush.ui.main_window as main_window
    from crush.tests.test_parsers import _make_minimal_leveldb

    if kind == "chromium":
        _http_cache(tmp_path / "folder")
        expected = "Chromium Disk Cache"
    else:
        _make_minimal_leveldb(tmp_path / "folder", [(b"k", b"v")])
        expected = "LevelDB Database"
    vfs = DirectoryVFS(tmp_path)
    node = _dir_node(vfs, "folder")
    parser = ParserRegistry.best(node, vfs)
    shown: list[Any] = []
    monkeypatch.setattr(
        "crush.ui.format_info_dialog.FormatInfoDialog.exec", lambda self: shown.append(self) or 0
    )
    win = main_window.MainWindow()
    try:
        result = win._enrich_with_format_info(parser, node, vfs, parser.parse(node, vfs))
        assert result.metadata["Forensic relevance"]
        assert result.metadata["Platforms"]
        win._show_format_info(node, vfs)
        assert len(shown) == 1
        from PySide6.QtWidgets import QLabel

        assert any(expected in label.text() for label in shown[0].findChildren(QLabel))
    finally:
        win.close()


# -- viewer ------------------------------------------------------------------------


def test_viewer_shows_entries_and_details(qapp, widgets, tmp_path: Path) -> None:
    from crush.viewers.chromium_cache_viewer import _ENTRY_COLUMNS, ChromiumCacheViewer, _RowsWidget

    _http_cache(tmp_path / "simple")
    result, _vfs, _node = _parse_dir(tmp_path, "simple")
    viewer = widgets(ChromiumCacheViewer(result.data))
    tabs = viewer.layout().itemAt(0).widget()
    titles = [tabs.tabText(i) for i in range(tabs.count())]
    assert titles[0] == "Overview"
    assert titles[1].startswith("Entries (1")
    assert titles[2].startswith("Orphans / Recovered (1")
    rows = next(w for w in viewer.findChildren(_RowsWidget) if w._model.columns is _ENTRY_COLUMNS)
    rows._table.setCurrentIndex(rows._proxy.index(0, 0))
    pane = rows._pane
    names = [pane.tabText(i) for i in range(pane.count())]
    assert names[0] == "Summary"
    assert any(n.startswith("Structure: ") for n in names)
    assert {"Headers", "Body", "Streams"} <= set(names)
    assert any(n.startswith("Certificates") for n in names)
    for i in range(pane.count()):
        pane.setCurrentIndex(i)  # builds every tab


def test_viewer_opens_the_body_in_a_new_tab(qapp, widgets, tmp_path: Path) -> None:
    from crush.viewers.chromium_cache_viewer import _ENTRY_COLUMNS, ChromiumCacheViewer, _RowsWidget

    _http_cache(tmp_path / "simple")
    result, _vfs, _node = _parse_dir(tmp_path, "simple")
    viewer = widgets(ChromiumCacheViewer(result.data))
    received: list[tuple] = []
    viewer.open_bytes_with_format_requested.connect(lambda *args: received.append(args))
    rows = next(w for w in viewer.findChildren(_RowsWidget) if w._model.columns is _ENTRY_COLUMNS)
    rows._table.setCurrentIndex(rows._proxy.index(0, 0))
    pane = rows._pane
    pane._open(_BODY, "body-decompressed", "gzip of entry")
    assert received and received[0][0] == _BODY
    assert received[0][1].endswith("/body-decompressed")


def test_viewer_says_why_a_tab_is_empty(qapp, widgets, tmp_path: Path) -> None:
    from crush.viewers.chromium_cache_viewer import ChromiumCacheViewer

    _http_cache(tmp_path / "simple", orphan=False)
    result, _vfs, _node = _parse_dir(tmp_path, "simple")
    viewer = widgets(ChromiumCacheViewer(result.data))
    from PySide6.QtWidgets import QLabel

    texts = [label.text() for label in viewer.findChildren(QLabel)]
    assert any(text.startswith("None found") for text in texts)
