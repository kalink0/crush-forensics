# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the generic JUMBF box reader.

Box layouts were verified against real C2PA-org sample files during
development; these tests use small synthetic boxes built with the same
layout to exercise the reader without bundling third-party binaries.
"""
from __future__ import annotations

import struct

from crush.parsers import jumbf

_MANIFEST_STORE_UUID = bytes.fromhex("63327061001100108000" "00AA00389B71")


def build_box(tbox: bytes, content: bytes) -> bytes:
    return struct.pack(">I", 8 + len(content)) + tbox + content


def build_jumd(uuid: bytes, label: str) -> bytes:
    content = uuid + bytes([0x03]) + label.encode("utf-8") + b"\x00"
    return build_box(b"jumd", content)


def build_superbox(uuid: bytes, label: str, children: bytes = b"") -> bytes:
    return build_box(b"jumb", build_jumd(uuid, label) + children)


def test_read_box_header_basic() -> None:
    data = build_box(b"test", b"hello")
    box = jumbf.read_box_header(data, 0)
    assert box is not None
    assert box.box_type == b"test"
    assert data[box.content_start:box.content_end] == b"hello"


def test_read_box_header_extended_length() -> None:
    content = b"x" * 10
    data = struct.pack(">I", 1) + b"test" + struct.pack(">Q", 16 + len(content)) + content
    box = jumbf.read_box_header(data, 0)
    assert box is not None
    assert data[box.content_start:box.content_end] == content


def test_read_box_header_zero_length_extends_to_end() -> None:
    content = b"remainder-of-buffer"
    data = struct.pack(">I", 0) + b"test" + content
    box = jumbf.read_box_header(data, 0)
    assert box is not None
    assert data[box.content_start:box.content_end] == content


def test_read_box_header_rejects_truncated_box() -> None:
    data = struct.pack(">I", 100) + b"test" + b"short"
    assert jumbf.read_box_header(data, 0) is None


def test_read_description_extracts_uuid_and_label() -> None:
    jumd = build_jumd(_MANIFEST_STORE_UUID, "c2pa")
    box = jumbf.read_box_header(jumd, 0)
    assert box is not None
    uuid, label = jumbf.read_description(jumd, box.content_start)
    assert uuid == _MANIFEST_STORE_UUID
    assert label == "c2pa"


def test_find_superbox_by_label_descends_into_nested_superboxes() -> None:
    inner = build_superbox(b"\x00" * 16, "inner.target")
    outer = build_superbox(b"\x00" * 16, "outer", inner)

    found = jumbf.find_superbox_by_label(outer, 0, len(outer), "inner.target")
    assert found is not None

    missing = jumbf.find_superbox_by_label(outer, 0, len(outer), "does.not.exist")
    assert missing is None


def test_iter_children_lists_siblings_without_descending() -> None:
    a = build_box(b"aaaa", b"1")
    b = build_box(b"bbbb", b"22")
    c = build_box(b"cccc", b"333")
    data = a + b + c

    children = jumbf.iter_children(data, 0, len(data))
    assert [box.box_type for box in children] == [b"aaaa", b"bbbb", b"cccc"]


def test_first_content_box_returns_sibling_after_description() -> None:
    payload = build_box(b"cbor", b"\xa0")
    superbox = build_superbox(b"\x00" * 16, "with.content", payload)
    box = jumbf.read_box_header(superbox, 0)
    assert box is not None

    content = jumbf.first_content_box(superbox, box)
    assert content is not None
    assert content.box_type == b"cbor"


def test_extract_from_jpeg_reassembles_multi_segment_app11() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    lbox_tbox = manifest_store[0:8]
    # Split into two APP11 segments the way real writers do: first segment
    # carries the box from the start, later segments duplicate LBox+TBox.
    split = 20
    seg1_body = manifest_store[:split]
    seg2_body = lbox_tbox + manifest_store[split:]

    def app11(en: bytes, z: int, body: bytes) -> bytes:
        payload = b"JP" + en + struct.pack(">I", z) + body
        return b"\xFF\xEB" + struct.pack(">H", len(payload) + 2) + payload

    jpeg = (
        b"\xFF\xD8"
        + app11(b"\x02\x11", 1, seg1_body)
        + app11(b"\x02\x11", 2, seg2_body)
        + b"\xFF\xDA\x00\x02\x00"
    )

    result = jumbf.extract_from_jpeg(jpeg)
    assert result == manifest_store


def test_extract_from_jpeg_returns_none_without_app11() -> None:
    jpeg = b"\xFF\xD8\xFF\xDA\x00\x02\x00"
    assert jumbf.extract_from_jpeg(jpeg) is None


def test_extract_from_png_reads_cabx_chunk() -> None:
    import zlib

    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")

    def chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(
            ">I", zlib.crc32(ctype + data)
        )

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"caBX", manifest_store) + chunk(b"IEND", b"")
    assert jumbf.extract_from_png(png) == manifest_store


def test_extract_from_png_returns_none_without_cabx() -> None:
    import zlib

    def chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(
            ">I", zlib.crc32(ctype + data)
        )

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IEND", b"")
    assert jumbf.extract_from_png(png) is None


def test_extract_from_riff_reads_c2pa_chunk() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")

    def riff_chunk(cid: bytes, data: bytes) -> bytes:
        padded = data + (b"\x00" if len(data) % 2 else b"")
        return cid + struct.pack("<I", len(data)) + padded

    body = b"WEBP" + riff_chunk(b"C2PA", manifest_store)
    webp = b"RIFF" + struct.pack("<I", len(body)) + body

    assert jumbf.extract_from_riff(webp) == manifest_store


def test_extract_from_riff_returns_none_without_c2pa_chunk() -> None:
    body = b"WEBP" + b"VP8 " + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    webp = b"RIFF" + struct.pack("<I", len(body)) + body
    assert jumbf.extract_from_riff(webp) is None


def _gif_subblocks(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 255):
        chunk = data[i:i + 255]
        out += bytes([len(chunk)]) + chunk
    return bytes(out) + b"\x00"


def test_extract_from_gif_reads_application_extension() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    app_ext = b"\x21\xFF" + _gif_subblocks(
        b"C2PA_GIF" + bytes([0x01, 0x00, 0x00]) + manifest_store
    )
    gif = b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0, 0, 0]) + app_ext + b"\x3B"

    assert jumbf.extract_from_gif(gif) == manifest_store


def test_extract_from_gif_skips_unrelated_extensions_and_image_data() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    comment_ext = b"\x21\xFE" + _gif_subblocks(b"not c2pa")
    app_ext = b"\x21\xFF" + _gif_subblocks(
        b"C2PA_GIF" + bytes([0x01, 0x00, 0x00]) + manifest_store
    )
    # A minimal image descriptor + LZW data block ahead of the target extension.
    image_desc = b"\x2C" + struct.pack("<HHHH", 0, 0, 1, 1) + bytes([0]) + bytes([2]) + _gif_subblocks(b"\x01")
    gif = (
        b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0, 0, 0])
        + comment_ext + image_desc + app_ext + b"\x3B"
    )

    assert jumbf.extract_from_gif(gif) == manifest_store


def test_extract_from_gif_returns_none_without_c2pa_extension() -> None:
    gif = b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0, 0, 0]) + b"\x3B"
    assert jumbf.extract_from_gif(gif) is None


def _build_tiff_with_c2pa_tag(manifest_store: bytes) -> bytes:
    endian = "<"
    ifd_offset = 8
    entry_count = 1
    value_offset = ifd_offset + 2 + entry_count * 12 + 4
    entry = struct.pack(f"{endian}HHI", 0xCD41, 7, len(manifest_store)) + struct.pack(
        f"{endian}I", value_offset
    )
    ifd = struct.pack(f"{endian}H", entry_count) + entry + struct.pack(f"{endian}I", 0)
    header = b"II" + struct.pack(f"{endian}H", 42) + struct.pack(f"{endian}I", ifd_offset)
    return header + ifd + manifest_store


def test_extract_from_tiff_reads_c2pa_tag() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    tiff = _build_tiff_with_c2pa_tag(manifest_store)
    assert jumbf.extract_from_tiff(tiff) == manifest_store


def test_extract_from_tiff_returns_none_without_c2pa_tag() -> None:
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    ifd = struct.pack("<H", 0) + struct.pack("<I", 0)  # zero entries
    assert jumbf.extract_from_tiff(header + ifd) is None


def _build_bmff_with_c2pa_uuid_box(manifest_store: bytes) -> bytes:
    def box(tbox: bytes, content: bytes) -> bytes:
        return struct.pack(">I", 8 + len(content)) + tbox + content

    ftyp = box(b"ftyp", b"heic" + b"\x00" * 4 + b"heic" + b"mif1")
    extended_type = bytes([
        0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
        0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
    ])
    content = extended_type + b"\x00\x00\x00\x00" + b"manifest\x00" + struct.pack(">Q", 0) + manifest_store
    return ftyp + box(b"uuid", content)


def test_extract_from_bmff_reads_c2pa_uuid_box() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    heic = _build_bmff_with_c2pa_uuid_box(manifest_store)
    assert jumbf.extract_from_bmff(heic) == manifest_store


def test_extract_from_bmff_ignores_unrelated_uuid_boxes() -> None:
    def box(tbox: bytes, content: bytes) -> bytes:
        return struct.pack(">I", 8 + len(content)) + tbox + content

    ftyp = box(b"ftyp", b"heic" + b"\x00" * 4 + b"heic" + b"mif1")
    other_uuid = box(b"uuid", b"\x00" * 16 + b"unrelated data")
    assert jumbf.extract_from_bmff(ftyp + other_uuid) is None


def test_extract_from_jpeg_xl_reads_top_level_jumb_box() -> None:
    manifest_store = build_superbox(_MANIFEST_STORE_UUID, "c2pa")
    sig = bytes.fromhex("0000000c4a584c200d0a870a")
    jxl = sig + manifest_store
    assert jumbf.extract_from_jpeg_xl(jxl) == manifest_store


def test_extract_from_jpeg_xl_returns_none_for_bare_codestream() -> None:
    codestream = b"\xFF\x0A" + b"\x00" * 20
    assert jumbf.extract_from_jpeg_xl(codestream) is None
