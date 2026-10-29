# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""C2PA detection per container (audio/video and the scan statuses shared
with images): where the Manifest Store sits in each container, what is
reported when the structure ends early or C2PA data is not evaluated, and
how several stores in one file are shown.

All inputs are built here, with the layouts from the C2PA spec 2.4 Annex A,
the ID3v2.2/2.3/2.4 documents and RFC 3533 (Ogg).
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue
from crush.core.vfs import FileVFS
from crush.parsers import id3v2, jumbf
from crush.parsers.c2pa_reader import summarize_c2pa
from crush.parsers.media_parser import MediaParser

_STORE_UUID = bytes.fromhex("63327061001100108000" "00AA00389B71")
_MANIFEST_UUID = bytes.fromhex("63326D61001100108000" "00AA00389B71")
_CLAIM_UUID = bytes.fromhex("6332636C001100108000" "00AA00389B71")
_BMFF_C2PA_UUID = bytes.fromhex("D8FEC3D61B0E483C92975828877EC481")


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _box(tbox: bytes, content: bytes) -> bytes:
    return struct.pack(">I", 8 + len(content)) + tbox + content


def _superbox(uuid: bytes, label: str, children: bytes = b"") -> bytes:
    jumd = _box(b"jumd", uuid + bytes([0x03]) + label.encode() + b"\x00")
    return _box(b"jumb", jumd + children)


def _tstr(s: str) -> bytes:
    b = s.encode()
    assert len(b) < 24
    return bytes([0x60 | len(b)]) + b


def _store(generator: str = "acme/1.0") -> bytes:
    """A Manifest Store with one manifest whose claim names *generator*."""
    claim = _superbox(_CLAIM_UUID, "c2pa.claim", _box(b"cbor", b"\xa1" + _tstr("claim_generator") + _tstr(generator)))
    return _superbox(_STORE_UUID, "c2pa", _superbox(_MANIFEST_UUID, "urn:test", claim))


def _ftyp(brand: bytes) -> bytes:
    return _box(b"ftyp", brand + b"\x00\x00\x00\x00" + brand + b"isom")


def _c2pa_uuid(purpose: str, data: bytes, merkle_offset: int = 0) -> bytes:
    body = _BMFF_C2PA_UUID + b"\x00\x00\x00\x00" + purpose.encode() + b"\x00"
    if purpose != "merkle":
        body += struct.pack(">Q", merkle_offset)
    return _box(b"uuid", body + data)


def _riff(form: bytes, *chunks: bytes) -> bytes:
    body = form + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _chunk(cid: bytes, data: bytes) -> bytes:
    return cid + struct.pack("<I", len(data)) + data + (b"\x00" if len(data) % 2 else b"")


def _syncsafe(n: int) -> bytes:
    return bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])


def _geob_body(data: bytes, mime: str = "application/c2pa", encoding: int = 0) -> bytes:
    if encoding in (1, 2):
        bom = b"\xff\xfe" if encoding == 1 else b""
        codec = "utf-16-le" if encoding == 1 else "utf-16-be"
        name = bom + "c2pa".encode(codec) + b"\x00\x00"
        desc = bom + "c2pa manifest store".encode(codec) + b"\x00\x00"
    else:
        name, desc = b"c2pa\x00", b"c2pa manifest store\x00"
    return bytes([encoding]) + mime.encode("latin-1") + b"\x00" + name + desc + data


def _frame(version: int, frame_id: bytes, body: bytes, fmt: int = 0) -> bytes:
    if version == 2:
        return frame_id + len(body).to_bytes(3, "big") + body
    size = _syncsafe(len(body)) if version == 4 else struct.pack(">I", len(body))
    return frame_id + size + bytes([0, fmt]) + body


def _id3(version: int, frames: bytes, flags: int = 0, padding: int = 16) -> bytes:
    body = frames + b"\x00" * padding
    return b"ID3" + bytes([version, 0, flags]) + _syncsafe(len(body)) + body


def _unsync(data: bytes) -> bytes:
    """ID3 unsynchronisation: a 0x00 after every 0xFF followed by >= 0xE0 or 0x00
    (and after a trailing 0xFF)."""
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b)
        if b == 0xFF and (i + 1 == len(data) or data[i + 1] >= 0xE0 or data[i + 1] == 0):
            out.append(0)
    return bytes(out)


def _ogg_page(serial: int, seq: int, packets: list[bytes], *, bos: bool = False,
              continued: bool = False, ends_packet: bool = True) -> bytes:
    """One page; the last packet stays open (no terminating lacing value)
    when *ends_packet* is False."""
    lacing = bytearray()
    for i, pkt in enumerate(packets):
        n = len(pkt)
        lacing += b"\xff" * (n // 255)
        if i < len(packets) - 1 or ends_packet:
            lacing.append(n % 255)
        else:
            assert n % 255 == 0
    header_type = (0x02 if bos else 0) | (0x01 if continued else 0)
    header = (
        b"OggS" + bytes([0, header_type]) + struct.pack("<qIII", 0, serial, seq, 0)
        + bytes([len(lacing)]) + bytes(lacing)
    )
    return header + b"".join(packets)


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def _codes(value: Any) -> list[str]:
    return [issue.code for issue in value]


# ---------------------------------------------------------------------------
# BMFF (MP4, MOV, M4A, 3GP ...)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("brand", [b"isom", b"mp42", b"qt  ", b"M4A ", b"3gp4", b"heic"])
def test_bmff_store_is_read_for_every_brand(brand: bytes) -> None:
    mp4 = _ftyp(brand) + _c2pa_uuid("manifest", _store()) + _box(b"mdat", b"\x00" * 8)
    result = summarize_c2pa(mp4)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA Generator"] == "acme/1.0"
    assert "C2PA scan notes" not in result


def test_bmff_without_store_reports_not_present() -> None:
    mp4 = _ftyp(b"isom") + _box(b"moov", b"") + _box(b"mdat", b"\x00" * 8)
    assert summarize_c2pa(mp4) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_bmff_box_running_past_the_end_is_reported_with_its_offset() -> None:
    head = _ftyp(b"isom") + _box(b"moov", b"")
    mp4 = head + struct.pack(">I", 1000) + b"mdat" + b"\x00" * 10
    assert summarize_c2pa(mp4) == {
        "C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": len(head)}),
    }


def test_bmff_box_with_size_below_its_header_is_invalid() -> None:
    head = _ftyp(b"isom")
    mp4 = head + struct.pack(">I", 4) + b"free" + b"\x00" * 10
    assert summarize_c2pa(mp4) == {
        "C2PA": ParseIssue("c2pa.not_found_invalid", {"offset": len(head)}),
    }


def test_store_followed_by_a_truncated_box_lists_the_truncation() -> None:
    head = _ftyp(b"isom") + _c2pa_uuid("manifest", _store())
    mp4 = head + struct.pack(">I", 1000) + b"mdat"
    result = summarize_c2pa(mp4)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA scan notes"] == [ParseIssue("c2pa.scan_truncated", {"offset": len(head)})]


def test_single_merkle_box_is_named_as_hash_data() -> None:
    head = _ftyp(b"isom") + _box(b"mdat", b"")
    mp4 = head + _c2pa_uuid("merkle", b"\xa0")
    assert summarize_c2pa(mp4) == {"C2PA": ParseIssue("c2pa.bmff_merkle", {"offset": len(head)})}


def test_merkle_boxes_are_counted_next_to_the_store() -> None:
    head = _ftyp(b"isom") + _c2pa_uuid("manifest", _store()) + _box(b"mdat", b"")
    merkle = _c2pa_uuid("merkle", b"\xa0")
    mp4 = head + merkle * 3
    result = summarize_c2pa(mp4)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA scan notes"] == [ParseIssue("c2pa.bmff_merkle_boxes", {
        "count": 3, "first": len(head), "last": len(head) + 2 * len(merkle),
    })]


def test_unknown_box_purpose_is_reported_not_skipped() -> None:
    head = _ftyp(b"isom")
    mp4 = head + _c2pa_uuid("future", _store())
    assert summarize_c2pa(mp4) == {"C2PA": ParseIssue(
        "c2pa.bmff_unknown_purpose", {"purpose": "future", "offset": len(head)},
    )}


def test_box_purpose_without_terminator_is_reported() -> None:
    head = _ftyp(b"isom")
    mp4 = head + _box(b"uuid", _BMFF_C2PA_UUID + b"\x00\x00\x00\x00manifest")
    assert summarize_c2pa(mp4)["C2PA"] == ParseIssue("c2pa.bmff_no_purpose", {"offset": len(head)})


def test_manifest_box_without_jumbf_is_not_evaluated() -> None:
    head = _ftyp(b"isom")
    mp4 = head + _c2pa_uuid("manifest", b"not a jumbf box at all")
    assert summarize_c2pa(mp4)["C2PA"] == ParseIssue("c2pa.item_not_jumbf", {
        "item": "BMFF C2PA 'uuid' box (box_purpose 'manifest')", "offset": len(head),
    })


def test_original_and_update_stores_are_both_summarized() -> None:
    first = _ftyp(b"isom") + _box(b"free", b"")
    original = _c2pa_uuid("original", _store("first/1.0"))
    middle = _box(b"mdat", b"\x00" * 4)
    mp4 = first + original + middle + _c2pa_uuid("update", _store("update/2.0"))
    result = summarize_c2pa(mp4)
    assert result["C2PA"] == ParseIssue("c2pa.stores_original_update", {
        "original": 1, "original_offset": len(first),
        "update": 2, "update_offset": len(first + original + middle),
    })
    assert result["C2PA #1 Generator"] == "first/1.0"
    assert result["C2PA #2 Generator"] == "update/2.0"
    assert result["C2PA #1"].code == "c2pa.manifest_found"
    assert "C2PA scan notes" not in result


def test_update_store_without_original_is_summarized_and_noted() -> None:
    head = _ftyp(b"isom")
    mp4 = head + _c2pa_uuid("update", _store("update/2.0"))
    result = summarize_c2pa(mp4)
    assert result["C2PA Generator"] == "update/2.0"
    assert result["C2PA scan notes"] == [ParseIssue("c2pa.bmff_unpaired", {
        "purpose": "update", "missing": "original", "offset": len(head),
    })]


def test_two_manifest_boxes_are_both_shown_and_flagged() -> None:
    head = _ftyp(b"isom")
    first = _c2pa_uuid("manifest", _store("one/1"))
    mp4 = head + first + _c2pa_uuid("manifest", _store("two/2"))
    result = summarize_c2pa(mp4)
    assert result["C2PA"] == ParseIssue("c2pa.stores_multiple", {
        "count": 2, "offsets": f"{len(head):,}, {len(head + first):,}",
    })
    assert result["C2PA #1 Generator"] == "one/1"
    assert result["C2PA #2 Generator"] == "two/2"
    assert "C2PA Generator" not in result


# ---------------------------------------------------------------------------
# RIFF (WAV, AVI)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("form", [b"WAVE", b"AVI ", b"WEBP"])
def test_riff_c2pa_chunk_is_read(form: bytes) -> None:
    wav = _riff(form, _chunk(b"fmt ", b"\x00" * 16), _chunk(b"C2PA", _store()))
    result = summarize_c2pa(wav)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA Generator"] == "acme/1.0"


def test_riff_c2pa_chunk_without_jumbf_is_not_evaluated() -> None:
    fmt = _chunk(b"fmt ", b"\x00" * 16)
    wav = _riff(b"WAVE", fmt, _chunk(b"C2PA", b"garbage!"))
    assert summarize_c2pa(wav)["C2PA"] == ParseIssue(
        "c2pa.item_not_jumbf", {"item": "RIFF 'C2PA' chunk", "offset": 12 + len(fmt)},
    )


def test_riff_declaring_more_than_the_file_holds_is_truncated() -> None:
    wav = _riff(b"WAVE", _chunk(b"fmt ", b"\x00" * 16))
    cut = wav[:4] + struct.pack("<I", 10_000) + wav[8:]
    assert summarize_c2pa(cut) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": len(cut)})}


def test_data_after_the_first_riff_chunk_is_named_as_not_scanned() -> None:
    avi = _riff(b"AVI ", _chunk(b"LIST", b"hdrl"))
    avix = b"RIFF" + struct.pack("<I", 12) + b"AVIX" + _chunk(b"LIST", b"movi")
    assert summarize_c2pa(avi + avix) == {"C2PA": ParseIssue(
        "c2pa.riff_trailing_data", {"count": len(avix), "offset": len(avi)},
    )}


def test_pad_byte_of_an_odd_sized_riff_chunk_is_not_trailing_data() -> None:
    wav = b"RIFF" + struct.pack("<I", 4 + 9) + b"WAVE" + b"abcd" + struct.pack("<I", 1) + b"x" + b"\x00"
    assert summarize_c2pa(wav) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_two_riff_c2pa_chunks_are_numbered() -> None:
    first = _chunk(b"C2PA", _store("one/1"))
    wav = _riff(b"WAVE", first, _chunk(b"C2PA", _store("two/2")))
    result = summarize_c2pa(wav)
    assert result["C2PA"].code == "c2pa.stores_multiple"
    assert result["C2PA"].params["count"] == 2
    assert (result["C2PA #1 Generator"], result["C2PA #2 Generator"]) == ("one/1", "two/2")


# ---------------------------------------------------------------------------
# ID3v2 (MP3, FLAC with a prepended tag)
# ---------------------------------------------------------------------------

_AUDIO = b"\xff\xfb\x90\x00" + b"\x00" * 32  # an MPEG audio frame header and some data


@pytest.mark.parametrize("version,frame_id", [(2, b"GEO"), (3, b"GEOB"), (4, b"GEOB")])
def test_id3_geob_store_is_read_in_every_version(version: int, frame_id: bytes) -> None:
    mp3 = _id3(version, _frame(version, b"TIT2" if version > 2 else b"TT2", b"\x00x")
               + _frame(version, frame_id, _geob_body(_store()))) + _AUDIO
    result = summarize_c2pa(mp3)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA Generator"] == "acme/1.0"


def test_id3_deprecated_media_type_is_still_read() -> None:
    mp3 = _id3(4, _frame(4, b"GEOB", _geob_body(_store(), mime="application/x-c2pa-manifest-store")))
    assert summarize_c2pa(mp3 + _AUDIO)["C2PA"].code == "c2pa.manifest_found"


@pytest.mark.parametrize("encoding", [0, 1, 2, 3])
def test_id3_geob_text_encodings_are_skipped_by_their_terminators(encoding: int) -> None:
    mp3 = _id3(4, _frame(4, b"GEOB", _geob_body(_store(), encoding=encoding)))
    assert summarize_c2pa(mp3 + _AUDIO)["C2PA Generator"] == "acme/1.0"


def test_id3_geob_with_other_media_type_is_not_c2pa() -> None:
    mp3 = _id3(3, _frame(3, b"GEOB", _geob_body(b"PK\x03\x04", mime="application/zip")))
    assert summarize_c2pa(mp3 + _AUDIO) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_id3v23_tag_level_unsynchronisation_is_undone() -> None:
    # 0xFF 0xE0 / 0xFF 0x00 sequences before and inside the GEOB frame:
    # unsynchronisation inserts 0x00 bytes that must be removed again
    # before frame sizes and the frame content are read.
    title = _frame(3, b"TIT2", b"\x00\xff\xe0")
    frames = title + _frame(3, b"GEOB", _geob_body(_store() + b"\xff\xe0\xff\x00"))
    body = _unsync(frames)
    assert body != frames
    mp3 = b"ID3" + bytes([3, 0, 0x80]) + _syncsafe(len(body)) + body + _AUDIO
    assert summarize_c2pa(mp3)["C2PA Generator"] == "acme/1.0"


def test_id3v23_unsynchronised_offsets_are_file_offsets() -> None:
    title = _frame(3, b"TIT2", b"\x00\xff\xe0\xff\xe0")  # gains two 0x00 bytes
    geob = _frame(3, b"GEOB", _geob_body(b"no JUMBF box here"))
    body = _unsync(title + geob)
    mp3 = b"ID3" + bytes([3, 0, 0x80]) + _syncsafe(len(body)) + body
    note = summarize_c2pa(mp3)["C2PA"]
    assert note.code == "c2pa.item_not_jumbf"
    assert note.params["offset"] == 10 + len(title) + 2
    assert mp3[note.params["offset"]:note.params["offset"] + 4] == b"GEOB"


def test_id3v24_frame_level_unsynchronisation_is_undone() -> None:
    store = _store() + b"\xff\xe0"
    geob = _unsync(_geob_body(store))
    mp3 = _id3(4, _frame(4, b"GEOB", geob, fmt=0x02)) + _AUDIO
    assert summarize_c2pa(mp3)["C2PA Generator"] == "acme/1.0"


def test_id3v24_tag_flag_applies_unsynchronisation_to_every_frame() -> None:
    geob = _unsync(_geob_body(_store() + b"\xff\x00"))
    mp3 = _id3(4, _frame(4, b"GEOB", geob), flags=0x80) + _AUDIO
    assert summarize_c2pa(mp3)["C2PA Generator"] == "acme/1.0"


def test_id3v24_data_length_indicator_and_group_byte_are_skipped() -> None:
    body = _geob_body(_store())
    mp3 = _id3(4, _frame(4, b"GEOB", b"\x07" + _syncsafe(len(body)) + body, fmt=0x41)) + _AUDIO
    assert summarize_c2pa(mp3)["C2PA Generator"] == "acme/1.0"


@pytest.mark.parametrize("version", [3, 4])
def test_id3_extended_header_is_skipped(version: int) -> None:
    ext = struct.pack(">I", 6) + b"\x00" * 6 if version == 3 else _syncsafe(6) + b"\x01\x00"
    frames = ext + _frame(version, b"GEOB", _geob_body(_store()))
    mp3 = _id3(version, frames, flags=0x40) + _AUDIO
    assert summarize_c2pa(mp3)["C2PA Generator"] == "acme/1.0"


@pytest.mark.parametrize("version,fmt,code", [
    (3, 0x80, "c2pa.item_compressed"),
    (3, 0x40, "c2pa.item_encrypted"),
    (4, 0x08 | 0x01, "c2pa.item_compressed"),
    (4, 0x04, "c2pa.item_encrypted"),
])
def test_compressed_or_encrypted_geob_frame_is_reported(version: int, fmt: int, code: str) -> None:
    # Content stays opaque: the MIME type sits inside the compressed/encrypted data.
    mp3 = _id3(version, _frame(version, b"GEOB", b"x" * 24, fmt=fmt)) + _AUDIO
    assert summarize_c2pa(mp3)["C2PA"] == ParseIssue(code, {"item": "ID3 GEOB frame", "offset": 10})


def test_frame_running_past_the_tag_end_of_a_cut_file_is_truncated() -> None:
    mp3 = _id3(4, _frame(4, b"GEOB", _geob_body(_store())), padding=0)
    cut = mp3[:40]
    assert summarize_c2pa(cut) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": 10})}


def test_invalid_frame_id_stops_the_scan_as_invalid() -> None:
    title = _frame(4, b"TIT2", b"\x00x")
    mp3 = _id3(4, title + b"t!t2" + b"\x00" * 6, padding=0) + _AUDIO
    assert summarize_c2pa(mp3) == {"C2PA": ParseIssue("c2pa.not_found_invalid", {"offset": 10 + len(title)})}


def test_unsupported_id3_version_is_reported() -> None:
    mp3 = b"ID3" + bytes([5, 0, 0]) + _syncsafe(0) + _AUDIO
    assert summarize_c2pa(mp3) == {"C2PA": ParseIssue("c2pa.id3_version_unsupported", {"version": 5})}


def test_two_c2pa_geob_frames_are_numbered_and_flagged() -> None:
    first = _frame(4, b"GEOB", _geob_body(_store("one/1")))
    mp3 = _id3(4, first + _frame(4, b"GEOB", _geob_body(_store("two/2")))) + _AUDIO
    result = summarize_c2pa(mp3)
    assert result["C2PA"] == ParseIssue("c2pa.stores_multiple", {
        "count": 2, "offsets": f"10, {10 + len(first):,}",
    })
    assert (result["C2PA #1 Generator"], result["C2PA #2 Generator"]) == ("one/1", "two/2")


def test_flac_with_prepended_id3_tag_is_read() -> None:
    flac = _id3(4, _frame(4, b"GEOB", _geob_body(_store()))) + b"fLaC" + b"\x00" * 38
    assert summarize_c2pa(flac)["C2PA"].code == "c2pa.manifest_found"


def test_native_flac_has_no_embedding_defined() -> None:
    assert summarize_c2pa(b"fLaC" + b"\x00" * 38) == {"C2PA": ParseIssue("c2pa.not_defined")}


def test_id3_reader_reports_file_offsets_of_frames() -> None:
    title = _frame(3, b"TIT2", b"\x00abc")
    tag = id3v2.read_id3v2(_id3(3, title + _frame(3, b"GEOB", b"\x00")))
    assert tag is not None
    assert [(f.frame_id, f.offset) for f in tag.frames] == [("TIT2", 10), ("GEOB", 10 + len(title))]


# ---------------------------------------------------------------------------
# Ogg
# ---------------------------------------------------------------------------

_VORBIS_ID = b"\x01vorbis" + b"\x00" * 23


def test_ogg_c2pa_bitstream_is_read() -> None:
    ogg = (
        _ogg_page(1, 0, [_VORBIS_ID], bos=True)
        + _ogg_page(2, 0, [b"\x00c2pa" + _store()], bos=True)
        + _ogg_page(1, 1, [b"\x03vorbis"])
    )
    result = summarize_c2pa(ogg)
    assert result["C2PA"].code == "c2pa.manifest_found"
    assert result["C2PA Generator"] == "acme/1.0"


def test_ogg_c2pa_packet_continued_on_a_later_page() -> None:
    packet = b"\x00c2pa" + _store() + b"\x00" * 600
    split = 510  # two full 255-byte segments on the first page
    ogg = (
        _ogg_page(1, 0, [_VORBIS_ID], bos=True)
        + _ogg_page(7, 0, [packet[:split]], bos=True, ends_packet=False)
        + _ogg_page(1, 1, [b"\x03vorbis"])
        + _ogg_page(7, 1, [packet[split:]], continued=True)
    )
    result = summarize_c2pa(ogg)
    assert result["C2PA Generator"] == "acme/1.0"
    assert "C2PA scan notes" not in result


def test_ogg_without_c2pa_bitstream_reports_not_present() -> None:
    ogg = _ogg_page(1, 0, [_VORBIS_ID], bos=True) + _ogg_page(1, 1, [b"\x03vorbis"])
    assert summarize_c2pa(ogg) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_ogg_c2pa_packet_cut_by_the_end_of_the_data_is_truncated() -> None:
    first = _ogg_page(1, 0, [_VORBIS_ID], bos=True)
    packet = b"\x00c2pa" + _store() + b"\x00" * 600
    ogg = first + _ogg_page(7, 0, [packet[:510]], bos=True, ends_packet=False)
    assert summarize_c2pa(ogg) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": len(first)})}


def test_ogg_page_running_past_the_end_is_truncated() -> None:
    first = _ogg_page(1, 0, [_VORBIS_ID], bos=True)
    ogg = first + _ogg_page(1, 1, [b"\x03vorbis" + b"\x00" * 50])[:-10]
    assert summarize_c2pa(ogg) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": len(first)})}


# ---------------------------------------------------------------------------
# Containers without an embedding, and media recognised only by name
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("head", [
    b"\x1a\x45\xdf\xa3" + b"\x00" * 28,  # Matroska / WebM (EBML)
    bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C") + b"\x00" * 16,  # ASF (WMA/WMV)
    b"#!AMR\n" + b"\x00" * 26,
    b"fLaC" + b"\x00" * 28,
])
def test_containers_without_a_c2pa_embedding(head: bytes) -> None:
    assert summarize_c2pa(head) == {"C2PA": ParseIssue("c2pa.not_defined")}


@pytest.mark.parametrize("head", [
    b"\xff\xfb\x90\x00" + b"\x00" * 28,  # MPEG audio frame without an ID3v2 tag
    b"\xff\xf1\x50\x80" + b"\x00" * 28,  # AAC in ADTS
])
def test_media_not_identified_by_content_is_not_checked(head: bytes) -> None:
    assert summarize_c2pa(head) == {"C2PA": ParseIssue("c2pa.not_checked")}


# ---------------------------------------------------------------------------
# Image containers: the same honest statuses
# ---------------------------------------------------------------------------

def test_png_chunk_running_past_the_end_is_truncated() -> None:
    head = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", b"\x00" * 13)
    png = head + struct.pack(">I", 500) + b"IDAT" + b"\x00" * 20
    assert summarize_c2pa(png) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": len(head)})}


def test_png_cabx_with_jumbf_longer_than_the_chunk_is_reported() -> None:
    store = _store()
    head = b"\x89PNG\r\n\x1a\n"
    png = head + _png_chunk(b"caBX", store[:-10]) + _png_chunk(b"IEND", b"")
    assert summarize_c2pa(png) == {"C2PA": ParseIssue(
        "c2pa.store_exceeds_item", {"item": "PNG 'caBX' chunk", "offset": len(head)},
    )}


def test_jpeg_segment_running_past_the_end_is_truncated() -> None:
    jpeg = b"\xFF\xD8" + b"\xFF\xE1\x10\x00" + b"\x00" * 20
    assert summarize_c2pa(jpeg) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": 2})}


def _app11(en: bytes, z: int, body: bytes) -> bytes:
    payload = b"JP" + en + struct.pack(">I", z) + body
    return b"\xFF\xEB" + struct.pack(">H", len(payload) + 2) + payload


def test_jpeg_app11_sequence_gap_is_reported() -> None:
    store = _store()
    jpeg = (
        b"\xFF\xD8" + _app11(b"\x00\x01", 1, store[:30])
        + _app11(b"\x00\x01", 3, store[:8] + store[30:]) + b"\xFF\xDA\x00\x02\x00"
    )
    assert summarize_c2pa(jpeg) == {"C2PA": ParseIssue("c2pa.jpeg_sequence_gap", {"offset": 2})}


def test_jpeg_app11_jumbf_that_is_not_c2pa_is_ignored() -> None:
    other = _superbox(b"\x00" * 16, "jpeg360")
    jpeg = b"\xFF\xD8" + _app11(b"\x00\x01", 1, other) + b"\xFF\xDA\x00\x02\x00"
    assert summarize_c2pa(jpeg) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_jpeg_two_c2pa_box_instances_are_numbered() -> None:
    first = _app11(b"\x00\x01", 1, _store("one/1"))
    jpeg = b"\xFF\xD8" + first + _app11(b"\x00\x02", 1, _store("two/2")) + b"\xFF\xDA\x00\x02\x00"
    result = summarize_c2pa(jpeg)
    assert result["C2PA"] == ParseIssue("c2pa.stores_multiple", {"count": 2, "offsets": f"2, {2 + len(first):,}"})
    assert (result["C2PA #1 Generator"], result["C2PA #2 Generator"]) == ("one/1", "two/2")


def _gif(*blocks: bytes) -> bytes:
    return b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0, 0, 0]) + b"".join(blocks) + b"\x3B"


def _gif_ext(label: int, data: bytes) -> bytes:
    blocks = b"".join(bytes([len(data[i:i + 255])]) + data[i:i + 255] for i in range(0, len(data), 255))
    return bytes([0x21, label]) + blocks + b"\x00"


def test_gif_extension_without_terminator_is_truncated() -> None:
    gif = _gif(_gif_ext(0xFE, b"comment"))[:-3]
    assert summarize_c2pa(gif) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": 13})}


def test_gif_c2pa_extension_with_other_block_version_is_reported() -> None:
    gif = _gif(_gif_ext(0xFF, b"C2PA_GIF" + bytes([1, 1, 0]) + _store()))
    assert summarize_c2pa(gif) == {"C2PA": ParseIssue("c2pa.gif_block_version", {"version": "1.1", "offset": 13})}


def _tiff(ifds: list[list[tuple[int, int, bytes]]], big: bool = False) -> bytes:
    """Little-endian TIFF/BigTIFF, IFDs chained in order; each entry (tag,
    type, value bytes), values stored after each IFD."""
    if big:
        out = bytearray(b"II+\x00" + struct.pack("<HHQ", 8, 0, 16))
        count_fmt, entry_fmt, off_fmt, inline = "<Q", "<HHQ", "<Q", 8
    else:
        out = bytearray(b"II*\x00" + struct.pack("<I", 8))
        count_fmt, entry_fmt, off_fmt, inline = "<H", "<HHI", "<I", 4
    entry_size = 4 + 2 * inline
    for n, entries in enumerate(ifds):
        ifd_start = len(out)
        data_start = ifd_start + struct.calcsize(count_fmt) + len(entries) * entry_size + inline
        values = bytearray()
        table = bytearray(struct.pack(count_fmt, len(entries)))
        for tag, dtype, value in entries:
            table += struct.pack(entry_fmt, tag, dtype, len(value))
            if len(value) <= inline:
                table += value.ljust(inline, b"\x00")
            else:
                table += struct.pack(off_fmt, data_start + len(values))
                values += value
        next_ifd = data_start + len(values) if n + 1 < len(ifds) else 0
        out += table + struct.pack(off_fmt, next_ifd) + values
    return bytes(out)


def test_tiff_c2pa_tag_in_ifd0_of_a_chain_is_read() -> None:
    tiff = _tiff([[(0xCD41, 7, _store())], [(0x0100, 4, b"\x01\x00\x00\x00")]])
    assert summarize_c2pa(tiff)["C2PA Generator"] == "acme/1.0"


def test_bigtiff_c2pa_tag_is_read() -> None:
    tiff = _tiff([[(0x0100, 4, b"\x01\x00\x00\x00"), (0xCD41, 7, _store())]], big=True)
    assert summarize_c2pa(tiff)["C2PA Generator"] == "acme/1.0"


def test_tiff_ifd_offset_past_the_end_is_truncated() -> None:
    tiff = b"II*\x00" + struct.pack("<I", 5000) + b"\x00" * 8
    assert summarize_c2pa(tiff) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": 5000})}


@pytest.mark.parametrize("dtype", [1, 4])  # BYTE, LONG
def test_tiff_c2pa_tag_with_other_field_type_is_reported(dtype: int) -> None:
    tiff = _tiff([[(0xCD41, dtype, _store())]])
    assert summarize_c2pa(tiff) == {"C2PA": ParseIssue("c2pa.tiff_tag_type", {"type": dtype, "offset": 10})}


def test_tiff_more_than_512_entries_are_all_read() -> None:
    entries = [(0x8000 + i, 4, b"\x00\x00\x00\x00") for i in range(600)] + [(0xCD41, 7, _store())]
    assert summarize_c2pa(_tiff([entries]))["C2PA Generator"] == "acme/1.0"


_JXL = bytes.fromhex("0000000c4a584c200d0a870a")


def test_jpeg_xl_brotli_compressed_jumbf_is_reported() -> None:
    head = _JXL + _box(b"ftyp", b"jxl \x00\x00\x00\x00jxl ")
    jxl = head + _box(b"brob", b"jumb" + b"\x1b\x00compressed")
    assert summarize_c2pa(jxl) == {"C2PA": ParseIssue("c2pa.item_compressed", {
        "item": "JPEG XL 'brob' box (Brotli-compressed 'jumb')", "offset": len(head),
    })}


def test_jpeg_xl_jumbf_that_is_not_c2pa_is_ignored() -> None:
    jxl = _JXL + _superbox(b"\x00" * 16, "other")
    assert summarize_c2pa(jxl) == {"C2PA": ParseIssue("c2pa.not_present")}


def test_jpeg_xl_box_running_past_the_end_is_truncated() -> None:
    jxl = _JXL + struct.pack(">I", 999) + b"jxlc" + b"\x00" * 4
    assert summarize_c2pa(jxl) == {"C2PA": ParseIssue("c2pa.not_found_truncated", {"offset": 12})}


def test_several_notes_without_a_store_are_listed() -> None:
    head = _ftyp(b"isom")
    merkle = _c2pa_uuid("merkle", b"\xa0")
    mp4 = head + merkle + _c2pa_uuid("odd", b"")
    result = summarize_c2pa(mp4)
    assert result["C2PA"] == ParseIssue("c2pa.not_found_see_notes", {"count": 2})
    assert _codes(result["C2PA scan notes"]) == ["c2pa.bmff_unknown_purpose", "c2pa.bmff_merkle"]


def test_scan_results_record_store_offsets() -> None:
    head = _ftyp(b"isom")
    result = jumbf.extract_from_bmff(head + _c2pa_uuid("manifest", _store()))
    assert [(hit.offset, hit.purpose) for hit in result.stores] == [(len(head), "manifest")]


# ---------------------------------------------------------------------------
# MediaParser
# ---------------------------------------------------------------------------

_XMP = (
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
    b'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/>'
    b"</rdf:RDF></x:xmpmeta>"
)


def _parse(tmp_path: Path, name: str, data: bytes) -> dict[str, Any]:
    path = tmp_path / name
    path.write_bytes(data)
    vfs = FileVFS(path)
    return MediaParser().parse(vfs.root(), vfs).metadata


def test_media_parser_reports_c2pa_and_xmp_rows(tmp_path: Path) -> None:
    mp4 = (
        _ftyp(b"isom") + _c2pa_uuid("manifest", _store())
        + _box(b"uuid", bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC") + _XMP)
        + _box(b"mdat", b"\x00" * 8)
    )
    meta = _parse(tmp_path, "clip.bin", mp4)
    assert meta["Metadata"] == ParseIssue("media.metadata_not_checked")
    assert meta["C2PA"].code == "c2pa.manifest_found"
    assert meta["C2PA Generator"] == "acme/1.0"
    assert meta["XMP"].code == "xmp.present"
    assert meta["XMP Digital Source Type"] == "Created using Generative AI (trainedAlgorithmicMedia)"


def test_media_parser_reports_explicit_statuses_without_provenance(tmp_path: Path) -> None:
    meta = _parse(tmp_path, "song.mp3", b"\xff\xfb\x90\x00" + b"\x00" * 64)
    assert meta["C2PA"] == ParseIssue("c2pa.not_checked")
    assert meta["XMP"] == ParseIssue("xmp.not_present")


def test_media_parser_keeps_the_c2pa_exception_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import crush.parsers.c2pa_reader as c2pa_reader

    def _boom(_raw: bytes) -> dict[str, Any]:
        raise ValueError("box table corrupt")

    monkeypatch.setattr(c2pa_reader, "summarize_c2pa", _boom)
    meta = _parse(tmp_path, "clip.mp4", _ftyp(b"isom"))
    assert meta["C2PA"] == ParseIssue("media.c2pa_detection_failed", detail="box table corrupt")
