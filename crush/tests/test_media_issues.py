"""Media parsers report why something is missing or could not be read
(parser-reason audit, part 2d): EXIF/XMP/C2PA status rows, image format by
content, frame count, ATX block-order heuristic, PDF check failures and
revision-chain stops, media metadata status."""
from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import Any

import pytest

from crush.core.issues import ParseIssue
from crush.core.vfs import DirectoryVFS
from crush.parsers.exif_reader import _parse_tiff, exif_metadata
from crush.parsers.image_parser import ImageParser
from crush.parsers.media_parser import MediaParser
from crush.parsers.pdf_parser import PDFParser

PIL_Image = pytest.importorskip("PIL.Image")


def _node(tmp_path: Path, name: str, content: bytes):  # type: ignore[no-untyped-def]
    (tmp_path / name).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return node, vfs


def _image_bytes(fmt: str, **save_args: Any) -> bytes:
    out = io.BytesIO()
    PIL_Image.new("RGB", (4, 4), color="red").save(out, fmt, **save_args)
    return out.getvalue()


# -- TIFF building blocks for hand-made EXIF ---------------------------------

def _tiff(entries: list[tuple[int, int, int, bytes]], extra: bytes = b"") -> bytes:
    """Little-endian TIFF: one IFD at offset 8 with *entries* (tag, type,
    count, 4-byte value field), followed by *extra* (for out-of-line values,
    starting at offset 8 + 2 + 12*n + 4)."""
    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, value in entries:
        ifd += struct.pack("<HHI", tag, dtype, count) + value.ljust(4, b"\x00")
    ifd += struct.pack("<I", 0)
    return b"II*\x00" + struct.pack("<I", 8) + ifd + extra


def _gps_tiff(latitude: list[tuple[int, int]]) -> bytes:
    """IFD0 -> GPS IFD with GPSLatitudeRef 'N', GPSLatitude, GPSLongitudeRef
    'E', GPSLongitude 10/1 0/1 0/1."""
    gps_ifd_offset = 8 + 2 + 12 + 4
    gps_entries = 4
    data_offset = gps_ifd_offset + 2 + 12 * gps_entries + 4
    lat = b"".join(struct.pack("<II", n, d) for n, d in latitude)
    lon = b"".join(struct.pack("<II", n, d) for n, d in [(10, 1), (0, 1), (0, 1)])
    gps = struct.pack("<H", gps_entries)
    gps += struct.pack("<HHI", 0x0001, 2, 2) + b"N\x00\x00\x00"
    gps += struct.pack("<HHII", 0x0002, 5, 3, data_offset)
    gps += struct.pack("<HHI", 0x0003, 2, 2) + b"E\x00\x00\x00"
    gps += struct.pack("<HHII", 0x0004, 5, 3, data_offset + 24)
    gps += struct.pack("<I", 0)
    ifd0 = struct.pack("<H", 1) + struct.pack("<HHII", 0x8825, 4, 1, gps_ifd_offset)
    ifd0 += struct.pack("<I", 0)
    return b"II*\x00" + struct.pack("<I", 8) + ifd0 + gps + lat + lon


# -- EXIF ---------------------------------------------------------------------

def test_exif_status_row_is_always_present() -> None:
    exif = PIL_Image.Exif()
    exif[0x010F] = "CrushCam"
    with_exif = _image_bytes("JPEG", exif=exif)
    assert exif_metadata(with_exif)["EXIF"] == ParseIssue("exif.present")
    assert exif_metadata(_image_bytes("JPEG"))["EXIF"] == ParseIssue("exif.not_present")
    assert exif_metadata(_image_bytes("GIF"))["EXIF"] == ParseIssue("exif.not_defined")
    assert exif_metadata(_image_bytes("BMP"))["EXIF"] == ParseIssue("exif.not_defined")
    assert exif_metadata(_image_bytes("WEBP"))["EXIF"] == ParseIssue("exif.not_checked")
    assert exif_metadata(_image_bytes("PNG"))["EXIF"] == ParseIssue("exif.png_not_checked")


def test_exif_present_without_listed_fields_says_so() -> None:
    exif = PIL_Image.Exif()
    exif[0x0100] = 4  # ImageWidth -- not one of the fields shown
    result = exif_metadata(_image_bytes("JPEG", exif=exif))
    assert result == {"EXIF": ParseIssue("exif.present_no_listed_fields")}


def test_exif_bad_tiff_header_is_a_parse_failure_not_absence() -> None:
    jpeg = b"\xFF\xD8" + b"\xFF\xE1" + struct.pack(">H", 2 + 6 + 8) + b"Exif\x00\x00" + b"XX*\x00\x08\x00\x00\x00"
    status = exif_metadata(jpeg)["EXIF"]
    assert status.code == "exif.parse_failed"
    assert status.params["reason"].code == "exif.bad_tiff_header"


def test_negative_altitude_keeps_its_sign() -> None:
    # GPSAltitudeRef is a BYTE; it used to be dropped, so every altitude
    # below sea level was shown as positive.
    exif = PIL_Image.Exif()
    gps = exif.get_ifd(0x8825)
    gps[5] = b"\x01"
    gps[6] = 12.5
    result = exif_metadata(_image_bytes("JPEG", exif=exif))
    assert result["GPSAltitude"] == "-12.5 m"


def test_zero_denominator_gps_is_invalid_not_zero() -> None:
    result = exif_metadata(_gps_tiff([(52, 1), (30, 0), (0, 1)]))
    gps = result["GPS"]
    assert isinstance(gps, ParseIssue) and gps.code == "exif.gps_invalid"
    assert "30/0" in str(gps)


def test_valid_gps_still_decodes() -> None:
    result = exif_metadata(_gps_tiff([(52, 1), (30, 1), (0, 1)]))
    assert result["GPS"] == "52.500000, 10.000000"


def test_ifd_entries_beyond_512_are_read() -> None:
    dummies = [(0x9000 + i, 3, 1, b"\x00\x00") for i in range(600)]
    make = (0x010F, 2, 4, b"Cam\x00")
    assert exif_metadata(_tiff(dummies + [make]))["Make"] == "Cam"


def test_array_values_are_not_capped_at_eight() -> None:
    offset = 8 + 2 + 12 + 4
    values = struct.pack("<10H", *range(10))
    tiff = _tiff([(0x0112, 3, 10, struct.pack("<I", offset))], values)  # Orientation, 10 SHORTs
    assert _parse_tiff(tiff, [])["Orientation"] == list(range(10))


def test_unreadable_listed_tag_is_reported() -> None:
    tiff = _tiff([(0x010F, 2, 64, struct.pack("<I", 10_000))])  # Make -> beyond EOF
    result = exif_metadata(tiff)
    assert result["EXIF problems"] == [
        ParseIssue("exif.value_out_of_range", {"tag": "Make", "offset": 10_000})
    ]


# -- ImageParser --------------------------------------------------------------

def test_format_comes_from_content_not_extension(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "renamed.png", _image_bytes("JPEG"))
    assert ImageParser().parse(node, vfs).metadata["Format"] == "JPEG"


def test_unrecognised_content_names_the_extension(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "fake.jpg", b"not an image at all")
    fmt = ImageParser().parse(node, vfs).metadata["Format"]
    assert fmt == ParseIssue("image.format_unrecognised", {"ext": ".jpg"})


def test_multi_frame_image_says_only_first_is_shown(tmp_path: Path) -> None:
    out = io.BytesIO()
    frames = [PIL_Image.new("RGB", (4, 4), c) for c in ("red", "blue")]
    frames[0].save(out, "GIF", save_all=True, append_images=frames[1:])
    node, vfs = _node(tmp_path, "anim.gif", out.getvalue())
    meta = ImageParser().parse(node, vfs).metadata
    assert meta["Frames"] == ParseIssue("image.frames_first_only", {"count": 2})


def test_single_frame_image_has_no_frames_row(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "one.png", _image_bytes("PNG"))
    assert "Frames" not in ImageParser().parse(node, vfs).metadata


def test_image_has_exif_c2pa_and_xmp_status_rows(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "plain.jpg", _image_bytes("JPEG"))
    meta = ImageParser().parse(node, vfs).metadata
    assert meta["EXIF"].code == "exif.not_present"
    assert meta["C2PA"].code == "c2pa.not_present"
    assert meta["XMP"].code == "xmp.not_present"


def test_c2pa_failure_keeps_the_exception_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import crush.parsers.c2pa_reader as c2pa_reader

    def _boom(_raw: bytes) -> dict[str, Any]:
        raise ValueError("box table corrupt")

    monkeypatch.setattr(c2pa_reader, "summarize_c2pa", _boom)
    node, vfs = _node(tmp_path, "plain.jpg", _image_bytes("JPEG"))
    meta = ImageParser().parse(node, vfs).metadata
    assert meta["C2PA"] == ParseIssue("image.c2pa_detection_failed", detail="box table corrupt")


# -- ATX ----------------------------------------------------------------------

_VOID_EXTENT_BLOCK = bytes.fromhex("fcfdffffffffffff") + struct.pack(
    "<4H", 0xFFFF, 0x8000, 0x0000, 0xFFFF
)


def test_atx_macro_tiled_block_order_is_marked_heuristic_with_both_scores() -> None:
    pytest.importorskip("astc_decomp_faster")
    from crush.parsers.apple_atx import decode_atx

    head = bytearray(0x54)
    struct.pack_into("<5I", head, 0x18, 128, 128, 1, 0, 1)
    struct.pack_into("<I", head, 0x2C, 1)
    struct.pack_into("<2I", head, 0x4C, 3, 5)
    payload = struct.pack("<I", 0) + _VOID_EXTENT_BLOCK * (32 * 32)
    data = (
        b"AAPL\r\n\x1a\n"
        + struct.pack("<I4s", len(head), b"HEAD") + bytes(head)
        + struct.pack("<I4s", len(payload), b"astc") + payload
    )
    result = decode_atx(data)

    assert result.image is not None
    order = result.block_order
    assert order is not None and order.code == "atx.block_order_heuristic"
    assert {order.params["chosen"].code, order.params["other"].code} == {
        "atx.morton_as_stored", "atx.morton_swapped",
    }
    assert "chosen_score" in order.params and "other_score" in order.params


def test_atx_decode_failure_keeps_its_reason() -> None:
    from crush.parsers.apple_atx import decode_atx

    head = bytearray(0x54)
    struct.pack_into("<2I", head, 0x18, 0, 16)  # zero width
    struct.pack_into("<2I", head, 0x4C, 3, 5)
    payload = struct.pack("<I", 16) + bytes(16)
    data = (
        b"AAPL\r\n\x1a\n"
        + struct.pack("<I4s", len(head), b"HEAD") + bytes(head)
        + struct.pack("<I4s", len(payload), b"astc") + payload
    )
    warning = decode_atx(data).warnings[-1]
    assert warning.code == "atx.decode_failed"
    assert warning.params["reason"] == ParseIssue("atx.invalid_dimensions", {"width": 0, "height": 16})
    assert str(warning) == "ATX image decode failed: invalid ATX dimensions: 0x16"


# -- PDF ----------------------------------------------------------------------

class _Broken:
    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(f"cannot read {name}")


def test_pdf_checks_that_fail_say_so_instead_of_reporting_absence() -> None:
    assert PDFParser._javascript_status(_Broken()) == ParseIssue(
        "pdf.js_check_failed", detail="cannot read root_object",
    )
    assert PDFParser._signature_status(_Broken()).code == "pdf.signatures_check_failed"
    attachments, status = PDFParser._extract_attachments(_Broken())
    assert attachments == []
    assert status.code == "pdf.attachments_failed"


def test_pdf_text_status_names_failed_pages_and_empty_text() -> None:
    class _Page:
        def __init__(self, text: str | None) -> None:
            self._text = text

        def extract_text(self) -> str:
            if self._text is None:
                raise ValueError("bad content stream")
            return self._text

    class _Reader:
        def __init__(self, pages: list[_Page]) -> None:
            self.pages = pages

    text, status = PDFParser._extract_text(_Reader([_Page("one"), _Page(None)]))
    assert "one" in text
    assert status is not None and status.code == "pdf.text_pages_failed"
    assert str(status) == "Text extraction failed on 1 page(s): page 2: bad content stream"

    text, status = PDFParser._extract_text(_Reader([_Page("")]))
    assert text == ""
    assert status == ParseIssue("pdf.no_text")


def test_pdf_revision_chain_stop_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    import pypdf

    class _Reader:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.trailer = {"/Prev": 0}

    monkeypatch.setattr(pypdf, "PdfReader", _Reader)
    revisions, stop = PDFParser._split_revisions(b"%PDF-1.4 %%EOF tail")
    assert len(revisions) == 2
    assert stop == ParseIssue("pdf.revchain_cycle", {"count": 2, "offset": 0})

    revisions, stop = PDFParser._split_revisions(b"%PDF-1.4 no end marker")
    assert len(revisions) == 1
    assert stop == ParseIssue("pdf.revchain_no_eof", {"count": 1, "offset": 0})


def test_pdf_info_values_are_not_truncated(tmp_path: Path) -> None:
    pypdf = pytest.importorskip("pypdf")
    title = "T" * 500
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.add_metadata({"/Title": title})
    out = io.BytesIO()
    writer.write(out)
    node, vfs = _node(tmp_path, "long.pdf", out.getvalue())

    meta = PDFParser().parse(node, vfs).metadata
    assert meta["Title"] == title
    assert meta["XMP"].code == "pdf.xmp_not_present"
    assert meta["Text extraction"] == ParseIssue("pdf.no_text")


def test_pdf_wrong_password_carries_a_code(tmp_path: Path) -> None:
    pypdf = pytest.importorskip("pypdf")
    from crush.core.passwords import WrongPasswordError

    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("secret")
    out = io.BytesIO()
    writer.write(out)
    node, vfs = _node(tmp_path, "locked.pdf", out.getvalue())

    with pytest.raises(WrongPasswordError) as excinfo:
        PDFParser().parse(node, vfs, password="wrong")
    assert excinfo.value.args[0].code == "pdf.wrong_password"
    assert str(excinfo.value) == f"Wrong password for encrypted PDF: {node.path}"


# -- Media --------------------------------------------------------------------

def test_media_metadata_not_checked_outside_ogg_amr(tmp_path: Path) -> None:
    node, vfs = _node(tmp_path, "clip.mp4", b"\x00\x00\x00\x18ftypmp42" + bytes(16))
    meta = MediaParser().parse(node, vfs).metadata
    assert meta["Metadata"] == ParseIssue("media.metadata_not_checked")


def test_media_metadata_failure_is_reported(tmp_path: Path) -> None:
    pytest.importorskip("av")
    node, vfs = _node(tmp_path, "voice.ogg", b"OggS" + bytes(60))
    meta = MediaParser().parse(node, vfs).metadata
    assert meta["Metadata"].code in {"media.metadata_failed", "media.no_audio_stream"}
