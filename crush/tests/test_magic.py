# SPDX-License-Identifier: Apache-2.0
"""Tests for crush.core.magic.detect_fast_label()."""
from __future__ import annotations

from crush.core.magic import detect_fast_label

# ---------------------------------------------------------------------------
# Helpers — synthetic byte sequences
# ---------------------------------------------------------------------------

def _isobmff(brand: bytes) -> bytes:
    """Minimal ISOBMFF header: 4-byte box size, 'ftyp', 4-byte brand."""
    return b"\x00" * 4 + b"ftyp" + brand + b"\x00" * 20


# Ogg page header: OggS(4) + version(1) + type(1) + granule_pos(8) +
#   serial(4) + seqno(4) + crc(4) + page_segs(1) + seg_table(1) = 28 bytes
_OGG_HDR = b"OggS" + b"\x00" * 22 + b"\x01" + b"\x1f"

_JXL_CONTAINER = b"\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A" + b"\x00" * 20
_JXL_BARE      = b"\xFF\x0A" + b"\x00" * 20
_JPEG          = b"\xFF\xD8\xFF\xE0" + b"\x00" * 100
_PNG           = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
_ATX           = b"AAPL\r\n\x1a\n" + b"\x00" * 100
_KTX           = b"\xabKTX 11\xbb\r\n\x1a\n" + b"\x00" * 100

# ---------------------------------------------------------------------------
# ISOBMFF image brands
# ---------------------------------------------------------------------------

def test_detect_heic() -> None:
    assert detect_fast_label(_isobmff(b"heic"), "photo.heic") == "HEIC"


def test_detect_heix() -> None:
    assert detect_fast_label(_isobmff(b"heix"), "photo.heic") == "HEIC"


def test_detect_hevc_brand() -> None:
    assert detect_fast_label(_isobmff(b"hevc"), "photo.heic") == "HEIC"


def test_detect_mif1_heif() -> None:
    assert detect_fast_label(_isobmff(b"mif1"), "photo.heif") == "HEIF"


def test_detect_msf1_heif() -> None:
    assert detect_fast_label(_isobmff(b"msf1"), "photo.heif") == "HEIF"


def test_detect_avif() -> None:
    assert detect_fast_label(_isobmff(b"avif"), "image.avif") == "AVIF"


def test_detect_avis_animated() -> None:
    assert detect_fast_label(_isobmff(b"avis"), "animation.avif") == "AVIF"


def test_isobmff_non_image_brand_not_heic_avif() -> None:
    # MP4 container — brand 'isom' should not return HEIC/HEIF/AVIF
    label = detect_fast_label(_isobmff(b"isom"), "video.mp4")
    assert label not in {"HEIC", "HEIF", "AVIF"}

# ---------------------------------------------------------------------------
# JPEG XL
# ---------------------------------------------------------------------------

def test_detect_jxl_container() -> None:
    assert detect_fast_label(_JXL_CONTAINER, "image.jxl") == "JXL"


def test_detect_jxl_bare_codestream() -> None:
    assert detect_fast_label(_JXL_BARE, "image.jxl") == "JXL"


def test_detect_atx() -> None:
    assert detect_fast_label(_ATX, "image.atx") == "ATX"


def test_detect_ktx() -> None:
    assert detect_fast_label(_KTX, "snapshot.ktx") == "KTX"

# ---------------------------------------------------------------------------
# OGG container codecs
# ---------------------------------------------------------------------------

def test_detect_opus() -> None:
    peek = _OGG_HDR + b"OpusHead" + b"\x00" * 20
    assert detect_fast_label(peek, "voice.opus") == "Opus"


def test_detect_ogg_vorbis() -> None:
    peek = _OGG_HDR + b"\x01vorbis" + b"\x00" * 20
    assert detect_fast_label(peek, "music.ogg") == "OGG"


def test_detect_ogg_unknown_codec() -> None:
    peek = _OGG_HDR + b"SPEEX   " + b"\x00" * 20
    assert detect_fast_label(peek, "audio.ogg") == "OGG"

# ---------------------------------------------------------------------------
# Standard images fall through to filetype → return "Image"
# ---------------------------------------------------------------------------

def test_detect_jpeg_returns_image() -> None:
    assert detect_fast_label(_JPEG, "photo.jpg") == "Image"


def test_detect_png_returns_image() -> None:
    assert detect_fast_label(_PNG, "photo.png") == "Image"

# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_detect_empty_bytes_no_crash() -> None:
    result = detect_fast_label(b"", "file.bin")
    assert isinstance(result, str)


def test_detect_short_bytes_no_crash() -> None:
    result = detect_fast_label(b"\x00\x01\x02", "file.bin")
    assert isinstance(result, str)


def test_detect_isobmff_too_short_for_brand() -> None:
    # Only 11 bytes — can't read brand at offset 8..12
    result = detect_fast_label(b"\x00" * 4 + b"ftyp" + b"\x00" * 3, "file.bin")
    assert result not in {"HEIC", "HEIF", "AVIF"}
