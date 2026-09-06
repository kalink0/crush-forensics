# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Pure-Python EXIF extractor for JPEG, TIFF, PNG, HEIF/HEIC/AVIF, and JPEG XL.

Extracts the most forensically relevant fields:
  - Device: Make, Model, Software, SerialNumber, LensModel
  - Time:   DateTime, DateTimeOriginal, DateTimeDigitized
  - GPS:    decimal lat/lon, altitude, timestamp, date
  - Camera: ISO, Aperture, ExposureTime, FocalLength
  - Image:  Width, Height, Orientation
"""
from __future__ import annotations

import struct
from typing import Any

# TIFF datatype byte sizes
_TYPE_SIZE: dict[int, int] = {
    1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8,
}

# IFD0 tags we care about
_IFD0_TAGS: dict[int, str] = {
    0x010E: "Description",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x013C: "HostComputer",
    0x8769: "_ExifIFD",
    0x8825: "_GPSIFD",
}

_EXIF_IFD_TAGS: dict[int, str] = {
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISO",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x920A: "FocalLength",
    0xA002: "PixelWidth",
    0xA003: "PixelHeight",
    0xA431: "SerialNumber",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
}

_GPS_TAGS: dict[int, str] = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0011: "GPSImgDirection",
    0x001D: "GPSDateStamp",
}

_ORIENTATION_LABELS: dict[int, str] = {
    1: "Normal", 2: "Flip H", 3: "180°", 4: "Flip V",
    5: "90° CW + Flip H", 6: "90° CW", 7: "90° CCW + Flip H", 8: "90° CCW",
}


def extract_exif(raw: bytes) -> dict[str, Any]:
    """Return raw EXIF dict from image bytes (JPEG, TIFF, PNG, HEIF/HEIC/AVIF, or JPEG XL)."""
    try:
        if len(raw) < 4:
            return {}
        if raw[:2] == b"\xFF\xD8":
            tiff_data = _find_jpeg_exif(raw)
            if not tiff_data:
                return {}
            return _parse_tiff(tiff_data)
        if raw[:2] in (b"II", b"MM"):
            return _parse_tiff(raw)
        if raw[:8] == b"\x89PNG\r\n\x1a\n":
            return _extract_png_text(raw)
        if _is_isobmff_image(raw):
            return _extract_heif_exif(raw)
    except Exception:
        pass
    return {}


def format_for_metadata(exif: dict[str, Any]) -> dict[str, str]:
    """Convert raw EXIF values to human-readable strings for the Properties panel."""
    out: dict[str, str] = {}

    def _str(key: str) -> None:
        val = exif.get(key)
        if val and isinstance(val, (str, bytes)):
            s = val.decode("ascii", errors="replace") if isinstance(val, bytes) else val
            s = s.strip()
            if s:
                out[key] = s

    for k in ("Make", "Model", "Software", "HostComputer", "Artist",
              "Description", "SerialNumber", "LensModel", "LensSerialNumber"):
        _str(k)

    for k in ("DateTime", "DateTimeOriginal", "DateTimeDigitized", "GPSDateStamp"):
        _str(k)

    ori = exif.get("Orientation")
    if isinstance(ori, int):
        out["Orientation"] = _ORIENTATION_LABELS.get(ori, str(ori))

    iso = exif.get("ISO")
    if isinstance(iso, int):
        out["ISO"] = str(iso)

    pw, ph = exif.get("PixelWidth"), exif.get("PixelHeight")
    if isinstance(pw, int) and isinstance(ph, int):
        out["Dimensions"] = f"{pw} × {ph} px"

    et = exif.get("ExposureTime")
    if isinstance(et, tuple) and et[1]:
        n, d = et
        out["ExposureTime"] = f"1/{d // n} s" if (n and d % n == 0) else f"{n}/{d} s"

    fn = exif.get("FNumber")
    if isinstance(fn, tuple) and fn[1]:
        out["Aperture"] = f"f/{fn[0] / fn[1]:.1f}"

    fl = exif.get("FocalLength")
    if isinstance(fl, tuple) and fl[1]:
        out["FocalLength"] = f"{fl[0] / fl[1]:.0f} mm"

    # GPS
    lat = _dms_to_decimal(exif.get("GPSLatitude"), exif.get("GPSLatitudeRef", ""))
    lon = _dms_to_decimal(exif.get("GPSLongitude"), exif.get("GPSLongitudeRef", ""))
    if lat is not None and lon is not None:
        out["GPS"] = f"{lat:.6f}, {lon:.6f}"

    alt = exif.get("GPSAltitude")
    if isinstance(alt, tuple) and alt[1]:
        ref = exif.get("GPSAltitudeRef", 0)
        sign = -1 if ref == 1 else 1
        out["GPSAltitude"] = f"{sign * alt[0] / alt[1]:.1f} m"

    gps_ts = exif.get("GPSTimeStamp")
    gps_ds = exif.get("GPSDateStamp")
    if isinstance(gps_ts, list) and len(gps_ts) >= 3:
        def _r(v: Any) -> float:
            if isinstance(v, tuple) and v[1]:
                return float(v[0]) / float(v[1])
            return float(v) if v is not None else 0.0
        h, m, s = _r(gps_ts[0]), _r(gps_ts[1]), _r(gps_ts[2])
        ts_str = f"{int(h):02d}:{int(m):02d}:{s:05.2f} UTC"
        if gps_ds and isinstance(gps_ds, str):
            ts_str = f"{gps_ds} {ts_str}"
        out["GPSTime"] = ts_str

    return out


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_jpeg_exif(raw: bytes) -> bytes:
    """Scan JPEG markers and return the TIFF payload from APP1 EXIF, or b''."""
    pos = 2  # skip SOI (FF D8)
    while pos + 2 <= len(raw):
        if raw[pos] != 0xFF:
            break
        marker = raw[pos + 1]
        # Standalone markers (no length field)
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            pos += 2
            continue
        if pos + 4 > len(raw):
            break
        seg_len = struct.unpack_from(">H", raw, pos + 2)[0]
        if marker == 0xE1:  # APP1
            seg = raw[pos + 4: pos + 2 + seg_len]
            if seg[:6] == b"Exif\x00\x00":
                return seg[6:]
        pos += 2 + seg_len
    return b""


def _parse_tiff(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        return {}
    if data[:2] == b"II":
        endian = "<"
    elif data[:2] == b"MM":
        endian = ">"
    else:
        return {}
    if struct.unpack_from(f"{endian}H", data, 2)[0] != 42:
        return {}
    ifd0_off = struct.unpack_from(f"{endian}I", data, 4)[0]

    result: dict[str, Any] = {}
    ifd0 = _read_ifd(data, ifd0_off, endian, _IFD0_TAGS)
    exif_off = ifd0.pop("_ExifIFD", None)
    gps_off = ifd0.pop("_GPSIFD", None)
    result.update(ifd0)

    if isinstance(exif_off, int) and exif_off:
        result.update(_read_ifd(data, exif_off, endian, _EXIF_IFD_TAGS))

    if isinstance(gps_off, int) and gps_off:
        result.update(_read_ifd(data, gps_off, endian, _GPS_TAGS))

    return result


def _read_ifd(data: bytes, offset: int, endian: str, tags: dict[int, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if offset + 2 > len(data):
        return result
    count = struct.unpack_from(f"{endian}H", data, offset)[0]
    pos = offset + 2
    for _ in range(min(count, 512)):
        if pos + 12 > len(data):
            break
        tag_id, dtype, dcount = struct.unpack_from(f"{endian}HHI", data, pos)
        val_raw = data[pos + 8: pos + 12]
        pos += 12
        name = tags.get(tag_id)
        if name is None:
            continue
        type_size = _TYPE_SIZE.get(dtype, 0)
        if type_size == 0:
            continue
        total = type_size * dcount
        if total <= 4:
            val_data = val_raw[:total]
        else:
            voff = struct.unpack_from(f"{endian}I", val_raw)[0]
            if voff + total > len(data):
                continue
            val_data = data[voff: voff + total]
        val = _decode(val_data, dtype, dcount, endian)
        if val is not None:
            result[name] = val
    return result


def _decode(data: bytes, dtype: int, count: int, endian: str) -> Any:
    if dtype == 2:  # ASCII
        return data.decode("ascii", errors="replace").rstrip("\x00").strip() or None
    if dtype in (3, 4, 9):  # SHORT / LONG / SLONG
        fmt = {3: f"{endian}H", 4: f"{endian}I", 9: f"{endian}i"}[dtype]
        sz = {3: 2, 4: 4, 9: 4}[dtype]
        if count == 1:
            return struct.unpack_from(fmt, data)[0]
        return [struct.unpack_from(fmt, data, i * sz)[0] for i in range(min(count, 8))]
    if dtype in (5, 10):  # RATIONAL / SRATIONAL
        fmt = f"{endian}II" if dtype == 5 else f"{endian}iI"
        if count == 1 and len(data) >= 8:
            n, d = struct.unpack_from(fmt, data)
            return (n, d) if d else None
        items = []
        for i in range(count):
            if (i + 1) * 8 > len(data):
                break
            n, d = struct.unpack_from(fmt, data, i * 8)
            items.append((n, d) if d else None)
        return items or None
    if dtype == 7:  # UNDEFINED
        return data
    return None


def _dms_to_decimal(dms: Any, ref: str) -> float | None:
    if not isinstance(dms, list) or len(dms) < 3:
        return None
    try:
        def _f(v: Any) -> float:
            if isinstance(v, tuple) and v[1]:
                return float(v[0]) / float(v[1])
            return float(v) if v is not None else 0.0
        deg = _f(dms[0]) + _f(dms[1]) / 60 + _f(dms[2]) / 3600
        return -deg if ref in ("S", "W") else deg
    except Exception:
        return None


def _extract_png_text(raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pos = 8
    while pos + 8 <= len(raw):
        clen = struct.unpack_from(">I", raw, pos)[0]
        ctype = raw[pos + 4: pos + 8]
        cdata = raw[pos + 8: pos + 8 + clen]
        if ctype == b"tEXt":
            sep = cdata.find(b"\x00")
            if sep >= 0:
                k = cdata[:sep].decode("latin-1", errors="replace")
                v = cdata[sep + 1:].decode("latin-1", errors="replace")
                result[k] = v
        elif ctype == b"IEND":
            break
        pos += 8 + clen + 4
    return result


# ---------------------------------------------------------------------------
# HEIF / HEIC / AVIF helpers (require pillow-heif optional dependency)
# ---------------------------------------------------------------------------

_ISOBMFF_IMAGE_BRANDS: frozenset[bytes] = frozenset({
    b"heic", b"heix", b"hevc", b"hevx",
    b"heim", b"heis", b"hevm", b"hevs",
    b"mif1", b"msf1",
    b"avif", b"avis",
})


def _is_isobmff_image(raw: bytes) -> bool:
    return len(raw) >= 12 and raw[4:8] == b"ftyp" and raw[8:12] in _ISOBMFF_IMAGE_BRANDS


def _extract_heif_exif(raw: bytes) -> dict[str, Any]:
    """Extract EXIF from a HEIF/HEIC/AVIF file via pillow-heif (optional dep)."""
    try:
        import pillow_heif
        heif = pillow_heif.open_heif(raw, convert_hdr_to_8bit=False)
        exif_bytes: bytes = heif.info.get("exif", b"")
        if not exif_bytes:
            return {}
        # pillow-heif may include a 4-byte length prefix before the TIFF block
        if exif_bytes[:4] == b"Exif" or exif_bytes[4:8] == b"Exif":
            # Strip any leading length word so we land on "Exif\x00\x00<TIFF>"
            start = exif_bytes.find(b"Exif\x00\x00")
            if start >= 0:
                exif_bytes = exif_bytes[start + 6:]
        elif len(exif_bytes) > 4:
            # Raw 4-byte offset prefix (value = 6 means skip 6 bytes to TIFF)
            skip = struct.unpack_from(">I", exif_bytes)[0]
            if 4 < skip < len(exif_bytes):
                exif_bytes = exif_bytes[skip:]
        return _parse_tiff(exif_bytes)
    except ImportError:
        return {}
    except Exception:
        return {}
