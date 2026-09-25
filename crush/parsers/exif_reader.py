# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Pure-Python EXIF extractor for JPEG, TIFF, PNG, HEIF/HEIC/AVIF, and JPEG XL.

Extracts the most forensically relevant fields:
  - Device: Make, Model, Software, SerialNumber, LensModel
  - Time:   DateTime, DateTimeOriginal, DateTimeDigitized
  - GPS:    decimal lat/lon, altitude, timestamp, date
  - Camera: ISO, Aperture, ExposureTime, FocalLength
  - Image:  Width, Height, Orientation

JPEG XL, WebP and the PNG eXIf chunk are not read yet; exif_metadata()
says so in its "EXIF" status row rather than returning nothing.
"""
from __future__ import annotations

import struct
from typing import Any

from crush.core.issues import ParseIssue, ParseIssueError, issue_from_exception

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


def exif_metadata(raw: bytes) -> dict[str, Any]:
    """Properties-panel rows for the EXIF in *raw*: always an "EXIF" status
    row first (present / not present / not checked for this format /
    parse failure), then the formatted fields, then "EXIF problems" for
    tags that were present but could not be read."""
    problems: list[ParseIssue] = []
    try:
        exif, status = _read_exif(raw, problems)
    except Exception as exc:
        return {"EXIF": ParseIssue("exif.parse_failed", {"reason": issue_from_exception(exc)})}
    fields = format_for_metadata(exif)
    if status.code == "exif.present" and not fields:
        status = ParseIssue("exif.present_no_listed_fields")
    out: dict[str, Any] = {"EXIF": status}
    out.update(fields)
    if problems:
        out["EXIF problems"] = problems
    return out


def _read_exif(raw: bytes, problems: list[ParseIssue]) -> tuple[dict[str, Any], ParseIssue]:
    """(raw tag values, status) for image bytes, by content."""
    present = ParseIssue("exif.present")
    if raw[:2] == b"\xFF\xD8":
        tiff_data = _find_jpeg_exif(raw)
        if not tiff_data:
            return {}, ParseIssue("exif.not_present")
        return _parse_tiff(tiff_data, problems), present
    if raw[:2] in (b"II", b"MM"):
        return _parse_tiff(raw, problems), present
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return _extract_png_text(raw), ParseIssue("exif.png_not_checked")
    if _is_isobmff_image(raw):
        return _extract_heif_exif(raw, problems)
    if raw[:6] in (b"GIF87a", b"GIF89a") or raw[:2] == b"BM" or raw[:2] == b"\xFF\x0A":
        # GIF and BMP define no EXIF embedding; a bare JPEG XL codestream
        # has no box structure to carry one (only the container form does).
        return {}, ParseIssue("exif.not_defined")
    return {}, ParseIssue("exif.not_checked")


def format_for_metadata(exif: dict[str, Any]) -> dict[str, Any]:
    """Convert raw EXIF values to human-readable strings for the Properties panel.

    A rational with denominator 0 is shown as invalid, never as 0.
    """
    out: dict[str, Any] = {}

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
    if isinstance(et, tuple):
        n, d = et
        if not d:
            out["ExposureTime"] = _invalid_rational(et)
        else:
            out["ExposureTime"] = f"1/{d // n} s" if (n and d % n == 0) else f"{n}/{d} s"

    fn = exif.get("FNumber")
    if isinstance(fn, tuple):
        out["Aperture"] = f"f/{fn[0] / fn[1]:.1f}" if fn[1] else _invalid_rational(fn)

    fl = exif.get("FocalLength")
    if isinstance(fl, tuple):
        out["FocalLength"] = f"{fl[0] / fl[1]:.0f} mm" if fl[1] else _invalid_rational(fl)

    # GPS
    lat_raw, lon_raw = exif.get("GPSLatitude"), exif.get("GPSLongitude")
    if _has_zero_denominator(lat_raw) or _has_zero_denominator(lon_raw):
        out["GPS"] = ParseIssue("exif.gps_invalid", {
            "lat": _rationals_text(lat_raw), "lon": _rationals_text(lon_raw),
        })
    else:
        lat = _dms_to_decimal(lat_raw, exif.get("GPSLatitudeRef", ""))
        lon = _dms_to_decimal(lon_raw, exif.get("GPSLongitudeRef", ""))
        if lat is not None and lon is not None:
            out["GPS"] = f"{lat:.6f}, {lon:.6f}"
        elif lat is not None:
            out["GPS"] = ParseIssue("exif.gps_latitude_only", {"lat": f"{lat:.6f}"})
        elif lon is not None:
            out["GPS"] = ParseIssue("exif.gps_longitude_only", {"lon": f"{lon:.6f}"})

    alt = exif.get("GPSAltitude")
    if isinstance(alt, tuple):
        if not alt[1]:
            out["GPSAltitude"] = _invalid_rational(alt)
        else:
            ref = exif.get("GPSAltitudeRef", 0)
            sign = -1 if ref == 1 else 1
            out["GPSAltitude"] = f"{sign * alt[0] / alt[1]:.1f} m"

    gps_ts = exif.get("GPSTimeStamp")
    gps_ds = exif.get("GPSDateStamp")
    if isinstance(gps_ts, list) and len(gps_ts) >= 3 and _has_zero_denominator(gps_ts):
        out["GPSTime"] = ParseIssue("exif.invalid_rational", {"value": _rationals_text(gps_ts)})
    elif isinstance(gps_ts, list) and len(gps_ts) >= 3:
        def _r(v: Any) -> float:
            if isinstance(v, tuple):
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

def _invalid_rational(value: tuple[int, int]) -> ParseIssue:
    return ParseIssue("exif.invalid_rational", {"value": f"{value[0]}/{value[1]}"})


def _has_zero_denominator(value: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    return any(isinstance(v, tuple) and not v[1] for v in items)


def _rationals_text(value: Any) -> str:
    if value is None:
        return "—"
    items = value if isinstance(value, list) else [value]
    return ", ".join(f"{v[0]}/{v[1]}" if isinstance(v, tuple) else str(v) for v in items)


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


def _parse_tiff(data: bytes, problems: list[ParseIssue]) -> dict[str, Any]:
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        raise ParseIssueError(ParseIssue("exif.bad_tiff_header"))
    endian = "<" if data[:2] == b"II" else ">"
    if struct.unpack_from(f"{endian}H", data, 2)[0] != 42:
        raise ParseIssueError(ParseIssue("exif.bad_tiff_header"))
    ifd0_off = struct.unpack_from(f"{endian}I", data, 4)[0]

    result: dict[str, Any] = {}
    ifd0 = _read_ifd(data, ifd0_off, endian, _IFD0_TAGS, problems)
    exif_off = ifd0.pop("_ExifIFD", None)
    gps_off = ifd0.pop("_GPSIFD", None)
    result.update(ifd0)

    if isinstance(exif_off, int) and exif_off:
        result.update(_read_ifd(data, exif_off, endian, _EXIF_IFD_TAGS, problems))

    if isinstance(gps_off, int) and gps_off:
        result.update(_read_ifd(data, gps_off, endian, _GPS_TAGS, problems))

    return result


def _read_ifd(
    data: bytes, offset: int, endian: str, tags: dict[int, str], problems: list[ParseIssue],
) -> dict[str, Any]:
    """Read the listed *tags* from one IFD. A listed tag that is present
    but unreadable is reported in *problems*, never dropped silently."""
    result: dict[str, Any] = {}
    if offset + 2 > len(data):
        problems.append(ParseIssue("exif.ifd_out_of_range", {"offset": offset}))
        return result
    count = struct.unpack_from(f"{endian}H", data, offset)[0]
    pos = offset + 2
    for read in range(count):
        if pos + 12 > len(data):
            problems.append(ParseIssue("exif.ifd_truncated", {
                "offset": offset, "count": count, "read": read,
            }))
            break
        tag_id, dtype, dcount = struct.unpack_from(f"{endian}HHI", data, pos)
        val_raw = data[pos + 8: pos + 12]
        pos += 12
        name = tags.get(tag_id)
        if name is None:
            continue
        type_size = _TYPE_SIZE.get(dtype, 0)
        if type_size == 0:
            problems.append(ParseIssue("exif.unknown_type", {"tag": name, "dtype": dtype}))
            continue
        total = type_size * dcount
        if total <= 4:
            val_data = val_raw[:total]
        else:
            voff = struct.unpack_from(f"{endian}I", val_raw)[0]
            if voff + total > len(data):
                problems.append(ParseIssue("exif.value_out_of_range", {"tag": name, "offset": voff}))
                continue
            val_data = data[voff: voff + total]
        val = _decode(val_data, dtype, dcount, endian)
        if val is not None:
            result[name] = val
    return result


# Integer and float TIFF types -> struct format character.
_NUMERIC_FORMATS: dict[int, str] = {
    1: "B", 3: "H", 4: "I", 6: "b", 8: "h", 9: "i", 11: "f", 12: "d",
}


def _decode(data: bytes, dtype: int, count: int, endian: str) -> Any:
    """Decode one TIFF value. Rationals stay (numerator, denominator)
    tuples, also with a 0 denominator, so the formatter can flag them."""
    if dtype == 2:  # ASCII
        return data.decode("ascii", errors="replace").rstrip("\x00").strip() or None
    if dtype in _NUMERIC_FORMATS:
        fmt = f"{endian}{_NUMERIC_FORMATS[dtype]}"
        size = _TYPE_SIZE[dtype]
        if count == 1:
            return struct.unpack_from(fmt, data)[0]
        return [struct.unpack_from(fmt, data, i * size)[0] for i in range(count)]
    if dtype in (5, 10):  # RATIONAL / SRATIONAL
        fmt = f"{endian}II" if dtype == 5 else f"{endian}iI"
        if count == 1:
            return struct.unpack_from(fmt, data)
        return [struct.unpack_from(fmt, data, i * 8) for i in range(count)] or None
    # UNDEFINED (7)
    return data


def _dms_to_decimal(dms: Any, ref: str) -> float | None:
    """Degrees/minutes/seconds rationals -> signed decimal degrees. The
    caller has already rejected zero denominators."""
    if not isinstance(dms, list) or len(dms) < 3:
        return None

    def _f(v: Any) -> float:
        return float(v[0]) / float(v[1]) if isinstance(v, tuple) else float(v)
    deg = _f(dms[0]) + _f(dms[1]) / 60 + _f(dms[2]) / 3600
    return -deg if ref in ("S", "W") else deg


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


def _extract_heif_exif(
    raw: bytes, problems: list[ParseIssue],
) -> tuple[dict[str, Any], ParseIssue]:
    """Extract EXIF from a HEIF/HEIC/AVIF file via pillow-heif (optional dep)."""
    try:
        import pillow_heif
    except ImportError:
        return {}, ParseIssue("exif.heif_plugin_missing")
    heif = pillow_heif.open_heif(raw, convert_hdr_to_8bit=False)
    exif_bytes: bytes = heif.info.get("exif", b"") or b""
    if not exif_bytes:
        return {}, ParseIssue("exif.not_present")
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
    return _parse_tiff(exif_bytes, problems), ParseIssue("exif.present")
