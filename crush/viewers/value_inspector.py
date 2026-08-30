# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Value Inspector — flat interpretation panel for text/numeric cell values."""
from __future__ import annotations

import base64
import struct
import uuid as _uuid_mod
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard, QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_MUTED = QColor(140, 140, 140)
_GROUP_BG = QColor(240, 240, 240)

# Reference epochs
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_HFS_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)

# Plausible timestamp ranges: 1990-01-01 to 2100-01-01 (Unix seconds)
_TS_S_MIN, _TS_S_MAX = 631_152_000, 4_102_444_800
_TS_MS_MIN, _TS_MS_MAX = _TS_S_MIN * 1_000, _TS_S_MAX * 1_000
_TS_US_MIN, _TS_US_MAX = _TS_S_MIN * 1_000_000, _TS_S_MAX * 1_000_000

# Cocoa: seconds since 2001-01-01; Cocoa epoch is 978_307_200s after Unix epoch
_COCOA_OFFSET = 978_307_200
_COCOA_MIN = _TS_S_MIN - _COCOA_OFFSET
_COCOA_MAX = _TS_S_MAX - _COCOA_OFFSET

# Chrome/WebKit: µs since 1601-01-01
_CHROME_US_MIN = 12_591_158_400_000_000
_CHROME_US_MAX = 15_778_476_000_000_000

# Windows FILETIME: 100ns intervals since 1601-01-01
_WIN_FT_MIN = _CHROME_US_MIN * 10
_WIN_FT_MAX = _CHROME_US_MAX * 10

# HFS+: seconds since 1904-01-01; offset from Unix epoch
_HFS_OFFSET = 2_082_844_800
_HFS_MIN = _TS_S_MIN + _HFS_OFFSET
_HFS_MAX = _TS_S_MAX + _HFS_OFFSET

# Apple Absolute Time (Nanosecond): ns since 2001-01-01
_COCOA_NS_MIN = _COCOA_MIN * 1_000_000_000
_COCOA_NS_MAX = _COCOA_MAX * 1_000_000_000

# Microsoft .NET Ticks: 100ns intervals since 0001-01-01
_NET_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
_NET_EPOCH_OFFSET_S = 62_135_596_800   # seconds from 0001-01-01 to Unix epoch
_NET_TICKS_PER_S = 10_000_000
_NET_EPOCH_TICKS = _NET_EPOCH_OFFSET_S * _NET_TICKS_PER_S
_TICKS_MIN = (_TS_S_MIN + _NET_EPOCH_OFFSET_S) * _NET_TICKS_PER_S
_TICKS_MAX = (_TS_S_MAX + _NET_EPOCH_OFFSET_S) * _NET_TICKS_PER_S

# OLE Automation Date: days (float) since 1899-12-30
_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)
_OLE_MIN = 32874.0   # 1990-01-01
_OLE_MAX = 73050.0   # 2100-01-01

# Twitter / X Snowflake ID: upper 41 bits = ms since 2010-11-04 01:42:54.657 UTC
_TWITTER_EPOCH_MS = 1_288_834_974_657

# FAT / exFAT (MS-DOS): 32-bit packed, upper 16 = date, lower 16 = time (2s resolution)
# Date word: bits 15-9 = year offset from 1980, bits 8-5 = month, bits 4-0 = day
# Time word: bits 15-11 = hour, bits 10-5 = minute, bits 4-0 = 2-second count
_FAT_TS_MIN = 0x0021_0000  # 1980-01-01 00:00:00
_FAT_TS_MAX = 0xFF9F_BF7D  # 2107-12-31 23:59:58

# UUID v1: 60-bit timestamp = 100ns intervals since Gregorian epoch 1582-10-15
_UUID_V1_GREG_OFFSET = 0x01B21DD213814000  # 100ns intervals from 1582-10-15 to 1970-01-01

# GPS Time: seconds (or nanoseconds) since 1980-01-06 00:00:00 UTC, NO leap seconds.
# GPS is currently 18 s ahead of UTC; displayed values are raw GPS time (not UTC-corrected).
_GPS_EPOCH_UNIX = 315_964_800   # Unix timestamp of GPS epoch 1980-01-06
_GPS_S_MIN = _TS_S_MIN - _GPS_EPOCH_UNIX    # ~315_187_200  (≈ 1990-01-01 in GPS seconds)
_GPS_S_MAX = _TS_S_MAX - _GPS_EPOCH_UNIX    # ~3_786_480_000 (≈ 2100-01-01 in GPS seconds)
_GPS_NS_MIN = _GPS_S_MIN * 1_000_000_000
_GPS_NS_MAX = _GPS_S_MAX * 1_000_000_000


def _fmt_dt(dt: datetime) -> str:
    if dt.microsecond:
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}.{dt.microsecond:06d} UTC"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_ts(ts_s: float) -> str | None:
    # epoch + timedelta rather than datetime.fromtimestamp(): the latter is OS-clamped on
    # Windows and rejects timestamps fromtimestamp() would otherwise handle fine on Linux/Mac.
    try:
        dt = _UNIX_EPOCH + timedelta(seconds=ts_s)
    except (OverflowError, ValueError):
        return None
    return _fmt_dt(dt)


def _bcd_byte(b: int) -> int | None:
    """Decode a single BCD byte to decimal (0-99), or None if nibbles are not 0-9."""
    hi, lo = (b >> 4) & 0xF, b & 0xF
    if hi > 9 or lo > 9:
        return None
    return hi * 10 + lo


# ---------------------------------------------------------------------------
# Interpretation engine
# ---------------------------------------------------------------------------

class _Row:
    __slots__ = ("group", "label", "value")

    def __init__(self, group: str, label: str, value: str | None) -> None:
        self.group = group
        self.label = label
        self.value = value


def _interpret(raw: str) -> list[_Row]:
    rows: list[_Row] = []
    raw = raw.strip()
    if not raw:
        return rows

    R = _Row

    # --- Parse attempts ---
    int_val: int | None = None
    try:
        int_val = int(raw, 0) if raw.startswith(("0x", "0X")) else int(raw)
    except (ValueError, OverflowError):
        pass

    float_val: float | None = None
    try:
        float_val = float(raw)
    except ValueError:
        pass

    # Hex-clean: only keep hex digits, detect if input looks like a hex string
    hex_clean = "".join(c for c in raw.lower() if c in "0123456789abcdef")
    # Truncate to even number of nibbles (e.g. "f7 f8 f" → "f7f8", not a parse error)
    if len(hex_clean) % 2 != 0:
        hex_clean = hex_clean[:-1]
    is_hex_str = (
        all(c in "0123456789abcdefABCDEF:- " for c in raw)
        and bool(hex_clean)
    )
    # Integer value of bare hex string (e.g. "c0a80101" or "f7 f8 f9 fa" without 0x prefix)
    hex_int_val: int | None = None
    hex_le_int_val: int | None = None
    hex_bytes_val: bytes | None = None
    if is_hex_str and int_val is None and hex_clean:
        try:
            hex_int_val = int(hex_clean, 16)
            hex_bytes_val = bytes.fromhex(hex_clean)
            hex_le_int_val = int.from_bytes(hex_bytes_val, "little")
        except ValueError:
            pass

    # UUID parse — done early so uuid_obj is available in the Timestamp group
    uuid_obj: _uuid_mod.UUID | None = None
    if len(raw) == 36 and raw.count("-") == 4:
        try:
            uuid_obj = _uuid_mod.UUID(raw)
        except ValueError:
            pass
    elif is_hex_str and len(hex_clean) == 32:
        try:
            uuid_obj = _uuid_mod.UUID(hex_clean)
        except ValueError:
            pass
    uuid_val = str(uuid_obj) if uuid_obj is not None else None

    # -----------------------------------------------------------------------
    # Group: Integer
    # -----------------------------------------------------------------------
    # Use decimal int if available, fall back to big-endian interpretation of hex bytes
    eff_int = int_val if int_val is not None else hex_int_val

    if eff_int is not None:
        rows.append(R("Integer", "Decimal", f"{eff_int:,}"))
        rows.append(R("Integer", "Hex", hex(eff_int)))
        if 0 <= eff_int <= 0xFFFF_FFFF:
            s32 = eff_int if eff_int < 0x8000_0000 else eff_int - 0x1_0000_0000
            rows.append(R("Integer", "Signed 32-bit", str(s32)))
            rows.append(R("Integer", "Unsigned 32-bit", str(eff_int)))
        else:
            rows.append(R("Integer", "Signed 32-bit", None))
            rows.append(R("Integer", "Unsigned 32-bit", None))
        if -(2**63) <= eff_int <= 2**63 - 1:
            rows.append(R("Integer", "Signed 64-bit", str(eff_int)))
        else:
            rows.append(R("Integer", "Signed 64-bit", None))
        if 0 <= eff_int <= 2**64 - 1:
            rows.append(R("Integer", "Unsigned 64-bit", str(eff_int)))
        else:
            rows.append(R("Integer", "Unsigned 64-bit", None))
    else:
        for lbl in ("Decimal", "Hex", "Signed 32-bit", "Unsigned 32-bit", "Signed 64-bit", "Unsigned 64-bit"):
            rows.append(R("Integer", lbl, None))

    # Little-endian variants — only shown for hex byte inputs (not decimal)
    if hex_le_int_val is not None and int_val is None:
        le = hex_le_int_val
        rows.append(R("Integer", "Decimal (LE)", f"{le:,}"))
        rows.append(R("Integer", "Hex (LE)", hex(le)))
        if 0 <= le <= 0xFFFF_FFFF:
            s32 = le if le < 0x8000_0000 else le - 0x1_0000_0000
            rows.append(R("Integer", "Signed 32-bit (LE)", str(s32)))
            rows.append(R("Integer", "Unsigned 32-bit (LE)", str(le)))
        else:
            rows.append(R("Integer", "Signed 32-bit (LE)", None))
            rows.append(R("Integer", "Unsigned 32-bit (LE)", None))
        if -(2**63) <= le <= 2**63 - 1:
            rows.append(R("Integer", "Signed 64-bit (LE)", str(le)))
        else:
            rows.append(R("Integer", "Signed 64-bit (LE)", None))
        if 0 <= le <= 2**64 - 1:
            rows.append(R("Integer", "Unsigned 64-bit (LE)", str(le)))
        else:
            rows.append(R("Integer", "Unsigned 64-bit (LE)", None))

    # -----------------------------------------------------------------------
    # Group: Float
    # -----------------------------------------------------------------------
    if float_val is not None and int_val is None:
        rows.append(R("Float", "Double (64-bit)", f"{float_val:.17g}"))
    else:
        rows.append(R("Float", "Double (64-bit)", None))

    if eff_int is not None and 0 <= eff_int <= 0xFFFF_FFFF:
        f32 = struct.unpack(">f", eff_int.to_bytes(4, "big"))[0]
        rows.append(R("Float", "Float32 · 4 bytes BE", f"{f32:.9g}"))
    else:
        rows.append(R("Float", "Float32 · 4 bytes BE", None))

    if hex_bytes_val is not None and len(hex_bytes_val) == 4:
        f32_le = struct.unpack("<f", hex_bytes_val)[0]
        rows.append(R("Float", "Float32 · 4 bytes LE", f"{f32_le:.9g}"))
    else:
        rows.append(R("Float", "Float32 · 4 bytes LE", None))

    if eff_int is not None and 0 <= eff_int <= 2**64 - 1:
        try:
            f64 = struct.unpack(">d", eff_int.to_bytes(8, "big"))[0]
            rows.append(R("Float", "Double · 8 bytes BE", f"{f64:.17g}"))
        except struct.error:
            rows.append(R("Float", "Double · 8 bytes BE", None))
    else:
        rows.append(R("Float", "Double · 8 bytes BE", None))

    if hex_bytes_val is not None and len(hex_bytes_val) == 8:
        try:
            f64_le = struct.unpack("<d", hex_bytes_val)[0]
            rows.append(R("Float", "Double · 8 bytes LE", f"{f64_le:.17g}"))
        except struct.error:
            rows.append(R("Float", "Double · 8 bytes LE", None))
    else:
        rows.append(R("Float", "Double · 8 bytes LE", None))

    # -----------------------------------------------------------------------
    # Group: Timestamps
    # -----------------------------------------------------------------------
    # `ts` drives the arithmetic-based formats (division/addition against an epoch) and falls
    # back to the parsed float so a value with a fractional component (e.g. sub-ms noise
    # appended to a ms epoch, "1760996870913.061") still resolves instead of being dropped.
    # `ts_int` stays integer-only, for the two formats below that unpack exact bit fields.
    ts_int = eff_int
    ts: int | float | None = eff_int if eff_int is not None else float_val

    if ts is not None and _TS_S_MIN <= ts <= _TS_S_MAX:
        rows.append(R("Timestamp", "Unix (s)", _safe_ts(ts)))
    else:
        rows.append(R("Timestamp", "Unix (s)", None))

    if ts is not None and _TS_MS_MIN <= ts <= _TS_MS_MAX:
        rows.append(R("Timestamp", "Unix (ms)", _safe_ts(ts / 1_000)))
    else:
        rows.append(R("Timestamp", "Unix (ms)", None))

    if ts is not None and _TS_US_MIN <= ts <= _TS_US_MAX:
        rows.append(R("Timestamp", "Unix (µs)", _safe_ts(ts / 1_000_000)))
    else:
        rows.append(R("Timestamp", "Unix (µs)", None))

    # Cocoa: seconds since 2001-01-01; for floats require > 1M to avoid false positives on
    # tiny values (Cocoa's plausible range dips below zero, unlike the other formats).
    cocoa_src = ts if eff_int is not None else (float_val if float_val is not None and float_val > 1_000_000 else None)
    if cocoa_src is not None and _COCOA_MIN <= cocoa_src <= _COCOA_MAX:
        try:
            rows.append(R("Timestamp", "Cocoa / Apple (s)", _fmt_dt(_COCOA_EPOCH + timedelta(seconds=cocoa_src))))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "Cocoa / Apple (s)", None))
    else:
        rows.append(R("Timestamp", "Cocoa / Apple (s)", None))

    # Cocoa nanoseconds: ns since 2001-01-01; same float-magnitude guard as Cocoa (s) above —
    # _COCOA_NS_MIN is deep negative, so an unguarded float fallback would match trivial values.
    cocoa_ns_src = ts if eff_int is not None else (float_val if float_val is not None and float_val > 1_000_000 else None)
    if cocoa_ns_src is not None and _COCOA_NS_MIN <= cocoa_ns_src <= _COCOA_NS_MAX:
        try:
            dt = _COCOA_EPOCH + timedelta(seconds=cocoa_ns_src / 1_000_000_000)
            rows.append(R("Timestamp", "Cocoa / Apple (ns)", _fmt_dt(dt)))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "Cocoa / Apple (ns)", None))
    else:
        rows.append(R("Timestamp", "Cocoa / Apple (ns)", None))

    # Chrome / WebKit: µs since 1601-01-01
    if ts is not None and _CHROME_US_MIN <= ts <= _CHROME_US_MAX:
        try:
            rows.append(R("Timestamp", "Chrome / WebKit (µs)", _fmt_dt(_CHROME_EPOCH + timedelta(microseconds=ts))))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "Chrome / WebKit (µs)", None))
    else:
        rows.append(R("Timestamp", "Chrome / WebKit (µs)", None))

    # Windows FILETIME: 100ns intervals since 1601-01-01
    if ts is not None and _WIN_FT_MIN <= ts <= _WIN_FT_MAX:
        try:
            rows.append(R("Timestamp", "Windows FILETIME", _fmt_dt(_CHROME_EPOCH + timedelta(microseconds=ts / 10))))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "Windows FILETIME", None))
    else:
        rows.append(R("Timestamp", "Windows FILETIME", None))

    # HFS+: seconds since 1904-01-01
    if ts is not None and _HFS_MIN <= ts <= _HFS_MAX:
        try:
            rows.append(R("Timestamp", "HFS+ / Mac OS (s)", _fmt_dt(_HFS_EPOCH + timedelta(seconds=ts))))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "HFS+ / Mac OS (s)", None))
    else:
        rows.append(R("Timestamp", "HFS+ / Mac OS (s)", None))

    # Microsoft .NET Ticks: 100ns intervals since 0001-01-01
    if ts is not None and _TICKS_MIN <= ts <= _TICKS_MAX:
        try:
            unix_s = (ts - _NET_EPOCH_TICKS) / _NET_TICKS_PER_S
            rows.append(R("Timestamp", "Microsoft .NET Ticks", _safe_ts(unix_s)))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "Microsoft .NET Ticks", None))
    else:
        rows.append(R("Timestamp", "Microsoft .NET Ticks", None))

    # OLE Automation Date: days (float) since 1899-12-30
    ole_val = float_val if float_val is not None else (float(eff_int) if eff_int is not None else None)
    if ole_val is not None and _OLE_MIN <= ole_val <= _OLE_MAX:
        try:
            rows.append(R("Timestamp", "OLE Automation Date", _fmt_dt(_OLE_EPOCH + timedelta(days=ole_val))))
        except (OverflowError, ValueError):
            rows.append(R("Timestamp", "OLE Automation Date", None))
    else:
        rows.append(R("Timestamp", "OLE Automation Date", None))

    # Twitter / X Snowflake ID: upper 41 bits = ms since Twitter epoch (bit-packed, integer-only)
    if ts_int is not None and ts_int >= (1 << 22):  # timestamp part must be > 0
        tw_ms = (ts_int >> 22) + _TWITTER_EPOCH_MS
        if _TS_MS_MIN <= tw_ms <= _TS_MS_MAX:
            rows.append(R("Timestamp", "Twitter / X Snowflake", _safe_ts(tw_ms / 1000.0)))
        else:
            rows.append(R("Timestamp", "Twitter / X Snowflake", None))
    else:
        rows.append(R("Timestamp", "Twitter / X Snowflake", None))

    # FAT / exFAT (MS-DOS): 32-bit packed date+time, 2-second resolution, epoch 1980-01-01
    if ts_int is not None and _FAT_TS_MIN <= ts_int <= _FAT_TS_MAX:
        date_word = (ts_int >> 16) & 0xFFFF
        time_word = ts_int & 0xFFFF
        fat_year  = ((date_word >> 9) & 0x7F) + 1980
        fat_month = (date_word >> 5) & 0x0F
        fat_day   = date_word & 0x1F
        fat_hour  = (time_word >> 11) & 0x1F
        fat_min   = (time_word >> 5) & 0x3F
        fat_sec   = (time_word & 0x1F) * 2
        if 1 <= fat_month <= 12 and 1 <= fat_day <= 31 and fat_hour <= 23 and fat_min <= 59 and fat_sec <= 58:
            try:
                dt = datetime(fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec, tzinfo=timezone.utc)
                rows.append(R("Timestamp", "FAT / exFAT (MS-DOS)", _fmt_dt(dt)))
            except (ValueError, OverflowError):
                rows.append(R("Timestamp", "FAT / exFAT (MS-DOS)", None))
        else:
            rows.append(R("Timestamp", "FAT / exFAT (MS-DOS)", None))
    else:
        rows.append(R("Timestamp", "FAT / exFAT (MS-DOS)", None))

    # BCD timestamp: 7 hex bytes = YYYY MM DD HH mm SS (each byte = 2 BCD digits)
    if hex_bytes_val is not None and len(hex_bytes_val) == 7:
        bcd = [_bcd_byte(b) for b in hex_bytes_val]
        if all(v is not None for v in bcd):
            by, bmo, bd, bh, bmi, bs = bcd[0] * 100 + bcd[1], bcd[2], bcd[3], bcd[4], bcd[5], bcd[6]  # type: ignore[operator]
            if 1 <= bmo <= 12 and 1 <= bd <= 31 and bh <= 23 and bmi <= 59 and bs <= 59:
                try:
                    dt = datetime(by, bmo, bd, bh, bmi, bs, tzinfo=timezone.utc)
                    rows.append(R("Timestamp", "BCD (YYYYMMDDHHmmSS)", _fmt_dt(dt)))
                except (ValueError, OverflowError):
                    rows.append(R("Timestamp", "BCD (YYYYMMDDHHmmSS)", None))
            else:
                rows.append(R("Timestamp", "BCD (YYYYMMDDHHmmSS)", None))
        else:
            rows.append(R("Timestamp", "BCD (YYYYMMDDHHmmSS)", None))
    else:
        rows.append(R("Timestamp", "BCD (YYYYMMDDHHmmSS)", None))

    # UUID v1 timestamp: 60-bit, 100ns intervals since Gregorian epoch 1582-10-15
    if uuid_obj is not None and uuid_obj.version == 1:
        unix_s = (uuid_obj.time - _UUID_V1_GREG_OFFSET) / 10_000_000
        rows.append(R("Timestamp", "UUID v1 Timestamp", _safe_ts(unix_s)))
    else:
        rows.append(R("Timestamp", "UUID v1 Timestamp", None))

    # GPS Time (s): seconds since 1980-01-06, no leap-second correction
    if ts is not None and _GPS_S_MIN <= ts <= _GPS_S_MAX:
        rows.append(R("Timestamp", "GPS Time (s)", _safe_ts(ts + _GPS_EPOCH_UNIX)))
    else:
        rows.append(R("Timestamp", "GPS Time (s)", None))

    # GPS Time (ns): nanoseconds since 1980-01-06, no leap-second correction
    if ts is not None and _GPS_NS_MIN <= ts <= _GPS_NS_MAX:
        rows.append(R("Timestamp", "GPS Time (ns)", _safe_ts(ts / 1_000_000_000 + _GPS_EPOCH_UNIX)))
    else:
        rows.append(R("Timestamp", "GPS Time (ns)", None))

    # Windows SYSTEMTIME: 16 hex bytes = 8×WORD LE (year, month, dow, day, h, m, s, ms)
    if hex_bytes_val is not None and len(hex_bytes_val) == 16:
        try:
            st_year, st_month, st_dow, st_day, st_hour, st_min, st_sec, st_ms = struct.unpack_from("<8H", hex_bytes_val)
            if (1 <= st_month <= 12 and 0 <= st_dow <= 6 and 1 <= st_day <= 31
                    and st_hour <= 23 and st_min <= 59 and st_sec <= 59 and st_ms <= 999):
                dt = datetime(st_year, st_month, st_day, st_hour, st_min, st_sec,
                              st_ms * 1000, tzinfo=timezone.utc)
                val = f"{dt.strftime('%Y-%m-%d %H:%M:%S')}.{st_ms:03d} UTC"
                rows.append(R("Timestamp", "Windows SYSTEMTIME", val))
            else:
                rows.append(R("Timestamp", "Windows SYSTEMTIME", None))
        except (struct.error, ValueError, OverflowError):
            rows.append(R("Timestamp", "Windows SYSTEMTIME", None))
    else:
        rows.append(R("Timestamp", "Windows SYSTEMTIME", None))

    # -----------------------------------------------------------------------
    # Group: UUID
    # -----------------------------------------------------------------------
    rows.append(R("UUID", "UUID", uuid_val))

    # -----------------------------------------------------------------------
    # Group: Network
    # -----------------------------------------------------------------------
    ipv4_src = eff_int if eff_int is not None and len(hex_clean) <= 8 else None
    if ipv4_src is not None and 0 <= ipv4_src <= 0xFFFF_FFFF:
        b_be = ipv4_src.to_bytes(4, "big")
        b_le = ipv4_src.to_bytes(4, "little")
        rows.append(R("Network", "IPv4 (big-endian)", ".".join(str(x) for x in b_be)))
        rows.append(R("Network", "IPv4 (little-endian)", ".".join(str(x) for x in b_le)))
    else:
        rows.append(R("Network", "IPv4 (big-endian)", None))
        rows.append(R("Network", "IPv4 (little-endian)", None))

    mac_val: str | None = None
    if is_hex_str and len(hex_clean) == 12:
        mac_val = ":".join(hex_clean[i:i + 2] for i in range(0, 12, 2))
    elif len(raw) == 17 and raw.count(":") == 5:
        mac_val = raw.lower()
    rows.append(R("Network", "MAC address", mac_val))

    # -----------------------------------------------------------------------
    # Group: Text
    # -----------------------------------------------------------------------
    if hex_bytes_val:
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in hex_bytes_val)
        rows.append(R("Text", "ASCII (hex bytes)", ascii_text))
        try:
            utf8_text = hex_bytes_val.decode("utf-8")
            rows.append(R("Text", "UTF-8 (hex bytes)", utf8_text))
        except UnicodeDecodeError:
            rows.append(R("Text", "UTF-8 (hex bytes)", None))

    # -----------------------------------------------------------------------
    # Group: Encoding
    # -----------------------------------------------------------------------
    # Only attempt Base64 if the input contains chars that are in Base64 but NOT in hex
    # (G-Z, g-z, +, /, =, -, _) — avoids false positives on plain numbers and hex strings
    _B64_DISTINGUISHING = set("GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz+/=-_")
    b64_clean = raw.strip().replace(" ", "").replace("\r", "").replace("\n", "")
    b64_decoded: bytes | None = None
    if len(b64_clean) >= 4 and any(c in _B64_DISTINGUISHING for c in b64_clean):
        for candidate in (b64_clean, b64_clean.replace("-", "+").replace("_", "/")):
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                b64_decoded = base64.b64decode(padded, validate=True)
                break
            except Exception:
                pass

    if b64_decoded is not None:
        rows.append(R("Encoding", "Base64 → bytes", b64_decoded.hex(" ")))
        try:
            rows.append(R("Encoding", "Base64 → UTF-8", b64_decoded.decode("utf-8")))
        except UnicodeDecodeError:
            rows.append(R("Encoding", "Base64 → UTF-8", None))

    return rows


# ---------------------------------------------------------------------------
# Singleton management
# ---------------------------------------------------------------------------

_instance: "ValueInspector | None" = None


def _clear_instance() -> None:
    global _instance
    _instance = None


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class ValueInspector(QDialog):
    """Non-modal singleton dialog showing all interpretations of a text/numeric value."""

    @staticmethod
    def inspect(value: str, parent: QWidget | None = None) -> None:
        global _instance
        if _instance is None:
            _instance = ValueInspector(parent)
            _instance.show()
        _instance._set_value(value)
        _instance.raise_()
        _instance.activateWindow()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Value Inspector")
        self.resize(500, 560)
        self.destroyed.connect(_clear_instance)
        self._build_ui()
        # Connect to X11 PRIMARY selection (Linux); fires when user highlights text anywhere
        clipboard = QApplication.clipboard()
        if clipboard.supportsSelection():
            clipboard.selectionChanged.connect(self._on_selection_changed)

    def _on_selection_changed(self) -> None:
        focused = QApplication.focusWidget()
        if focused is None:
            return  # another application has focus — ignore external selections
        if focused is self or self.isAncestorOf(focused):
            return  # selection came from within the inspector itself
        text = QApplication.clipboard().text(QClipboard.Mode.Selection).strip()
        if text:
            self._set_value(text)

    def closeEvent(self, event: object) -> None:
        clipboard = QApplication.clipboard()
        if clipboard.supportsSelection():
            try:
                clipboard.selectionChanged.disconnect(self._on_selection_changed)
            except RuntimeError:
                pass
        super().closeEvent(event)  # type: ignore[arg-type]

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setSpacing(8)
        outer.setContentsMargins(8, 8, 8, 8)

        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Value:"))
        self._input = QLineEdit()
        self._input.setPlaceholderText("Enter or paste a value…")
        self._input.textChanged.connect(self._refresh)
        input_row.addWidget(self._input)
        outer.addLayout(input_row)

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(["Interpretation", "Value"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setDefaultSectionSize(190)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        outer.addWidget(self._table)

        bottom = QHBoxLayout()
        copy_btn = QPushButton("Copy value")
        copy_btn.clicked.connect(self._copy_selected)
        bottom.addWidget(copy_btn)
        bottom.addStretch()
        outer.addLayout(bottom)

    def _set_value(self, value: str) -> None:
        self._input.blockSignals(True)
        self._input.setText(value.strip())
        self._input.blockSignals(False)
        self._refresh(value.strip())

    def _refresh(self, text: str = "") -> None:
        rows = _interpret(text or self._input.text())

        bold = QFont()
        bold.setBold(True)

        # Flatten rows into display items, inserting group headers
        items: list[tuple[bool, str, str | None]] = []
        prev_group: str | None = None
        for row in rows:
            if row.group != prev_group:
                items.append((True, row.group, None))
                prev_group = row.group
            items.append((False, row.label, row.value))

        self._table.setRowCount(len(items))
        for i, (is_header, label, value) in enumerate(items):
            if is_header:
                for col, text in enumerate((label, "")):
                    item = QTableWidgetItem(text)
                    item.setFont(bold)
                    item.setBackground(_GROUP_BG)
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                    self._table.setItem(i, col, item)
                self._table.setRowHeight(i, 20)
            else:
                applicable = value is not None
                val_text = value if applicable else "—"
                lbl_item = QTableWidgetItem(label)
                val_item = QTableWidgetItem(val_text)
                lbl_item.setToolTip(label)
                val_item.setToolTip(val_text)
                if not applicable:
                    lbl_item.setForeground(_MUTED)
                    val_item.setForeground(_MUTED)
                for col, item in enumerate((lbl_item, val_item)):
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    self._table.setItem(i, col, item)

    def _copy_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 1)
        if item and item.text() and item.text() != "—":
            QApplication.clipboard().setText(item.text())
