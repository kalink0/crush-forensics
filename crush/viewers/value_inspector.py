# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Value Inspector — flat interpretation panel for text/numeric cell values."""
from __future__ import annotations

import base64
import struct
import uuid as _uuid_mod
from decimal import Decimal, InvalidOperation

from PySide6.QtCore import QT_TRANSLATE_NOOP, Qt
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
from crush.core.ts_decode import decode_ts
from crush.ui.i18n import translate

_MUTED = QColor(140, 140, 140)
_GROUP_BG = QColor(240, 240, 240)

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
_NET_EPOCH_OFFSET_S = 62_135_596_800   # seconds from 0001-01-01 to Unix epoch
_NET_TICKS_PER_S = 10_000_000
_TICKS_MIN = (_TS_S_MIN + _NET_EPOCH_OFFSET_S) * _NET_TICKS_PER_S
_TICKS_MAX = (_TS_S_MAX + _NET_EPOCH_OFFSET_S) * _NET_TICKS_PER_S

# OLE Automation Date: days (float) since 1899-12-30
_OLE_MIN = 32874.0   # 1990-01-01
_OLE_MAX = 73050.0   # 2100-01-01

# Twitter / X Snowflake ID: upper 41 bits = ms since 2010-11-04 01:42:54.657 UTC
_TWITTER_EPOCH_MS = 1_288_834_974_657

# FAT / exFAT (MS-DOS): 32-bit packed, upper 16 = date, lower 16 = time (2s resolution)
# Date word: bits 15-9 = year offset from 1980, bits 8-5 = month, bits 4-0 = day
# Time word: bits 15-11 = hour, bits 10-5 = minute, bits 4-0 = 2-second count
_FAT_TS_MIN = 0x0021_0000  # 1980-01-01 00:00:00
_FAT_TS_MAX = 0xFF9F_BF7D  # 2107-12-31 23:59:58

# GPS Time: seconds (or nanoseconds) since 1980-01-06 00:00:00 UTC, NO leap seconds.
# GPS is currently 18 s ahead of UTC; displayed values are raw GPS time (not UTC-corrected).
_GPS_EPOCH_UNIX = 315_964_800   # Unix timestamp of GPS epoch 1980-01-06
_GPS_S_MIN = _TS_S_MIN - _GPS_EPOCH_UNIX    # ~315_187_200  (≈ 1990-01-01 in GPS seconds)
_GPS_S_MAX = _TS_S_MAX - _GPS_EPOCH_UNIX    # ~3_786_480_000 (≈ 2100-01-01 in GPS seconds)
_GPS_NS_MIN = _GPS_S_MIN * 1_000_000_000
_GPS_NS_MAX = _GPS_S_MAX * 1_000_000_000


_DECIMAL_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB", "PB", "EB")
_BINARY_SIZE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")


def _fmt_size(n: int, base: int, units: tuple[str, ...]) -> str:
    """Auto-scale a byte count to the largest unit where the value is >= 1, at 4-5 significant digits."""
    size = float(n)
    unit = units[0]
    for candidate in units[1:]:
        if size < base:
            break
        size /= base
        unit = candidate
    if unit == units[0]:
        return f"{n:,} {unit}"
    int_digits = len(str(int(size))) if size >= 1 else 1
    decimals = min(3, max(0, 5 - int_digits))
    return f"{size:.{decimals}f} {unit}"


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
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                QT_TRANSLATE_NOOP("ValueInspector", "Decimal"),
                f"{eff_int:,}",
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                QT_TRANSLATE_NOOP("ValueInspector", "Hex"),
                hex(eff_int),
            )
        )
        if 0 <= eff_int <= 0xFFFF_FFFF:
            s32 = eff_int if eff_int < 0x8000_0000 else eff_int - 0x1_0000_0000
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 32-bit"),
                    str(s32),
                )
            )
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 32-bit"),
                    str(eff_int),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 32-bit"),
                    None,
                )
            )
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 32-bit"),
                    None,
                )
            )
        if -(2**63) <= eff_int <= 2**63 - 1:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 64-bit"),
                    str(eff_int),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 64-bit"),
                    None,
                )
            )
        if 0 <= eff_int <= 2**64 - 1:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 64-bit"),
                    str(eff_int),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 64-bit"),
                    None,
                )
            )
    else:
        for lbl in (QT_TRANSLATE_NOOP("ValueInspector", "Decimal"), QT_TRANSLATE_NOOP("ValueInspector", "Hex"), QT_TRANSLATE_NOOP("ValueInspector", "Signed 32-bit"), QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 32-bit"), QT_TRANSLATE_NOOP("ValueInspector", "Signed 64-bit"), QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 64-bit")):
            rows.append(R(QT_TRANSLATE_NOOP("ValueInspector", "Integer"), lbl, None))

    # Little-endian variants — only shown for hex byte inputs (not decimal)
    if hex_le_int_val is not None and int_val is None:
        le = hex_le_int_val
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                QT_TRANSLATE_NOOP("ValueInspector", "Decimal (LE)"),
                f"{le:,}",
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                QT_TRANSLATE_NOOP("ValueInspector", "Hex (LE)"),
                hex(le),
            )
        )
        if 0 <= le <= 0xFFFF_FFFF:
            s32 = le if le < 0x8000_0000 else le - 0x1_0000_0000
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 32-bit (LE)"),
                    str(s32),
                )
            )
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 32-bit (LE)"),
                    str(le),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 32-bit (LE)"),
                    None,
                )
            )
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 32-bit (LE)"),
                    None,
                )
            )
        if -(2**63) <= le <= 2**63 - 1:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 64-bit (LE)"),
                    str(le),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Signed 64-bit (LE)"),
                    None,
                )
            )
        if 0 <= le <= 2**64 - 1:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 64-bit (LE)"),
                    str(le),
                )
            )
        else:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Integer"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Unsigned 64-bit (LE)"),
                    None,
                )
            )

    # -----------------------------------------------------------------------
    # Group: Data Size
    # -----------------------------------------------------------------------
    if eff_int is not None and eff_int >= 0:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Data Size"),
                QT_TRANSLATE_NOOP("ValueInspector", "Decimal (KB/MB/GB…)"),
                _fmt_size(eff_int, 1000, _DECIMAL_SIZE_UNITS),
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Data Size"),
                QT_TRANSLATE_NOOP("ValueInspector", "Binary (KiB/MiB/GiB…)"),
                _fmt_size(eff_int, 1024, _BINARY_SIZE_UNITS),
            )
        )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Data Size"),
                QT_TRANSLATE_NOOP("ValueInspector", "Decimal (KB/MB/GB…)"),
                None,
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Data Size"),
                QT_TRANSLATE_NOOP("ValueInspector", "Binary (KiB/MiB/GiB…)"),
                None,
            )
        )

    # -----------------------------------------------------------------------
    # Group: Float
    # -----------------------------------------------------------------------
    if float_val is not None and int_val is None:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Double (64-bit)"),
                f"{float_val:.17g}",
            )
        )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Double (64-bit)"),
                None,
            )
        )

    if eff_int is not None and 0 <= eff_int <= 0xFFFF_FFFF:
        f32 = struct.unpack(">f", eff_int.to_bytes(4, "big"))[0]
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Float32 · 4 bytes BE"),
                f"{f32:.9g}",
            )
        )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Float32 · 4 bytes BE"),
                None,
            )
        )

    if hex_bytes_val is not None and len(hex_bytes_val) == 4:
        f32_le = struct.unpack("<f", hex_bytes_val)[0]
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Float32 · 4 bytes LE"),
                f"{f32_le:.9g}",
            )
        )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Float32 · 4 bytes LE"),
                None,
            )
        )

    if eff_int is not None and 0 <= eff_int <= 2**64 - 1:
        try:
            f64 = struct.unpack(">d", eff_int.to_bytes(8, "big"))[0]
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes BE"),
                    f"{f64:.17g}",
                )
            )
        except struct.error:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes BE"),
                    None,
                )
            )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes BE"),
                None,
            )
        )

    if hex_bytes_val is not None and len(hex_bytes_val) == 8:
        try:
            f64_le = struct.unpack("<d", hex_bytes_val)[0]
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes LE"),
                    f"{f64_le:.17g}",
                )
            )
        except struct.error:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes LE"),
                    None,
                )
            )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Float"),
                QT_TRANSLATE_NOOP("ValueInspector", "Double · 8 bytes LE"),
                None,
            )
        )

    # -----------------------------------------------------------------------
    # Group: Timestamps
    # -----------------------------------------------------------------------
    # The plausibility windows below decide which formats are offered for a value
    # (the inspector guesses; the table's "Decode column as timestamp" doesn't).
    # The decoding itself is crush.core.ts_decode's, shared with the table, and
    # exact: it gets the integer or the typed decimal digit for digit, so no
    # sub-second digit is lost to float rounding.
    # `ts` drives the window checks and falls back to the parsed float so a value
    # with a fractional component (e.g. sub-ms noise appended to a ms epoch,
    # "1760996870913.061") still resolves instead of being dropped.
    # `ts_int` stays integer-only, for the two formats below that unpack exact bit fields.
    ts_int = eff_int
    ts: int | float | None = eff_int if eff_int is not None else float_val
    ts_exact: int | Decimal | None = eff_int
    if ts_exact is None and float_val is not None:
        try:
            ts_exact = Decimal(raw)
        except InvalidOperation:
            ts_exact = None

    def ts_row(label: str, offered: bool, value: object, fmt: str) -> None:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Timestamp"),
                label,
                decode_ts(value, fmt) if offered else None,
            )
        )

    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Unix (s)"),
        ts is not None and _TS_S_MIN <= ts <= _TS_S_MAX, ts_exact, "unix_s",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Unix (ms)"),
        ts is not None and _TS_MS_MIN <= ts <= _TS_MS_MAX, ts_exact, "unix_ms",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Unix (µs)"),
        ts is not None and _TS_US_MIN <= ts <= _TS_US_MAX, ts_exact, "unix_us",
    )

    # Cocoa: seconds since 2001-01-01; for floats require > 1M to avoid false positives on
    # tiny values (Cocoa's plausible range dips below zero, unlike the other formats).
    # Cocoa nanoseconds use the same guard -- _COCOA_NS_MIN is deep negative, so an
    # unguarded float fallback would match trivial values.
    cocoa_src = ts if eff_int is not None else (float_val if float_val is not None and float_val > 1_000_000 else None)
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Cocoa / Apple (s)"),
        cocoa_src is not None and _COCOA_MIN <= cocoa_src <= _COCOA_MAX, ts_exact, "mac_abs",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Cocoa / Apple (ns)"),
        cocoa_src is not None and _COCOA_NS_MIN <= cocoa_src <= _COCOA_NS_MAX, ts_exact, "cocoa_ns",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "Chrome / WebKit (µs)"),
        ts is not None and _CHROME_US_MIN <= ts <= _CHROME_US_MAX, ts_exact, "chrome",
    )
    ts_row(
        "Windows FILETIME",
        ts is not None and _WIN_FT_MIN <= ts <= _WIN_FT_MAX, ts_exact, "win_ft",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "HFS+ / Mac OS (s)"),
        ts is not None and _HFS_MIN <= ts <= _HFS_MAX, ts_exact, "hfs",
    )
    ts_row(
        "Microsoft .NET Ticks",
        ts is not None and _TICKS_MIN <= ts <= _TICKS_MAX, ts_exact, "net_ticks",
    )
    ole_val = float_val if float_val is not None else (float(eff_int) if eff_int is not None else None)
    ts_row(
        "OLE Automation Date",
        ole_val is not None and _OLE_MIN <= ole_val <= _OLE_MAX, ts_exact, "ole",
    )

    # Twitter / X Snowflake ID: upper 41 bits = ms since Twitter epoch (bit-packed, integer-only)
    ts_row(
        "Twitter / X Snowflake",
        ts_int is not None
        and ts_int >= (1 << 22)  # timestamp part must be > 0
        and _TS_MS_MIN <= (ts_int >> 22) + _TWITTER_EPOCH_MS <= _TS_MS_MAX,
        ts_int,
        "snowflake",
    )
    # FAT / exFAT (MS-DOS): 32-bit packed date+time, 2-second resolution, epoch 1980-01-01
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "FAT / exFAT (MS-DOS)"),
        ts_int is not None and _FAT_TS_MIN <= ts_int <= _FAT_TS_MAX, ts_int, "fat",
    )
    # BCD timestamp: 7 hex bytes = YYYY MM DD HH mm SS (each byte = 2 BCD digits)
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "BCD (YYYYMMDDHHmmSS)"),
        hex_bytes_val is not None and len(hex_bytes_val) == 7, hex_bytes_val, "bcd",
    )
    # UUID v1 timestamp: 60-bit, 100ns intervals since Gregorian epoch 1582-10-15
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "UUID v1 Timestamp"),
        uuid_obj is not None and uuid_obj.version == 1, str(uuid_obj), "uuid_v1",
    )
    # GPS Time: seconds / nanoseconds since 1980-01-06, no leap-second correction
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "GPS Time (s)"),
        ts is not None and _GPS_S_MIN <= ts <= _GPS_S_MAX, ts_exact, "gps_s",
    )
    ts_row(
        QT_TRANSLATE_NOOP("ValueInspector", "GPS Time (ns)"),
        ts is not None and _GPS_NS_MIN <= ts <= _GPS_NS_MAX, ts_exact, "gps_ns",
    )
    # Windows SYSTEMTIME: 16 hex bytes = 8×WORD LE (year, month, dow, day, h, m, s, ms)
    ts_row(
        "Windows SYSTEMTIME",
        hex_bytes_val is not None and len(hex_bytes_val) == 16, hex_bytes_val, "systemtime",
    )

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
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Network"),
                QT_TRANSLATE_NOOP("ValueInspector", "IPv4 (big-endian)"),
                ".".join(str(x) for x in b_be),
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Network"),
                QT_TRANSLATE_NOOP("ValueInspector", "IPv4 (little-endian)"),
                ".".join(str(x) for x in b_le),
            )
        )
    else:
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Network"),
                QT_TRANSLATE_NOOP("ValueInspector", "IPv4 (big-endian)"),
                None,
            )
        )
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Network"),
                QT_TRANSLATE_NOOP("ValueInspector", "IPv4 (little-endian)"),
                None,
            )
        )

    mac_val: str | None = None
    if is_hex_str and len(hex_clean) == 12:
        mac_val = ":".join(hex_clean[i:i + 2] for i in range(0, 12, 2))
    elif len(raw) == 17 and raw.count(":") == 5:
        mac_val = raw.lower()
    rows.append(
        R(
            QT_TRANSLATE_NOOP("ValueInspector", "Network"),
            QT_TRANSLATE_NOOP("ValueInspector", "MAC address"),
            mac_val,
        )
    )

    # -----------------------------------------------------------------------
    # Group: Text
    # -----------------------------------------------------------------------
    if hex_bytes_val:
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in hex_bytes_val)
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Text"),
                QT_TRANSLATE_NOOP("ValueInspector", "ASCII (hex bytes)"),
                ascii_text,
            )
        )
        try:
            utf8_text = hex_bytes_val.decode("utf-8")
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Text"),
                    QT_TRANSLATE_NOOP("ValueInspector", "UTF-8 (hex bytes)"),
                    utf8_text,
                )
            )
        except UnicodeDecodeError:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Text"),
                    QT_TRANSLATE_NOOP("ValueInspector", "UTF-8 (hex bytes)"),
                    None,
                )
            )

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
        rows.append(
            R(
                QT_TRANSLATE_NOOP("ValueInspector", "Encoding"),
                QT_TRANSLATE_NOOP("ValueInspector", "Base64 → bytes"),
                b64_decoded.hex(" "),
            )
        )
        try:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Encoding"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Base64 → UTF-8"),
                    b64_decoded.decode("utf-8"),
                )
            )
        except UnicodeDecodeError:
            rows.append(
                R(
                    QT_TRANSLATE_NOOP("ValueInspector", "Encoding"),
                    QT_TRANSLATE_NOOP("ValueInspector", "Base64 → UTF-8"),
                    None,
                )
            )

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
        self.setWindowTitle(translate("ValueInspector", "Value Inspector"))
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
        input_row.addWidget(QLabel(translate("ValueInspector", "Value:")))
        self._input = QLineEdit()
        self._input.setPlaceholderText(translate("ValueInspector", "Enter or paste a value…"))
        self._input.textChanged.connect(self._refresh)
        input_row.addWidget(self._input)
        outer.addLayout(input_row)

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(
            [translate("ValueInspector", "Interpretation"), translate("ValueInspector", "Value")]
        )
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setDefaultSectionSize(190)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        outer.addWidget(self._table)

        bottom = QHBoxLayout()
        copy_btn = QPushButton(translate("ValueInspector", "Copy value"))
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
                # Group and row labels are marked where the rows are built.
                shown = translate("ValueInspector", label)  # i18n: keep -- marked in R(...)
                for col, text in enumerate((shown, "")):
                    item = QTableWidgetItem(text)
                    item.setFont(bold)
                    item.setBackground(_GROUP_BG)
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                    self._table.setItem(i, col, item)
                self._table.setRowHeight(i, 20)
            else:
                applicable = value is not None
                val_text = value if applicable else "—"
                shown = translate("ValueInspector", label)  # i18n: keep -- marked in R(...)
                lbl_item = QTableWidgetItem(shown)
                val_item = QTableWidgetItem(val_text)
                lbl_item.setToolTip(shown)
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
