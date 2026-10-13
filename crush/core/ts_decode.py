# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Timestamp decoding helpers — no Qt dependency.

One place for every timestamp format Crush decodes: the Table View's
"Decode column as timestamp" (TS_FORMATS) and the Value Inspector both use
:func:`decode_ts` / :func:`decode_cell`, so the same value reads the same in
both.

Decoding is exact: integers stay integers and decimals are read digit for
digit (a float by its shortest repr, i.e. the digits SQLite returns), so no
sub-second digit is lost or invented. The output carries every fractional
digit the value holds -- ``2024-01-15 10:23:45.1234567 UTC`` -- and none when
there is no fraction.
"""
from __future__ import annotations

import math
import re
import struct
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from fractions import Fraction

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# A plain decimal literal and nothing else: ASCII digits, optional sign, fraction
# and exponent. No thousands separators, hex, "nan"/"inf" or non-ASCII digits --
# str.isdigit()/float() would accept several of those.
_NUMBER_TEXT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_INTEGER_TEXT = re.compile(r"[+-]?[0-9]+")
# Hex text for the byte formats: hex digit pairs, optionally separated by
# spaces, colons or hyphens (as a hex dump or the Value Inspector shows them).
_HEX_TEXT = re.compile(r"[0-9A-Fa-f]{2}(?:[ :-]?[0-9A-Fa-f]{2})*")

# Group labels for the Table View menu (shown via translate("TimestampFormat", ...)).
GROUP_UNIX = QT_TRANSLATE_NOOP("TimestampFormat", "Unix")
GROUP_APPLE = QT_TRANSLATE_NOOP("TimestampFormat", "Apple")
GROUP_WINDOWS = QT_TRANSLATE_NOOP("TimestampFormat", "Windows")
GROUP_OTHER = QT_TRANSLATE_NOOP("TimestampFormat", "Other")

# (internal_key, menu_label, header_suffix, menu_group) -- the formats the Table
# View offers. The menu label is marked for translation (the UI shows it via
# translate("TimestampFormat", label)); the header suffix is a short format ID
# and stays as it is. GPS time (gps_s / gps_ns) is decoded for the Value
# Inspector only and deliberately not offered here.
TS_FORMATS: list[tuple[str, str, str, str]] = [
    ("unix_s", QT_TRANSLATE_NOOP("TimestampFormat", "Unix — seconds since 1970-01-01"),
     "unix s", GROUP_UNIX),
    ("unix_ms", QT_TRANSLATE_NOOP("TimestampFormat", "Unix — milliseconds since 1970-01-01"),
     "unix ms", GROUP_UNIX),
    ("unix_us", QT_TRANSLATE_NOOP("TimestampFormat", "Unix — microseconds since 1970-01-01"),
     "unix µs", GROUP_UNIX),
    ("mac_abs",
     QT_TRANSLATE_NOOP("TimestampFormat", "Cocoa / Mac Absolute Time — seconds since 2001-01-01"),
     "cocoa s", GROUP_APPLE),
    ("cocoa_ns",
     QT_TRANSLATE_NOOP("TimestampFormat", "Cocoa / Mac Absolute Time — nanoseconds since 2001-01-01"),
     "cocoa ns", GROUP_APPLE),
    ("hfs", QT_TRANSLATE_NOOP("TimestampFormat", "HFS+ — seconds since 1904-01-01"),
     "hfs+", GROUP_APPLE),
    ("win_ft", QT_TRANSLATE_NOOP("TimestampFormat", "Windows FILETIME — 100 ns since 1601-01-01"),
     "win ft", GROUP_WINDOWS),
    ("systemtime",
     QT_TRANSLATE_NOOP("TimestampFormat", "Windows SYSTEMTIME — 16 bytes, 8 little-endian WORDs"),
     "systemtime", GROUP_WINDOWS),
    ("net_ticks", QT_TRANSLATE_NOOP("TimestampFormat", ".NET Ticks — 100 ns since 0001-01-01"),
     "ticks", GROUP_WINDOWS),
    ("ole", QT_TRANSLATE_NOOP("TimestampFormat", "OLE Automation Date — days since 1899-12-30"),
     "ole", GROUP_WINDOWS),
    ("fat",
     QT_TRANSLATE_NOOP("TimestampFormat", "FAT / exFAT (MS-DOS) — 32-bit packed date (high) and time (low)"),
     "dos", GROUP_WINDOWS),
    ("chrome", QT_TRANSLATE_NOOP("TimestampFormat", "Chrome / WebKit — µs since 1601-01-01"),
     "webkit", GROUP_OTHER),
    ("snowflake",
     QT_TRANSLATE_NOOP("TimestampFormat", "Twitter / X Snowflake ID — ms since 2010-11-04 01:42:54.657"),
     "snowflake", GROUP_OTHER),
    ("uuid_v1", QT_TRANSLATE_NOOP("TimestampFormat", "UUID v1 — 100 ns since 1582-10-15"),
     "uuid v1", GROUP_OTHER),
    ("bcd", QT_TRANSLATE_NOOP("TimestampFormat", "BCD — 7 bytes YYYY MM DD HH mm SS"),
     "bcd", GROUP_OTHER),
]

# Seconds from each format's epoch to the Unix epoch (negative: epoch before 1970).
_COCOA_OFFSET = 978_307_200          # 2001-01-01
_FILETIME_OFFSET = -11_644_473_600   # 1601-01-01
_HFS_OFFSET = -2_082_844_800         # 1904-01-01
_NET_OFFSET = -62_135_596_800        # 0001-01-01
_GPS_OFFSET = 315_964_800            # 1980-01-06
_OLE_EPOCH_DAYS = -25_569            # 1899-12-30, in days
_SNOWFLAKE_EPOCH_MS = 1_288_834_974_657
_UUID_GREGORIAN_OFFSET = 0x01B21DD213814000  # 100 ns intervals, 1582-10-15 -> 1970-01-01

# Formats that are a plain count of units since an epoch:
# key -> (seconds per unit, epoch in Unix seconds).
_LINEAR: dict[str, tuple[Fraction, int]] = {
    "unix_s": (Fraction(1), 0),
    "unix_ms": (Fraction(1, 1_000), 0),
    "unix_us": (Fraction(1, 1_000_000), 0),
    "mac_abs": (Fraction(1), _COCOA_OFFSET),
    "cocoa_ns": (Fraction(1, 1_000_000_000), _COCOA_OFFSET),
    "hfs": (Fraction(1), _HFS_OFFSET),
    "win_ft": (Fraction(1, 10_000_000), _FILETIME_OFFSET),
    "net_ticks": (Fraction(1, 10_000_000), _NET_OFFSET),
    "chrome": (Fraction(1, 1_000_000), _FILETIME_OFFSET),
    # GPS counts no leap seconds: the result is GPS time on a UTC calendar,
    # not corrected to UTC (currently 18 s ahead).
    "gps_s": (Fraction(1), _GPS_OFFSET),
    "gps_ns": (Fraction(1, 1_000_000_000), _GPS_OFFSET),
}
_INTEGER_FORMATS = frozenset({"snowflake", "fat"})
_BYTE_FORMATS = {"systemtime": 16, "bcd": 7}
_KNOWN = frozenset(_LINEAR) | _INTEGER_FORMATS | frozenset(_BYTE_FORMATS) | {"ole", "uuid_v1"}


def unix_to_utc(seconds: float) -> datetime | None:
    """Unix seconds as an aware UTC datetime, or ``None`` if datetime can't
    represent them (outside year 1 - 9999, NaN, inf).

    epoch + timedelta rather than datetime.fromtimestamp(): the latter calls the
    OS's C library, which on Windows rejects negative (pre-1970) and far-future
    timestamps that Linux/Mac handle fine, and without tz= it converts to the
    examiner's local time.
    """
    try:
        return _UNIX_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, ValueError, TypeError):
        return None


def format_unix(seconds: Fraction | int) -> str | None:
    """Exact Unix seconds as ``YYYY-MM-DD HH:MM:SS[.fraction] UTC``, or ``None``
    outside year 1 - 9999.

    The fraction has as many digits as the value needs to be exact (none for a
    whole second). Callers only pass terminating decimals: every input is a
    decimal and every format scale a power of ten or a whole number of seconds.
    """
    seconds = Fraction(seconds)
    whole = math.floor(seconds)
    try:
        # epoch + timedelta rather than datetime.fromtimestamp(): the latter calls the
        # OS's C library, which on Windows rejects negative (pre-1970) timestamps that
        # Linux/Mac handle fine — the same evidence value would decode differently
        # depending on the examiner's OS.
        dt = _UNIX_EPOCH + timedelta(seconds=whole)
    except (OverflowError, ValueError):
        return None
    # Built by hand: strftime("%Y") doesn't zero-pad years before 1000 on every platform.
    text = (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    )
    fraction = seconds - whole
    if fraction:
        text += "." + _fraction_digits(fraction)
    return text + " UTC"


def _fraction_digits(fraction: Fraction) -> str:
    """The decimal digits of 0 < *fraction* < 1, exactly (it must terminate)."""
    den = fraction.denominator
    twos = fives = 0
    while den % 2 == 0:
        den //= 2
        twos += 1
    while den % 5 == 0:
        den //= 5
        fives += 1
    if den != 1:
        raise ValueError(f"{fraction} has no finite decimal expansion")
    places = max(twos, fives)
    return str(fraction.numerator * 10**places // fraction.denominator).zfill(places)


def _utc_seconds(dt: datetime) -> int:
    """Whole Unix seconds of a naive-UTC or aware datetime without microseconds."""
    delta = dt.replace(tzinfo=timezone.utc) - _UNIX_EPOCH
    return delta.days * 86_400 + delta.seconds


# ---------------------------------------------------------------------------
# Reading the cell value
# ---------------------------------------------------------------------------

def numeric_value(value: object) -> int | float | None:
    """The number *value* holds, or ``None`` if it holds none.

    ints and floats pass through (a bool is not a number here). A string counts
    only if all of it, surrounding whitespace aside, is a plain decimal literal:
    SQLite is dynamically typed, and a TEXT-affinity column often stores an epoch
    as text (``'1713884690406'``). Anything else -- a date string, hex, ``12abc``,
    NULL, bytes -- is ``None``; nothing is guessed.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not _NUMBER_TEXT.fullmatch(text):
            return None
        try:
            return float(text) if any(c in text for c in ".eE") else int(text)
        except (ValueError, OverflowError):
            return None
    return None


class _NotFinite(Exception):
    """A number that has no finite value (inf, NaN)."""


def _exact_number(value: object) -> Fraction | None:
    """*value* as an exact Fraction, or ``None`` if it isn't a number.

    A float is read by its shortest repr -- the digits SQLite and the table
    show -- not by its binary expansion. Raises _NotFinite for inf/NaN.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _NotFinite
        return Fraction(Decimal(repr(value)))
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise _NotFinite
        return Fraction(value)
    if isinstance(value, str):
        text = value.strip()
        if not _NUMBER_TEXT.fullmatch(text):
            return None
        try:
            return Fraction(Decimal(text))
        except (InvalidOperation, ValueError, OverflowError):
            return None
    return None


def _cell_bytes(value: object) -> bytes | None:
    """The bytes a byte-format cell holds: a BLOB as is, or hex text."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if _HEX_TEXT.fullmatch(text):
            return bytes.fromhex(re.sub(r"[ :-]", "", text))
    return None


# ---------------------------------------------------------------------------
# The formats
# ---------------------------------------------------------------------------

_OUT_OF_RANGE = ParseIssue("ts_decode.out_of_range")
_INVALID_FIELDS = ParseIssue("ts_decode.invalid_fields")


def _done(text: str | None) -> tuple[str | None, ParseIssue | None]:
    return (text, None) if text is not None else (None, _OUT_OF_RANGE)


def _decode_ole(days: Fraction) -> tuple[str | None, ParseIssue | None]:
    # OLE Automation Date: the integer part counts days from 1899-12-30, the
    # fractional part is the time of day -- for negative values too, so
    # -1.25 is 1899-12-29 06:00, not 1899-12-28 18:00.
    whole_days = math.trunc(days)
    time_of_day = abs(days - whole_days)
    return _done(format_unix((whole_days + _OLE_EPOCH_DAYS + time_of_day) * 86_400))


def _decode_snowflake(number: int) -> tuple[str | None, ParseIssue | None]:
    if number < 0 or number >= 1 << 64:
        return None, _OUT_OF_RANGE
    return _done(format_unix(Fraction((number >> 22) + _SNOWFLAKE_EPOCH_MS, 1_000)))


def _decode_fat(number: int) -> tuple[str | None, ParseIssue | None]:
    # Upper 16 bits the date word, lower 16 the time word (2-second resolution).
    if number < 0 or number > 0xFFFF_FFFF:
        return None, _OUT_OF_RANGE
    date_word, time_word = number >> 16, number & 0xFFFF
    try:
        dt = datetime(
            ((date_word >> 9) & 0x7F) + 1980, (date_word >> 5) & 0x0F, date_word & 0x1F,
            (time_word >> 11) & 0x1F, (time_word >> 5) & 0x3F, (time_word & 0x1F) * 2,
        )
    except ValueError:
        return None, _INVALID_FIELDS
    return _done(format_unix(_utc_seconds(dt)))


def _decode_bcd(data: bytes) -> tuple[str | None, ParseIssue | None]:
    digits = []
    for b in data:
        hi, lo = b >> 4, b & 0xF
        if hi > 9 or lo > 9:
            return None, ParseIssue("ts_decode.not_bcd")
        digits.append(hi * 10 + lo)
    year = digits[0] * 100 + digits[1]
    try:
        dt = datetime(year, digits[2], digits[3], digits[4], digits[5], digits[6])
    except ValueError:
        return None, _INVALID_FIELDS
    return _done(format_unix(_utc_seconds(dt)))


def _decode_systemtime(data: bytes) -> tuple[str | None, ParseIssue | None]:
    year, month, dow, day, hour, minute, second, ms = struct.unpack("<8H", data)
    if dow > 6 or ms > 999:
        return None, _INVALID_FIELDS
    try:
        dt = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None, _INVALID_FIELDS
    return _done(format_unix(_utc_seconds(dt) + Fraction(ms, 1_000)))


def _decode_uuid_v1(value: object) -> tuple[str | None, ParseIssue | None]:
    try:
        if isinstance(value, (bytes, bytearray, memoryview)):
            if len(value) != 16:
                return None, ParseIssue(
                    "ts_decode.wrong_length", {"length": len(value), "expected": 16}
                )
            # RFC 9562 binary form: network (big-endian) byte order.
            parsed = uuid.UUID(bytes=bytes(value))
        elif isinstance(value, str):
            parsed = uuid.UUID(value.strip())
        else:
            return None, ParseIssue("ts_decode.not_a_uuid")
    except ValueError:
        return None, ParseIssue("ts_decode.not_a_uuid")
    if parsed.variant != uuid.RFC_4122 or parsed.version != 1:
        return None, ParseIssue("ts_decode.uuid_not_v1")
    return _done(format_unix(Fraction(parsed.time - _UUID_GREGORIAN_OFFSET, 10_000_000)))


def decode_cell(value: object, fmt: str) -> tuple[str | None, ParseIssue | None]:
    """Decode one table cell as *fmt*, returning ``(decoded_text, problem)``.

    *problem* is ``None`` when the cell decoded, and also when there was nothing to
    decode (NULL, empty text, or a BLOB under a number format -- the viewers
    already show those distinctly). Otherwise it is a short reason the cell has
    to be shown as stored, so a caller can mark it instead of leaving it looking
    decoded. No plausibility range is applied: the analyst chose the format, so
    anything the format can represent is decoded.
    """
    if fmt not in _KNOWN:
        raise ValueError(f"unknown timestamp format {fmt!r}")
    if value is None:
        return None, None
    if isinstance(value, str) and not value.strip():
        return None, None

    if fmt == "uuid_v1":
        return _decode_uuid_v1(value)

    if fmt in _BYTE_FORMATS:
        data = _cell_bytes(value)
        if data is None:
            return None, ParseIssue("ts_decode.not_bytes")
        expected = _BYTE_FORMATS[fmt]
        if len(data) != expected:
            return None, ParseIssue(
                "ts_decode.wrong_length", {"length": len(data), "expected": expected}
            )
        return _decode_bcd(data) if fmt == "bcd" else _decode_systemtime(data)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return None, None
    try:
        number = _exact_number(value)
    except _NotFinite:
        return None, _OUT_OF_RANGE
    if number is None:
        return None, ParseIssue("ts_decode.not_a_number")

    if fmt in _INTEGER_FORMATS:
        if number.denominator != 1:
            return None, ParseIssue("ts_decode.not_an_integer")
        whole = int(number)
        return _decode_snowflake(whole) if fmt == "snowflake" else _decode_fat(whole)
    if fmt == "ole":
        return _decode_ole(number)
    scale, epoch = _LINEAR[fmt]
    return _done(format_unix(number * scale + epoch))


def decode_ts(value: object, fmt: str) -> str | None:
    """Decode *value* as *fmt* (see :func:`decode_cell`); ``None`` if it can't be."""
    try:
        return decode_cell(value, fmt)[0]
    except ValueError:
        return None
