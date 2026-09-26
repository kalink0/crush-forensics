# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Timestamp column decoding helpers — no Qt dependency."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# A plain decimal literal and nothing else: ASCII digits, optional sign, fraction
# and exponent. No thousands separators, hex, "nan"/"inf" or non-ASCII digits --
# str.isdigit()/float() would accept several of those.
_NUMBER_TEXT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")

# (internal_key, menu_label, header_suffix)
# The menu label is marked for translation (the UI shows it via
# translate("TimestampFormat", label)); the header suffix is a short format
# ID and stays as it is.
TS_FORMATS: list[tuple[str, str, str]] = [
    ("unix_s", QT_TRANSLATE_NOOP("TimestampFormat", "Unix — seconds since 1970-01-01"), "unix s"),
    (
        "unix_ms",
        QT_TRANSLATE_NOOP("TimestampFormat", "Unix — milliseconds since 1970-01-01"),
        "unix ms",
    ),
    (
        "unix_us",
        QT_TRANSLATE_NOOP("TimestampFormat", "Unix — microseconds since 1970-01-01"),
        "unix µs",
    ),
    (
        "mac_abs",
        QT_TRANSLATE_NOOP("TimestampFormat", "Mac Absolute Time — seconds since 2001-01-01"),
        "mac abs",
    ),
    (
        "win_ft",
        QT_TRANSLATE_NOOP("TimestampFormat", "Windows FILETIME — 100 ns since 1601-01-01"),
        "win ft",
    ),
    (
        "chrome",
        QT_TRANSLATE_NOOP("TimestampFormat", "Chrome / WebKit — µs since 1601-01-01"),
        "webkit",
    ),
]

_MAC_EPOCH_OFFSET = 978_307_200     # seconds from Unix epoch to 2001-01-01
_WIN_EPOCH_OFFSET = 11_644_473_600  # seconds from 1601-01-01 to Unix epoch


def decode_ts(value: int | float, fmt: str) -> str | None:
    """Convert a raw integer/float to a UTC timestamp string using *fmt*.

    Returns ``"YYYY-MM-DD HH:MM:SS UTC"`` or ``None`` on error.
    """
    try:
        v = float(value)
        if fmt == "unix_s":
            unix = v
        elif fmt == "unix_ms":
            unix = v / 1_000.0
        elif fmt == "unix_us":
            unix = v / 1_000_000.0
        elif fmt == "mac_abs":
            unix = v + _MAC_EPOCH_OFFSET
        elif fmt == "win_ft":
            unix = v / 10_000_000.0 - _WIN_EPOCH_OFFSET
        elif fmt == "chrome":
            unix = v / 1_000_000.0 - _WIN_EPOCH_OFFSET
        else:
            return None
        # epoch + timedelta rather than datetime.fromtimestamp(): the latter calls the
        # OS's C library, which on Windows rejects negative (pre-1970) timestamps that
        # Linux/Mac handle fine — the same evidence value would decode differently
        # depending on the examiner's OS.
        dt = _UNIX_EPOCH + timedelta(seconds=unix)
        return dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    except (OverflowError, ValueError, TypeError):
        return None


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


def decode_cell(value: object, fmt: str) -> tuple[str | None, ParseIssue | None]:
    """Decode one table cell as *fmt*, returning ``(decoded_text, problem)``.

    *problem* is ``None`` when the cell decoded, and also when there was nothing to
    decode (NULL, empty text, a BLOB -- the viewers already show those distinctly).
    Otherwise it is a short reason the cell has to be shown as stored, so a caller
    can mark it instead of leaving it looking decoded.
    """
    if value is None or isinstance(value, (bytes, bytearray, memoryview)):
        return None, None
    if isinstance(value, str) and not value.strip():
        return None, None
    number = numeric_value(value)
    if number is None:
        return None, ParseIssue("ts_decode.not_a_number")
    decoded = decode_ts(number, fmt)
    if decoded is None:
        return None, ParseIssue("ts_decode.out_of_range")
    return decoded, None
