# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Timestamp column decoding helpers — no Qt dependency."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# (internal_key, menu_label, header_suffix)
TS_FORMATS: list[tuple[str, str, str]] = [
    ("unix_s",  "Unix — seconds since 1970-01-01",            "unix s"),
    ("unix_ms", "Unix — milliseconds since 1970-01-01",        "unix ms"),
    ("unix_us", "Unix — microseconds since 1970-01-01",        "unix µs"),
    ("mac_abs", "Mac Absolute Time — seconds since 2001-01-01", "mac abs"),
    ("win_ft",  "Windows FILETIME — 100 ns since 1601-01-01",   "win ft"),
    ("chrome",  "Chrome / WebKit — µs since 1601-01-01",        "webkit"),
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
