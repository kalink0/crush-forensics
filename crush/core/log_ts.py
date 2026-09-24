# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Log timestamp decoding shared by every Multi-Log Studio parser.

A log line records only part of a point in time more often than not: no
time zone (most text logs), no year (syslog RFC 3164, Android logcat).
Every entry therefore carries ``ts_flags`` next to its ``timestamp``, a
space-separated set of the tokens below, so the viewer can show what the
log actually recorded instead of a complete-looking UTC instant:

- TS_NO_ZONE: no zone/offset in the log. ``timestamp`` holds the recorded
  wall-clock time with tzinfo=UTC as a storage convention only; it must
  never be converted to another zone for display.
- TS_NO_YEAR: no year in the log. ``timestamp`` uses PLACEHOLDER_YEAR,
  which must never be displayed as if recorded.
- TS_UNPARSED: a timestamp was present but couldn't be decoded;
  ``timestamp`` is None and the raw line keeps the original text.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

TS_NO_ZONE = "no_zone"
TS_NO_YEAR = "no_year"
TS_UNPARSED = "unparsed"

# Stand-in year for logs that record none. A leap year, so a "Feb 29"
# line still decodes instead of being lost.
PLACEHOLDER_YEAR = 1972

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_SUBMICRO_RE = re.compile(r"(\.\d{6})\d+")


def join_flags(*flags: str) -> str:
    return " ".join(f for f in flags if f)


def parse_iso_ts(s: str) -> tuple[datetime | None, str]:
    """Decode an ISO-8601-like timestamp (``T`` or space separator, ``,``
    or ``.`` fractions, ``Z``/``+HH:MM``/``+HHMM`` offsets) or
    ``MM/DD/YY HH:MM:SS[.f]``. Returns (UTC datetime, flags).

    Digits beyond microseconds are truncated (datetime's resolution); the
    raw line keeps them.
    """
    text = _SUBMICRO_RE.sub(r"\1", s.strip().replace(",", "."))
    dt: datetime | None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = None
        for fmt in ("%m/%d/%y %H:%M:%S.%f", "%m/%d/%y %H:%M:%S"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None, TS_UNPARSED
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc), TS_NO_ZONE
    return dt.astimezone(timezone.utc), ""


def epoch_ts(value: str) -> tuple[datetime | None, str]:
    """Unix seconds, or milliseconds when above 1e12. UTC by definition."""
    try:
        val = float(value)
        if val > 1e12:
            val /= 1000.0
        return _EPOCH + timedelta(seconds=val), ""
    except (ValueError, OverflowError):
        return None, TS_UNPARSED


def naive_ts(dt: datetime) -> tuple[datetime, str]:
    """A datetime decoded without zone info (e.g. strptime without %z)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc), TS_NO_ZONE
    return dt.astimezone(timezone.utc), ""
