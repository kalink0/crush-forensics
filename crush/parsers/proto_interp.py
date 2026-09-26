# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Schema-less Protobuf field interpretation.

For each wire type, compute all plausible interpretations of the raw value
so analysts can see every candidate without needing a schema.
"""
from __future__ import annotations

import math
import struct
from datetime import datetime, timezone
from typing import NamedTuple

from crush.core.issues import QT_TRANSLATE_NOOP

# Seconds between Unix epoch (1970-01-01) and Cocoa epoch (2001-01-01)
_COCOA_OFFSET = 978_307_200

# Seconds between Unix epoch (1970-01-01) and Windows FILETIME epoch (1601-01-01)
_FILETIME_OFFSET = 11_644_473_600

# Plausible Unix-second range: 2000-01-01 … 2100-01-01
_UNIX_S_MIN = 946_684_800
_UNIX_S_MAX = 4_102_444_800

# Plausible Cocoa-second range: 2001-01-01 … 2100-01-01
_COCOA_MIN = 0.0
_COCOA_MAX = 3_155_673_600.0

# Plausible Chrome/WebKit microsecond range (µs since 1601-01-01): 2000 … 2100
_CHROME_MIN = 12_591_158_400_000_000
_CHROME_MAX = 15_778_800_000_000_000


class Interpretation(NamedTuple):
    label: str
    value: str


def interpret_varint(value: int) -> list[Interpretation]:
    """All plausible interpretations of a varint field value."""
    out: list[Interpretation] = []

    out.append(Interpretation("uint64", f"{value}"))

    signed = value if value < (1 << 63) else value - (1 << 64)
    if signed != value:
        out.append(Interpretation("int64", f"{signed}"))

    zigzag = (value >> 1) ^ -(value & 1)
    out.append(Interpretation("sint64 (zigzag)", f"{zigzag}"))

    if value in (0, 1):
        out.append(Interpretation("bool", "true" if value else "false"))

    if _UNIX_S_MIN <= value <= _UNIX_S_MAX:
        out.append(
            Interpretation(QT_TRANSLATE_NOOP("GeneratedView", "Unix timestamp (s)"), _fmt_ts(value))
        )

    if _CHROME_MIN <= value <= _CHROME_MAX:
        unix_s = (value / 1_000_000) - _FILETIME_OFFSET
        out.append(
            Interpretation(
                QT_TRANSLATE_NOOP("GeneratedView", "Chrome/WebKit timestamp (µs)"), _fmt_ts(unix_s)
            )
        )

    return out


def interpret_fixed64(raw: bytes) -> list[Interpretation]:
    """All plausible interpretations of an 8-byte fixed field."""
    if len(raw) != 8:
        return []
    out: list[Interpretation] = []

    uint64 = int.from_bytes(raw, "little", signed=False)
    int64 = int.from_bytes(raw, "little", signed=True)
    double = struct.unpack("<d", raw)[0]

    out.append(Interpretation("uint64", f"{uint64}"))
    if int64 != uint64:
        out.append(Interpretation("int64", f"{int64}"))

    if not math.isnan(double) and not math.isinf(double):
        out.append(Interpretation("double", repr(double)))
        if _COCOA_MIN < double <= _COCOA_MAX:
            out.append(
                Interpretation(
                    QT_TRANSLATE_NOOP("GeneratedView", "Cocoa timestamp"),
                    _fmt_ts(double + _COCOA_OFFSET),
                )
            )
        if _UNIX_S_MIN <= double <= _UNIX_S_MAX:
            out.append(
                Interpretation(
                    QT_TRANSLATE_NOOP("GeneratedView", "Unix timestamp (double, s)"),
                    _fmt_ts(double),
                )
            )

    if _UNIX_S_MIN <= uint64 <= _UNIX_S_MAX:
        out.append(
            Interpretation(
                QT_TRANSLATE_NOOP("GeneratedView", "Unix timestamp (uint64, s)"), _fmt_ts(uint64)
            )
        )

    if _CHROME_MIN <= uint64 <= _CHROME_MAX:
        unix_s = (uint64 / 1_000_000) - _FILETIME_OFFSET
        out.append(
            Interpretation(
                QT_TRANSLATE_NOOP("GeneratedView", "Chrome/WebKit timestamp (µs)"), _fmt_ts(unix_s)
            )
        )

    return out


def interpret_fixed32(raw: bytes) -> list[Interpretation]:
    """All plausible interpretations of a 4-byte fixed field."""
    if len(raw) != 4:
        return []
    out: list[Interpretation] = []

    uint32 = int.from_bytes(raw, "little", signed=False)
    int32 = int.from_bytes(raw, "little", signed=True)
    float32 = struct.unpack("<f", raw)[0]

    out.append(Interpretation("uint32", f"{uint32}"))
    if int32 != uint32:
        out.append(Interpretation("int32", f"{int32}"))

    if not math.isnan(float32) and not math.isinf(float32):
        out.append(Interpretation("float", repr(float32)))

    if _UNIX_S_MIN <= uint32 <= _UNIX_S_MAX:
        out.append(
            Interpretation(
                QT_TRANSLATE_NOOP("GeneratedView", "Unix timestamp (uint32, s)"), _fmt_ts(uint32)
            )
        )

    return out


def _fmt_ts(unix_seconds: float) -> str:
    try:
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"{unix_seconds}"
