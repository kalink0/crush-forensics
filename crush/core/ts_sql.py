# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Plain-SQLite expressions for the Table View's timestamp formats -- no Qt dependency.

:func:`sql_expression` writes the bare conversion of one column, for an analyst
to use in their own SELECT -- in Crush or in any other SQLite tool. It uses
only core SQLite (integer arithmetic, printf, substr, hex, datetime) and gives
``YYYY-MM-DD HH:MM:SS[.fraction]``: the same date and time as
:func:`crush.core.ts_decode.decode_cell`, without a time zone (the expression
can't know which zone the stored value was written in).

The expression has no per-row checks, so it is exact only for the values
:func:`sql_covers` accepts -- typically non-negative INTEGER values. For others
(a REAL, a negative count of sub-second units, text, a value out of range) it
gives a wrong result or NULL without saying so; the caller tells the analyst
how many values of the column that applies to.
"""
from __future__ import annotations

from crush.core.issues import ParseIssue
from crush.core.ts_decode import decode_cell

# key -> (units per second, epoch in Unix seconds), as in ts_decode._LINEAR.
_LINEAR: dict[str, tuple[int, int]] = {
    "unix_s": (1, 0),
    "unix_ms": (1_000, 0),
    "unix_us": (1_000_000, 0),
    "mac_abs": (1, 978_307_200),
    "cocoa_ns": (1_000_000_000, 978_307_200),
    "hfs": (1, -2_082_844_800),
    "win_ft": (10_000_000, -11_644_473_600),
    "net_ticks": (10_000_000, -62_135_596_800),
    "chrome": (1_000_000, -11_644_473_600),
}
_SNOWFLAKE_EPOCH_MS = 1_288_834_974_657

# Formats plain SQLite can't render exactly, and why (shown in the menu).
SQL_UNSUPPORTED: dict[str, ParseIssue] = {
    "ole": ParseIssue("ts_sql.fractional_days"),
    "systemtime": ParseIssue("ts_sql.no_hex_to_number"),
    "uuid_v1": ParseIssue("ts_sql.no_hex_to_number"),
}

# Digit-only text up to this length is a 64-bit integer to SQLite's arithmetic;
# longer text may turn into a REAL.
_MAX_TEXT_DIGITS = 18


def sql_supported(fmt: str) -> bool:
    return fmt in _LINEAR or fmt in {"snowflake", "fat", "bcd"}


def _identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _offset(value: str, epoch: int) -> str:
    if epoch > 0:
        return f"{value} + {epoch}"
    if epoch < 0:
        return f"{value} - {-epoch}"
    return value


def _linear(value: str, per_second: int, epoch: int) -> str:
    if per_second == 1:
        return f"datetime({_offset(value, epoch)}, 'unixepoch')"
    digits = len(str(per_second)) - 1
    # rtrim drops the fraction's trailing zeros, and the dot with them for a whole second.
    return (
        f"datetime({_offset(f'{value} / {per_second}', epoch)}, 'unixepoch') "
        f"|| rtrim(printf('.%0{digits}d', {value} % {per_second}), '.0')"
    )


def sql_expression(column: str, fmt: str) -> str:
    """The plain-SQLite conversion of *column* as *fmt* (see the module docstring).
    Raises ValueError for a format in SQL_UNSUPPORTED or unknown."""
    if not sql_supported(fmt):
        raise ValueError(f"no SQL expression for timestamp format {fmt!r}")
    col = _identifier(column)
    if fmt in _LINEAR:
        return _linear(col, *_LINEAR[fmt])
    if fmt == "snowflake":
        # Upper 42 bits: ms since 2010-11-04 01:42:54.657 UTC.
        return _linear(f"(({col} >> 22) + {_SNOWFLAKE_EPOCH_MS})", 1_000, 0)
    if fmt == "fat":
        # Date word in the upper 16 bits, time word in the lower 16 (2-second resolution).
        return (
            f"printf('%04d-%02d-%02d %02d:%02d:%02d', "
            f"(({col} >> 25) & 127) + 1980, ({col} >> 21) & 15, ({col} >> 16) & 31, "
            f"({col} >> 11) & 31, ({col} >> 5) & 63, ({col} & 31) * 2)"
        )
    # bcd: 7 bytes YYYY MM DD HH mm SS, two decimal digits per byte -- the hex digits.
    h = f"hex({col})"
    return (
        f"substr({h}, 1, 4) || '-' || substr({h}, 5, 2) || '-' || substr({h}, 7, 2) || ' ' || "
        f"substr({h}, 9, 2) || ':' || substr({h}, 11, 2) || ':' || substr({h}, 13, 2)"
    )


def sql_covers(value: object, fmt: str) -> bool:
    """Whether :func:`sql_expression` gives exactly Crush's date and time for
    *value* (NULL and empty text count as covered: there is nothing to decode)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return True
    decoded, _ = decode_cell(value, fmt)
    if decoded is None:
        return False  # out of range or invalid fields: the expression shows something else
    if fmt == "bcd":
        return isinstance(value, (bytes, bytearray, memoryview))
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= _MAX_TEXT_DIGITS:
        number = int(value)
    else:
        return False  # REAL, signed or padded text, BLOB
    if fmt in _LINEAR and _LINEAR[fmt][0] == 1:
        return True  # whole seconds: negative values work too
    # SQLite's / and % truncate toward zero: a negative count of sub-second
    # units (or a negative Snowflake ID) lands on the wrong second.
    return number >= 0
