# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ts_sql: the bare plain-SQLite conversions give Crush's date and time for
every value sql_covers() accepts."""
from __future__ import annotations

import sqlite3

import pytest

from crush.core.ts_decode import TS_FORMATS, decode_cell
from crush.core.ts_sql import SQL_UNSUPPORTED, sql_covers, sql_expression, sql_supported

_SQL_FORMATS = [key for key, _, _, _ in TS_FORMATS if sql_supported(key)]

_UNIX = 1_705_314_225  # 2024-01-15 10:23:45
_VALUES: dict[str, list[object]] = {
    "unix_s": [_UNIX, -1, 0, -62_135_596_800, 253_402_300_799, 253_402_300_800],
    "unix_ms": [_UNIX * 1_000 + 406, 1_713_884_690_500, 1_713_884_690_000, -1, -1_500],
    "unix_us": [_UNIX * 1_000_000 + 1, -999_999],
    "mac_abs": [_UNIX - 978_307_200, -978_307_200, -31_000_000],
    "cocoa_ns": [726_000_000_123_456_789, -1, 9_223_372_036_854_775_807],
    "hfs": [_UNIX + 2_082_844_800, 0],
    "win_ft": [133_500_000_001_234_567, 0, -1],
    "net_ticks": [(_UNIX + 62_135_596_800) * 10_000_000 + 5, 0],
    "chrome": [(_UNIX + 11_644_473_600) * 1_000_000 + 120, 0],
    "snowflake": [((_UNIX * 1_000 - 1_288_834_974_657) << 22) | 0x3F_FFFF, 0, -5],
    "fat": [
        (((44 << 9) | (6 << 5) | 15) << 16) | ((13 << 11) | (17 << 5) | 1),
        ((44 << 9) | (13 << 5) | 15) << 16,  # month 13
        -1,
    ],
    "bcd": [
        bytes.fromhex("20240627143642"), bytes.fromhex("2024062714364A"),
        bytes.fromhex("2024"), "20240627143642",
    ],
}
_EXTRA: list[object] = [
    10**15, -(10**15), 2**62, "1705314225", "007", " 5", "+5", "1.5", "abc",
    760_000_000.5, 760_000_000.0, "1" * 19, None, "",
]


def _run(column_values: list[object], fmt: str) -> list[object]:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute('CREATE TABLE t ("my col")')  # no affinity: values stay as given
        conn.executemany("INSERT INTO t VALUES (?)", [(v,) for v in column_values])
        sql = f"SELECT {sql_expression('my col', fmt)} FROM t ORDER BY rowid"
        return [row[0] for row in conn.execute(sql)]
    finally:
        conn.close()


@pytest.mark.parametrize("fmt", _SQL_FORMATS)
def test_covered_values_match_crush(fmt: str) -> None:
    values = _VALUES[fmt] + _EXTRA
    covered = 0
    for value, sql_text in zip(values, _run(values, fmt)):
        if not sql_covers(value, fmt) or value is None or value == "":
            continue
        decoded, _ = decode_cell(value, fmt)
        assert decoded is not None
        assert sql_text == decoded.removesuffix(" UTC"), (fmt, value)
        covered += 1
    assert covered >= 1


def test_not_covered_examples() -> None:
    assert not sql_covers(760_000_000.5, "mac_abs")  # REAL
    assert not sql_covers(-1_500, "unix_ms")  # negative sub-second count
    assert sql_covers(-31_000_000, "mac_abs")  # whole seconds: negative is fine
    assert not sql_covers(" 5", "unix_s")  # padded text
    assert not sql_covers("1" * 19, "unix_ms")  # may become a REAL in SQLite
    assert not sql_covers(253_402_300_800, "unix_s")  # beyond year 9999
    assert not sql_covers("20240627143642", "bcd")  # hex text, not a BLOB
    assert sql_covers(None, "unix_s") and sql_covers("", "unix_s")


def test_expression_is_bare_and_quotes_the_name() -> None:
    expr = sql_expression('a "b"', "unix_ms")
    assert expr == (
        "datetime(\"a \"\"b\"\"\" / 1000, 'unixepoch') "
        "|| rtrim(printf('.%03d', \"a \"\"b\"\"\" % 1000), '.0')"
    )
    assert sql_expression("x", "unix_s") == "datetime(\"x\", 'unixepoch')"
    assert sql_expression("x", "mac_abs") == "datetime(\"x\" + 978307200, 'unixepoch')"
    for fmt in _SQL_FORMATS:
        assert "UTC" not in sql_expression("x", fmt)
        assert " AS " not in sql_expression("x", fmt)


@pytest.mark.parametrize("fmt", sorted(SQL_UNSUPPORTED))
def test_unsupported_formats_raise(fmt: str) -> None:
    assert not sql_supported(fmt)
    with pytest.raises(ValueError):
        sql_expression("c", fmt)


def test_every_table_format_is_supported_or_has_a_reason() -> None:
    for key, _, _, _ in TS_FORMATS:
        assert sql_supported(key) != (key in SQL_UNSUPPORTED), key
