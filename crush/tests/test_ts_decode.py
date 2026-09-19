# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for ts_decode — decode_ts and TS_FORMATS."""
from __future__ import annotations

import pytest

from crush.core.ts_decode import TS_FORMATS, decode_cell, decode_ts, numeric_value


# ---------------------------------------------------------------------------
# decode_ts — known reference values
# ---------------------------------------------------------------------------

class TestDecodeTsFormats:
    # 2024-01-15 10:23:45 UTC
    _UNIX_S   = 1_705_314_225
    _UNIX_MS  = 1_705_314_225_000
    _UNIX_US  = 1_705_314_225_000_000
    _MAC_ABS  = 1_705_314_225 - 978_307_200          # unix_s - mac offset
    _WIN_FT   = (1_705_314_225 + 11_644_473_600) * 10_000_000
    _CHROME   = (1_705_314_225 + 11_644_473_600) * 1_000_000
    _EXPECTED = "2024-01-15 10:23:45 UTC"

    def test_unix_s(self) -> None:
        assert decode_ts(self._UNIX_S, "unix_s") == self._EXPECTED

    def test_unix_ms(self) -> None:
        assert decode_ts(self._UNIX_MS, "unix_ms") == self._EXPECTED

    def test_unix_us(self) -> None:
        assert decode_ts(self._UNIX_US, "unix_us") == self._EXPECTED

    def test_mac_abs(self) -> None:
        assert decode_ts(self._MAC_ABS, "mac_abs") == self._EXPECTED

    def test_win_ft(self) -> None:
        assert decode_ts(self._WIN_FT, "win_ft") == self._EXPECTED

    def test_chrome(self) -> None:
        assert decode_ts(self._CHROME, "chrome") == self._EXPECTED

    def test_float_input_accepted(self) -> None:
        result = decode_ts(float(self._UNIX_S), "unix_s")
        assert result == self._EXPECTED

    def test_unknown_fmt_returns_none(self) -> None:
        assert decode_ts(self._UNIX_S, "bogus_format") is None

    def test_string_input_returns_none(self) -> None:
        assert decode_ts("not a number", "unix_s") is None  # type: ignore[arg-type]

    def test_none_input_returns_none(self) -> None:
        assert decode_ts(None, "unix_s") is None  # type: ignore[arg-type]

    def test_overflow_returns_none(self) -> None:
        # A value far in the future that overflows datetime
        assert decode_ts(10**18, "unix_s") is None

    def test_negative_unix_s_pre_1970(self) -> None:
        # datetime.fromtimestamp() rejects negative values on Windows (OSError) while
        # working fine on Linux/Mac; epoch+timedelta must decode this the same everywhere.
        assert decode_ts(-86400, "unix_s") == "1969-12-31 00:00:00 UTC"

    def test_output_ends_with_utc(self) -> None:
        result = decode_ts(self._UNIX_S, "unix_s")
        assert result is not None
        assert result.endswith(" UTC")

    def test_output_format_yyyy_mm_dd(self) -> None:
        result = decode_ts(self._UNIX_S, "unix_s")
        assert result is not None
        # Must be exactly "YYYY-MM-DD HH:MM:SS UTC"
        parts = result.split(" ")
        assert len(parts) == 3
        date_part, time_part, tz = parts
        assert len(date_part) == 10 and date_part[4] == "-"
        assert len(time_part) == 8 and time_part[2] == ":"
        assert tz == "UTC"


# ---------------------------------------------------------------------------
# TS_FORMATS — structural checks
# ---------------------------------------------------------------------------

class TestTsFormats:
    def test_has_six_formats(self) -> None:
        assert len(TS_FORMATS) == 6

    def test_all_keys_unique(self) -> None:
        keys = [k for k, _, _ in TS_FORMATS]
        assert len(keys) == len(set(keys))

    def test_all_suffixes_unique(self) -> None:
        suffixes = [s for _, _, s in TS_FORMATS]
        assert len(suffixes) == len(set(suffixes))

    @pytest.mark.parametrize("key", ["unix_s", "unix_ms", "unix_us", "mac_abs", "win_ft", "chrome"])
    def test_expected_keys_present(self, key: str) -> None:
        keys = [k for k, _, _ in TS_FORMATS]
        assert key in keys


# ---------------------------------------------------------------------------
# numeric_value / decode_cell -- TEXT-affinity cells that hold a number
# ---------------------------------------------------------------------------

class TestNumericValue:
    @pytest.mark.parametrize("value, expected", [
        (5, 5),
        (1.5, 1.5),
        ("1713884690406", 1713884690406),
        ("  42  ", 42),
        ("-5", -5),
        ("+5", 5),
        ("1713884690.406", 1713884690.406),
        (".5", 0.5),
        ("1.", 1.0),
        ("1.7138846904064E12", 1.7138846904064e12),
    ])
    def test_numbers_and_number_literals(self, value: object, expected: float) -> None:
        assert numeric_value(value) == expected

    def test_integer_text_stays_an_int(self) -> None:
        # Sub-second digits of a big epoch must not be lost to float rounding.
        result = numeric_value("1713884690406")
        assert isinstance(result, int)

    @pytest.mark.parametrize("value", [
        "", "   ", "abc", "12abc", "0x10", "1,000", "1_000", "nan", "inf", "-inf",
        "2024-04-23", "1 2", "1e", "--5", "\u0661\u0662\u0663",  # Arabic-Indic digits
        None, True, False, b"12", [1], {"a": 1},
    ])
    def test_everything_else_is_not_a_number(self, value: object) -> None:
        assert numeric_value(value) is None


class TestDecodeCell:
    _EXPECTED = "2024-04-23 15:04:50 UTC"

    def test_integer_and_text_decode_identically(self) -> None:
        assert decode_cell(1713884690406, "unix_ms") == (self._EXPECTED, None)
        assert decode_cell("1713884690406", "unix_ms") == (self._EXPECTED, None)
        assert decode_cell(" 1713884690406 ", "unix_ms") == (self._EXPECTED, None)

    def test_fractional_text(self) -> None:
        assert decode_cell("1713884690.406", "unix_s") == (self._EXPECTED, None)

    @pytest.mark.parametrize("value", [None, "", "   ", b"\x00\x01", bytearray(b"ab")])
    def test_nothing_to_decode_is_not_a_problem(self, value: object) -> None:
        assert decode_cell(value, "unix_ms") == (None, None)

    @pytest.mark.parametrize("value", ["abc", "12abc", "2024-04-23", "nan"])
    def test_non_numeric_text_is_reported(self, value: str) -> None:
        assert decode_cell(value, "unix_ms") == (None, "not a number")

    @pytest.mark.parametrize("value", [1713884690406, "1713884690406", "1e999"])
    def test_out_of_range_is_reported(self, value: object) -> None:
        # ms value read as seconds lands beyond year 9999; 1e999 overflows to inf.
        assert decode_cell(value, "unix_s") == (None, "out of range for this format")
