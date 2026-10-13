# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for ts_decode — decode_ts and TS_FORMATS."""
from __future__ import annotations

import struct
import uuid

import pytest

from crush.core.issues import ParseIssue
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
    def test_all_keys_unique(self) -> None:
        keys = [k for k, _, _, _ in TS_FORMATS]
        assert len(keys) == len(set(keys))

    def test_all_suffixes_unique(self) -> None:
        suffixes = [s for _, _, s, _ in TS_FORMATS]
        assert len(suffixes) == len(set(suffixes))

    @pytest.mark.parametrize("key", [
        "unix_s", "unix_ms", "unix_us", "mac_abs", "cocoa_ns", "hfs", "win_ft",
        "systemtime", "net_ticks", "ole", "fat", "chrome", "snowflake", "uuid_v1", "bcd",
    ])
    def test_expected_keys_present(self, key: str) -> None:
        keys = [k for k, _, _, _ in TS_FORMATS]
        assert key in keys

    def test_gps_is_not_offered(self) -> None:
        keys = {k for k, _, _, _ in TS_FORMATS}
        assert not keys & {"gps_s", "gps_ns"}

    def test_cocoa_is_findable_by_name(self) -> None:
        label = next(label for k, label, _, _ in TS_FORMATS if k == "mac_abs")
        assert "Cocoa" in label

    def test_every_offered_format_decodes(self) -> None:
        for key, _, _, _ in TS_FORMATS:
            decode_cell(0, key)  # must not raise "unknown format"


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
    _EXPECTED = "2024-04-23 15:04:50.406 UTC"

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
        assert decode_cell(value, "unix_ms") == (None, ParseIssue("ts_decode.not_a_number"))

    @pytest.mark.parametrize("value", [1713884690406, "1713884690406", "1e999"])
    def test_out_of_range_is_reported(self, value: object) -> None:
        # ms value read as seconds lands beyond year 9999; 1e999 overflows to inf.
        assert decode_cell(value, "unix_s") == (None, ParseIssue("ts_decode.out_of_range"))


# ---------------------------------------------------------------------------
# The formats beyond Unix -- reference values
# ---------------------------------------------------------------------------

class TestMoreFormats:
    # 2024-01-15 10:23:45 UTC
    _UNIX = 1_705_314_225
    _EXPECTED = "2024-01-15 10:23:45 UTC"

    @pytest.mark.parametrize("value, fmt", [
        ((_UNIX - 978_307_200) * 1_000_000_000, "cocoa_ns"),
        (_UNIX + 2_082_844_800, "hfs"),
        ((_UNIX + 62_135_596_800) * 10_000_000, "net_ticks"),
        (_UNIX - 315_964_800, "gps_s"),
        ((_UNIX - 315_964_800) * 1_000_000_000, "gps_ns"),
    ])
    def test_linear_formats(self, value: int, fmt: str) -> None:
        assert decode_cell(value, fmt) == (self._EXPECTED, None)

    def test_ole_automation_date(self) -> None:
        assert decode_cell(45306.5, "ole") == ("2024-01-15 12:00:00 UTC", None)
        assert decode_cell(0, "ole") == ("1899-12-30 00:00:00 UTC", None)

    def test_ole_negative_keeps_time_of_day_positive(self) -> None:
        # Spec: the fraction is the time of day regardless of sign.
        assert decode_cell(-1.25, "ole") == ("1899-12-29 06:00:00 UTC", None)

    def test_snowflake(self) -> None:
        # Upper 42 bits: ms since 2010-11-04 01:42:54.657 UTC; the low 22 bits
        # (worker/sequence) don't touch the time.
        value = ((self._UNIX * 1_000 - 1_288_834_974_657) << 22) | 0x3F_FFFF
        assert decode_cell(value, "snowflake") == (self._EXPECTED, None)

    def test_snowflake_and_fat_need_an_integer(self) -> None:
        for fmt in ("snowflake", "fat"):
            assert decode_cell(1.5, fmt) == (None, ParseIssue("ts_decode.not_an_integer"))

    def test_fat(self) -> None:
        # 2024-06-15 13:17:02: date word (44<<9)|(6<<5)|15, time word (13<<11)|(17<<5)|1
        value = (((44 << 9) | (6 << 5) | 15) << 16) | ((13 << 11) | (17 << 5) | 1)
        assert decode_cell(value, "fat") == ("2024-06-15 13:17:02 UTC", None)
        assert decode_cell(str(value), "fat") == ("2024-06-15 13:17:02 UTC", None)

    def test_fat_invalid_month(self) -> None:
        value = (((44 << 9) | (13 << 5) | 15) << 16)
        assert decode_cell(value, "fat") == (None, ParseIssue("ts_decode.invalid_fields"))

    def test_systemtime_blob_and_hex_text(self) -> None:
        data = struct.pack("<8H", 2024, 6, 4, 27, 14, 36, 42, 500)
        assert decode_cell(data, "systemtime") == ("2024-06-27 14:36:42.5 UTC", None)
        assert decode_cell(data.hex(" "), "systemtime") == ("2024-06-27 14:36:42.5 UTC", None)
        assert decode_cell(data.hex(), "systemtime") == ("2024-06-27 14:36:42.5 UTC", None)

    def test_systemtime_wrong_length_and_fields(self) -> None:
        assert decode_cell(b"\x00" * 15, "systemtime") == (
            None, ParseIssue("ts_decode.wrong_length", {"length": 15, "expected": 16}),
        )
        bad = struct.pack("<8H", 2024, 13, 0, 1, 0, 0, 0, 0)
        assert decode_cell(bad, "systemtime") == (None, ParseIssue("ts_decode.invalid_fields"))

    def test_byte_formats_reject_numbers_and_plain_text(self) -> None:
        assert decode_cell(12, "bcd") == (None, ParseIssue("ts_decode.not_bytes"))
        assert decode_cell("hello", "systemtime") == (None, ParseIssue("ts_decode.not_bytes"))

    def test_bcd(self) -> None:
        assert decode_cell(bytes.fromhex("20240627143642"), "bcd") == ("2024-06-27 14:36:42 UTC", None)
        assert decode_cell("20 24 06 27 14 36 42", "bcd") == ("2024-06-27 14:36:42 UTC", None)
        assert decode_cell(bytes.fromhex("2024062714364A"), "bcd") == (
            None, ParseIssue("ts_decode.not_bcd"),
        )

    def test_uuid_v1_text_and_blob(self) -> None:
        value = uuid.UUID("c232ab00-9414-11ec-b3c8-9f6bdeced846")  # RFC 9562 test vector
        expected = ("2022-02-22 19:22:22 UTC", None)
        assert decode_cell(str(value), "uuid_v1") == expected
        assert decode_cell(value.bytes, "uuid_v1") == expected

    def test_uuid_other_version_or_not_a_uuid(self) -> None:
        v4 = "919108f7-52d1-4320-9bac-f847db4148a8"
        assert decode_cell(v4, "uuid_v1") == (None, ParseIssue("ts_decode.uuid_not_v1"))
        assert decode_cell("nope", "uuid_v1") == (None, ParseIssue("ts_decode.not_a_uuid"))
        assert decode_cell(5, "uuid_v1") == (None, ParseIssue("ts_decode.not_a_uuid"))

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_cell(1, "bogus")


# ---------------------------------------------------------------------------
# Exactness -- no sub-second digit lost or invented
# ---------------------------------------------------------------------------

class TestExactFractions:
    def test_filetime_keeps_all_seven_digits(self) -> None:
        # Above 2**53: a float conversion would round the last digits away.
        value = 133_500_000_001_234_567
        assert decode_cell(value, "win_ft") == ("2024-01-17 21:20:00.1234567 UTC", None)

    def test_cocoa_ns_keeps_all_nine_digits(self) -> None:
        value = 726_000_000_123_456_789
        result, _ = decode_cell(value, "cocoa_ns")
        assert result is not None and result.endswith(".123456789 UTC")

    def test_float_reads_its_shortest_repr(self) -> None:
        # 760000000.1 is not exact in binary; the stored digits are what counts.
        assert decode_cell(760_000_000.1, "mac_abs") == ("2025-01-31 07:06:40.1 UTC", None)

    def test_decimal_text_digit_for_digit(self) -> None:
        assert decode_cell("1713884690.123456789", "unix_s") == (
            "2024-04-23 15:04:50.123456789 UTC", None,
        )

    def test_trailing_zeros_carry_no_digits(self) -> None:
        assert decode_cell(1_713_884_690_500, "unix_ms") == ("2024-04-23 15:04:50.5 UTC", None)

    def test_negative_fraction(self) -> None:
        assert decode_cell(-0.5, "unix_s") == ("1969-12-31 23:59:59.5 UTC", None)

    def test_years_before_1000_are_zero_padded(self) -> None:
        assert decode_cell(0, "net_ticks") == ("0001-01-01 00:00:00 UTC", None)


# ---------------------------------------------------------------------------
# Value Inspector <-> table: every inspector timestamp is a table format
# ---------------------------------------------------------------------------

# Inspector row label -> ts_decode key. A new inspector timestamp format must be
# added here and, unless deliberately excluded like GPS, to TS_FORMATS.
_INSPECTOR_FORMATS = {
    "Unix (s)": "unix_s",
    "Unix (ms)": "unix_ms",
    "Unix (µs)": "unix_us",
    "Cocoa / Apple (s)": "mac_abs",
    "Cocoa / Apple (ns)": "cocoa_ns",
    "Chrome / WebKit (µs)": "chrome",
    "Windows FILETIME": "win_ft",
    "HFS+ / Mac OS (s)": "hfs",
    "Microsoft .NET Ticks": "net_ticks",
    "OLE Automation Date": "ole",
    "Twitter / X Snowflake": "snowflake",
    "FAT / exFAT (MS-DOS)": "fat",
    "BCD (YYYYMMDDHHmmSS)": "bcd",
    "UUID v1 Timestamp": "uuid_v1",
    "GPS Time (s)": "gps_s",
    "GPS Time (ns)": "gps_ns",
    "Windows SYSTEMTIME": "systemtime",
}
_NOT_IN_TABLE = {"gps_s", "gps_ns"}  # GPS: inspector only, by decision


def test_inspector_timestamp_formats_are_all_mapped() -> None:
    from crush.viewers.value_inspector import _interpret

    labels = {row.label for row in _interpret("0") if row.group == "Timestamp"}
    assert labels == set(_INSPECTOR_FORMATS)


def test_table_offers_every_inspector_format_except_gps() -> None:
    table = {k for k, _, _, _ in TS_FORMATS}
    assert set(_INSPECTOR_FORMATS.values()) - _NOT_IN_TABLE <= table
