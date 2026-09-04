# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for the Value Inspector interpretation engine (_interpret)."""
from __future__ import annotations

import struct

import pytest

from crush.viewers.value_inspector import _interpret, _Row


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(rows: list[_Row], group: str, label: str) -> str | None | type[KeyError]:
    for r in rows:
        if r.group == group and r.label == label:
            return r.value
    return KeyError  # sentinel: row not present at all


def _present(rows: list[_Row], group: str, label: str) -> bool:
    return _get(rows, group, label) is not KeyError


def _value(rows: list[_Row], group: str, label: str) -> str:
    """Return the value; raises AssertionError if the row is absent or None."""
    v = _get(rows, group, label)
    assert v is not KeyError and v is not None, f"[{group}] {label!r} has no value"
    assert isinstance(v, str)
    return v


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_string_returns_empty_list(self) -> None:
        assert _interpret("") == []

    def test_whitespace_only_returns_empty_list(self) -> None:
        assert _interpret("   \t\n") == []


# ---------------------------------------------------------------------------
# Integer group — decimal input
# ---------------------------------------------------------------------------

class TestIntegerDecimal:
    def test_decimal_shows_decimal_and_hex(self) -> None:
        rows = _interpret("255")
        assert _value(rows, "Integer", "Decimal") == "255"
        assert _value(rows, "Integer", "Hex") == "0xff"

    def test_signed_32bit_positive(self) -> None:
        rows = _interpret("2147483647")  # INT32_MAX
        assert _value(rows, "Integer", "Signed 32-bit") == "2147483647"

    def test_signed_32bit_wraps_for_large_uint32(self) -> None:
        rows = _interpret("3000000000")
        signed = _value(rows, "Integer", "Signed 32-bit")
        assert int(signed) < 0  # wraps to negative

    def test_large_decimal_no_le_variants(self) -> None:
        """LE variants only appear for hex-byte input, not plain decimal."""
        rows = _interpret("1718000000")
        assert not _present(rows, "Integer", "Decimal (LE)")

    def test_0x_prefix_parsed_as_integer(self) -> None:
        rows = _interpret("0xff")
        assert _value(rows, "Integer", "Decimal") == "255"
        assert _value(rows, "Integer", "Hex") == "0xff"


# ---------------------------------------------------------------------------
# Integer group — hex-byte input (BE and LE)
# ---------------------------------------------------------------------------

class TestIntegerHexBytes:
    def test_4_bytes_be_and_le(self) -> None:
        # c0 a8 01 01 → BE = 0xc0a80101, LE = 0x0101a8c0
        rows = _interpret("c0 a8 01 01")
        assert _value(rows, "Integer", "Decimal") == "3,232,235,777"
        assert _value(rows, "Integer", "Decimal (LE)") == "16,885,952"

    def test_6_bytes_le_present(self) -> None:
        rows = _interpret("f7 f8 f9 fa fb fc")
        be = int(_value(rows, "Integer", "Decimal").replace(",", ""))
        le = int(_value(rows, "Integer", "Decimal (LE)").replace(",", ""))
        assert be != le

    def test_odd_nibble_truncated_silently(self) -> None:
        # "f7 f8 f" truncates to "f7 f8" (2 bytes)
        rows_full = _interpret("f7 f8")
        rows_trunc = _interpret("f7 f8 f")
        assert _value(rows_full, "Integer", "Decimal") == _value(rows_trunc, "Integer", "Decimal")

    def test_hex_bytes_signed_32bit_negative(self) -> None:
        rows = _interpret("c0 a8 01 01")
        signed = _value(rows, "Integer", "Signed 32-bit")
        assert int(signed) < 0


# ---------------------------------------------------------------------------
# Data Size group
# ---------------------------------------------------------------------------

class TestDataSize:
    def test_bytes_under_1000_shown_as_bytes_both_units(self) -> None:
        rows = _interpret("512")
        assert _value(rows, "Data Size", "Decimal (KB/MB/GB…)") == "512 B"
        assert _value(rows, "Data Size", "Binary (KiB/MiB/GiB…)") == "512 B"

    def test_decimal_and_binary_scale_differently_at_1024(self) -> None:
        rows = _interpret("1024")
        assert _value(rows, "Data Size", "Decimal (KB/MB/GB…)") == "1.024 KB"
        assert _value(rows, "Data Size", "Binary (KiB/MiB/GiB…)") == "1.000 KiB"

    def test_mib_scale_matches_expected_precision(self) -> None:
        rows = _interpret("423123456")
        assert _value(rows, "Data Size", "Binary (KiB/MiB/GiB…)") == "403.52 MiB"

    def test_gib_scale_matches_expected_precision(self) -> None:
        rows = _interpret("1330000000")
        assert _value(rows, "Data Size", "Binary (KiB/MiB/GiB…)") == "1.239 GiB"

    def test_zero_shown_as_zero_bytes(self) -> None:
        rows = _interpret("0")
        assert _value(rows, "Data Size", "Decimal (KB/MB/GB…)") == "0 B"
        assert _value(rows, "Data Size", "Binary (KiB/MiB/GiB…)") == "0 B"

    def test_negative_int_shows_none(self) -> None:
        rows = _interpret("-5")
        assert _get(rows, "Data Size", "Decimal (KB/MB/GB…)") is None
        assert _get(rows, "Data Size", "Binary (KiB/MiB/GiB…)") is None

    def test_non_numeric_shows_none(self) -> None:
        rows = _interpret("hello")
        assert _get(rows, "Data Size", "Decimal (KB/MB/GB…)") is None
        assert _get(rows, "Data Size", "Binary (KiB/MiB/GiB…)") is None


# ---------------------------------------------------------------------------
# Float group
# ---------------------------------------------------------------------------

class TestFloat:
    def test_float_string_shows_double(self) -> None:
        rows = _interpret("3.14159")
        assert _value(rows, "Float", "Double (64-bit)").startswith("3.")

    def test_float_does_not_trigger_cocoa_for_small_value(self) -> None:
        # 3.14159 < 1_000_000 → Cocoa guard must suppress it
        rows = _interpret("3.14159")
        assert _get(rows, "Timestamp", "Cocoa / Apple (s)") is None

    def test_4_byte_hex_shows_float32_be_and_le(self) -> None:
        # Known BE float: 0x3fc00000 = 1.5 in IEEE-754
        be_bytes = struct.pack(">f", 1.5)
        hex_input = " ".join(f"{b:02x}" for b in be_bytes)
        rows = _interpret(hex_input)
        assert float(_value(rows, "Float", "Float32 · 4 bytes BE")) == pytest.approx(1.5)
        # LE interpretation of same bytes is a different (non-trivial) value
        assert _present(rows, "Float", "Float32 · 4 bytes LE")

    def test_8_byte_hex_shows_double_be_and_le(self) -> None:
        be_bytes = struct.pack(">d", 1.5)
        hex_input = " ".join(f"{b:02x}" for b in be_bytes)
        rows = _interpret(hex_input)
        assert float(_value(rows, "Float", "Double · 8 bytes BE")) == pytest.approx(1.5)
        assert _present(rows, "Float", "Double · 8 bytes LE")


# ---------------------------------------------------------------------------
# Timestamp group
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_unix_second_in_range(self) -> None:
        rows = _interpret("1718000000")
        ts = _value(rows, "Timestamp", "Unix (s)")
        assert "2024" in ts

    def test_unix_ms_in_range(self) -> None:
        rows = _interpret("1718000000000")
        ts = _value(rows, "Timestamp", "Unix (ms)")
        assert "2024" in ts

    def test_cocoa_second_in_range(self) -> None:
        # 760_000_000 Cocoa seconds ≈ 2025-02-03
        rows = _interpret("760000000")
        ts = _value(rows, "Timestamp", "Cocoa / Apple (s)")
        assert "2025" in ts

    def test_small_float_not_cocoa(self) -> None:
        rows = _interpret("12345.6789")
        assert _get(rows, "Timestamp", "Cocoa / Apple (s)") is None

    def test_out_of_range_int_no_unix(self) -> None:
        rows = _interpret("1")  # 1970-01-01 → below _TS_S_MIN
        assert _get(rows, "Timestamp", "Unix (s)") is None

    def test_cocoa_nanosecond_in_range(self) -> None:
        # 750_000_000_000_000_000 ns ≈ 2024-10-07
        rows = _interpret("750000000000000000")
        ts = _value(rows, "Timestamp", "Cocoa / Apple (ns)")
        assert "2024" in ts

    def test_net_ticks_in_range(self) -> None:
        # 638_000_000_000_000_000 ticks ≈ 2022-09
        rows = _interpret("638000000000000000")
        ts = _value(rows, "Timestamp", "Microsoft .NET Ticks")
        assert "2022" in ts

    def test_ole_automation_float(self) -> None:
        # 45000.5 days since 1899-12-30 ≈ 2023-03-15 12:00:00
        rows = _interpret("45000.5")
        ts = _value(rows, "Timestamp", "OLE Automation Date")
        assert "2023" in ts
        assert "12:00:00" in ts

    def test_twitter_snowflake_in_range(self) -> None:
        # Real-world Snowflake ID from ~2023
        rows = _interpret("1641183228246523904")
        ts = _value(rows, "Timestamp", "Twitter / X Snowflake")
        assert "2023" in ts

    def test_small_int_no_snowflake(self) -> None:
        rows = _interpret("12345")
        assert _get(rows, "Timestamp", "Twitter / X Snowflake") is None

    def test_fat_ms_dos_timestamp(self) -> None:
        # 2024-06-07 14:30:22: year_off=44, date=(44<<9)|(6<<5)|7, time=(14<<11)|(30<<5)|11
        date_word = (44 << 9) | (6 << 5) | 7
        time_word = (14 << 11) | (30 << 5) | 11  # 11 * 2 = 22s
        rows = _interpret(str((date_word << 16) | time_word))
        ts = _value(rows, "Timestamp", "FAT / exFAT (MS-DOS)")
        assert "2024" in ts and "14:30:22" in ts

    def test_bcd_7byte_timestamp(self) -> None:
        rows = _interpret("20 24 06 07 14 30 22")
        ts = _value(rows, "Timestamp", "BCD (YYYYMMDDHHmmSS)")
        assert "2024-06-07" in ts and "14:30:22" in ts

    def test_bcd_invalid_nibble_shows_none(self) -> None:
        rows = _interpret("20 24 AB 07 14 30 22")
        assert _get(rows, "Timestamp", "BCD (YYYYMMDDHHmmSS)") is None

    def test_uuid_v1_timestamp(self) -> None:
        rows = _interpret("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
        ts = _value(rows, "Timestamp", "UUID v1 Timestamp")
        assert "1998" in ts

    def test_uuid_v4_no_timestamp(self) -> None:
        rows = _interpret("550e8400-e29b-41d4-a716-446655440000")
        assert _get(rows, "Timestamp", "UUID v1 Timestamp") is None

    def test_gps_time_seconds(self) -> None:
        # 1402718933 GPS seconds since 1980-01-06 ≈ 2024-06
        rows = _interpret("1402718933")
        ts = _value(rows, "Timestamp", "GPS Time (s)")
        assert "2024" in ts

    def test_gps_time_nanoseconds(self) -> None:
        rows = _interpret("1402718933000000000")
        ts = _value(rows, "Timestamp", "GPS Time (ns)")
        assert "2024" in ts

    def test_gps_small_value_shows_none(self) -> None:
        rows = _interpret("12345")
        assert _get(rows, "Timestamp", "GPS Time (s)") is None

    def test_windows_systemtime(self) -> None:
        import struct as _struct
        # 2024-06-27 14:36:42.500, dow=4 (Thursday)
        data = _struct.pack("<8H", 2024, 6, 4, 27, 14, 36, 42, 500)
        rows = _interpret(" ".join(f"{b:02x}" for b in data))
        ts = _value(rows, "Timestamp", "Windows SYSTEMTIME")
        assert ts == "2024-06-27 14:36:42.500 UTC"

    def test_windows_systemtime_invalid_month(self) -> None:
        import struct as _struct
        data = _struct.pack("<8H", 2024, 13, 0, 1, 0, 0, 0, 0)  # month=13 invalid
        rows = _interpret(" ".join(f"{b:02x}" for b in data))
        assert _get(rows, "Timestamp", "Windows SYSTEMTIME") is None

    # -- Fractional-value timestamps (issue #51) --------------------------------

    def test_unix_ms_with_fractional_component(self) -> None:
        # Reported case: a ms epoch with a sub-ms fraction appended ("...913.061").
        # int(raw) rejects the "." so this must fall back to a float parse.
        rows = _interpret("1760996870913.061")
        ts = _value(rows, "Timestamp", "Unix (ms)")
        assert ts == "2025-10-20 21:47:50.913061 UTC"

    def test_unix_s_with_fractional_component(self) -> None:
        rows = _interpret("1718000000.5")
        ts = _value(rows, "Timestamp", "Unix (s)")
        assert ts == "2024-06-10 06:13:20.500000 UTC"

    def test_fractional_input_no_bitfield_formats(self) -> None:
        # Twitter Snowflake / FAT unpack exact bit fields (shift/mask) and can't
        # accept a float, even though the arithmetic-based formats now resolve one.
        rows = _interpret("1760996870913.061")
        assert _get(rows, "Timestamp", "Twitter / X Snowflake") is None
        assert _get(rows, "Timestamp", "FAT / exFAT (MS-DOS)") is None

    def test_small_fractional_no_spurious_cocoa_ns(self) -> None:
        # Cocoa (ns)'s plausible range dips below zero (like Cocoa (s)'s), so an
        # unguarded float fallback would match trivial values such as "123.0".
        rows = _interpret("123.0")
        assert _get(rows, "Timestamp", "Cocoa / Apple (ns)") is None

    def test_negative_fractional_no_spurious_timestamps(self) -> None:
        rows = _interpret("-1760996870913.061")
        assert _get(rows, "Timestamp", "Unix (ms)") is None
        assert _get(rows, "Timestamp", "Cocoa / Apple (ns)") is None


# ---------------------------------------------------------------------------
# UUID group
# ---------------------------------------------------------------------------

class TestUUID:
    UUID_DASHED = "550e8400-e29b-41d4-a716-446655440000"
    UUID_HEX    = "550e8400e29b41d4a716446655440000"

    def test_dashed_uuid_parsed(self) -> None:
        rows = _interpret(self.UUID_DASHED)
        assert _value(rows, "UUID", "UUID") == self.UUID_DASHED

    def test_hex_uuid_parsed(self) -> None:
        rows = _interpret(self.UUID_HEX)
        assert _value(rows, "UUID", "UUID") == self.UUID_DASHED

    def test_non_uuid_string_shows_none(self) -> None:
        rows = _interpret("hello world")
        assert _get(rows, "UUID", "UUID") is None


# ---------------------------------------------------------------------------
# Network group
# ---------------------------------------------------------------------------

class TestNetwork:
    def test_4_byte_hex_ipv4_be(self) -> None:
        rows = _interpret("c0 a8 01 01")
        assert _value(rows, "Network", "IPv4 (big-endian)") == "192.168.1.1"

    def test_4_byte_hex_ipv4_le(self) -> None:
        rows = _interpret("c0 a8 01 01")
        assert _value(rows, "Network", "IPv4 (little-endian)") == "1.1.168.192"

    def test_6_byte_hex_mac(self) -> None:
        rows = _interpret("f7 f8 f9 fa fb fc")
        assert _value(rows, "Network", "MAC address") == "f7:f8:f9:fa:fb:fc"

    def test_colon_mac_input(self) -> None:
        rows = _interpret("aa:bb:cc:dd:ee:ff")
        assert _value(rows, "Network", "MAC address") == "aa:bb:cc:dd:ee:ff"

    def test_5_byte_hex_no_ipv4(self) -> None:
        # 5 bytes → too long for IPv4, no IPv4 row should be filled
        rows = _interpret("c0 a8 01 01 ff")
        assert _get(rows, "Network", "IPv4 (big-endian)") is None


# ---------------------------------------------------------------------------
# Text group
# ---------------------------------------------------------------------------

class TestText:
    def test_ascii_hello(self) -> None:
        rows = _interpret("48 65 6c 6c 6f")
        assert _value(rows, "Text", "ASCII (hex bytes)") == "Hello"
        assert _value(rows, "Text", "UTF-8 (hex bytes)") == "Hello"

    def test_non_printable_shown_as_dots(self) -> None:
        rows = _interpret("f7 f8 f9")
        ascii_val = _value(rows, "Text", "ASCII (hex bytes)")
        assert ascii_val == "..."

    def test_valid_utf8_non_ascii(self) -> None:
        # é = U+00E9, UTF-8: c3 a9
        rows = _interpret("c3 a9")
        assert _value(rows, "Text", "UTF-8 (hex bytes)") == "é"

    def test_invalid_utf8_shows_none(self) -> None:
        # 0xf7 alone is not valid UTF-8
        rows = _interpret("f7")
        assert _get(rows, "Text", "UTF-8 (hex bytes)") is None

    def test_no_text_group_for_plain_decimal(self) -> None:
        rows = _interpret("1718000000")
        assert not _present(rows, "Text", "ASCII (hex bytes)")


# ---------------------------------------------------------------------------
# Encoding group
# ---------------------------------------------------------------------------

class TestEncoding:
    def test_base64_standard_with_padding(self) -> None:
        # dGVzdA== → b"test"
        rows = _interpret("dGVzdA==")
        assert _value(rows, "Encoding", "Base64 → bytes") == "74 65 73 74"
        assert _value(rows, "Encoding", "Base64 → UTF-8") == "test"

    def test_base64_no_padding(self) -> None:
        # SGVsbG8gV29ybGQ → "Hello World"
        rows = _interpret("SGVsbG8gV29ybGQ")
        assert _value(rows, "Encoding", "Base64 → UTF-8") == "Hello World"

    def test_base64url_variant(self) -> None:
        # URL-safe Base64 uses - and _ instead of + and /
        import base64 as _b64
        payload = b"\xfb\xff\xfe"
        encoded = _b64.urlsafe_b64encode(payload).decode()  # e.g. +// → -__
        rows = _interpret(encoded)
        assert _value(rows, "Encoding", "Base64 → bytes") == "fb ff fe"

    def test_base64_binary_no_utf8(self) -> None:
        # Pure binary payload that is not valid UTF-8
        import base64 as _b64
        encoded = _b64.b64encode(b"\xff\xfe\xfd").decode()
        rows = _interpret(encoded)
        assert _value(rows, "Encoding", "Base64 → bytes") == "ff fe fd"
        assert _get(rows, "Encoding", "Base64 → UTF-8") is None

    def test_no_base64_for_hex_string(self) -> None:
        rows = _interpret("deadbeef")
        assert not _present(rows, "Encoding", "Base64 → bytes")

    def test_no_base64_for_plain_integer(self) -> None:
        rows = _interpret("12345")
        assert not _present(rows, "Encoding", "Base64 → bytes")
