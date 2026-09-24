# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for paste_decode helpers — try_decode_input and FORMATS consistency."""
from __future__ import annotations

import base64

from crush.core.paste_decode import (
    ENCODING_AUTO,
    ENCODING_BASE64,
    ENCODING_HEX,
    ENCODING_UTF8,
    FORMATS,
    try_decode_input,
)

# ---------------------------------------------------------------------------
# try_decode_input — Auto mode
# ---------------------------------------------------------------------------

class TestTryDecodeInputAuto:
    def test_empty_returns_none(self) -> None:
        data, msg = try_decode_input("", ENCODING_AUTO)
        assert data is None
        assert "Paste" in msg

    def test_whitespace_only_returns_none(self) -> None:
        data, _ = try_decode_input("   \n\t  ", ENCODING_AUTO)
        assert data is None

    def test_hex_plain(self) -> None:
        data, msg = try_decode_input("62706c6973743030", ENCODING_AUTO)
        assert data == b"bplist00"
        assert "hex" in msg

    def test_hex_with_spaces(self) -> None:
        data, msg = try_decode_input("62 70 6c 69 73 74 30 30", ENCODING_AUTO)
        assert data == b"bplist00"
        assert "hex" in msg

    def test_hex_with_colons(self) -> None:
        data, msg = try_decode_input("62:70:6c:69:73:74:30:30", ENCODING_AUTO)
        assert data == b"bplist00"
        assert "hex" in msg

    def test_hex_mixed_separators(self) -> None:
        data, msg = try_decode_input("62 70:6c_69-73 74 30 30", ENCODING_AUTO)
        assert data == b"bplist00"
        assert "hex" in msg

    def test_hex_odd_length_falls_through(self) -> None:
        # Odd-length hex string → not valid hex → falls through to UTF-8
        data, msg = try_decode_input("abc", ENCODING_AUTO)
        assert data is not None
        assert "UTF-8" in msg

    def test_base64_detected(self) -> None:
        encoded = base64.b64encode(b"bplist00").decode()
        data, msg = try_decode_input(encoded, ENCODING_AUTO)
        assert data == b"bplist00"
        assert "base64" in msg

    def test_base64_with_mime_linebreaks(self) -> None:
        raw = b"A" * 60
        encoded = base64.b64encode(raw).decode()
        # Insert MIME-style line break every 20 chars
        wrapped = "\n".join(encoded[i:i+20] for i in range(0, len(encoded), 20))
        data, msg = try_decode_input(wrapped, ENCODING_AUTO)
        assert data == raw
        assert "base64" in msg

    def test_plain_text_with_spaces_not_base64(self) -> None:
        # "hello world" contains a space → must not be decoded as base64
        data, msg = try_decode_input("hello world", ENCODING_AUTO)
        assert data is not None
        assert "UTF-8" in msg
        assert data == b"hello world"

    def test_utf8_fallback(self) -> None:
        text = "<?xml version='1.0'?><root/>"
        data, msg = try_decode_input(text, ENCODING_AUTO)
        assert data == text.encode("utf-8")
        assert "UTF-8" in msg

    def test_byte_count_in_message(self) -> None:
        data, msg = try_decode_input("62706c6973743030", ENCODING_AUTO)
        assert data is not None
        assert str(len(data)) in msg


# ---------------------------------------------------------------------------
# try_decode_input — forced encoding modes
# ---------------------------------------------------------------------------

class TestTryDecodeInputForced:
    def test_hex_mode_valid(self) -> None:
        data, msg = try_decode_input("deadbeef", ENCODING_HEX)
        assert data == bytes.fromhex("deadbeef")
        assert "hex" in msg

    def test_hex_mode_invalid(self) -> None:
        data, msg = try_decode_input("not hex!", ENCODING_HEX)
        assert data is None
        assert "Invalid" in msg

    def test_hex_mode_odd_length(self) -> None:
        data, msg = try_decode_input("abc", ENCODING_HEX)
        assert data is None
        assert "Invalid" in msg

    def test_base64_mode_valid(self) -> None:
        encoded = base64.b64encode(b"hello").decode()
        data, msg = try_decode_input(encoded, ENCODING_BASE64)
        assert data == b"hello"
        assert "base64" in msg

    def test_base64_mode_invalid(self) -> None:
        data, msg = try_decode_input("hello world", ENCODING_BASE64)
        assert data is None
        assert "Invalid" in msg

    def test_utf8_mode_always_succeeds(self) -> None:
        data, msg = try_decode_input("any text 123 !@#", ENCODING_UTF8)
        assert data == b"any text 123 !@#"
        assert "UTF-8" in msg

    def test_utf8_mode_empty(self) -> None:
        data, _ = try_decode_input("", ENCODING_UTF8)
        assert data is None


# ---------------------------------------------------------------------------
# FORMATS — consistency: every parser_display_name matches a real parser
# ---------------------------------------------------------------------------

class TestFormatsConsistency:
    def test_all_display_names_match_registered_parsers(self) -> None:
        from crush.parsers import ParserRegistry

        registered = {p.DISPLAY_NAME for p in ParserRegistry._parsers}
        for label, _hint, display_name in FORMATS:
            if display_name is None or display_name == "__hex__":
                continue
            assert display_name in registered, (
                f"FORMATS entry '{label}' references parser_display_name "
                f"'{display_name}' which is not registered"
            )

    def test_no_duplicate_labels(self) -> None:
        labels = [label for label, _, _ in FORMATS]
        assert len(labels) == len(set(labels))

    def test_auto_detect_is_first(self) -> None:
        assert FORMATS[0][2] is None  # parser_display_name=None means auto-detect

    def test_hex_sentinel_present(self) -> None:
        sentinels = [dn for _, _, dn in FORMATS if dn == "__hex__"]
        assert len(sentinels) == 1
