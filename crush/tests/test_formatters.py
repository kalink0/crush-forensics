# SPDX-License-Identifier: Apache-2.0
"""Tests for pure formatting helpers."""
from __future__ import annotations

from crush.core import formatters


def test_pretty_json() -> None:
    text = '{"a":1,"b":true,"c":[1,2]}'
    pretty = formatters.pretty_json(text)
    assert pretty is not None
    assert "\n" in pretty
    assert '"a"' in pretty


def test_try_plist_text() -> None:
    import plistlib
    blob = plistlib.dumps({"k": "v"}, fmt=plistlib.FMT_XML)
    text = formatters.try_plist_text(blob)
    assert text is not None
    assert "k" in text and "v" in text


def test_try_xml_text() -> None:
    blob = b"<root><child>ok</child></root>"
    text = formatters.try_xml_text(blob)
    assert text is not None
    assert "<root" in text


def test_bytes_to_hexview() -> None:
    blob = bytes(range(16))
    view = formatters.bytes_to_hexview(blob, width=8)
    lines = view.splitlines()
    assert lines[0].startswith("00000000:")
    assert "00 01 02 03 04 05 06 07" in lines[0]
