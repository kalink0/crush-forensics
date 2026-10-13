# SPDX-License-Identifier: Apache-2.0
"""Tests for crush/core/byte_strings.py -- the shared string-run scanner."""
from __future__ import annotations

import mmap
import random
import re
from pathlib import Path

from crush.core import byte_strings as bs
from crush.core.byte_strings import scan_strings


def _found(data: bytes, min_chars: int = 4) -> list[tuple[int, int, str, str]]:
    return [(h.offset, h.length, h.encoding, h.value) for h in scan_strings(data, min_chars)]


def test_ascii_run_with_offset_and_length() -> None:
    assert _found(b"\x00\x01hello\x00") == [(2, 5, "ASCII", "hello")]


def test_utf8_run_counts_characters_not_bytes() -> None:
    text = "äöü€"  # 4 characters, 9 bytes
    data = b"\x00" + text.encode("utf-8") + b"\x00"
    assert _found(data) == [(1, 9, "UTF-8", text)]
    assert _found("äöü".encode("utf-8")) == []  # 3 characters < 4


def test_ascii_and_utf8_are_one_entry_per_run() -> None:
    data = "abc ä def".encode("utf-8")
    assert _found(data) == [(0, len(data), "UTF-8", "abc ä def")]


def test_utf8_four_byte_characters_are_found() -> None:
    text = "hi 😀 there"
    assert _found(text.encode("utf-8"))[0][3] == text


def test_c1_controls_and_invalid_utf8_break_a_run() -> None:
    assert _found(b"abcd\xc2\x85efgh") == [(0, 4, "ASCII", "abcd"), (6, 4, "ASCII", "efgh")]
    assert _found(b"abcd\xed\xa0\x80efgh") == [(0, 4, "ASCII", "abcd"), (7, 4, "ASCII", "efgh")]
    assert _found(b"abcd\xc0\xafefgh") == [(0, 4, "ASCII", "abcd"), (6, 4, "ASCII", "efgh")]


def test_tab_lf_cr_are_part_of_a_run_and_nothing_is_trimmed() -> None:
    text = "  line one\r\n\tline two  "
    data = b"\x00" + text.encode("ascii") + b"\x00"
    assert _found(data) == [(1, len(text), "ASCII", text)]


def test_equal_values_are_listed_at_each_offset() -> None:
    data = b"same\x00same\x00same"
    assert [h[0] for h in _found(data)] == [0, 5, 10]


def test_utf16le_and_utf16be_at_both_alignments() -> None:
    le = "Grüße".encode("utf-16-le")
    be = "Hallo".encode("utf-16-be")
    data = b"\x01" + le + b"\x01\x01\x01" + be
    found = [(o, enc, v) for o, _n, enc, v in _found(data) if enc.startswith("UTF-16")]
    assert (1, "UTF-16LE", "Grüße") in found
    be_offset = 1 + len(le) + 3
    assert (be_offset, "UTF-16BE", "Hallo") in found


def test_utf16_outside_latin1_is_not_found() -> None:
    data = "Привет мир".encode("utf-16-le")
    assert [h for h in _found(data) if h[2] == "UTF-16LE"] == []


def test_full_range_utf16_only_for_the_named_byte_order() -> None:
    text = "Привет мир 你好"
    le = text.encode("utf-16-le")
    full = [h for h in scan_strings(le, 4, bs.ENCODING_UTF16LE)
            if h.encoding == bs.ENCODING_UTF16LE_FULL]
    assert (0, len(le), text) in [(h.offset, h.length, h.value) for h in full]
    # Without the switch, and for the other byte order, the Latin-1 rule applies.
    assert not [h for h in scan_strings(le, 4) if "При" in h.value]
    be = text.encode("utf-16-be")
    assert not [h for h in scan_strings(be, 4, bs.ENCODING_UTF16LE) if h.value == text]


def test_full_range_utf16_reads_both_alignments_separately() -> None:
    """A byte before the text that pairs into a valid code unit must not
    shift the reading: the correctly aligned run is listed as well."""
    text = "Привет мир"
    data = b"\x41" + text.encode("utf-16-le") + b"\x00\x00"
    values = {(h.offset, h.value) for h in scan_strings(data, 4, bs.ENCODING_UTF16LE)
              if h.encoding == bs.ENCODING_UTF16LE_FULL}
    assert (1, text) in values


def test_full_range_utf16_excludes_controls_and_surrogates() -> None:
    data = "abcd".encode("utf-16-le") + b"\x01\x00" + "efgh".encode("utf-16-le") \
        + b"\x00\xd8" + "ijkl".encode("utf-16-le")
    values = [h.value for h in scan_strings(data, 4, bs.ENCODING_UTF16LE)
              if h.encoding == bs.ENCODING_UTF16LE_FULL and h.offset % 2 == 0]
    assert values == ["abcd", "efgh", "ijkl"]


def test_utf16_same_bytes_also_read_shifted_are_both_listed() -> None:
    data = "abcde".encode("utf-16-le") + b"\x00"
    encodings = {h[2] for h in _found(data)}
    assert {"UTF-16LE", "UTF-16BE"} <= encodings


def test_min_chars_is_a_threshold() -> None:
    data = b"ab\x00abc\x00abcd"
    assert [h[3] for h in _found(data, 2)] == ["ab", "abc", "abcd"]
    assert [h[3] for h in _found(data, 4)] == ["abcd"]


def test_reads_an_mmap(tmp_path: Path) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"\x00\x00hello world\x00")
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert _found(mm) == [(2, 11, "ASCII", "hello world")]  # type: ignore[arg-type]


def test_prefilter_finds_the_same_runs_as_the_exact_pattern() -> None:
    """The UTF-8 scan first finds runs of possible bytes, then applies the
    exact pattern inside them; that must not change any result."""
    rng = random.Random(3)
    pieces = [bytes([b]) for b in range(256)] + [
        "ä".encode(), "€".encode(), "😀".encode(), b"text", b"\xc2\x85", b"\xed\xa0\x80",
    ]
    data = b"".join(rng.choice(pieces) for _ in range(200_000))
    for n in (1, 3, 4, 6):
        exact = re.compile(rb"(?:" + bs._UTF8_CHAR + rb"){%d,}" % n)
        expected = [(m.start(), m.group().decode("utf-8")) for m in exact.finditer(data)]
        got = [
            (h.offset, h.value) for h in scan_strings(data, n)
            if h.encoding in (bs.ENCODING_ASCII, bs.ENCODING_UTF8)
        ]
        assert got == expected
