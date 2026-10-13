# SPDX-License-Identifier: Apache-2.0
"""Find text runs ("strings") in raw bytes.

Shared building block for every Strings view: it only finds runs and
reports where they are; what a run's bytes belong to (a page, a freeblock,
a WAL frame ...) is the caller's job (e.g. ``sqlite_strings.py``).

What counts as a string is a fixed, declared rule -- not a guess about
whether the bytes are "really" text:

- ASCII / UTF-8: printable ASCII (0x20-0x7E) plus tab, LF and CR, and every
  well-formed UTF-8 multi-byte sequence except C1 controls (U+0080-U+009F).
  A run made of ASCII bytes only is reported as ASCII, a run with at least
  one multi-byte character as UTF-8 -- one entry per run, never both.
- UTF-16LE / UTF-16BE: code units U+0020-U+007E and U+00A0-U+00FF (ASCII and
  Latin-1, e.g. umlauts) plus tab, LF and CR, at even and odd offsets alike.
  Other scripts in UTF-16 are not found: almost every byte pair is a valid
  printable code unit, so the full range would turn binary data into
  "strings".
- A run needs at least *min_chars* characters. That is a threshold, not a
  property of the data: shorter runs exist but are not listed.

The same bytes can be found as a UTF-16LE run and, shifted by one byte, as a
UTF-16BE run; both are listed, since both readings are valid. Every run is
listed at its own offset: equal values are not merged, nothing is trimmed,
and there is no cap on the number of results.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

DEFAULT_MIN_CHARS = 4

ENCODING_ASCII = "ASCII"
ENCODING_UTF8 = "UTF-8"
ENCODING_UTF16LE = "UTF-16LE"
ENCODING_UTF16BE = "UTF-16BE"

# One alternative per character, so a {n,} quantifier counts characters.
_UTF8_CHAR = (
    rb"[\t\n\r\x20-\x7E]"
    rb"|\xC2[\xA0-\xBF]"                   # U+00A0-U+00BF (U+0080-U+009F are C1 controls)
    rb"|[\xC3-\xDF][\x80-\xBF]"
    rb"|\xE0[\xA0-\xBF][\x80-\xBF]"        # no overlong forms
    rb"|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}"
    rb"|\xED[\x80-\x9F][\x80-\xBF]"        # no UTF-16 surrogates
    rb"|\xF0[\x90-\xBF][\x80-\xBF]{2}"
    rb"|[\xF1-\xF3][\x80-\xBF]{3}"
    rb"|\xF4[\x80-\x8F][\x80-\xBF]{2}"     # up to U+10FFFF
)
# Every byte any _UTF8_CHAR can contain. Runs of these are found first (a
# single byte class is several times faster than the alternation); the exact
# pattern then only runs inside them. A valid run never crosses a byte outside
# this class, so this finds exactly the same runs.
_UTF8_BYTE_CLASS = rb"[\t\n\r\x20-\x7E\x80-\xBF\xC2-\xF4]"
_UTF16_UNIT_BYTE = rb"[\t\n\r\x20-\x7E\xA0-\xFF]"
_NON_ASCII = re.compile(rb"[\x80-\xFF]")


@dataclass(frozen=True, slots=True)
class StringHit:
    offset: int     # absolute offset of the first byte in the scanned data
    length: int     # length in bytes
    encoding: str   # one of the ENCODING_* values
    value: str      # the run decoded exactly, nothing trimmed or replaced

    @property
    def end(self) -> int:
        return self.offset + self.length


_CODECS = {
    ENCODING_ASCII: "ascii",
    ENCODING_UTF8: "utf-8",
    ENCODING_UTF16LE: "utf-16-le",
    ENCODING_UTF16BE: "utf-16-be",
}


def scan_strings(data: Any, min_chars: int = DEFAULT_MIN_CHARS) -> list[StringHit]:
    """Every run in *data* (bytes, bytearray, memoryview or mmap) with at
    least *min_chars* characters, ordered by offset (then encoding)."""
    n = max(1, int(min_chars))
    hits: list[StringHit] = []

    candidates = re.compile(_UTF8_BYTE_CLASS + rb"{%d,}" % n)
    utf8 = re.compile(rb"(?:" + _UTF8_CHAR + rb"){%d,}" % n)
    for candidate in candidates.finditer(data):
        chunk = candidate.group()
        base = candidate.start()
        for match in utf8.finditer(chunk):
            raw = match.group()
            encoding = ENCODING_UTF8 if _NON_ASCII.search(raw) else ENCODING_ASCII
            hits.append(StringHit(base + match.start(), len(raw), encoding, raw.decode(_CODECS[encoding])))

    for pattern, encoding in (
        (rb"(?:" + _UTF16_UNIT_BYTE + rb"\x00){%d,}", ENCODING_UTF16LE),
        (rb"(?:\x00" + _UTF16_UNIT_BYTE + rb"){%d,}", ENCODING_UTF16BE),
    ):
        for match in re.compile(pattern % n).finditer(data):
            raw = match.group()
            hits.append(StringHit(match.start(), len(raw), encoding, raw.decode(_CODECS[encoding])))
    order = {e: i for i, e in enumerate(_CODECS)}
    hits.sort(key=lambda h: (h.offset, order[h.encoding]))
    return hits
