# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Unit tests for multi_log_parser — CustomFormatProfile, CustomFormatParser, helpers."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from crush.core.log_ts import parse_iso_ts
from crush.parsers.multi_log_parser import (
    CustomFormatParser,
    CustomFormatProfile,
    _group_events,
    _normalise_level,
)


def _parse_iso_fallback(s: str) -> datetime | None:
    return parse_iso_ts(s)[0]


# ---------------------------------------------------------------------------
# _normalise_level
# ---------------------------------------------------------------------------

class TestNormaliseLevel:
    @pytest.mark.parametrize("raw,expected", [
        ("error",    "ERROR"),
        ("ERROR",    "ERROR"),
        ("err",      "ERROR"),
        ("fatal",    "ERROR"),
        ("critical", "ERROR"),
        ("E",        "ERROR"),
        ("F",        "ERROR"),
        ("warn",     "WARN"),
        ("warning",  "WARN"),
        ("W",        "WARN"),
        ("info",     "INFO"),
        ("information", "INFO"),
        ("notice",   "INFO"),
        ("I",        "INFO"),
        ("debug",    "DEBUG"),
        ("dbg",      "DEBUG"),
        ("verbose",  "DEBUG"),
        ("D",        "DEBUG"),
        ("trace",    "TRACE"),
        ("V",        "TRACE"),
        ("unknown_level", "UNKNOWN"),
        ("",         "UNKNOWN"),
    ])
    def test_mapping(self, raw: str, expected: str) -> None:
        assert _normalise_level(raw) == expected

    def test_strips_whitespace(self) -> None:
        assert _normalise_level("  warn  ") == "WARN"


# ---------------------------------------------------------------------------
# _parse_iso_fallback
# ---------------------------------------------------------------------------

class TestParseIsoFallback:
    def test_full_with_microseconds(self) -> None:
        dt = _parse_iso_fallback("2024-07-16 18:35:04.469449")
        assert dt == datetime(2024, 7, 16, 18, 35, 4, 469449, tzinfo=timezone.utc)

    def test_without_microseconds(self) -> None:
        dt = _parse_iso_fallback("2024-07-16 18:35:04")
        assert dt == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)

    def test_z_suffix_stripped(self) -> None:
        dt = _parse_iso_fallback("2024-07-16T18:35:04.000Z")
        assert dt is not None
        assert dt.year == 2024

    def test_t_separator_normalised(self) -> None:
        dt = _parse_iso_fallback("2024-07-16T18:35:04")
        assert dt == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)

    def test_comma_as_decimal_separator(self) -> None:
        dt = _parse_iso_fallback("2024-07-16 18:35:04,123456")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_slash_format(self) -> None:
        dt = _parse_iso_fallback("07/16/24 18:35:04.000000")
        assert dt is not None
        assert dt.month == 7 and dt.day == 16

    def test_invalid_returns_none(self) -> None:
        assert _parse_iso_fallback("not-a-date") is None

    def test_empty_returns_none(self) -> None:
        assert _parse_iso_fallback("") is None


# ---------------------------------------------------------------------------
# _group_events
# ---------------------------------------------------------------------------

class TestGroupEvents:
    def _starts_with_date(self, line: str) -> bool:
        return bool(line[:4].isdigit())

    def test_single_line_events(self) -> None:
        lines = ["2024-01-01 first", "2024-01-02 second"]
        groups = _group_events(lines, self._starts_with_date)
        assert len(groups) == 2
        assert groups[0] == ["2024-01-01 first"]

    def test_multiline_event_grouped(self) -> None:
        lines = ["2024-01-01 start", "  continuation", "  more"]
        groups = _group_events(lines, self._starts_with_date)
        assert len(groups) == 1
        assert groups[0] == ["2024-01-01 start", "  continuation", "  more"]

    def test_blank_lines_skipped(self) -> None:
        lines = ["2024-01-01 first", "", "  ", "2024-01-02 second"]
        groups = _group_events(lines, self._starts_with_date)
        assert len(groups) == 2

    def test_pre_start_lines_become_individual_groups(self) -> None:
        lines = ["orphan line", "2024-01-01 start"]
        groups = _group_events(lines, self._starts_with_date)
        assert len(groups) == 2
        assert groups[0] == ["orphan line"]

    def test_empty_input(self) -> None:
        assert _group_events([], self._starts_with_date) == []


# ---------------------------------------------------------------------------
# CustomFormatProfile — serialisation round-trip
# ---------------------------------------------------------------------------

class TestCustomFormatProfile:
    def test_round_trip(self) -> None:
        p = CustomFormatProfile(
            name="test",
            parse_pattern=r"(?P<timestamp>\S+) (?P<level>\w+) (?P<message>.*)",
            timestamp_format="%Y-%m-%d",
            level_default="INFO",
        )
        assert CustomFormatProfile.from_dict(p.to_dict()) == p

    def test_from_dict_defaults(self) -> None:
        p = CustomFormatProfile.from_dict({})
        assert p.name == "Unnamed"
        assert p.level_default == "UNKNOWN"
        assert p.parse_pattern == ""


# ---------------------------------------------------------------------------
# CustomFormatParser.parse_lines — core parsing logic
# ---------------------------------------------------------------------------

SIMPLE_PATTERN = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<message>.*)"


class TestCustomFormatParserParseLinesBasic:
    def _parser(self, **kw: object) -> CustomFormatParser:
        return CustomFormatParser(CustomFormatProfile(
            name="test",
            parse_pattern=SIMPLE_PATTERN,
            **kw,  # type: ignore[arg-type]
        ))

    def test_single_matching_line(self) -> None:
        parser = self._parser()
        entries = parser.parse_lines(["2024-07-16 18:35:04 ERROR something broke"])
        assert len(entries) == 1
        e = entries[0]
        assert e["level"] == "ERROR"
        assert e["message"] == "something broke"
        assert e["timestamp"] == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)

    def test_level_normalisation_applied(self) -> None:
        parser = self._parser()
        entries = parser.parse_lines(["2024-07-16 18:35:04 warn low disk"])
        assert entries[0]["level"] == "WARN"

    def test_no_match_falls_back(self) -> None:
        parser = self._parser()
        entries = parser.parse_lines(["this line does not match"])
        assert len(entries) == 1
        assert entries[0]["level"] == "UNKNOWN"
        assert entries[0]["message"] == "this line does not match"
        assert entries[0]["timestamp"] is None

    def test_blank_lines_ignored(self) -> None:
        parser = self._parser()
        entries = parser.parse_lines(["", "  ", "2024-07-16 18:35:04 INFO ok"])
        assert len(entries) == 1

    def test_multiple_lines(self) -> None:
        parser = self._parser()
        lines = [
            "2024-07-16 18:35:04 ERROR boom",
            "2024-07-16 18:35:05 INFO fine",
        ]
        entries = parser.parse_lines(lines)
        assert len(entries) == 2
        assert entries[1]["level"] == "INFO"

    def test_custom_strptime_format(self) -> None:
        pattern = r"(?P<timestamp>\d{2}/\d{2}/\d{4}) (?P<level>\w+) (?P<message>.*)"
        parser = CustomFormatParser(CustomFormatProfile(
            name="slash",
            parse_pattern=pattern,
            timestamp_format="%d/%m/%Y",
        ))
        entries = parser.parse_lines(["16/07/2024 INFO all good"])
        ts = entries[0]["timestamp"]
        assert ts is not None
        assert ts.day == 16 and ts.month == 7 and ts.year == 2024

    def test_level_map_used_when_provided(self) -> None:
        parser = CustomFormatParser(CustomFormatProfile(
            name="mapped",
            parse_pattern=SIMPLE_PATTERN,
            level_map={"ERROR": "ERROR", "warn": "WARN", "V": "TRACE"},
            level_default="INFO",
        ))
        entries = parser.parse_lines(["2024-07-16 18:35:04 warn mapped level"])
        assert entries[0]["level"] == "WARN"

    def test_level_map_unknown_falls_to_default(self) -> None:
        parser = CustomFormatParser(CustomFormatProfile(
            name="mapped",
            parse_pattern=SIMPLE_PATTERN,
            level_map={"ERROR": "ERROR"},
            level_default="INFO",
        ))
        entries = parser.parse_lines(["2024-07-16 18:35:04 trace not in map"])
        assert entries[0]["level"] == "INFO"

    def test_extra_named_groups_captured(self) -> None:
        pattern = r"(?P<timestamp>\S+ \S+) \[(?P<subsystem>\w+)\] (?P<level>\w+) (?P<message>.*)"
        parser = CustomFormatParser(CustomFormatProfile(
            name="extra",
            parse_pattern=pattern,
        ))
        entries = parser.parse_lines(["2024-07-16 18:35:04 [kernel] INFO booted"])
        assert entries[0]["extra"]["subsystem"] == "kernel"

    def test_no_pattern_returns_raw_entry(self) -> None:
        parser = CustomFormatParser(CustomFormatProfile(name="empty", parse_pattern=""))
        entries = parser.parse_lines(["any line"])
        assert len(entries) == 1
        assert entries[0]["message"] == "any line"


class TestCustomFormatParserMultiline:
    def test_multiline_event_joined(self) -> None:
        pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<message>.*)"
        parser = CustomFormatParser(CustomFormatProfile(
            name="ml",
            parse_pattern=pattern,
            line_start_pattern=r"\d{4}-\d{2}-\d{2}",
        ))
        lines = [
            "2024-07-16 18:35:04 ERROR first line",
            "  stack frame 1",
            "  stack frame 2",
            "2024-07-16 18:35:05 INFO next event",
        ]
        entries = parser.parse_lines(lines)
        assert len(entries) == 2
        assert "stack frame 1" in entries[0]["message"]
        assert "stack frame 2" in entries[0]["message"]
        assert entries[1]["message"] == "next event"

    def test_no_line_start_pattern_each_line_is_own_entry(self) -> None:
        parser = CustomFormatParser(CustomFormatProfile(
            name="single",
            parse_pattern=SIMPLE_PATTERN,
        ))
        lines = ["2024-07-16 18:35:04 INFO a", "2024-07-16 18:35:05 INFO b"]
        entries = parser.parse_lines(lines)
        assert len(entries) == 2
