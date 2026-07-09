# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Unit tests for LogParser — format detection, timestamp parsing, multiline grouping."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crush.core.vfs import DirectoryVFS
from crush.parsers.log_parser import (
    LogParser,
    _parse_iso,
    _parse_ctime,
    _parse_epoch,
    _try_json_lines,
    _try_logcat,
    _try_syslog,
    _try_generic,
    _group_events,
)


# ---------------------------------------------------------------------------
# Timestamp parsers
# ---------------------------------------------------------------------------

class TestParseIso:
    def test_basic(self) -> None:
        dt = _parse_iso("2024-07-16 18:35:04")
        assert dt == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)

    def test_with_microseconds(self) -> None:
        dt = _parse_iso("2024-07-16 18:35:04.469449")
        assert dt is not None
        assert dt.microsecond == 469449

    def test_with_z_suffix(self) -> None:
        dt = _parse_iso("2024-07-16 18:35:04.469449Z")
        assert dt is not None
        assert dt.year == 2024

    def test_t_separator(self) -> None:
        dt = _parse_iso("2024-07-16T18:35:04")
        assert dt is not None
        assert dt.hour == 18

    def test_slash_format(self) -> None:
        dt = _parse_iso("07/16/24 18:35:04.123456")
        assert dt is not None
        assert dt.month == 7
        assert dt.day == 16

    def test_invalid_returns_none(self) -> None:
        assert _parse_iso("not-a-date") is None


class TestParseCtime:
    def test_double_digit_day(self) -> None:
        dt = _parse_ctime("Mon Jun 17 18:17:42 2024")
        assert dt == datetime(2024, 6, 17, 18, 17, 42, tzinfo=timezone.utc)

    def test_single_digit_day(self) -> None:
        dt = _parse_ctime("Sun Jul  7 07:57:00 2024")
        assert dt == datetime(2024, 7, 7, 7, 57, 0, tzinfo=timezone.utc)

    def test_locale_independent(self) -> None:
        # Must not fail on non-English locale systems
        dt = _parse_ctime("Wed Dec 25 00:00:00 2024")
        assert dt is not None
        assert dt.month == 12

    def test_invalid_month_returns_none(self) -> None:
        assert _parse_ctime("Mon Xyz 17 18:17:42 2024") is None

    def test_wrong_structure_returns_none(self) -> None:
        assert _parse_ctime("not a ctime string") is None


class TestParseEpoch:
    def test_seconds(self) -> None:
        dt = _parse_epoch("1705316096")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_milliseconds(self) -> None:
        dt = _parse_epoch("1705316096123")
        assert dt is not None

    def test_float(self) -> None:
        dt = _parse_epoch("1705316096.5")
        assert dt is not None


# ---------------------------------------------------------------------------
# Format detectors
# ---------------------------------------------------------------------------

class TestTryJsonLines:
    def test_detects_json_lines(self) -> None:
        lines = [
            '{"timestamp": "2024-01-15T12:00:00Z", "level": "info", "msg": "started"}',
            '{"timestamp": "2024-01-15T12:00:01Z", "level": "error", "msg": "failed"}',
        ] * 5
        entries = _try_json_lines(lines)
        assert entries is not None
        assert entries[0]["level"] == "INFO"
        assert entries[0]["message"] == "started"
        assert entries[0]["timestamp"] is not None

    def test_rejects_non_json(self) -> None:
        lines = ["2024-01-15 12:00:00 INFO plain log"] * 10
        assert _try_json_lines(lines) is None

    def test_epoch_timestamp(self) -> None:
        lines = ['{"ts": 1705316096, "level": "warn", "msg": "watch out"}'] * 5
        entries = _try_json_lines(lines)
        assert entries is not None
        assert entries[0]["level"] == "WARN"
        assert entries[0]["timestamp"] is not None

    def test_normalises_level(self) -> None:
        lines = ['{"timestamp": "2024-01-15T12:00:00Z", "level": "FATAL", "msg": "boom"}'] * 5
        entries = _try_json_lines(lines)
        assert entries is not None
        assert entries[0]["level"] == "ERROR"

    def test_ambiguous_keys_resolve_deterministically(self) -> None:
        """A line with more than one candidate key for the same field (e.g.
        both "ts" and "timestamp", both "level" and "severity") must always
        resolve to the same, well-defined priority key — not depend on
        Python's per-process string-hash randomisation, which is what a
        plain `set` (the previous implementation) would do: the same file
        could silently parse to a different timestamp/level across runs."""
        lines = [
            '{"ts": "2024-06-15T12:00:00Z", "timestamp": "2024-01-01T00:00:00Z", '
            '"severity": "ERROR", "level": "INFO", "msg": "m"}'
        ] * 5
        entries = _try_json_lines(lines)
        assert entries is not None
        assert entries[0]["timestamp"] is not None
        assert entries[0]["timestamp"].month == 1  # "timestamp" wins over "ts"
        assert entries[0]["level"] == "INFO"  # "level" wins over "severity"


class TestTryLogcat:
    _SAMPLE = (
        "07-16 18:35:04.469  1234  5678 E MyTag: something went wrong\n"
        "07-16 18:35:04.470  1234  5678 I MyTag: all good\n"
        "07-16 18:35:04.471  1234  5678 D MyTag: debug info\n"
    )

    def test_detects_logcat(self) -> None:
        lines = self._SAMPLE.splitlines() * 5
        entries = _try_logcat(lines)
        assert entries is not None
        assert entries[0]["level"] == "ERROR"
        assert entries[0]["process"] == "MyTag"

    def test_rejects_other_format(self) -> None:
        lines = ["2024-01-15 12:00:00 INFO plain log"] * 10
        assert _try_logcat(lines) is None


class TestTrySyslog:
    _SAMPLE = (
        "Jan 15 12:00:00 myhost kernel[0]: disk I/O error\n"
        "Jan 15 12:00:01 myhost sshd[1234]: accepted connection\n"
        "Jan 15 12:00:02 myhost cron[5678]: job started\n"
    )

    def test_detects_syslog(self) -> None:
        lines = self._SAMPLE.splitlines() * 5
        entries = _try_syslog(lines)
        assert entries is not None
        assert entries[0]["process"] == "kernel"
        assert entries[0]["timestamp"] is not None

    def test_rejects_other_format(self) -> None:
        lines = ["2024-01-15 12:00:00 INFO plain log"] * 10
        assert _try_syslog(lines) is None


class TestTryGeneric:
    def test_iso_timestamps(self) -> None:
        lines = [
            "2024-07-16 18:35:04.469449Z [104] userKeybagOpaqueData retrieval successful",
            "2024-07-16 18:35:05.000000Z [104] another event",
        ] * 3
        entries = _try_generic(lines)
        assert entries is not None
        assert entries[0]["timestamp"] is not None
        assert entries[0]["timestamp"].year == 2024

    def test_ctime_timestamps(self) -> None:
        lines = [
            "Mon Jun 17 18:17:42 2024 [53] <err> something failed",
            "Mon Jun 17 18:17:43 2024 [53] <info> recovered",
        ] * 3
        entries = _try_generic(lines)
        assert entries is not None
        assert entries[0]["timestamp"] == datetime(2024, 6, 17, 18, 17, 42, tzinfo=timezone.utc)

    def test_multiline_event_grouping(self) -> None:
        lines = [
            "2024-07-16 18:35:04Z [104] session attributes: {",
            "    key = value;",
            "    other = 123;",
            "}",
            "2024-07-16 18:35:05Z [104] done",
        ]
        entries = _try_generic(lines)
        assert entries is not None
        assert len(entries) == 2
        assert "key = value" in entries[0]["message"]
        assert "2 more line" in entries[0]["message"].split("\n")[0] or \
               "key = value" in entries[0]["message"]

    def test_bracket_preserved(self) -> None:
        lines = [
            "2024-07-16 18:35:04Z [104] (0x16d8c3000) message here",
            "2024-07-16 18:35:05Z [105] another",
        ]
        entries = _try_generic(lines)
        assert entries is not None
        assert "[104]" in entries[0]["message"]

    def test_requires_at_least_two_ts_lines(self) -> None:
        # Only 1 timestamp line → should not detect
        lines = ["2024-07-16 18:35:04Z only one"] + ["plain text"] * 30
        assert _try_generic(lines) is None

    def test_multiline_skews_not_ratio(self) -> None:
        # Simulate a log where multiline events mean only ~10% of lines have timestamps
        header = [
            "2024-07-16 18:35:04Z [104] event one: {",
        ] + ["    continuation line"] * 20 + [
            "2024-07-16 18:35:05Z [104] event two",
        ]
        entries = _try_generic(header)
        # Should still detect (2 ts lines) even though ratio is ~9%
        assert entries is not None
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# Multiline grouping helper
# ---------------------------------------------------------------------------

class TestGroupEvents:
    def test_groups_continuation_lines(self) -> None:
        lines = [
            "2024-01-15 12:00:00 event one",
            "  continuation of one",
            "  still one",
            "2024-01-15 12:00:01 event two",
        ]
        groups = _group_events(lines, lambda ln: ln.startswith("2024"))
        assert len(groups) == 2
        assert len(groups[0]) == 3
        assert len(groups[1]) == 1

    def test_pre_header_lines_become_own_entries(self) -> None:
        lines = [
            "# header comment",
            "2024-01-15 12:00:00 first event",
        ]
        groups = _group_events(lines, lambda ln: ln.startswith("2024"))
        assert len(groups) == 2
        assert groups[0] == ["# header comment"]


# ---------------------------------------------------------------------------
# LogParser integration (via VFS)
# ---------------------------------------------------------------------------

class TestLogParser:
    def _write_and_parse(self, tmp_path: Path, content: str) -> list[dict[str, Any]]:
        log_path = tmp_path / "test.log"
        log_path.write_text(content, encoding="utf-8")
        vfs = DirectoryVFS(tmp_path)
        root = vfs.root()
        node = next(c for c in root.children if c.name == "test.log")
        parser = LogParser()
        result = parser.parse(node, vfs)
        assert result.viewer_type == "log"
        assert isinstance(result.data, list)
        return result.data

    def test_can_parse_always_false(self) -> None:
        assert LogParser().can_parse("anything.log", b"") is False

    def test_parse_json_lines(self, tmp_path: Path) -> None:
        content = "\n".join([
            '{"timestamp": "2024-01-15T12:00:00Z", "level": "info", "msg": "ok"}',
        ] * 5)
        entries = self._write_and_parse(tmp_path, content)
        assert len(entries) == 5
        assert entries[0]["level"] == "INFO"

    def test_parse_generic_iso(self, tmp_path: Path) -> None:
        content = (
            "2024-07-16 18:35:04.469449Z [104] retrieval successful\n"
            "2024-07-16 18:35:05.000000Z [104] done\n"
        )
        entries = self._write_and_parse(tmp_path, content)
        assert len(entries) == 2
        assert entries[0]["timestamp"] is not None

    def test_parse_ctime(self, tmp_path: Path) -> None:
        content = (
            "Mon Jun 17 18:17:42 2024 [53] <err> error message\n"
            "Mon Jun 17 18:17:43 2024 [53] <info> info message\n"
        )
        entries = self._write_and_parse(tmp_path, content)
        assert len(entries) == 2
        assert entries[0]["timestamp"] == datetime(2024, 6, 17, 18, 17, 42, tzinfo=timezone.utc)

    def test_parse_multiline_event(self, tmp_path: Path) -> None:
        content = (
            "2024-07-16 18:35:04Z [104] session: {\n"
            "    key = value;\n"
            "}\n"
            "2024-07-16 18:35:05Z [104] done\n"
        )
        entries = self._write_and_parse(tmp_path, content)
        assert len(entries) == 2
        assert "key = value" in entries[0]["message"]

    def test_parse_fallback_no_crash(self, tmp_path: Path) -> None:
        content = "just some\nrandom text\nno timestamps here\n"
        entries = self._write_and_parse(tmp_path, content)
        assert len(entries) == 3
        for e in entries:
            assert e["timestamp"] is None

    def test_metadata_contains_format(self, tmp_path: Path) -> None:
        content = "\n".join([
            '{"timestamp": "2024-01-15T12:00:00Z", "level": "info", "msg": "ok"}',
        ] * 5)
        log_path = tmp_path / "test.log"
        log_path.write_text(content, encoding="utf-8")
        vfs = DirectoryVFS(tmp_path)
        root = vfs.root()
        node = next(c for c in root.children if c.name == "test.log")
        result = LogParser().parse(node, vfs)
        assert "Log format" in result.metadata
        assert "JSON" in result.metadata["Log format"]
