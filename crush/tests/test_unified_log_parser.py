# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Unit tests for unified_log_parser and log_db."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from crush.parsers import unified_log_parser as ulp
from crush.parsers.unified_log_parser import (
    _ANSI_RE,
    UnifiedLogConverter,
    _entry_from_mandiant_csv,
    _entry_from_mandiant_json,
    _extract_message_entries,
    _normalise_ul_level,
    _parse_ul_timestamp,
    _path_basename,
    try_unified_log,
)


# ---------------------------------------------------------------------------
# Timestamp parser
# ---------------------------------------------------------------------------

class TestParseUlTimestamp:
    def test_iso8601_z_nanoseconds(self) -> None:
        dt = _parse_ul_timestamp("2024-01-15T10:23:45.123456789Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.tzinfo is not None

    def test_iso8601_space_offset(self) -> None:
        dt = _parse_ul_timestamp("2024-01-15 10:23:45.123456-0700")
        assert dt is not None
        assert dt.year == 2024

    def test_empty_returns_none(self) -> None:
        assert _parse_ul_timestamp("") is None

    def test_invalid_returns_none(self) -> None:
        assert _parse_ul_timestamp("not-a-date") is None

    def test_colon_in_offset_normalised(self) -> None:
        dt = _parse_ul_timestamp("2024-06-01T08:00:00.000000+02:00")
        assert dt is not None
        assert dt.year == 2024

    def test_csv_format_space_before_tz(self) -> None:
        # unifiedlog_iterator CSV output: space before timezone offset
        dt = _parse_ul_timestamp("2024-01-15 10:23:45.123456789 +0000")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15


# ---------------------------------------------------------------------------
# Level normalisation
# ---------------------------------------------------------------------------

class TestNormaliseLevel:
    @pytest.mark.parametrize("raw,expected", [
        ("Default", "INFO"),
        ("default", "INFO"),
        ("Info",    "INFO"),
        ("Debug",   "DEBUG"),
        ("Error",   "ERROR"),
        ("Fault",   "ERROR"),
        ("Notice",  "INFO"),
        ("Warn",    "WARN"),
        ("warning", "WARN"),
        ("garbage", "UNKNOWN"),
        ("",        "UNKNOWN"),
    ])
    def test_mapping(self, raw: str, expected: str) -> None:
        assert _normalise_ul_level(raw) == expected


# ---------------------------------------------------------------------------
# Path basename helper
# ---------------------------------------------------------------------------

class TestPathBasename:
    def test_unix_path(self) -> None:
        assert _path_basename("/usr/sbin/sshd") == "sshd"

    def test_empty(self) -> None:
        assert _path_basename("") == ""

    def test_filename_only(self) -> None:
        assert _path_basename("kernel") == "kernel"


# ---------------------------------------------------------------------------
# message_entries extraction
# ---------------------------------------------------------------------------

class TestExtractMessageEntries:
    def test_public_entries_joined(self) -> None:
        obj: dict[str, Any] = {
            "message_entries": [
                {"message_type": "Public", "message_strings": "hello"},
                {"message_type": "Public", "message_strings": "world"},
            ]
        }
        result = _extract_message_entries(obj)
        assert result == "hello | world"

    def test_private_entry_prefixed(self) -> None:
        obj: dict[str, Any] = {
            "message_entries": [
                {"message_type": "Private", "message_strings": "secret123"},
            ]
        }
        result = _extract_message_entries(obj)
        assert result == "[private] secret123"

    def test_sensitive_entry_prefixed(self) -> None:
        obj: dict[str, Any] = {
            "message_entries": [
                {"message_type": "Sensitive", "message_strings": "tok"},
            ]
        }
        result = _extract_message_entries(obj)
        assert result == "[sensitive] tok"

    def test_mixed_types(self) -> None:
        obj: dict[str, Any] = {
            "message_entries": [
                {"message_type": "literal",  "message_strings": "User:"},
                {"message_type": "Private",  "message_strings": "alice"},
            ]
        }
        result = _extract_message_entries(obj)
        assert result == "User: | [private] alice"

    def test_empty_message_strings_skipped(self) -> None:
        obj: dict[str, Any] = {
            "message_entries": [
                {"message_type": "Public", "message_strings": ""},
                {"message_type": "Public", "message_strings": "ok"},
            ]
        }
        assert _extract_message_entries(obj) == "ok"

    def test_no_entries_returns_empty(self) -> None:
        assert _extract_message_entries({}) == ""
        assert _extract_message_entries({"message_entries": []}) == ""


# ---------------------------------------------------------------------------
# Mandiant JSON → entry dict
# ---------------------------------------------------------------------------

class TestEntryFromMandiantJson:
    def _base(self) -> dict[str, Any]:
        return {
            "timestamp":     "2024-03-10T14:00:00.000000000Z",
            "log_type":      "Default",
            "event_type":    "logEvent",
            "process":       "/usr/sbin/sshd",
            "pid":           "1234",
            "euid":          "0",
            "subsystem":     "com.apple.security",
            "category":      "networking",
            "thread_id":     255,
            "activity_id":   1024,
            "library":       "/usr/lib/libssl.dylib",
            "boot_uuid":     "AABBCCDD-1234-5678-ABCD-001122334455",
            "timezone_name": "UTC",
            "message":       "Connection established",
            "message_entries": [],
        }

    def test_standard_fields(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["level"]   == "INFO"
        assert entry["process"] == "sshd"
        assert entry["pid"]     == "1234"
        assert entry["message"] == "Connection established"

    def test_timestamp_parsed(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert isinstance(entry["timestamp"], datetime)
        assert entry["timestamp"].year == 2024

    def test_event_type_in_extra(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["event_type"] == "logEvent"

    def test_euid_in_extra(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["euid"] == "0"

    def test_subsystem_and_category_in_extra(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["subsystem"] == "com.apple.security"
        assert entry["extra"]["category"]  == "networking"

    def test_thread_id_hex(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["thread_id"] == hex(255)

    def test_activity_id_hex(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["activity_id"] == hex(1024)

    def test_sender_basename(self) -> None:
        entry = _entry_from_mandiant_json(self._base())
        assert entry["extra"]["sender"] == "libssl.dylib"

    def test_unknown_message_falls_back_to_entries(self) -> None:
        obj = self._base()
        obj["message"] = "Unknown shared string message"
        obj["message_entries"] = [
            {"message_type": "Public", "message_strings": "raw fragment"},
        ]
        entry = _entry_from_mandiant_json(obj)
        assert "[partial]" in entry["message"]
        assert "raw fragment" in entry["message"]

    def test_loss_event_gets_warn_and_message(self) -> None:
        obj = self._base()
        obj["log_type"]   = ""
        obj["event_type"] = "lossEvent"
        obj["message"]    = ""
        entry = _entry_from_mandiant_json(obj)
        assert entry["level"] == "WARN"
        assert "loss event" in entry["message"].lower()
        assert entry["extra"]["event_type"] == "lossEvent"

    def test_boot_relative_timestamp_is_none(self) -> None:
        obj = self._base()
        obj["timestamp"] = "1970-01-01T00:00:01.000000000Z"
        entry = _entry_from_mandiant_json(obj)
        assert entry["timestamp"] is None

    def test_boot_relative_timestamp_preserved_in_extra(self) -> None:
        """The excluded pre-2000 value must not be lost — it's kept visible
        (a genuinely tampered/reset clock would also produce a pre-2000
        timestamp, and that's evidence, not noise to discard)."""
        obj = self._base()
        obj["timestamp"] = "1970-01-01T00:00:01.000000000Z"
        obj["time"] = 1_000_000_000
        entry = _entry_from_mandiant_json(obj)
        assert entry["extra"]["excluded_timestamp"].startswith("1970-01-01")
        assert entry["extra"]["boot_time_ns"] == "1000000000"

    def test_private_message_entry_annotated(self) -> None:
        obj = self._base()
        obj["message"] = "Unknown shared string message"
        obj["message_entries"] = [
            {"message_type": "Private", "message_strings": "pw=hunter2"},
        ]
        entry = _entry_from_mandiant_json(obj)
        assert "[private]" in entry["message"]
        assert "hunter2" in entry["message"]


class TestEntryFromMandiantCsv:
    def test_boot_relative_timestamp_preserved_in_extra(self) -> None:
        """Same exclusion as the JSON path (see TestEntryFromMandiantJson);
        the CSV row has no raw nanosecond field, so only excluded_timestamp
        is available here, but it must still not be silently dropped."""
        row = {
            "Timestamp": "1970-01-01 00:00:01.000000-0000",
            "Log Type": "Default",
            "Process": "/usr/sbin/sshd",
            "Message": "hello",
        }
        entry = _entry_from_mandiant_csv(row)
        assert entry["timestamp"] is None
        assert entry["extra"]["excluded_timestamp"].startswith("1970-01-01")


# ---------------------------------------------------------------------------
# ANSI stripping regex
# ---------------------------------------------------------------------------

class TestAnsiRe:
    def test_strips_color_codes(self) -> None:
        raw = "\x1b[33m[WARN]\x1b[0m something"
        assert _ANSI_RE.sub("", raw) == "[WARN] something"

    def test_no_ansi_unchanged(self) -> None:
        raw = "[WARN] plain text"
        assert _ANSI_RE.sub("", raw) == raw


# ---------------------------------------------------------------------------
# UnifiedLogConverter — configurable temp directory
# ---------------------------------------------------------------------------

class TestUnifiedLogConverterTempDir:
    def test_defaults_to_none(self) -> None:
        assert UnifiedLogConverter()._temp_dir is None

    def test_blank_string_treated_as_none(self) -> None:
        assert UnifiedLogConverter(temp_dir="")._temp_dir is None

    def test_stream_entries_creates_tmp_dir_under_configured_base(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The single-file branch of stream_entries() must pass the configured
        base through to tempfile.mkdtemp(), not fall back to the OS default."""
        real_mkdtemp = ulp.tempfile.mkdtemp
        captured: dict[str, Any] = {}

        def fake_mkdtemp(*, prefix: str, dir: str | None = None) -> str:
            captured["dir"] = dir
            return real_mkdtemp(prefix=prefix, dir=dir)

        monkeypatch.setattr(ulp.tempfile, "mkdtemp", fake_mkdtemp)
        monkeypatch.setattr(UnifiedLogConverter, "_select_binary", lambda self: __file__)

        converter = UnifiedLogConverter(temp_dir=str(tmp_path))
        node = type("Node", (), {"is_dir": False, "name": "x.tracev3"})()
        gen = converter.stream_entries(node, vfs=None)  # type: ignore[arg-type]
        with pytest.raises(AttributeError):
            next(gen)  # fails reading from vfs=None, after mkdtemp already ran

        assert captured["dir"] == str(tmp_path)


# ---------------------------------------------------------------------------
# try_unified_log — format detection
# ---------------------------------------------------------------------------

class TestTryUnifiedLog:
    def test_detects_json_array(self) -> None:
        lines = [
            '[',
            '{"timestamp":"2024-01-01 10:00:00.000000+0000","messageType":"Default",'
            '"eventMessage":"hello","subsystem":"com.apple.test","category":"test",'
            '"processImagePath":"/usr/bin/foo","processID":42,"threadID":1}',
            ']',
        ]
        result = try_unified_log(lines)
        assert result is not None
        entries, fmt = result
        assert "JSON" in fmt
        assert entries[0]["message"] == "hello"

    def test_detects_ndjson(self) -> None:
        line = (
            '{"timestamp":"2024-01-01 10:00:00.000000+0000","messageType":"Error",'
            '"eventMessage":"boom","subsystem":"com.apple.x","category":"y",'
            '"processImagePath":"/bin/bar","processID":1,"threadID":2}'
        )
        result = try_unified_log([line])
        assert result is not None
        entries, fmt = result
        assert "NDJSON" in fmt
        assert entries[0]["level"] == "ERROR"

    def test_detects_text_format(self) -> None:
        lines = [
            "2024-01-15 10:23:45.123456-0700 0x2f4b  Default  0x0  1234  0  sshd: (libsys) Msg",
        ]
        result = try_unified_log(lines)
        assert result is not None
        entries, fmt = result
        assert "text" in fmt.lower()
        assert entries[0]["process"] == "sshd"

    def test_returns_none_for_unrelated(self) -> None:
        lines = ["this is just a plain text line", "no timestamp here"]
        assert try_unified_log(lines) is None


# ---------------------------------------------------------------------------
# LogDatabase — schema + insert + fetch
# ---------------------------------------------------------------------------

class TestLogDatabase:
    def test_insert_and_count(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            entries = [
                {
                    "timestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "level":   "INFO",
                    "process": "sshd",
                    "pid":     "1",
                    "message": "hello",
                    "raw":     "raw",
                    "extra":   {"subsystem": "com.apple.security", "category": "net"},
                },
                {
                    "timestamp": datetime(2024, 1, 2, tzinfo=timezone.utc),
                    "level":   "ERROR",
                    "process": "kernel",
                    "pid":     "0",
                    "message": "panic",
                    "raw":     "raw2",
                    "extra":   {},
                },
            ]
            db.insert_batch(0, entries)
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO", "ERROR"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="",
            )
            assert db.count(fspec) == 2

    def test_subsystem_category_stored_as_columns(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [{
                "timestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "level": "INFO", "process": "p", "pid": "1",
                "message": "m", "raw": "r",
                "extra": {"subsystem": "com.apple.test", "category": "auth"},
            }])
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="",
            )
            rowids = db.fetch_sorted_rowids(fspec, "ts_unix", True)
            rows = db.fetch_by_rowids(rowids)
            # tuple: rowid, source_id, ts_unix, level, process, pid, message, subsystem, category
            assert len(rows) == 1
            assert rows[0][7] == "com.apple.test"
            assert rows[0][8] == "auth"

    def test_text_search_on_subsystem(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [
                {
                    "timestamp": None, "level": "INFO", "process": "p",
                    "pid": "1", "message": "msg", "raw": "r",
                    "extra": {"subsystem": "com.apple.security", "category": ""},
                },
                {
                    "timestamp": None, "level": "INFO", "process": "q",
                    "pid": "2", "message": "other", "raw": "r",
                    "extra": {},
                },
            ])
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="security",
            )
            assert db.count(fspec) == 1

    def test_text_search_on_category(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [
                {
                    "timestamp": None, "level": "INFO", "process": "p",
                    "pid": "1", "message": "msg", "raw": "r",
                    "extra": {"subsystem": "", "category": "networking"},
                },
                {
                    "timestamp": None, "level": "INFO", "process": "q",
                    "pid": "2", "message": "other", "raw": "r",
                    "extra": {},
                },
            ])
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="networking",
            )
            assert db.count(fspec) == 1

    def test_level_filter(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [
                {"timestamp": None, "level": "ERROR", "process": "p", "pid": "1",
                 "message": "e", "raw": "r", "extra": {}},
                {"timestamp": None, "level": "INFO",  "process": "p", "pid": "1",
                 "message": "i", "raw": "r", "extra": {}},
            ])
            fspec = FilterSpec(
                allowed_levels=frozenset(["ERROR"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="",
            )
            assert db.count(fspec) == 1

    def test_fetch_sorted_rowids_order(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [
                {"timestamp": datetime(2024, 1, 2, tzinfo=timezone.utc),
                 "level": "INFO", "process": "p", "pid": "1",
                 "message": "second", "raw": "r", "extra": {}},
                {"timestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                 "level": "INFO", "process": "p", "pid": "1",
                 "message": "first", "raw": "r", "extra": {}},
            ])
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="",
            )
            rowids = db.fetch_sorted_rowids(fspec, "ts_unix", order_asc=True)
            rows = db.fetch_by_rowids(rowids)
            assert rows[0][6] == "first"
            assert rows[1][6] == "second"

    def test_fetch_row_detail(self) -> None:
        from crush.core.log_db import FilterSpec, LogDatabase

        with LogDatabase() as db:
            db.insert_batch(0, [{
                "timestamp": None, "level": "INFO", "process": "p", "pid": "1",
                "message": "m", "raw": "original raw line",
                "extra": {"thread_id": "0xff"},
            }])
            fspec = FilterSpec(
                allowed_levels=frozenset(["INFO"]),
                hidden_source_ids=frozenset(),
                ts_from=None, ts_to=None, text="",
            )
            rowids = db.fetch_sorted_rowids(fspec, "ts_unix", True)
            detail = db.fetch_row_detail(rowids[0])
            assert detail is not None
            raw, extra = detail
            assert raw == "original raw line"
            assert extra["thread_id"] == "0xff"
