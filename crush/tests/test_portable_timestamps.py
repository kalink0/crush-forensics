# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Unix-seconds display must be UTC and identical on every OS.

datetime.fromtimestamp() calls the platform C library: Windows rejects
negative and far-future values that Linux/Mac accept, and without tz= it
converts to the examiner's local time. Every site goes through
ts_decode.unix_to_utc (epoch + timedelta) instead.
"""
from __future__ import annotations

import math
import time
from datetime import datetime, timezone

import pytest
from PySide6.QtWidgets import QLabel

from crush.core.log_db import _unix_to_ts
from crush.core.ts_decode import unix_to_utc
from crush.parsers.proto_interp import _fmt_ts as proto_fmt_ts
from crush.ui.props_panel import PropertiesPanel
from crush.ui.search_panel import _fmt_ts as search_fmt_ts

_TOO_BIG = 1e13  # seconds -> beyond year 9999


class TestUnixToUtc:
    def test_zero_is_the_epoch(self) -> None:
        assert unix_to_utc(0) == datetime(1970, 1, 1, tzinfo=timezone.utc)

    def test_negative_is_pre_1970(self) -> None:
        assert unix_to_utc(-86400) == datetime(1969, 12, 31, tzinfo=timezone.utc)

    def test_fraction_kept(self) -> None:
        dt = unix_to_utc(1.5)
        assert dt is not None and dt.microsecond == 500_000

    def test_result_is_utc_aware(self) -> None:
        dt = unix_to_utc(1_705_314_225)
        assert dt is not None and dt.tzinfo is timezone.utc

    @pytest.mark.parametrize("value", [_TOO_BIG, -_TOO_BIG, math.inf, -math.inf, math.nan])
    def test_unrepresentable_is_none(self, value: float) -> None:
        assert unix_to_utc(value) is None


class TestSearchPanelTimestamp:
    def test_utc_labelled(self) -> None:
        assert search_fmt_ts(1_705_314_225) == "2024-01-15 10:23:45 UTC"

    def test_none_means_missing(self) -> None:
        assert search_fmt_ts(None) == ""

    def test_zero_is_the_epoch(self) -> None:
        assert search_fmt_ts(0) == "1970-01-01 00:00:00 UTC"

    def test_negative_is_shown(self) -> None:
        assert search_fmt_ts(-1) == "1969-12-31 23:59:59 UTC"

    def test_out_of_range_keeps_raw_value(self) -> None:
        assert search_fmt_ts(_TOO_BIG) == f"{_TOO_BIG} (out of range)"

    @pytest.mark.skipif(not hasattr(time, "tzset"), reason="time.tzset is Unix-only")
    def test_independent_of_local_time_zone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TZ", "Pacific/Kiritimati")  # UTC+14
        time.tzset()
        try:
            assert search_fmt_ts(1_705_314_225) == "2024-01-15 10:23:45 UTC"
        finally:
            monkeypatch.undo()
            time.tzset()


class TestPropertiesPanelTimestamp:
    def _text(self, value: float | None) -> str:
        panel = PropertiesPanel()
        panel._add_timestamp("Modified", value)
        labels = [
            panel._layout.itemAt(i).widget()
            for i in range(panel._layout.count())
            if isinstance(panel._layout.itemAt(i).widget(), QLabel)
        ]
        return labels[-1].text()

    def test_utc_labelled(self, qapp) -> None:
        assert self._text(1_705_314_225) == "2024-01-15 10:23:45 UTC"

    def test_none_means_missing(self, qapp) -> None:
        assert self._text(None) == "—"

    def test_zero_is_the_epoch(self, qapp) -> None:
        assert self._text(0) == "1970-01-01 00:00:00 UTC"

    def test_negative_is_shown(self, qapp) -> None:
        assert self._text(-1) == "1969-12-31 23:59:59 UTC"

    def test_out_of_range_keeps_raw_value(self, qapp) -> None:
        assert self._text(_TOO_BIG) == f"{_TOO_BIG} (out of range)"


class TestOtherSites:
    def test_proto_interp_utc(self) -> None:
        assert proto_fmt_ts(1_705_314_225) == "2024-01-15 10:23:45 UTC"

    def test_proto_interp_out_of_range_keeps_raw_value(self) -> None:
        assert proto_fmt_ts(_TOO_BIG) == f"{_TOO_BIG}"

    def test_log_db_round_trips_pre_1970(self) -> None:
        assert _unix_to_ts(-86400) == datetime(1969, 12, 31, tzinfo=timezone.utc)

    def test_log_db_none_stays_none(self) -> None:
        assert _unix_to_ts(None) is None
