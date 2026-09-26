# SPDX-License-Identifier: Apache-2.0
"""Multi-Log Studio: Crush's own markers in log cells ("(no zone)",
"(guessed)", "— (not decoded)") are shown in the UI language; the TSV copy
writes them in English, like an export. Log levels are the log's values."""
from __future__ import annotations

from datetime import datetime, timezone

import crush.viewers.generated_text as gen_module
from crush.core.log_ts import TS_NO_ZONE, TS_UNPARSED
from crush.viewers.multi_log_viewer import _fmt_ts, _level_display


def _fake_translation(monkeypatch) -> None:
    monkeypatch.setattr(
        gen_module, "translate",
        lambda context, text, *a: f"«{text}»" if context == "GeneratedView" else text,
    )


def test_markers_translated_on_screen_english_in_copy(monkeypatch) -> None:
    _fake_translation(monkeypatch)
    dt = datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)

    assert _fmt_ts(dt, flags=TS_NO_ZONE) == "2024-07-16 18:35:04« (no zone)»"
    assert _fmt_ts(dt, flags=TS_NO_ZONE, english=True) == "2024-07-16 18:35:04 (no zone)"
    assert _fmt_ts(None, flags=TS_UNPARSED) == "«— (not decoded)»"
    assert _fmt_ts(None, flags=TS_UNPARSED, english=True) == "— (not decoded)"

    assert _level_display("ERROR", "error") == "«ERROR (guessed)»"
    assert _level_display("ERROR", "error", english=True) == "ERROR (guessed)"
    assert _level_display("WARN", "") == "WARN"  # the log's own level, never translated
