"""Log parsing: what the log recorded (zone, year), format detection
transparency, analyst override, and explicit reasons (parser-reason audit)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from crush.core.log_db import LogDatabase
from crush.core.log_ts import (
    PLACEHOLDER_YEAR,
    TS_NO_YEAR,
    TS_NO_ZONE,
    TS_UNPARSED,
    epoch_ts,
    parse_iso_ts,
)
from crush.core.vfs import DirectoryVFS
from crush.parsers.log_parser import LogParser
from crush.parsers.multi_log_parser import CustomFormatParser, CustomFormatProfile


def _parse(tmp_path: Path, content: bytes, log_format: str | None = None) -> Any:
    (tmp_path / "x.log").write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "x.log")
    return LogParser().parse(node, vfs, log_format=log_format)


# -- timestamp decoding ---------------------------------------------------------

def test_offset_is_applied_not_dropped() -> None:
    dt, flags = parse_iso_ts("2024-07-16T18:35:04+02:00")
    assert dt == datetime(2024, 7, 16, 16, 35, 4, tzinfo=timezone.utc)
    assert flags == ""
    dt, flags = parse_iso_ts("2024-07-16 18:35:04.123456789 +0200")
    assert dt == datetime(2024, 7, 16, 16, 35, 4, 123456, tzinfo=timezone.utc)
    assert flags == ""


def test_zone_less_time_is_flagged_not_silently_utc() -> None:
    dt, flags = parse_iso_ts("2024-07-16 18:35:04")
    assert dt == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)
    assert flags == TS_NO_ZONE
    assert parse_iso_ts("2024-07-16T18:35:04Z")[1] == ""


def test_epoch_is_utc_and_undecodable_is_flagged() -> None:
    assert epoch_ts("1705316096") == (
        datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=1705316096), "",
    )
    assert parse_iso_ts("not-a-date") == (None, TS_UNPARSED)


# -- syslog / logcat: no year, no zone -----------------------------------------

def test_syslog_year_is_placeholder_never_the_clock_year(tmp_path: Path) -> None:
    lines = b"".join(
        b"Feb 29 10:00:0%d host proc[1]: msg %d\n" % (i, i) for i in range(3)
    )
    result = _parse(tmp_path, lines)
    entry = result.data[0]
    assert entry["timestamp"].year == PLACEHOLDER_YEAR  # Feb 29 survives
    assert set(entry["ts_flags"].split()) == {TS_NO_YEAR, TS_NO_ZONE}
    codes = [n.code for n in result.metadata["Timestamp notes"]]
    assert codes == ["log.ts_no_zone", "log.ts_no_year"]


def test_logcat_flags_missing_year_and_zone(tmp_path: Path) -> None:
    lines = b"".join(
        b"07-16 18:35:0%d.123  100  200 I Tag: hello\n" % i for i in range(3)
    )
    entry = _parse(tmp_path, lines).data[0]
    assert entry["timestamp"].year == PLACEHOLDER_YEAR
    assert set(entry["ts_flags"].split()) == {TS_NO_YEAR, TS_NO_ZONE}


# -- format detection transparency and override --------------------------------

def test_detection_scores_all_lines_and_reports_every_candidate(tmp_path: Path) -> None:
    # A long plain header used to hide the format when only the first 40
    # lines were sampled.
    header = b"".join(b"banner line %d\n" % i for i in range(60))
    body = b"".join(b"07-16 18:35:%02d.123  100  200 I Tag: m\n" % (i % 60) for i in range(200))
    result = _parse(tmp_path, header + body)

    fmt = result.metadata["Log format"]
    assert fmt.code == "log.format_detected"
    assert str(fmt) == "Android logcat (heuristic)"
    scores = {s.params["name"]: s.params["hits"] for s in result.metadata["Format candidates"]}
    assert scores == {
        "JSON Lines": 0, "Android logcat": 200, "Syslog (RFC 3164)": 0,
        "Generic (timestamp-prefixed)": 0,
    }
    assert all(s.params["total"] == 260 for s in result.metadata["Format candidates"])
    assert result.metadata["Detection rule"].code == "log.detection_rule"
    assert result.metadata["Lines not matching the format"].params["count"] == 60


def test_analyst_can_force_a_format(tmp_path: Path) -> None:
    lines = b"".join(b"07-16 18:35:0%d.123  100  200 I Tag: hello\n" % i for i in range(3))
    result = _parse(tmp_path, lines, log_format="plain")
    assert result.metadata["Log format"].code == "log.format_selected"
    assert str(result.metadata["Log format"]) == (
        "Plain text (no structure detected) (selected by analyst)"
    )
    assert all(e["timestamp"] is None for e in result.data)
    assert len(result.data) == 3


def test_log_not_utf8_is_reported(tmp_path: Path) -> None:
    result = _parse(tmp_path, b"2024-07-16 18:35:04 M\xfcller\n2024-07-16 18:35:05 ok\n")
    enc = result.metadata["Encoding"]
    assert enc.code == "log.not_utf8"
    assert enc.params["offset"] == 21


# -- custom format profiles ------------------------------------------------------

def test_custom_profile_keeps_offset_and_flags_zone_less() -> None:
    profile = CustomFormatProfile(
        name="p", parse_pattern=r"^(?P<timestamp>\S+) (?P<message>.*)$",
    )
    aware, naive, broken = CustomFormatParser(profile).parse_lines([
        "2024-07-16T18:35:04+02:00 a",
        "2024-07-16T18:35:04 b",
        "not-a-time c",
    ])
    assert aware["timestamp"] == datetime(2024, 7, 16, 16, 35, 4, tzinfo=timezone.utc)
    assert aware["ts_flags"] == ""
    assert naive["timestamp"] == datetime(2024, 7, 16, 18, 35, 4, tzinfo=timezone.utc)
    assert naive["ts_flags"] == TS_NO_ZONE
    assert broken["timestamp"] is None
    assert broken["ts_flags"] == TS_UNPARSED


# -- storage and display ------------------------------------------------------------

def test_ts_flags_survive_the_log_database() -> None:
    with LogDatabase() as db:
        db.insert_batch(0, [{
            "timestamp": datetime(1972, 2, 29, 10, 0, tzinfo=timezone.utc),
            "ts_flags": f"{TS_NO_ZONE} {TS_NO_YEAR}",
            "level": "INFO", "message": "m", "raw": "r",
        }])
        rows = db.fetch_by_rowids([1])
    assert rows[0][-2] == f"{TS_NO_ZONE} {TS_NO_YEAR}"


def test_display_never_converts_zone_less_time_or_invents_a_year(qapp) -> None:  # type: ignore[no-untyped-def]
    from crush.viewers.multi_log_viewer import _fmt_ts

    plus_two = timezone(timedelta(hours=2))
    dt = datetime(1972, 7, 16, 18, 35, 4, tzinfo=timezone.utc)
    assert _fmt_ts(dt, plus_two, TS_NO_ZONE) == "1972-07-16 18:35:04 (no zone)"
    assert _fmt_ts(dt, plus_two, f"{TS_NO_ZONE} {TS_NO_YEAR}") == (
        "????-07-16 18:35:04 (no zone)"
    )
    assert _fmt_ts(dt, plus_two, "") == "1972-07-16 20:35:04"
    assert _fmt_ts(None, plus_two, TS_UNPARSED) == "— (not decoded)"
    assert _fmt_ts(None, plus_two, "") == "—"


# -- Multi-Log Studio -----------------------------------------------------------

def test_worker_honours_analyst_format_and_passes_metadata(tmp_path: Path) -> None:
    from crush.viewers.multi_log_viewer import LogLoaderWorker

    (tmp_path / "x.log").write_bytes(b"07-16 18:35:01.123  100  200 I Tag: hello\n")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "x.log")
    finished: list[tuple[int, str, dict[str, Any]]] = []
    with LogDatabase() as db:
        worker = LogLoaderWorker(node, vfs, 7, db.path, log_format="plain")
        worker.load_finished.connect(lambda *a: finished.append(a))
        worker.run()  # synchronously, in this thread
    assert len(finished) == 1
    sid, fmt, metadata = finished[0]
    assert sid == 7
    assert fmt == "Plain text (no structure detected) (selected by analyst)"
    assert metadata["Log format"].code == "log.format_selected"


def test_studio_offers_every_builtin_format_and_shows_details(
    qapp, tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    from crush.parsers.log_parser import LOG_FORMATS
    from crush.viewers.multi_log_viewer import MultiLogViewer

    (tmp_path / "x.log").write_bytes(b"2024-07-16 18:35:04 hello\n2024-07-16 18:35:05 b\n")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "x.log")
    viewer = MultiLogViewer(node, vfs)
    for w in viewer._workers.values():
        w.wait(10_000)
    qapp.processEvents()

    viewer._populate_format_menu()
    sub = viewer._fmt_menu.actions()[0].menu()
    assert [a.text() for a in sub.actions()] == [f.name for f in LOG_FORMATS]
    assert viewer._fmt_menu.actions()[-1].text() == "Define custom format…"

    sid = next(iter(viewer._source_meta))
    details = viewer._source_details(sid)
    assert "Log format: Generic (timestamp-prefixed) (heuristic)" in details
    assert "Format candidates: JSON Lines 0/2" in details
    assert "no time zone in the log" in details
    assert f'href="{sid}"' in viewer._fmt_label.text()
    viewer.close()


# -- guessed levels and lossless copy --------------------------------------------

def test_guessed_level_is_marked_with_every_keyword(tmp_path: Path) -> None:
    result = _parse(tmp_path, (
        b"2024-07-16 18:35:04 WARN disk nearly full, ERROR soon\n"
        b"2024-07-16 18:35:05 all good\n"
    ))
    warn, plain = result.data
    assert warn["level"] == "WARN"
    assert warn["level_note"] == "WARN, ERROR"
    assert plain["level"] == "UNKNOWN" and plain["level_note"] == ""
    assert result.metadata["Level"].code == "log.level_guessed"
    assert result.metadata["Level"].params["count"] == 1


def test_recorded_level_is_not_marked_guessed(tmp_path: Path) -> None:
    lines = b"".join(b"07-16 18:35:0%d.123  100  200 E Tag: ERROR x\n" % i for i in range(3))
    result = _parse(tmp_path, lines)
    assert all(e["level"] == "ERROR" and e["level_note"] == "" for e in result.data)
    assert "Level" not in result.metadata


def test_level_note_survives_the_log_database() -> None:
    with LogDatabase() as db:
        db.insert_batch(0, [{"level": "WARN", "level_note": "WARN, ERROR", "message": "m"}])
        assert db.fetch_by_rowids([1])[0][-1] == "WARN, ERROR"


def test_level_and_tsv_display_helpers(qapp) -> None:  # type: ignore[no-untyped-def]
    from crush.viewers.multi_log_viewer import _level_display, _tsv_field

    assert _level_display("WARN", "WARN, ERROR") == "WARN (guessed)"
    assert _level_display("WARN", "") == "WARN"
    assert _tsv_field("a\tb\nc\\d") == "a\\tb\\nc\\\\d"


def test_copy_message_and_tsv_carry_the_full_multiline_message(
    qapp, tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    import time

    from crush.viewers.multi_log_viewer import MultiLogViewer

    (tmp_path / "x.log").write_bytes(
        b"2024-07-16 18:35:04 first line\n  second line\n  third line\n"
        b"2024-07-16 18:35:05 next\n"
    )
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "x.log")
    viewer = MultiLogViewer(node, vfs)
    for w in viewer._workers.values():
        w.wait(10_000)
    deadline = time.monotonic() + 10
    while viewer._model.rowCount() == 0 and time.monotonic() < deadline:
        qapp.processEvents()  # load_finished + the async sort worker
        time.sleep(0.01)
    row = next(r for r in range(viewer._model.rowCount())
               if "first line" in viewer._model.entry_at(r)["message"])

    # "Copy message" copies entry["message"] as is.
    assert viewer._model.entry_at(row)["message"] == "first line\n  second line\n  third line"
    tsv = viewer._rows_as_tsv([row])
    assert "\n" not in tsv
    assert tsv.endswith("first line\\n  second line\\n  third line")
    assert "more line" not in tsv
    viewer.close()


def test_closing_the_studio_waits_for_every_sort_worker(
    qapp, tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    """Superseded sort workers keep querying the log database; closing the
    studio must wait for all of them, not just the latest, or one opens the
    database after it has been closed ("disk I/O error" in the thread)."""
    from crush.viewers.multi_log_viewer import MultiLogViewer

    (tmp_path / "x.log").write_bytes(b"2024-07-16 18:35:04 hello\n2024-07-16 18:35:05 b\n")
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "x.log")
    viewer = MultiLogViewer(node, vfs)
    for w in viewer._workers.values():
        w.wait(10_000)
    qapp.processEvents()  # let the load finish on the main thread
    for _ in range(5):
        viewer._model._invalidate()
    started = list(viewer._model._sort_workers)
    assert len(started) >= 1
    viewer.close()
    assert not any(w.isRunning() for w in started)
    qapp.processEvents()  # late sort results must be dropped, not applied to the closed DB
