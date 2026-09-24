# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Log parser — detects and parses common log file formats.

Not registered in the auto-detection pipeline (can_parse always returns False).
Used by Multi-Log Studio.

Supported formats:
  - JSON Lines  (each line is a JSON object with timestamp+message keys)
  - Android logcat  (MM-DD HH:MM:SS.mmm  PID  TID  L  tag: message)
  - Syslog RFC 3164  (Mon DD HH:MM:SS host process[pid]: message)
  - Generic  (ISO-8601 / common timestamp at start of line)
  - Plain text  (raw lines, no structure recognised)

Plain-text logs carry no format marker, so choosing among these is a
heuristic: every candidate is scored against every non-empty line, the
first one (in the order above) whose share of matching lines reaches its
threshold wins, and all scores are reported in the metadata. The analyst
can override the choice (LogParser.parse(..., log_format=...)).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Callable

from crush.core.issues import ParseIssue
from crush.core.log_ts import (
    PLACEHOLDER_YEAR,
    TS_NO_YEAR,
    TS_NO_ZONE,
    TS_UNPARSED,
    epoch_ts,
    join_flags,
    parse_iso_ts,
)
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

# ---------------------------------------------------------------------------
# Normalised log entry keys
# ---------------------------------------------------------------------------
# Each entry is a plain dict:
#   timestamp : datetime | None
#   level     : str  (ERROR / WARN / INFO / DEBUG / TRACE / UNKNOWN)
#   process   : str  (tag, process name, or "")
#   message   : str
#   raw       : str  (original line, for copy/export)
#   ts_flags  : str  (crush.core.log_ts TS_* tokens: what the log didn't record)


_LEVEL_MAP: dict[str, str] = {
    # JSON / generic keywords
    "error": "ERROR", "err": "ERROR", "fatal": "ERROR", "critical": "ERROR",
    "warn": "WARN",   "warning": "WARN",
    "info": "INFO",   "information": "INFO", "notice": "INFO",
    "debug": "DEBUG", "dbg": "DEBUG", "verbose": "DEBUG",
    "trace": "TRACE",
    # logcat single-char codes
    "e": "ERROR", "f": "ERROR",
    "w": "WARN",
    "i": "INFO",
    "d": "DEBUG",
    "v": "TRACE",
    "s": "TRACE",
}

def _normalise_level(raw: str) -> str:
    return _LEVEL_MAP.get(raw.strip().lower(), "UNKNOWN")


# ---------------------------------------------------------------------------
# Timestamp parsers -- each returns (datetime | None, ts_flags)
# ---------------------------------------------------------------------------

_ISO_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_EPOCH_RE = re.compile(r"^(\d{10,13}(?:\.\d+)?)")  # unix seconds or ms
# ctime() / asctime(): "Sun Jul 28 07:57:00 2024"
_CTIME_RE = re.compile(
    r"^([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})"
)

_SYSLOG_LEVEL_KEYWORDS = (
    ("ERROR", "ERROR"), ("WARN", "WARN"), ("CRIT", "ERROR"),
    ("NOTICE", "INFO"), ("INFO", "INFO"), ("DEBUG", "DEBUG"),
)

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def _parse_ctime(s: str) -> tuple[datetime | None, str]:
    """Parse ctime/asctime: 'Sun Jul 28 07:57:00 2024' (locale-independent,
    no zone recorded)."""
    parts = s.strip().split()
    if len(parts) != 5:
        return None, TS_UNPARSED
    mon = _MONTHS.get(parts[1])
    if mon is None:
        return None, TS_UNPARSED
    try:
        day = int(parts[2])
        h, m, sec = (int(x) for x in parts[3].split(":"))
        dt = datetime(int(parts[4]), mon, day, h, m, sec, tzinfo=timezone.utc)
    except ValueError:
        return None, TS_UNPARSED
    return dt, TS_NO_ZONE


def _entry(
    ts: tuple[datetime | None, str], level: str, process: str, message: str, raw: str,
    level_note: str = "",
) -> dict[str, Any]:
    return {"timestamp": ts[0], "ts_flags": ts[1], "level": level,
            "level_note": level_note, "process": process, "message": message, "raw": raw}


def _guess_inline_level(text: str) -> tuple[str, str]:
    """Level for formats without a level field, guessed from keywords in
    *text* (a heuristic). Returns (level, level_note): the note lists every
    keyword found, leftmost first -- the one used."""
    found = list(dict.fromkeys(m.upper() for m in _LEVEL_INLINE_RE.findall(text)))
    if not found:
        return "UNKNOWN", ""
    return _normalise_level(found[0]), ", ".join(found)


_NO_TS: tuple[datetime | None, str] = (None, "")


def _unmatched(line: str, message: str | None = None) -> dict[str, Any]:
    return _entry(_NO_TS, "UNKNOWN", "", line if message is None else message, line)


# ---------------------------------------------------------------------------
# Format: JSON Lines
# ---------------------------------------------------------------------------

# Common field names used by popular logging frameworks, in priority order —
# tuples, not sets: when a line has more than one candidate key (e.g. both
# "ts" and "timestamp"), the first match here must win deterministically.
# A set's iteration order depends on string hashing, which is randomised per
# process (PYTHONHASHSEED) — the same file could silently parse to a
# different timestamp/level on two separate runs of the tool.
_TS_KEYS   = ("timestamp", "ts", "time", "@timestamp", "date", "datetime", "t")
_MSG_KEYS  = ("message", "msg", "text", "body", "log", "event", "m")
_LVL_KEYS  = ("level", "lvl", "severity", "sev", "loglevel", "log_level", "l")
_PROC_KEYS = ("logger", "name", "source", "component", "service", "tag",
              "process", "caller", "module")
# Membership-only union for excluding structural keys from the message
# fallback (order doesn't matter here, so a real set is fine and faster).
_STRUCTURAL_KEYS = frozenset(_TS_KEYS) | frozenset(_LVL_KEYS) | frozenset(_PROC_KEYS)


def _is_json_object_line(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except (json.JSONDecodeError, ValueError):
        return False


def _parse_json_lines(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            entries.append(_unmatched(line))
            continue
        if not isinstance(obj, dict):
            entries.append(_unmatched(line, str(obj)))
            continue

        # -- timestamp --
        ts: tuple[datetime | None, str] = _NO_TS
        ts_raw = ""
        for k in _TS_KEYS:
            if k in obj:
                ts_raw = str(obj[k])
                break
        if ts_raw:
            ts = (None, TS_UNPARSED)
            m = _ISO_RE.search(ts_raw)
            if m:
                ts = parse_iso_ts(m.group(1))
            if ts[0] is None:
                m2 = _EPOCH_RE.match(ts_raw)
                if m2:
                    ts = epoch_ts(m2.group(1))

        # -- level --
        lvl_raw = ""
        for k in _LVL_KEYS:
            if k in obj:
                lvl_raw = str(obj[k])
                break
        level = _normalise_level(lvl_raw) if lvl_raw else "UNKNOWN"

        # -- process --
        proc = ""
        for k in _PROC_KEYS:
            if k in obj:
                proc = str(obj[k])
                break

        # -- message --
        msg = ""
        for k in _MSG_KEYS:
            if k in obj:
                msg = str(obj[k])
                break
        if not msg:
            # fallback: join all non-structural string values
            msg = " ".join(
                str(v) for k, v in obj.items()
                if k not in _STRUCTURAL_KEYS
            )

        entries.append(_entry(ts, level, proc, msg, line))
    return entries


# ---------------------------------------------------------------------------
# Format: Android logcat
# ---------------------------------------------------------------------------
# Brief format: MM-DD HH:MM:SS.mmm  PID  TID  L  tag: message
_LOGCAT_RE = re.compile(
    r"^(\d{2}-\d{2})\s+"           # month-day
    r"(\d{2}:\d{2}:\d{2}\.\d+)\s+" # time
    r"\d+\s+\d+\s+"                 # PID  TID
    r"([A-Z])\s+"                   # level char
    r"([^:]+):\s*"                  # tag
    r"(.*)"                         # message
)


def _parse_logcat(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        m = _LOGCAT_RE.match(line)
        if not m:
            entries.append(_unmatched(line))
            continue
        md, time_str, lvl_char, tag, msg = m.groups()
        # logcat records neither a year nor a zone.
        dt, flags = parse_iso_ts(f"{PLACEHOLDER_YEAR}-{md} {time_str}")
        ts = (dt, join_flags(flags, TS_NO_YEAR) if dt is not None else flags)
        entries.append(_entry(ts, _normalise_level(lvl_char), tag.strip(), msg, line))
    return entries


# ---------------------------------------------------------------------------
# Format: Syslog RFC 3164
# ---------------------------------------------------------------------------
# Jan  1 00:00:00 hostname process[pid]: message
_SYSLOG_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+"  # month day
    r"(\d{2}:\d{2}:\d{2})\s+"           # time
    r"(\S+)\s+"                          # hostname
    r"([^\[:]+)(?:\[\d+\])?:\s*"         # process[pid]
    r"(.*)"                              # message
)


def _parse_syslog(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        m = _SYSLOG_RE.match(line)
        if not m:
            entries.append(_unmatched(line))
            continue
        mon_str, day_str, time_str, _host, proc, msg = m.groups()
        mon = _MONTHS.get(mon_str)
        # RFC 3164 records neither a year nor a zone: the year is a
        # placeholder, never the year of the analysis machine's clock.
        ts: tuple[datetime | None, str] = (None, TS_UNPARSED)
        if mon is not None:
            dt, flags = parse_iso_ts(
                f"{PLACEHOLDER_YEAR}-{mon:02d}-{int(day_str):02d} {time_str}"
            )
            ts = (dt, join_flags(flags, TS_NO_YEAR) if dt is not None else flags)
        # RFC 3164 files carry no severity (the <PRI> is stripped when
        # syslogd writes them): guessed from keywords at the message start,
        # first in this list wins; every keyword found is kept as the note.
        upper_msg = msg.upper()[:20]
        found = [(kw, lv) for kw, lv in _SYSLOG_LEVEL_KEYWORDS if kw in upper_msg]
        level = found[0][1] if found else "UNKNOWN"
        note = ", ".join(kw for kw, _lv in found)
        entries.append(_entry(ts, level, proc.strip(), msg, line, note))
    return entries


# ---------------------------------------------------------------------------
# Format: Generic  (ISO-8601 or epoch at line start)
# ---------------------------------------------------------------------------
_GENERIC_TS_RE = re.compile(
    r"^(?:"
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"  # ISO
    r"|"
    r"(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"  # MM/dd/YY HH:MM:SS.ms
    r"|"
    r"(\d{10,13}(?:\.\d+)?)"  # epoch
    r")\s*"
)
_LEVEL_INLINE_RE = re.compile(
    r"\b(ERROR|ERR|FATAL|CRITICAL|WARN|WARNING|INFO|NOTICE|DEBUG|TRACE|VERBOSE)\b",
    re.IGNORECASE,
)


def _is_generic_start(line: str) -> bool:
    """Return True if line begins a new log event (has a timestamp prefix)."""
    return bool(_GENERIC_TS_RE.match(line) or _CTIME_RE.match(line))


def _group_events(lines: list[str], is_start: Any) -> list[list[str]]:
    """Group raw lines into events.

    A new event starts whenever is_start(line) is True.
    Continuation lines (no timestamp) are appended to the current event.
    Lines that arrive before the first event start are each their own group.
    """
    groups: list[list[str]] = []
    current: list[str] = []
    for raw in lines:
        line = raw.rstrip("\n\r")
        if not line.strip():
            continue
        if is_start(line):
            if current:
                groups.append(current)
            current = [line]
        else:
            if current:
                current.append(line)
            else:
                groups.append([line])   # pre-header lines → own entry
    if current:
        groups.append(current)
    return groups


def _parse_generic(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for group in _group_events(lines, _is_generic_start):
        first = group[0]
        ts: tuple[datetime | None, str] = _NO_TS
        remainder = first
        cm = _CTIME_RE.match(first)
        if cm:
            ts = _parse_ctime(cm.group(1))
            remainder = first[cm.end():]
        else:
            m = _GENERIC_TS_RE.match(first)
            if m:
                if m.group(1):
                    ts = parse_iso_ts(m.group(1))
                elif m.group(2):
                    ts = parse_iso_ts(m.group(2))
                else:
                    ts = epoch_ts(m.group(3))
                remainder = first[m.end():]

        level, level_note = _guess_inline_level(remainder[:60])

        if len(group) > 1:
            message = remainder.strip() + "\n" + "\n".join(group[1:])
        else:
            message = remainder.strip()

        entries.append(_entry(ts, level, "", message, "\n".join(group), level_note))
    return entries


# ---------------------------------------------------------------------------
# Fallback: raw lines
# ---------------------------------------------------------------------------

def _fallback(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        level, level_note = _guess_inline_level(line[:80])
        entries.append(_entry(_NO_TS, level, "", line, line, level_note))
    return entries


# ---------------------------------------------------------------------------
# Format detection (heuristic)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogFormat:
    key: str
    name: str
    # Line-level test for scoring; None for the plain-text fallback.
    matches: Callable[[str], bool] | None
    parse: Callable[[list[str]], list[dict[str, Any]]]
    # Detection threshold: share of non-empty lines that must match, or,
    # for "generic", an absolute count (multi-line events skew a share).
    min_share: float | None = None
    min_count: int | None = None


# Detection order matters: the first format reaching its threshold wins.
LOG_FORMATS: tuple[LogFormat, ...] = (
    LogFormat("jsonl", "JSON Lines", _is_json_object_line, _parse_json_lines, min_share=0.6),
    LogFormat("logcat", "Android logcat", lambda ln: bool(_LOGCAT_RE.match(ln)),
              _parse_logcat, min_share=0.5),
    LogFormat("syslog", "Syslog (RFC 3164)", lambda ln: bool(_SYSLOG_RE.match(ln)),
              _parse_syslog, min_share=0.5),
    LogFormat("generic", "Generic (timestamp-prefixed)", _is_generic_start,
              _parse_generic, min_count=2),
    LogFormat("plain", "Plain text (no structure detected)", None, _fallback),
)
_BY_KEY = {f.key: f for f in LOG_FORMATS}


def score_formats(lines: list[str]) -> tuple[dict[str, int], int]:
    """Matching-line count per candidate format over all non-empty lines,
    plus the number of non-empty lines."""
    non_empty = [ln.rstrip("\n\r") for ln in lines if ln.strip()]
    scores = {
        f.key: sum(1 for ln in non_empty if f.matches(ln))
        for f in LOG_FORMATS if f.matches is not None
    }
    return scores, len(non_empty)


def _meets_threshold(f: LogFormat, scores: dict[str, int], total: int) -> bool:
    if f.matches is None:
        return True
    hits = scores[f.key]
    if f.min_share is not None:
        return bool(total) and hits / total >= f.min_share
    return f.min_count is not None and hits >= f.min_count


def _pick_format(scores: dict[str, int], total: int) -> LogFormat:
    return next(f for f in LOG_FORMATS if _meets_threshold(f, scores, total))


def timestamp_notes(entries: list[dict[str, Any]]) -> list[ParseIssue]:
    counts = {TS_NO_ZONE: 0, TS_NO_YEAR: 0, TS_UNPARSED: 0}
    for e in entries:
        for flag in e.get("ts_flags", "").split():
            if flag in counts:
                counts[flag] += 1
    codes = {TS_NO_ZONE: "log.ts_no_zone", TS_NO_YEAR: "log.ts_no_year",
             TS_UNPARSED: "log.ts_unparsed"}
    return [ParseIssue(codes[f], {"count": n}) for f, n in counts.items() if n]


# ---------------------------------------------------------------------------
# LogParser
# ---------------------------------------------------------------------------

class LogParser(AbstractParser):
    """Explicit-only log file parser.

    can_parse() always returns False — this parser is never selected
    automatically. Multi-Log Studio calls it directly.
    """

    DISPLAY_NAME = "Log file"
    SUPPORTED_EXTENSIONS: list[str] = []

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False

    def parse(
        self, node: VFSNode, vfs: VFS, log_format: str | None = None,
    ) -> ParseResult:
        """*log_format*: a LOG_FORMATS key chosen by the analyst; None
        detects it (heuristic, see module docstring)."""
        raw = vfs.read(node)
        encoding_issue: ParseIssue | None = None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            text = raw.decode("utf-8", errors="replace")
            encoding_issue = ParseIssue(
                "log.not_utf8", {"offset": exc.start}, detail=exc.reason,
            )

        lines = text.splitlines(keepends=False)
        scores, total = score_formats(lines)
        if log_format is not None:
            fmt = _BY_KEY[log_format]
            format_issue = ParseIssue("log.format_selected", {"name": fmt.name})
        else:
            fmt = _pick_format(scores, total)
            format_issue = ParseIssue("log.format_detected", {"name": fmt.name})
        entries = fmt.parse(lines)

        ts_count = sum(1 for e in entries if e["timestamp"] is not None)
        metadata: dict[str, Any] = {
            "File size": f"{node.size:,} B",
            "Log format": format_issue,
            "Format candidates": [
                ParseIssue("log.format_score", {
                    "name": f.name, "hits": scores[f.key], "total": total,
                })
                for f in LOG_FORMATS if f.matches is not None
            ],
            "Detection rule": ParseIssue("log.detection_rule"),
            "Total entries": str(len(entries)),
            "Entries with timestamp": str(ts_count),
        }
        if fmt.matches is not None and fmt.key != "generic":
            unmatched = total - scores[fmt.key]
            if unmatched:
                metadata["Lines not matching the format"] = ParseIssue(
                    "log.lines_unmatched", {"count": unmatched},
                )
        notes = timestamp_notes(entries)
        if notes:
            metadata["Timestamp notes"] = notes
        guessed = sum(1 for e in entries if e.get("level_note"))
        if guessed:
            metadata["Level"] = ParseIssue("log.level_guessed", {"count": guessed})
        if encoding_issue is not None:
            metadata["Encoding"] = encoding_issue

        text_index = " ".join(e["message"] for e in entries[:500])

        return ParseResult(
            viewer_type="log",
            data=entries,
            metadata=metadata,
            text_index=text_index,
        )
