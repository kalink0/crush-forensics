# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Log parser — detects and parses common log file formats.

Not registered in the auto-detection pipeline (can_parse always returns False).
Invoked explicitly via the "Open as Log Viewer" context menu action.

Supported formats (auto-detected internally):
  - JSON Lines  (each line is a JSON object with timestamp+message keys)
  - Android logcat  (MM-DD HH:MM:SS.mmm  PID  TID  L  tag: message)
  - Syslog RFC 3164  (Mon DD HH:MM:SS host process[pid]: message)
  - Generic  (ISO-8601 / common timestamp at start of line)
  - Fallback  (raw lines, no structure recognised)
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

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

_SAMPLE_LINES = 40  # how many lines to inspect for format detection


def _normalise_level(raw: str) -> str:
    return _LEVEL_MAP.get(raw.strip().lower(), "UNKNOWN")


# ---------------------------------------------------------------------------
# Timestamp parsers
# ---------------------------------------------------------------------------

_ISO_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_EPOCH_RE = re.compile(r"^(\d{10,13}(?:\.\d+)?)")  # unix seconds or ms
# ctime() / asctime(): "Sun Jul 28 07:57:00 2024"
_CTIME_RE = re.compile(
    r"^([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})"
)


def _parse_iso(s: str) -> datetime | None:
    s = s.rstrip("Z").replace("T", " ").replace(",", ".")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%y %H:%M:%S.%f",   # MM/dd/YY HH:MM:SS.ms
        "%m/%d/%y %H:%M:%S",      # MM/dd/YY HH:MM:SS
    ):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


_CTIME_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def _parse_ctime(s: str) -> datetime | None:
    """Parse ctime/asctime: 'Sun Jul 28 07:57:00 2024' (locale-independent)."""
    # Split: ['Sun', 'Jul', '28', '07:57:00', '2024']
    parts = s.strip().split()
    if len(parts) != 5:
        return None
    try:
        mon = _CTIME_MONTHS.get(parts[1])
        if mon is None:
            return None
        day  = int(parts[2])
        h, m, sec = (int(x) for x in parts[3].split(":"))
        year = int(parts[4])
        return datetime(year, mon, day, h, m, sec, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _parse_epoch(s: str) -> datetime | None:
    try:
        val = float(s)
        if val > 1e12:
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc)
    except (ValueError, OSError):
        return None


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


def _try_json_lines(lines: list[str]) -> list[dict[str, Any]] | None:
    """Return parsed entries if ≥60 % of non-empty lines are JSON objects."""
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return None
    hits = 0
    for line in non_empty[:_SAMPLE_LINES]:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                hits += 1
        except (json.JSONDecodeError, ValueError):
            pass
    if hits / len(non_empty[:_SAMPLE_LINES]) < 0.6:
        return None

    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            entries.append({"timestamp": None, "level": "UNKNOWN",
                            "process": "", "message": line, "raw": line})
            continue
        if not isinstance(obj, dict):
            entries.append({"timestamp": None, "level": "UNKNOWN",
                            "process": "", "message": str(obj), "raw": line})
            continue

        # -- timestamp --
        ts: datetime | None = None
        ts_raw = ""
        for k in _TS_KEYS:
            if k in obj:
                ts_raw = str(obj[k])
                break
        if ts_raw:
            m = _ISO_RE.search(ts_raw)
            if m:
                ts = _parse_iso(m.group(1))
            if ts is None:
                m2 = _EPOCH_RE.match(ts_raw)
                if m2:
                    ts = _parse_epoch(m2.group(1))

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

        entries.append({"timestamp": ts, "level": level,
                        "process": proc, "message": msg, "raw": line})
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


def _try_logcat(lines: list[str]) -> list[dict[str, Any]] | None:
    sample = [ln for ln in lines[:_SAMPLE_LINES] if ln.strip()]
    hits = sum(1 for ln in sample if _LOGCAT_RE.match(ln))
    if not sample or hits / len(sample) < 0.5:
        return None

    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        m = _LOGCAT_RE.match(line)
        if not m:
            entries.append({"timestamp": None, "level": "UNKNOWN",
                            "process": "", "message": line, "raw": line})
            continue
        md, time_str, lvl_char, tag, msg = m.groups()
        ts_str = f"1970-{md} {time_str}"  # no year in logcat
        ts = _parse_iso(ts_str)
        entries.append({
            "timestamp": ts,
            "level": _normalise_level(lvl_char),
            "process": tag.strip(),
            "message": msg,
            "raw": line,
        })
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
_MONTHS = {m: i+1 for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])}


def _try_syslog(lines: list[str]) -> list[dict[str, Any]] | None:
    sample = [ln for ln in lines[:_SAMPLE_LINES] if ln.strip()]
    hits = sum(1 for ln in sample if _SYSLOG_RE.match(ln))
    if not sample or hits / len(sample) < 0.5:
        return None

    current_year = datetime.now().year
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n\r")
        if not line.strip():
            continue
        m = _SYSLOG_RE.match(line)
        if not m:
            entries.append({"timestamp": None, "level": "UNKNOWN",
                            "process": "", "message": line, "raw": line})
            continue
        mon_str, day_str, time_str, _host, proc, msg = m.groups()
        mon = _MONTHS.get(mon_str, 1)
        ts_str = f"{current_year}-{mon:02d}-{int(day_str):02d} {time_str}"
        ts = _parse_iso(ts_str)
        # Syslog has no severity field — try to detect from message start
        level = "UNKNOWN"
        upper_msg = msg.upper()
        for kw, lv in [("ERROR", "ERROR"), ("WARN", "WARN"), ("CRIT", "ERROR"),
                        ("NOTICE", "INFO"), ("INFO", "INFO"), ("DEBUG", "DEBUG")]:
            if kw in upper_msg[:20]:
                level = lv
                break
        entries.append({
            "timestamp": ts,
            "level": level,
            "process": proc.strip(),
            "message": msg,
            "raw": line,
        })
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


def _try_generic(lines: list[str]) -> list[dict[str, Any]] | None:
    sample = [ln for ln in lines[:_SAMPLE_LINES] if ln.strip()]
    # Use absolute count instead of percentage — multiline events skew the ratio
    hits = sum(1 for ln in sample if _is_generic_start(ln))
    if hits < 2:
        return None

    entries: list[dict[str, Any]] = []
    for group in _group_events(lines, _is_generic_start):
        first = group[0]
        ts: datetime | None = None
        remainder = first
        cm = _CTIME_RE.match(first)
        if cm:
            ts = _parse_ctime(cm.group(1))
            remainder = first[cm.end():]
        else:
            m = _GENERIC_TS_RE.match(first)
            if m:
                if m.group(1):
                    ts = _parse_iso(m.group(1))
                elif m.group(2):
                    ts = _parse_iso(m.group(2))
                else:
                    ts = _parse_epoch(m.group(3))
                remainder = first[m.end():]

        lv_m = _LEVEL_INLINE_RE.search(remainder[:60])
        level = _normalise_level(lv_m.group(1)) if lv_m else "UNKNOWN"

        if len(group) > 1:
            message = remainder.strip() + "\n" + "\n".join(group[1:])
        else:
            message = remainder.strip()

        entries.append({
            "timestamp": ts,
            "level": level,
            "process": "",
            "message": message,
            "raw": "\n".join(group),
        })
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
        lv_m = _LEVEL_INLINE_RE.search(line[:80])
        level = _normalise_level(lv_m.group(1)) if lv_m else "UNKNOWN"
        entries.append({
            "timestamp": None,
            "level": level,
            "process": "",
            "message": line,
            "raw": line,
        })
    return entries


# ---------------------------------------------------------------------------
# LogParser
# ---------------------------------------------------------------------------

class LogParser(AbstractParser):
    """Explicit-only log file parser.

    can_parse() always returns False — this parser is never selected
    automatically. It is invoked directly from the UI via
    "Open as Log Viewer".
    """

    DISPLAY_NAME = "Log file"
    SUPPORTED_EXTENSIONS: list[str] = []

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")

        lines = text.splitlines(keepends=False)

        entries: list[dict[str, Any]] | None = None
        detected_format = "Unknown"

        entries = _try_json_lines(lines)
        if entries is not None:
            detected_format = "JSON Lines"
        if entries is None:
            entries = _try_logcat(lines)
            if entries is not None:
                detected_format = "Android logcat"
        if entries is None:
            entries = _try_syslog(lines)
            if entries is not None:
                detected_format = "Syslog (RFC 3164)"
        if entries is None:
            entries = _try_generic(lines)
            if entries is not None:
                detected_format = "Generic (timestamp-prefixed)"
        if entries is None:
            entries = _fallback(lines)
            detected_format = "Plain text (no structure detected)"

        ts_count = sum(1 for e in entries if e["timestamp"] is not None)
        metadata: dict[str, Any] = {
            "File size": f"{node.size:,} B",
            "Log format": detected_format,
            "Total entries": str(len(entries)),
            "Entries with timestamp": str(ts_count),
        }

        text_index = " ".join(e["message"] for e in entries[:500])

        return ParseResult(
            viewer_type="log",
            data=entries,
            metadata=metadata,
            text_index=text_index,
        )
