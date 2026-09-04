# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Apple Unified Log (OSLog) parser for Multi-Log Studio.

Supported input formats
-----------------------
1. JSON array   — ``log show --style json``
   The file is a single JSON array ``[{...}, ...]`` where every object
   contains Apple UL-specific keys like ``messageType`` and ``eventMessage``.

2. NDJSON       — ``log show --style ndjson``
   One JSON object per line (JSON Lines variant).  Detected by checking
   for UL-specific keys on the first few parsed objects.

3. Text default — ``log show`` (no --style flag)
   Space-aligned tabular output produced by the macOS ``log`` command:
   ``2024-01-15 10:23:45.123456-0700 0x2f4b Default 0x0 1234 0  Process: (Sender) Msg``

4. Binary       — ``.tracev3`` / ``.logarchive`` (converted via UnifiedLogConverter)
   Requires the platform-appropriate ``unifiedlog_iterator`` binary from
   Mandiant's macos-UnifiedLogs project (Apache 2.0) to be present under
   ``crush/bin/unifiedlog_iterator/``.

Standard field mapping
----------------------
timestamp  ← "timestamp" field / first column
level      ← "messageType"  (Default → INFO, Info → INFO,
                              Debug → DEBUG, Error → ERROR, Fault → ERROR)
process    ← last path component of "processImagePath" / process column
pid        ← "processID" / PID column (as str)
message    ← "eventMessage" / message column

Extra fields (stored in entry["extra"])
---------------------------------------
subsystem   ← "subsystem"
category    ← "category"
thread_id   ← "threadID" / thread hex value (str)
activity_id ← "activityIdentifier" / activity hex value (str)
sender      ← last path component of "senderImagePath"
"""
from __future__ import annotations

import concurrent.futures
import csv
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

if TYPE_CHECKING:
    from crush.core.vfs import VFS, VFSNode

_log = logging.getLogger("crush")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SAMPLE_LINES = 40

# Keys that are distinctive for Apple Unified Log JSON objects
_UL_JSON_KEYS = frozenset({"messageType", "eventMessage", "subsystem", "category"})

_UL_LEVEL_MAP: dict[str, str] = {
    "default": "INFO",
    "info":    "INFO",
    "debug":   "DEBUG",
    "error":   "ERROR",
    "fault":   "ERROR",
    "notice":  "INFO",
    "warn":    "WARN",
    "warning": "WARN",
}

# Header line emitted by `log show` before the data rows
_UL_HEADER_RE = re.compile(
    r"^Timestamp\s+Thread\s+Type\s+Activity", re.IGNORECASE
)

# Default text format:
# 2024-01-15 10:23:45.123456-0700 0x2f4b  Default  0x0  1234  0  Process: (Sender) Msg
_UL_TEXT_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})"  # 1 timestamp
    r"\s+(0x[0-9a-fA-F]+)"                  # 2 thread_id
    r"\s+(Default|Error|Fault|Debug|Info)"  # 3 message_type
    r"\s+(0x[0-9a-fA-F]+)"                  # 4 activity_id
    r"\s+(\d+)"                              # 5 pid
    r"\s+\d+"                                # ttl (ignored)
    r"\s+(.*)",                              # 6 rest: "Process: (Sender) Message"
    re.IGNORECASE,
)

# Dissect the "rest" column: "ProcessName: (SenderLib) Message body"
_UL_REST_RE = re.compile(
    r"^([^:(]+):\s*"         # 1 process name
    r"(?:\(([^)]*)\)\s*)?"   # 2 optional sender in parentheses
    r"(.*)",                  # 3 message
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_ul_level(raw: str) -> str:
    return _UL_LEVEL_MAP.get(raw.strip().lower(), "UNKNOWN")


def _path_basename(path: str) -> str:
    """Return last path component, e.g. '/usr/sbin/sshd' → 'sshd'."""
    return Path(path).name if path else ""


def _parse_ul_timestamp(s: str) -> datetime | None:
    """Parse Apple Unified Log timestamp.

    Handles both ``log show`` space-separated format and the ISO 8601 format
    produced by Mandiant's ``unifiedlog_iterator``:
      ``2024-01-15T10:23:45.123456789Z``   (T separator, Z suffix, nanoseconds)
      ``2024-01-15 10:23:45.123456-0700``  (space separator, UTC offset)
    """
    s = s.strip()
    if not s:
        return None
    # Normalise ISO 8601 → strptime-compatible:
    #   T  → space
    #   trailing Z → +0000
    #   colon in tz offset (+HH:MM) → +HHMM
    #   nanoseconds (9 digits) → truncate to microseconds (6 digits)
    s = s.replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1] + "+0000"
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)          # ns → µs
    s = re.sub(r"\s+([+-]\d)", r"\1", s)             # space before tz: "... .µs +0000" → "...+0000"
    s = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", s)  # +HH:MM → +HHMM
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    _log.debug("[UnifiedLog] Unrecognised timestamp format: %r", s)
    return None


def _entry_from_ul_json_obj(obj: dict[str, Any]) -> dict[str, Any]:
    """Convert one Apple Unified Log JSON object to the standard entry dict."""
    ts = _parse_ul_timestamp(str(obj.get("timestamp", "") or ""))
    level = _normalise_ul_level(str(obj.get("messageType", "") or ""))

    proc_path = str(obj.get("processImagePath", "") or obj.get("process", "") or "")
    process = _path_basename(proc_path) or str(obj.get("processID", ""))

    sender = _path_basename(str(obj.get("senderImagePath", "") or ""))
    pid = str(obj.get("processID", ""))
    message = str(obj.get("eventMessage", "") or obj.get("message", "") or "")

    extra: dict[str, str] = {}
    subsystem = str(obj.get("subsystem", "") or "")
    if subsystem:
        extra["subsystem"] = subsystem
    category = str(obj.get("category", "") or "")
    if category:
        extra["category"] = category
    thread_raw = obj.get("threadID")
    if thread_raw is not None:
        extra["thread_id"] = (
            hex(int(thread_raw)) if isinstance(thread_raw, int) else str(thread_raw)
        )
    act_raw = obj.get("activityIdentifier")
    if act_raw is not None:
        extra["activity_id"] = (
            hex(int(act_raw)) if isinstance(act_raw, int) else str(act_raw)
        )
    if sender:
        extra["sender"] = sender

    return {
        "timestamp": ts,
        "level":     level,
        "process":   process,
        "pid":       pid,
        "message":   message,
        "raw":       json.dumps(obj, default=str),
        "extra":     extra,
    }


# ---------------------------------------------------------------------------
# Format 1 — JSON array  (log show --style json)
# ---------------------------------------------------------------------------

def _try_unified_log_json(lines: list[str]) -> list[dict[str, Any]] | None:
    """Parse Apple Unified Log JSON array format.

    The file is one big JSON array.  Quick heuristic: first non-empty line is
    ``[`` or ``[{``.  Then we load the full text and verify that the objects
    contain Apple UL-specific keys before accepting.
    """
    stripped = [ln.strip() for ln in lines if ln.strip()]
    if not stripped:
        return None
    first = stripped[0]
    if not (first == "[" or first.startswith("[{")):
        return None

    text = "\n".join(lines)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, list) or not data:
        return None

    sample = [x for x in data[:20] if isinstance(x, dict)]
    if not sample:
        return None
    hits = sum(1 for obj in sample if _UL_JSON_KEYS & obj.keys())
    if hits / len(sample) < 0.5:
        return None

    return [_entry_from_ul_json_obj(obj) for obj in data if isinstance(obj, dict)]


# ---------------------------------------------------------------------------
# Format 2 — NDJSON  (log show --style ndjson)
# ---------------------------------------------------------------------------

def _try_unified_log_ndjson(lines: list[str]) -> list[dict[str, Any]] | None:
    """Parse Apple Unified Log NDJSON format (one JSON object per line).

    Distinguished from generic JSON Lines by requiring UL-specific keys
    on ≥50 % of the sampled objects.
    """
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return None
    if not non_empty[0].strip().startswith("{"):
        return None

    sample_objs: list[dict[str, Any]] = []
    for ln in non_empty[:_SAMPLE_LINES]:
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                sample_objs.append(obj)
        except (json.JSONDecodeError, ValueError):
            pass

    if not sample_objs:
        return None
    hits = sum(1 for obj in sample_objs if _UL_JSON_KEYS & obj.keys())
    if hits / len(sample_objs) < 0.5:
        return None

    entries: list[dict[str, Any]] = []
    for ln in non_empty:
        ln = ln.rstrip("\n\r")
        if not ln.strip():
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                entries.append(_entry_from_ul_json_obj(obj))
            else:
                entries.append({
                    "timestamp": None, "level": "UNKNOWN",
                    "process": "", "pid": "", "message": str(obj),
                    "raw": ln, "extra": {},
                })
        except (json.JSONDecodeError, ValueError):
            entries.append({
                "timestamp": None, "level": "UNKNOWN",
                "process": "", "pid": "", "message": ln,
                "raw": ln, "extra": {},
            })
    return entries or None


# ---------------------------------------------------------------------------
# Format 3 — Text default  (log show)
# ---------------------------------------------------------------------------

def _try_unified_log_text(lines: list[str]) -> list[dict[str, Any]] | None:
    """Parse Apple Unified Log default text output format.

    Matches the space-aligned columnar output produced by ``log show``:
      ``2024-01-15 10:23:45.123456-0700 0x2f4b Default 0x0 1234 0  sshd: (libsys...) Msg``

    The optional header line (``Timestamp  Thread  Type  Activity ...``) is skipped.
    """
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return None

    sample = [ln for ln in non_empty[:_SAMPLE_LINES] if not _UL_HEADER_RE.match(ln)]
    if not sample:
        return None

    hits = sum(1 for ln in sample if _UL_TEXT_RE.match(ln))
    if hits / len(sample) < 0.4:
        return None

    entries: list[dict[str, Any]] = []
    for line in non_empty:
        line = line.rstrip("\n\r")
        if not line.strip() or _UL_HEADER_RE.match(line):
            continue

        m = _UL_TEXT_RE.match(line)
        if not m:
            entries.append({
                "timestamp": None, "level": "UNKNOWN",
                "process": "", "pid": "", "message": line,
                "raw": line, "extra": {},
            })
            continue

        ts_str, thread_id, msg_type, activity_id, pid_str, rest = m.groups()
        ts = _parse_ul_timestamp(ts_str)
        level = _normalise_ul_level(msg_type)

        process = ""
        sender = ""
        message = rest.strip()
        rm = _UL_REST_RE.match(rest)
        if rm:
            process = (rm.group(1) or "").strip()
            sender = (rm.group(2) or "").strip()
            message = (rm.group(3) or "").strip()

        extra: dict[str, str] = {}
        if thread_id:
            extra["thread_id"] = thread_id
        if activity_id and activity_id != "0x0":
            extra["activity_id"] = activity_id
        if sender:
            extra["sender"] = sender

        entries.append({
            "timestamp": ts,
            "level":     level,
            "process":   process,
            "pid":       pid_str,
            "message":   message,
            "raw":       line,
            "extra":     extra,
        })

    return entries or None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def try_unified_log(lines: list[str]) -> tuple[list[dict[str, Any]], str] | None:
    """Try all three Apple Unified Log formats in priority order.

    Returns ``(entries, format_name)`` on success, ``None`` if no UL format
    was detected.  Called by ``LogParser`` during auto-detection.
    """
    result = _try_unified_log_json(lines)
    if result is not None:
        return result, "Apple Unified Log (JSON)"

    result = _try_unified_log_ndjson(lines)
    if result is not None:
        return result, "Apple Unified Log (NDJSON)"

    result = _try_unified_log_text(lines)
    if result is not None:
        return result, "Apple Unified Log (text)"

    return None


# ---------------------------------------------------------------------------
# Binary format — UnifiedLogConverter (Mandiant unifiedlog_iterator)
# ---------------------------------------------------------------------------

# Field names used in Mandiant's NDJSON output (differ from `log show` JSON)
_MANDIANT_LEVEL_MAP: dict[str, str] = {
    "default": "INFO",
    "info":    "INFO",
    "debug":   "DEBUG",
    "error":   "ERROR",
    "fault":   "ERROR",
    "notice":  "INFO",
    "warn":    "WARN",
    "warning": "WARN",
    "trace":   "TRACE",
}

# Maps (sys.platform, platform.machine()) → binary filename inside _BINARY_DIR
_PLATFORM_BINARY_MAP: dict[tuple[str, str], str] = {
    ("linux",  "x86_64"):  "unifiedlog_iterator-x86_64-unknown-linux-gnu",
    ("linux",  "aarch64"): "unifiedlog_iterator-aarch64-unknown-linux-gnu",
    ("darwin", "x86_64"):  "unifiedlog_iterator-x86_64-apple-darwin",
    ("darwin", "arm64"):   "unifiedlog_iterator-aarch64-apple-darwin",
    ("win32",  "AMD64"):   "unifiedlog_iterator-x86_64-pc-windows-msvc.exe",
    ("win32",  "x86_64"):  "unifiedlog_iterator-x86_64-pc-windows-msvc.exe",
}

def _resolve_binary_dir() -> Path:
    # PyInstaller extracts data files to sys._MEIPASS when frozen.
    # --add-data places the binary at _MEIPASS/crush/bin/unifiedlog_iterator/.
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "crush" / "bin" / "unifiedlog_iterator"  # type: ignore[attr-defined]
    return Path(__file__).parent.parent / "bin" / "unifiedlog_iterator"


_BINARY_DIR = _resolve_binary_dir()


def get_bundled_ul_version() -> str | None:
    """Version of the bundled unifiedlog_iterator, per VERSION.txt written by
    scripts/download_unifiedlog_binaries.py (or the CI download steps) next
    to the binaries. None if running from source without downloaded
    binaries.
    """
    version_file = _BINARY_DIR / "VERSION.txt"
    if not version_file.exists():
        return None
    return version_file.read_text().strip() or None


def is_unified_log_node(node: "VFSNode") -> bool:
    """Return True if the VFS node is a .tracev3 file or .logarchive directory."""
    name = node.name.lower()
    return name.endswith(".tracev3") or name.endswith(".logarchive")


_UNKNOWN_MSG = "Unknown shared string message"

# Timestamps before this date are treated as boot-relative (not real wall-clock)
_MIN_REAL_TS = datetime(2000, 1, 1, tzinfo=timezone.utc)


def _extract_message_entries(obj: dict[str, Any]) -> str:
    """Build a best-effort message from message_entries when the DSC is unavailable.

    The Mandiant iterator cannot resolve format strings from Apple's Dyld Shared
    Cache (DSC) when only a standalone .tracev3 file is provided.  The raw string
    fragments are still present in message_entries and are useful for forensics.

    Private/Sensitive entries are prefixed so analysts can spot potentially
    redacted-in-live-logs data that was captured in the binary acquisition.
    """
    entries = obj.get("message_entries")
    if not entries or not isinstance(entries, list):
        return ""
    parts: list[str] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        val = e.get("message_strings")
        if not val:
            continue
        msg_type = str(e.get("message_type", "")).lower()
        if msg_type in ("private", "sensitive"):
            parts.append(f"[{msg_type}] {val}")
        else:
            parts.append(str(val))
    return " | ".join(parts) if parts else ""


def _entry_from_mandiant_json(obj: dict[str, Any]) -> dict[str, Any]:
    """Map one Mandiant unifiedlog_iterator JSON object to a standard entry dict.

    Mandiant field names differ from those produced by ``log show --style json``
    (handled by ``_entry_from_ul_json_obj`` above).

    DSC / shared-string limitation
    --------------------------------
    When only a standalone .tracev3 file is parsed (without the full
    logarchive context), the iterator cannot resolve Apple DSC format strings.
    In that case message == _UNKNOWN_MSG and we fall back to message_entries.

    Boot-relative timestamps
    ------------------------
    Without a matching boot record the iterator outputs timestamps anchored to
    Unix epoch + boot_offset, which land near 1970 and would be misleading if
    shown as the entry's real wall-clock time — so a timestamp before
    2000-01-01 is not put in the Timestamp column. It is not discarded,
    though: a device with a tampered/reset clock could in principle produce a
    genuine pre-2000 wall-clock timestamp too, and that's exactly the kind of
    anomaly an examiner needs to see, not lose. The excluded value is always
    kept in extra["excluded_timestamp"] (plus the raw boot_offset nanoseconds
    in extra["boot_time_ns"] when available) so it stays visible either way.
    """
    ts_str = str(obj.get("timestamp", "") or "")
    ts = _parse_ul_timestamp(ts_str) if ts_str else None
    boot_relative = ts is not None and ts < _MIN_REAL_TS
    excluded_ts_iso = ts.isoformat() if boot_relative and ts is not None else None
    if boot_relative:
        ts = None

    log_type = str(obj.get("log_type", "") or "")
    level = _MANDIANT_LEVEL_MAP.get(log_type.lower(), "UNKNOWN")

    event_type = str(obj.get("event_type", "") or "")

    process_raw = str(obj.get("process", "") or "")
    process = _path_basename(process_raw) or process_raw

    pid = str(obj.get("pid", "") or "")

    message = str(obj.get("message", "") or "")
    if message == _UNKNOWN_MSG or not message:
        fallback = _extract_message_entries(obj)
        if fallback:
            message = f"[partial] {fallback}"
        elif not message:
            message = ""

    # lossEvent = buffer overflow gap in the log stream; make it visible
    if event_type.lower() == "lossevent" and not message:
        message = "[loss event — log entries missing due to buffer overflow]"
        if level == "UNKNOWN":
            level = "WARN"

    extra: dict[str, str] = {}

    if event_type:
        extra["event_type"] = event_type
    subsystem = str(obj.get("subsystem", "") or "")
    if subsystem:
        extra["subsystem"] = subsystem
    category = str(obj.get("category", "") or "")
    if category:
        extra["category"] = category
    euid = str(obj.get("euid", "") or "")
    if euid:
        extra["euid"] = euid
    thread_raw = obj.get("thread_id")
    if thread_raw is not None:
        extra["thread_id"] = (
            hex(int(thread_raw)) if isinstance(thread_raw, int) else str(thread_raw)
        )
    act_raw = obj.get("activity_id")
    if act_raw is not None:
        extra["activity_id"] = (
            hex(int(act_raw)) if isinstance(act_raw, int) else str(act_raw)
        )
    library = str(obj.get("library", "") or "")
    if library:
        extra["sender"] = _path_basename(library) or library
    boot_uuid = str(obj.get("boot_uuid", "") or "")
    if boot_uuid:
        extra["boot_uuid"] = boot_uuid
    tz_name = str(obj.get("timezone_name", "") or "")
    if tz_name:
        extra["timezone"] = tz_name
    if boot_relative:
        if excluded_ts_iso is not None:
            extra["excluded_timestamp"] = excluded_ts_iso
        time_ns = obj.get("time")
        if time_ns is not None:
            extra["boot_time_ns"] = str(int(time_ns))

    return {
        "timestamp": ts,
        "level":     level,
        "process":   process,
        "pid":       pid,
        "message":   message,
        "raw":       json.dumps(obj, default=str),
        "extra":     extra,
    }


def _export_dir_to_real_fs(node: "VFSNode", vfs: "VFS", target: Path) -> None:
    """Recursively extract a VFS directory node to a real filesystem path."""
    target.mkdir(parents=True, exist_ok=True)
    for child in node.children:
        child_target = target / child.name
        if child.is_dir:
            _export_dir_to_real_fs(child, vfs, child_target)
        else:
            child_target.parent.mkdir(parents=True, exist_ok=True)
            with vfs.open(child) as src, open(child_target, "wb") as dst:
                dst.write(src.read())


def _stream_mandiant_ndjson(path: Path) -> Generator[dict[str, Any], None, None]:
    """Yield standard entry dicts from a Mandiant-format NDJSON output file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n\r")
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield _entry_from_mandiant_json(obj)
                else:
                    yield {
                        "timestamp": None, "level": "UNKNOWN",
                        "process": "", "pid": "", "message": str(obj),
                        "raw": line, "extra": {},
                    }
            except (json.JSONDecodeError, ValueError):
                yield {
                    "timestamp": None, "level": "UNKNOWN",
                    "process": "", "pid": "", "message": line,
                    "raw": line, "extra": {},
                }


def _entry_from_mandiant_csv(row: dict[str, str]) -> dict[str, Any]:
    """Map one CSV row (from DictReader) to a standard entry dict.

    CSV columns produced by unifiedlog_iterator -f csv:
    Timestamp, Event Type, Log Type, Subsystem, Thread ID, PID, EUID,
    Library, Library UUID, Activity ID, Category, Process, Process UUID,
    Message, Raw Message, Boot UUID, System Timezone Name

    See _entry_from_mandiant_json's "Boot-relative timestamps" note: the same
    before-2000 exclusion applies here, and the excluded value is likewise
    kept, in extra["excluded_timestamp"], rather than discarded.
    """
    ts_str = row.get("Timestamp", "")
    ts = _parse_ul_timestamp(ts_str) if ts_str else None
    boot_relative = ts is not None and ts < _MIN_REAL_TS
    excluded_ts_iso = ts.isoformat() if boot_relative and ts is not None else None
    if boot_relative:
        ts = None

    log_type = row.get("Log Type", "")
    level = _MANDIANT_LEVEL_MAP.get(log_type.lower(), "UNKNOWN")

    event_type = row.get("Event Type", "")

    process_raw = row.get("Process", "")
    process = _path_basename(process_raw) or process_raw

    pid = row.get("PID", "")

    message = row.get("Message", "")
    raw_message = row.get("Raw Message", "")
    if message == _UNKNOWN_MSG or not message:
        if raw_message and raw_message != _UNKNOWN_MSG:
            message = f"[partial] {raw_message}"
        else:
            message = ""

    if event_type.lower() == "lossevent" and not message:
        message = "[loss event — log entries missing due to buffer overflow]"
        if level == "UNKNOWN":
            level = "WARN"

    extra: dict[str, str] = {}

    if event_type:
        extra["event_type"] = event_type
    subsystem = row.get("Subsystem", "")
    if subsystem:
        extra["subsystem"] = subsystem
    category = row.get("Category", "")
    if category:
        extra["category"] = category
    euid = row.get("EUID", "")
    if euid:
        extra["euid"] = euid
    thread_raw = row.get("Thread ID", "")
    if thread_raw:
        try:
            extra["thread_id"] = hex(int(thread_raw))
        except ValueError:
            extra["thread_id"] = thread_raw
    act_raw = row.get("Activity ID", "")
    if act_raw:
        try:
            extra["activity_id"] = hex(int(act_raw))
        except ValueError:
            extra["activity_id"] = act_raw
    library = row.get("Library", "")
    if library:
        extra["sender"] = _path_basename(library) or library
    boot_uuid = row.get("Boot UUID", "")
    if boot_uuid:
        extra["boot_uuid"] = boot_uuid
    tz_name = row.get("System Timezone Name", "")
    if tz_name:
        extra["timezone"] = tz_name
    if boot_relative and excluded_ts_iso is not None:
        extra["excluded_timestamp"] = excluded_ts_iso

    return {
        "timestamp": ts,
        "level":     level,
        "process":   process,
        "pid":       pid,
        "message":   message,
        "raw":       raw_message,
        "extra":     extra,
    }


def _stream_mandiant_csv(path: Path) -> Generator[dict[str, Any], None, None]:
    """Yield standard entry dicts from a Mandiant-format CSV output file."""
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                yield _entry_from_mandiant_csv(row)
            except Exception:
                yield {
                    "timestamp": None, "level": "UNKNOWN",
                    "process": "", "pid": "", "message": str(row),
                    "raw": str(row), "extra": {},
                }


# ---------------------------------------------------------------------------
# iOS full filesystem acquisition support
# ---------------------------------------------------------------------------

_IOS_DIAG_SUBDIRS = frozenset({"Persist", "Special", "Signpost", "timesync"})
_IOS_DIAG_MIN_MATCHES = 2


def is_ios_diagnostics_node(node: "VFSNode") -> bool:
    """Return True if *node* looks like an iOS full-FS diagnostics root.

    Checks for ≥ 2 of: ``Persist/``, ``Special/``, ``Signpost/``, ``timesync/``
    as direct children of the node.
    """
    if not node.is_dir:
        return False
    child_names = {child.name for child in node.children}
    return len(_IOS_DIAG_SUBDIRS & child_names) >= _IOS_DIAG_MIN_MATCHES


def _find_uuidtext_sibling(diag_node: "VFSNode", vfs: "VFS") -> "VFSNode | None":
    """Walk the VFS to find the parent of *diag_node* and return its
    ``uuidtext/`` sibling, or ``None`` if not found."""

    def _walk(current: "VFSNode", target: "VFSNode") -> "VFSNode | None":
        for child in current.children:
            if child is target:
                for sibling in current.children:
                    if sibling.name.lower() == "uuidtext" and sibling.is_dir:
                        return sibling
                return None
            if child.is_dir:
                result = _walk(child, target)
                if result is not None:
                    return result
        return None

    return _walk(vfs.root(), diag_node)


def build_logarchive_from_acquisition(
    diag_node: "VFSNode",
    vfs: "VFS",
    tmp_root: Path,
) -> Path:
    """Assemble a proper logarchive layout from an iOS full-FS acquisition.

    Extracts the ``diagnostics/`` subtree into *tmp_root*, then locates
    the ``uuidtext/`` sibling one level up in the VFS and extracts it into
    ``tmp_root/uuidtext/`` (skipped if already present inside diagnostics).

    Returns *tmp_root*, ready for ``unifiedlog_iterator -m log-archive``.
    """
    _log.info("[UnifiedLog] Extracting diagnostics '%s' → %s", diag_node.path, tmp_root)
    _export_dir_to_real_fs(diag_node, vfs, tmp_root)

    top_level = [p.name for p in tmp_root.iterdir()] if tmp_root.exists() else []
    _log.info("[UnifiedLog] Logarchive top-level after diagnostics extract: %s", top_level)

    # uuidtext may already live inside diagnostics on some acquisition tools
    if (tmp_root / "uuidtext").exists():
        _log.info("[UnifiedLog] uuidtext/ already present inside diagnostics — skipping search")
        return tmp_root

    uuidtext_node = _find_uuidtext_sibling(diag_node, vfs)
    if uuidtext_node is not None:
        _log.info("[UnifiedLog] Found uuidtext/ at '%s' — extracting", uuidtext_node.path)
        _export_dir_to_real_fs(uuidtext_node, vfs, tmp_root / "uuidtext")
    else:
        _log.warning(
            "[UnifiedLog] uuidtext/ NOT found in VFS — message strings will NOT be resolved. "
            "Ensure the full filesystem acquisition includes /private/var/db/uuidtext/"
        )

    return tmp_root


def _log_stderr(stderr_bytes: bytes) -> None:
    """Log warnings/errors from unifiedlog_iterator stderr (deduplicated)."""
    raw = stderr_bytes.decode("utf-8", errors="replace").strip()
    if not raw:
        return
    lines = [_ANSI_RE.sub("", ln) for ln in raw.splitlines()]
    warn_count = sum(1 for ln in lines if "[WARN]" in ln)
    err_count  = sum(1 for ln in lines if "[ERROR]" in ln)
    if warn_count or err_count:
        _log.info("[UnifiedLog] converter: %d warnings, %d errors", warn_count, err_count)
    seen: set[str] = set()
    for ln in lines:
        ln = ln.strip()
        key = ln[20:] if len(ln) > 20 else ln
        if key not in seen and ("[WARN]" in ln or "[ERROR]" in ln):
            _log.info("[UnifiedLog] %s", ln)
            seen.add(key)
            if len(seen) >= 5:
                break


class UnifiedLogConverter:
    """Convert binary ``.tracev3`` / ``.logarchive`` to standard entry dicts.

    Uses Mandiant's ``unifiedlog_iterator`` binary (Apache 2.0 licence).
    The appropriate binary for the current platform must be present inside
    ``crush/bin/unifiedlog_iterator/``.

    See ``crush/bin/unifiedlog_iterator/README.md`` for download instructions.
    """

    def __init__(self, temp_dir: str | None = None) -> None:
        self._procs: list["subprocess.Popen[bytes]"] = []
        self._cancelled = False
        self._temp_dir = temp_dir or None

    def cancel(self) -> None:
        """Signal cancellation and kill all running subprocesses."""
        self._cancelled = True
        for proc in list(self._procs):
            try:
                proc.kill()
            except OSError:
                pass

    def _run_binary(self, cmd: list[str]) -> tuple[int, bytes]:
        """Run one command, return (returncode, stderr_bytes). Supports cancel()."""
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        self._procs.append(proc)
        try:
            _, stderr_bytes = proc.communicate()
        finally:
            try:
                self._procs.remove(proc)
            except ValueError:
                pass
        return proc.returncode, stderr_bytes

    def _run_binaries_parallel(self, cmds: list[list[str]]) -> list[tuple[int, bytes]]:
        """Launch all *cmds* concurrently and return (returncode, stderr) per cmd."""
        procs: list[subprocess.Popen[bytes]] = []
        for cmd in cmds:
            if self._cancelled:
                break
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            procs.append(proc)
            self._procs = procs  # update after each launch so cancel() sees them

        def _wait(p: "subprocess.Popen[bytes]") -> tuple[int, bytes]:
            _, stderr = p.communicate()
            return p.returncode, stderr

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(procs)) as ex:
                results = list(ex.map(_wait, procs))
        finally:
            self._procs = []
        return results

    def _select_binary(self) -> Path:
        """Return the path to the platform-appropriate binary.

        Raises
        ------
        RuntimeError
            If no binary mapping exists for the current platform.
        FileNotFoundError
            If the expected binary file is absent from the bundle directory.
        """
        machine = platform.machine()
        key = (sys.platform, machine)
        name = _PLATFORM_BINARY_MAP.get(key)
        if name is None:
            raise RuntimeError(
                f"No unifiedlog_iterator binary defined for platform "
                f"{sys.platform}/{machine}.\n"
                f"Supported: {list(_PLATFORM_BINARY_MAP.keys())}"
            )
        path = _BINARY_DIR / name
        if not path.exists():
            raise FileNotFoundError(
                f"unifiedlog_iterator binary not found:\n  {path}\n\n"
                f"Download the binary for your platform from:\n"
                f"  https://github.com/mandiant/macos-UnifiedLogs/releases\n"
                f"and place it in:\n  {_BINARY_DIR}/"
            )
        return path

    def _stream_logarchive_from_path(
        self,
        bin_path: Path,
        logarchive_path: Path,
        tmp_root: Path,
        n_workers: int | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Yield entries from an already-extracted logarchive directory.

        Splits ``Persist/*.tracev3`` across *n_workers* parallel processes
        (default: ``os.cpu_count()``).  Falls back to a single process when
        there is only one tracev3 file or *n_workers* is 1.
        """
        persist_dir = logarchive_path / "Persist"
        tracev3_files = sorted(persist_dir.glob("*.tracev3")) if persist_dir.is_dir() else []

        # Diagnostic: log what directories are present in the logarchive
        present = [d.name for d in logarchive_path.iterdir() if d.is_dir()] if logarchive_path.is_dir() else []
        ts_dir = logarchive_path / "timesync"
        ts_file_count = len(list(ts_dir.iterdir())) if ts_dir.is_dir() else 0
        _log.info(
            "[UnifiedLog] logarchive dirs present: %s  (%d tracev3 files, %d timesync files)",
            present, len(tracev3_files), ts_file_count,
        )
        if "timesync" not in present:
            _log.warning(
                "[UnifiedLog] timesync/ NOT present in extracted logarchive at %s — "
                "unifiedlog_iterator will output boot-relative timestamps (shown as '—'). "
                "Check that the acquisition includes /private/var/db/diagnostics/timesync/",
                logarchive_path,
            )
        elif ts_file_count == 0:
            _log.warning(
                "[UnifiedLog] timesync/ is empty — "
                "unifiedlog_iterator will output boot-relative timestamps (shown as '—'). "
                "The acquisition may not have captured /private/var/db/diagnostics/timesync/*",
            )

        # Default to physical cores — hyperthreading gives little benefit for
        # I/O-bound binary parsing and causes uuidtext read contention.
        cpu = os.cpu_count() or 1
        physical = max(1, cpu // 2)
        workers = min(
            len(tracev3_files) if tracev3_files else 1,
            n_workers if n_workers is not None else physical,
        )

        if workers <= 1 or len(tracev3_files) <= 1:
            out_file = tmp_root / "output.csv"
            _log.info("[UnifiedLog] Single process: -m log-archive -i %s", logarchive_path)
            returncode, stderr_bytes = self._run_binary(
                [str(bin_path), "-m", "log-archive",
                 "-i", str(logarchive_path), "-o", str(out_file), "-f", "csv"]
            )
            if self._cancelled:
                return
            _log_stderr(stderr_bytes)
            if returncode != 0:
                raise RuntimeError(
                    f"unifiedlog_iterator exited with code {returncode}:\n"
                    + stderr_bytes.decode("utf-8", errors="replace").strip()
                )
            if not out_file.exists():
                raise RuntimeError("unifiedlog_iterator produced no output file.")
            yield from _stream_mandiant_csv(out_file)
            return

        # Greedy size-based assignment: largest files first, always assign to
        # the chunk with the smallest current total — minimises the longest chunk.
        files_by_size = sorted(tracev3_files, key=lambda f: f.stat().st_size, reverse=True)
        chunk_bytes: list[int] = [0] * workers
        chunk_files: list[list[Path]] = [[] for _ in range(workers)]
        for f in files_by_size:
            smallest = min(range(workers), key=lambda i: chunk_bytes[i])
            chunk_files[smallest].append(f)
            chunk_bytes[smallest] += f.stat().st_size
        chunks = [c for c in chunk_files if c]
        _log.info("[UnifiedLog] Parallel: %d workers, %d tracev3 files", len(chunks), len(tracev3_files))

        shared_dirs = ["Special", "timesync", "uuidtext"]
        out_files: list[Path] = []
        cmds: list[list[str]] = []

        for i, chunk in enumerate(chunks):
            mini = tmp_root / f"chunk_{i}"
            mini_persist = mini / "Persist"
            mini_persist.mkdir(parents=True)

            for tv in chunk:
                dst = mini_persist / tv.name
                try:
                    os.link(tv, dst)
                except OSError:
                    shutil.copy2(tv, dst)

            for d in shared_dirs:
                src = logarchive_path / d
                if src.exists():
                    dst_dir = mini / d
                    if d == "uuidtext" and sys.platform != "win32":
                        # uuidtext can be several GB — symlink to avoid duplication
                        os.symlink(src, dst_dir)
                    else:
                        # timesync and Special are small; some binary builds do not
                        # follow symlinks for these dirs, so copy them instead
                        shutil.copytree(src, dst_dir, dirs_exist_ok=True)

            out_file = tmp_root / f"output_{i}.csv"
            out_files.append(out_file)
            cmds.append([
                str(bin_path), "-m", "log-archive",
                "-i", str(mini), "-o", str(out_file), "-f", "csv",
            ])

        # Launch all processes upfront so they run concurrently.
        procs: list[subprocess.Popen[bytes]] = []
        for cmd in cmds:
            if self._cancelled:
                break
            proc: subprocess.Popen[bytes] = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            procs.append(proc)
        self._procs = procs

        # Stream entries into the DB as each process finishes — no need to wait
        # for all chunks before yielding. SQLite sorts on query so insertion
        # order does not need to match timestamp order.
        futures: dict[concurrent.futures.Future[tuple[bytes, int]], tuple[int, Path]] = {}
        failed = 0
        yielded_any = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(procs)) as ex:
            for idx, (proc, out_file) in enumerate(zip(procs, out_files)):
                def _wait(p: subprocess.Popen[bytes] = proc) -> tuple[bytes, int]:
                    _, stderr = p.communicate()
                    return stderr, p.returncode
                futures[ex.submit(_wait)] = (idx, out_file)

            for future in concurrent.futures.as_completed(futures):
                if self._cancelled:
                    break
                idx, out_file = futures[future]
                stderr_bytes, rc = future.result()
                _log_stderr(stderr_bytes)
                if rc != 0:
                    failed += 1
                    _log.warning("[UnifiedLog] chunk %d exited with code %d", idx, rc)
                elif out_file.exists():
                    yield from _stream_mandiant_csv(out_file)
                    yielded_any = True

        self._procs = []
        if not yielded_any and not self._cancelled:
            raise RuntimeError(f"All {len(cmds)} unifiedlog_iterator processes failed.")
        if failed:
            _log.warning("[UnifiedLog] %d/%d chunks failed — results may be incomplete", failed, len(cmds))

    def stream_entries(
        self,
        node: "VFSNode",
        vfs: "VFS",
        n_workers: int | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Extract *node* to a temp path, run the converter, yield entry dicts.

        Works for both ``.logarchive`` directories and individual ``.tracev3``
        files.  Logarchive directories are processed with *n_workers* parallel
        subprocesses (default: ``os.cpu_count()``).

        Raises
        ------
        RuntimeError
            If the binary is missing or the conversion subprocess fails.
        """
        bin_path = self._select_binary()
        if sys.platform != "win32":
            os.chmod(bin_path, 0o755)

        tmp_in = Path(tempfile.mkdtemp(prefix="crush-ul-in-", dir=self._temp_dir))
        try:
            is_archive = node.is_dir or node.name.lower().endswith(".logarchive")

            if is_archive:
                dest = tmp_in / node.name
                _export_dir_to_real_fs(node, vfs, dest)
                yield from self._stream_logarchive_from_path(bin_path, dest, tmp_in, n_workers)
            else:
                # Single .tracev3 file — no parallelism possible
                dest = tmp_in / node.name
                dest.write_bytes(vfs.read(node))
                out_file = tmp_in / "output.csv"
                _log.info("[UnifiedLog] Running: unifiedlog_iterator -m single-file -i %s", dest)
                returncode, stderr_bytes = self._run_binary(
                    [str(bin_path), "-m", "single-file",
                     "-i", str(dest), "-o", str(out_file), "-f", "csv"]
                )
                if self._cancelled:
                    return
                _log_stderr(stderr_bytes)
                if returncode != 0:
                    raise RuntimeError(
                        f"unifiedlog_iterator exited with code {returncode}:\n"
                        + stderr_bytes.decode("utf-8", errors="replace").strip()
                    )
                if not out_file.exists():
                    raise RuntimeError(
                        "unifiedlog_iterator produced no output file. "
                        "The input may not be a valid tracev3."
                    )
                yield from _stream_mandiant_csv(out_file)

        finally:
            shutil.rmtree(tmp_in, ignore_errors=True)

    def stream_entries_from_diagnostics(
        self,
        diag_node: "VFSNode",
        vfs: "VFS",
        n_workers: int | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Assemble a logarchive from an iOS acquisition and yield entry dicts.

        Splits ``Persist/*.tracev3`` files across *n_workers* parallel
        ``unifiedlog_iterator`` processes (default: ``os.cpu_count()``).
        Each worker gets its own mini-logarchive directory with a subset of
        tracev3 files; shared directories (``uuidtext/``, ``timesync/``,
        ``Special/``) are symlinked (POSIX) or copied (Windows) to avoid
        duplicating large data.  Output CSVs are merged by timestamp.

        Falls back to a single process when only one tracev3 file exists or
        when *n_workers* is explicitly set to 1.

        Raises
        ------
        RuntimeError
            If the binary is missing or all conversion subprocesses fail.
        """
        bin_path = self._select_binary()
        if sys.platform != "win32":
            os.chmod(bin_path, 0o755)

        tmp_root = Path(tempfile.mkdtemp(prefix="crush-ul-ios-", dir=self._temp_dir))
        try:
            logarchive_path = build_logarchive_from_acquisition(diag_node, vfs, tmp_root)
            yield from self._stream_logarchive_from_path(bin_path, logarchive_path, tmp_root, n_workers)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
