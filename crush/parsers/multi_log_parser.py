# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Custom log format parser and profile management for Multi-Log Studio.

Provides:
  CustomFormatProfile  — dataclass describing a user-defined log format.
  ProfileManager       — load / save / delete profiles from
                         ~/.config/crush/log_profiles/.
  CustomFormatParser   — parses a VFS node using a CustomFormatProfile.

Named groups that map to standard columns:
  timestamp, level, process, pid, message

Any other named group is stored in the ``extra`` dict of the entry.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from crush.core.issues import ParseIssue
from crush.core.log_ts import TS_UNPARSED, naive_ts, parse_iso_ts
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import ParseResult
from crush.parsers.log_parser import timestamp_notes

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Profile dataclass
# ---------------------------------------------------------------------------

_STANDARD_GROUPS: frozenset[str] = frozenset(
    {"timestamp", "level", "process", "pid", "message"}
)


@dataclass
class CustomFormatProfile:
    """User-defined log format profile."""

    name: str
    parse_pattern: str                            # regex with named groups
    timestamp_format: str = ""                    # strptime format (empty = auto)
    line_start_pattern: str = ""                  # regex for multiline event start
    level_map: dict[str, str] = field(default_factory=dict)
    level_default: str = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name":               self.name,
            "parse_pattern":      self.parse_pattern,
            "timestamp_format":   self.timestamp_format,
            "line_start_pattern": self.line_start_pattern,
            "level_map":          self.level_map,
            "level_default":      self.level_default,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CustomFormatProfile:
        return cls(
            name=               d.get("name", "Unnamed"),
            parse_pattern=      d.get("parse_pattern", ""),
            timestamp_format=   d.get("timestamp_format", ""),
            line_start_pattern= d.get("line_start_pattern", ""),
            level_map=          d.get("level_map", {}),
            level_default=      d.get("level_default", "UNKNOWN"),
        )


# ---------------------------------------------------------------------------
# Profile manager
# ---------------------------------------------------------------------------

class ProfileManager:
    """Load, save and delete custom log format profiles.

    Profiles are stored as individual JSON files in
    ``~/.config/crush/log_profiles/``.  One file per profile; filename
    derived from the profile name (special characters replaced with ``_``).
    """

    DIR: Path = Path.home() / ".config" / "crush" / "log_profiles"

    @classmethod
    def _ensure_dir(cls) -> None:
        cls.DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _safe_stem(cls, name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_\-]", "_", name) or "profile"

    @classmethod
    def all(cls) -> list[CustomFormatProfile]:
        """Return all saved profiles, sorted by name."""
        cls._ensure_dir()
        profiles: list[CustomFormatProfile] = []
        for path in sorted(cls.DIR.glob("*.json")):
            try:
                with path.open(encoding="utf-8") as fh:
                    profiles.append(CustomFormatProfile.from_dict(json.load(fh)))
            except Exception as exc:  # noqa: BLE001
                # A broken profile file is user config, not evidence: skip
                # it so the others stay usable, but never silently.
                _logger.warning("Skipping unreadable log format profile %s: %s", path, exc)
        return profiles

    @classmethod
    def save(cls, profile: CustomFormatProfile) -> None:
        """Persist a profile.  Overwrites if a same-name file exists."""
        cls._ensure_dir()
        path = cls.DIR / f"{cls._safe_stem(profile.name)}.json"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(profile.to_dict(), fh, indent=2)

    @classmethod
    def delete(cls, name: str) -> None:
        """Delete a profile by its exact name (no-op if not found)."""
        path = cls.DIR / f"{cls._safe_stem(name)}.json"
        if path.exists():
            path.unlink()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_LEVEL_NORM: dict[str, str] = {
    "error": "ERROR", "err": "ERROR", "fatal": "ERROR", "critical": "ERROR",
    "warn": "WARN",   "warning": "WARN",
    "info": "INFO",   "information": "INFO", "notice": "INFO",
    "debug": "DEBUG", "dbg": "DEBUG", "verbose": "DEBUG",
    "trace": "TRACE",
    "e": "ERROR", "f": "ERROR",
    "w": "WARN",
    "i": "INFO",
    "d": "DEBUG",
    "v": "TRACE",
}


def _normalise_level(raw: str) -> str:
    return _LEVEL_NORM.get(raw.strip().lower(), "UNKNOWN")


def _group_events(
    lines: list[str],
    is_start: Callable[[str], bool],
) -> list[list[str]]:
    """Group lines into multi-line events.

    A new event begins whenever ``is_start(line)`` returns True.
    Continuation lines are appended to the current event.  Lines that
    arrive before the first event start are each their own group.
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
                groups.append([line])
    if current:
        groups.append(current)
    return groups


class CustomFormatParser:
    """Parser driven by a ``CustomFormatProfile``.

    Supports named-group regex extraction, custom strptime timestamp
    parsing, level normalisation via level_map, and multiline event
    grouping via line_start_pattern.

    The ``parse()`` method returns a ``ParseResult`` compatible with
    ``LogLoaderWorker`` (viewer_type="log", data=list[dict]).
    """

    def __init__(self, profile: CustomFormatProfile) -> None:
        self._profile  = profile
        self._re       = re.compile(profile.parse_pattern) if profile.parse_pattern else None
        self._start_re = (
            re.compile(profile.line_start_pattern)
            if profile.line_start_pattern else None
        )

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw_bytes = vfs.read(node)
        encoding_issue: ParseIssue | None = None
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            text = raw_bytes.decode("utf-8", errors="replace")
            encoding_issue = ParseIssue(
                "log.not_utf8", {"offset": exc.start}, detail=exc.reason,
            )

        lines = text.splitlines(keepends=False)
        entries = self.parse_lines(lines)

        ts_count = sum(1 for e in entries if e["timestamp"] is not None)
        metadata: dict[str, Any] = {
            "File size":              f"{node.size:,} B",
            "Log format":             ParseIssue(
                "log.format_custom", {"name": self._profile.name},
            ),
            "Total entries":          str(len(entries)),
            "Entries with timestamp": str(ts_count),
        }
        notes = timestamp_notes(entries)
        if notes:
            metadata["Timestamp notes"] = notes
        if encoding_issue is not None:
            metadata["Encoding"] = encoding_issue
        text_index = " ".join(e["message"] for e in entries[:500])
        return ParseResult(
            viewer_type="log",
            data=entries,
            metadata=metadata,
            text_index=text_index,
        )

    def parse_lines(self, lines: list[str]) -> list[dict[str, Any]]:
        """Parse raw text lines into entry dicts.  Public for live preview."""
        if self._start_re is not None:
            start_re = self._start_re  # local ref to avoid closure issues
            groups = _group_events(lines, lambda ln: bool(start_re.match(ln)))
        else:
            groups = [[ln] for ln in lines if ln.strip()]
        return [self._parse_group(g) for g in groups]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _parse_group(self, group: list[str]) -> dict[str, Any]:
        profile = self._profile
        raw     = "\n".join(group)
        first   = group[0]

        no_match: dict[str, Any] = {
            "timestamp": None,
            "ts_flags":  "",
            "level":     profile.level_default,
            "process":   "",
            "pid":       "",
            "message":   first,
            "raw":       raw,
            "extra":     {},
        }

        if self._re is None:
            return no_match

        m = self._re.search(first)
        if not m:
            return no_match

        gd = m.groupdict()

        # -- Timestamp --
        ts: datetime | None = None
        ts_flags = ""
        ts_str = gd.get("timestamp") or ""
        if ts_str:
            if profile.timestamp_format:
                try:
                    ts, ts_flags = naive_ts(
                        datetime.strptime(ts_str, profile.timestamp_format)
                    )
                except ValueError:
                    pass
            if ts is None:
                ts, ts_flags = parse_iso_ts(ts_str)

        # -- Level --
        raw_level = gd.get("level") or ""
        if raw_level:
            level = (
                profile.level_map.get(raw_level, profile.level_default)
                if profile.level_map
                else _normalise_level(raw_level)
            )
        else:
            level = profile.level_default

        # -- Message (includes continuation lines) --
        message = gd.get("message") or ""
        if len(group) > 1:
            tail = "\n".join(group[1:])
            message = f"{message}\n{tail}" if message else tail

        # -- Extra: named groups not in the standard set --
        extra = {
            k: v
            for k, v in gd.items()
            if k not in _STANDARD_GROUPS and v is not None
        }

        return {
            "timestamp": ts,
            "ts_flags":  ts_flags if ts is not None else TS_UNPARSED if ts_str else "",
            "level":     level,
            "process":   gd.get("process") or "",
            "pid":       gd.get("pid") or "",
            "message":   message,
            "raw":       raw,
            "extra":     extra,
        }
