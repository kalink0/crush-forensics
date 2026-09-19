# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Central temp-directory handling for every place Crush stages bytes on disk.

One user-configurable root (Tools -> Temp Directory...) replaces the
OS default everywhere a temporary file or directory is created. The OS
default is a poor choice for evidence-sized data: on many Linux systems
/tmp is a RAM-backed tmpfs, so "spilling to disk" would silently fill
memory instead.

The configured root is never silently replaced by another location: if it
cannot be created, callers get the OSError. Falling back to /tmp would move
multi-GB extractions into RAM behind the user's back.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from crush.core.sysmem import available_memory

_configured_root: Path | None = None

# Head-room kept free on top of the bytes about to be written.
_SPACE_MARGIN = 64 * 1024 * 1024

# A RAM-backed temp root only warns once the write would take more than this
# share of currently available memory; below it the copy is harmless.
_RAM_WARN_FRACTION = 0.25

_RAM_FS_TYPES = frozenset({"tmpfs", "ramfs"})


def configure(path: str | Path | None) -> None:
    """Set (or, with an empty value, clear) the configured temp root."""
    global _configured_root
    text = str(path).strip() if path is not None else ""
    _configured_root = Path(text).expanduser() if text else None


def configured_root() -> Path | None:
    return _configured_root


def root() -> Path:
    """The directory new temp files/directories are created in."""
    return _configured_root if _configured_root is not None else Path(tempfile.gettempdir())


def _ensure_root() -> Path:
    r = root()
    r.mkdir(parents=True, exist_ok=True)
    return r


def mkdtemp(prefix: str = "crush-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=_ensure_root()))


def mkstemp(prefix: str = "crush-", suffix: str = "") -> tuple[int, str]:
    return tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=_ensure_root())


def named_temporary_file(
    *, prefix: str = "crush-", suffix: str = "", delete: bool = False
) -> "tempfile._TemporaryFileWrapper[bytes]":
    return tempfile.NamedTemporaryFile(
        prefix=prefix, suffix=suffix, delete=delete, dir=_ensure_root()
    )


def temporary_directory(prefix: str = "crush-") -> "tempfile.TemporaryDirectory[str]":
    return tempfile.TemporaryDirectory(prefix=prefix, dir=_ensure_root())


def spool_file(prefix: str = "crush-spool-") -> IO[bytes]:
    """An unlinked read/write temp file that disappears once closed."""
    return tempfile.TemporaryFile(prefix=prefix, dir=_ensure_root())


# ---------------------------------------------------------------------------
# Free-space / RAM-backed checks
# ---------------------------------------------------------------------------


def _read_mountinfo() -> str:
    try:
        return Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _mem_available() -> int | None:
    return available_memory()


def _unescape_mount_field(value: str) -> str:
    # /proc escapes space, tab, newline and backslash as octal (\040, ...).
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and len(value[i + 1 : i + 4]) == 3 and value[i + 1 : i + 4].isdigit():
            out.append(chr(int(value[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def _fs_type_for(target: str, mountinfo: str) -> str | None:
    """Filesystem type of the mount holding the absolute POSIX path *target*,
    from /proc/self/mountinfo text; the longest matching mount point wins."""
    best_len = -1
    best_type: str | None = None
    for line in mountinfo.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 5 or not right_fields:
            continue
        mount_point = _unescape_mount_field(left_fields[4])
        if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
            if len(mount_point) > best_len:
                best_len = len(mount_point)
                best_type = right_fields[0]
    return best_type


def filesystem_type(path: Path) -> str | None:
    """Filesystem type of the mount that holds *path* (Linux only, else None)."""
    if not sys.platform.startswith("linux"):
        return None
    text = _read_mountinfo()
    if not text:
        return None
    try:
        target = str(path.resolve())
    except OSError:
        target = str(path)
    return _fs_type_for(target, text)


@dataclass(frozen=True)
class SpaceCheck:
    """Outcome of checking whether *needed* bytes fit in the temp root."""

    location: Path
    needed: int
    free: int
    ram_backed: bool
    ram_available: int | None

    @property
    def enough_space(self) -> bool:
        return self.free >= self.needed + _SPACE_MARGIN

    @property
    def ram_warning(self) -> bool:
        """RAM-backed root and the write would take a large share of memory."""
        if not self.ram_backed:
            return False
        if self.ram_available is None:
            return True
        return self.needed > self.ram_available * _RAM_WARN_FRACTION


def check_space(needed: int, at: Path | None = None) -> SpaceCheck:
    """Compare *needed* bytes against free space in the temp root.

    The root is created first when missing so the check reflects the real
    target instead of a parent directory.
    """
    location = at if at is not None else _ensure_root()
    free = shutil.disk_usage(location).free
    fs = filesystem_type(location)
    return SpaceCheck(
        location=location,
        needed=max(needed, 0),
        free=free,
        ram_backed=fs in _RAM_FS_TYPES,
        ram_available=_mem_available() if fs in _RAM_FS_TYPES else None,
    )
