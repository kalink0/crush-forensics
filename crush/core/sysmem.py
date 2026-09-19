# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""How much memory is free right now, without a psutil dependency."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _linux() -> int | None:
    for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="replace").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return None


def _windows() -> int | None:
    import ctypes

    class _Status(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = _Status()
    status.dwLength = ctypes.sizeof(_Status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
        return None
    return int(status.ullAvailPhys)


def _macos() -> int | None:
    out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=2, check=True).stdout
    page_size = 4096
    pages = 0
    for line in out.splitlines():
        if "page size of" in line:
            page_size = int(line.split("page size of")[1].split()[0])
        elif line.startswith(("Pages free", "Pages inactive", "Pages speculative")):
            pages += int(line.split(":")[1].strip().rstrip("."))
    return pages * page_size or None


def available_memory() -> int | None:
    """Bytes of RAM available to new allocations, or None when unknown."""
    try:
        if sys.platform.startswith("linux"):
            return _linux()
        if sys.platform == "win32":
            return _windows()
        if sys.platform == "darwin":
            return _macos()
    except Exception:  # noqa: BLE001 - "unknown" is a valid, handled answer
        return None
    return None
