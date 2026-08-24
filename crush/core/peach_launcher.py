# SPDX-License-Identifier: Apache-2.0
"""Locate and launch the bundled peach-forensics binary.

Peach is a sibling forensic log viewer (Rust + egui + DuckDB), part of the
same "Finding-Nemo ecosystem" as Crush. Crush hands off log evidence to it
via a one-shot CLI spawn (`--add-source`/`--cleanup-dir`) — there's no IPC
after launch, matching peach's own "runs completely independently" design.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

# Maps (sys.platform, platform.machine()) -> binary filename inside _BINARY_DIR.
# No linux/aarch64 entry -- peach's own release matrix doesn't build one.
_PLATFORM_BINARY_MAP: dict[tuple[str, str], str] = {
    ("linux",  "x86_64"): "peach-linux",
    ("darwin", "x86_64"): "peach-macos-intel",
    ("darwin", "arm64"):  "peach-macos-arm",
    ("win32",  "AMD64"):  "peach-windows.exe",
    ("win32",  "x86_64"): "peach-windows.exe",
}


def _resolve_binary_dir() -> Path:
    if getattr(sys, "frozen", False):
        # PyInstaller extracts data files to sys._MEIPASS when frozen.
        # --add-data places the binary at _MEIPASS/crush/bin/peach/.
        #
        # On Windows the build is --onefile, so _MEIPASS is a fresh,
        # ephemeral per-process temp dir (%TEMP%\_MEIxxxxxx) torn down once
        # crush.exe exits -- fine for unifiedlog_iterator (invoked
        # synchronously while crush is still running) but wrong for peach,
        # which must keep running detached after crush.exe closes. See
        # _stabilize_windows_binary() below, which copies the binary out of
        # here into a persistent cache before it's launched.
        return Path(sys._MEIPASS) / "crush" / "bin" / "peach"  # type: ignore[attr-defined]
    return Path(__file__).parent.parent / "bin" / "peach"


_BINARY_DIR = _resolve_binary_dir()


def get_bundled_peach_version() -> str | None:
    """Version of the bundled peach binary, per VERSION.txt written by
    scripts/download_peach_binaries.py next to the binaries. None if running
    from source without downloaded binaries.
    """
    version_file = _BINARY_DIR / "VERSION.txt"
    if not version_file.exists():
        return None
    return version_file.read_text().strip() or None


def _stabilize_windows_binary(embedded_path: Path) -> Path:
    """Copy the onefile-embedded peach binary into a persistent cache dir.

    Needed only on Windows: the bundled binary otherwise lives under
    sys._MEIPASS, a per-process temp dir PyInstaller deletes once crush.exe
    exits -- but peach is launched detached and must keep running after
    that. Skips the copy if a matching-size copy is already cached, so a
    normal launch doesn't re-copy the binary every time.
    """
    cache_root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    cache_dir = Path(cache_root) / "Crush" / "peach"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached_path = cache_dir / embedded_path.name
    if not cached_path.exists() or cached_path.stat().st_size != embedded_path.stat().st_size:
        shutil.copy2(embedded_path, cached_path)
    return cached_path


def find_peach_binary(override_path: str = "") -> Path:
    """Return the path to the peach binary to launch.

    *override_path*, if set (from Settings), always wins over the bundled
    binary — lets an analyst point at a newer peach build than the one
    bundled with the current Crush release, without waiting for a new
    Crush release.

    Raises
    ------
    FileNotFoundError
        If neither the override nor the bundled binary exists.
    RuntimeError
        If there's no bundled binary defined for the current platform.
    """
    if override_path:
        path = Path(override_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"Configured Peach binary path does not exist:\n  {path}"
            )
        return path

    machine = platform.machine()
    key = (sys.platform, machine)
    name = _PLATFORM_BINARY_MAP.get(key)
    if name is None:
        raise RuntimeError(
            f"No bundled peach binary defined for platform "
            f"{sys.platform}/{machine}.\n"
            f"Supported: {list(_PLATFORM_BINARY_MAP.keys())}"
        )
    path = _BINARY_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Bundled peach binary not found:\n  {path}\n\n"
            f"Run scripts/download_peach_binaries.py, or set a Peach binary "
            f"path override in Settings."
        )
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        path = _stabilize_windows_binary(path)
    return path


def launch_peach(
    sources: Sequence[Path],
    cleanup_dirs: Sequence[Path] = (),
    override_path: str = "",
    ephemeral_session: bool = False,
) -> None:
    """Spawn peach with the given source paths, fire-and-forget.

    No IPC after launch, by design — matches peach's own "runs completely
    independently" model. Crush never waits for, or tracks, the process
    afterward.

    *ephemeral_session* should be set whenever *sources* came from a temp
    extraction (i.e. *cleanup_dirs* is non-empty) or another decrypted/
    otherwise-not-already-durable origin — without it, peach would leave a
    permanent, unencrypted session copy of the handed-off evidence behind
    in its own sessions directory, outliving the temp extraction and
    bypassing whatever protection the original source had.
    """
    binary = find_peach_binary(override_path)

    if sys.platform != "win32":
        mode = binary.stat().st_mode
        if not mode & 0o111:
            try:
                binary.chmod(mode | 0o111)
            except OSError:
                # Read-only mount (e.g. a FUSE-mounted AppImage) -- fine as
                # long as the bundled binary already has its exec bit set,
                # which download_peach_binaries.py guarantees at build time.
                pass

    cmd: list[str] = [str(binary)]
    if ephemeral_session:
        cmd.append("--ephemeral-session")
    for src in sources:
        cmd += ["--add-source", str(src)]
    for d in cleanup_dirs:
        cmd += ["--cleanup-dir", str(d)]

    subprocess.Popen(cmd)
