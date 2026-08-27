# SPDX-License-Identifier: Apache-2.0
"""Locate and launch the bundled peach-forensics binary.

Peach is a sibling forensic log viewer (Rust + egui + DuckDB), part of the
same "Finding-Nemo ecosystem" as Crush. Crush hands off log evidence to it
via a one-shot CLI spawn (`--add-source`/`--cleanup-dir`) — there's no IPC
after launch, matching peach's own "runs completely independently" design.
"""
from __future__ import annotations

import platform
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

# Maps (sys.platform, platform.machine()) -> binary filename inside _BINARY_DIR.
# No linux/aarch64 entry -- peach's own release matrix doesn't build one.
# macOS is a single universal (arm64+x86_64) binary as of peach v0.2.1.
_PLATFORM_BINARY_MAP: dict[tuple[str, str], str] = {
    ("linux",  "x86_64"): "peach-linux",
    ("darwin", "x86_64"): "peach-macos",
    ("darwin", "arm64"):  "peach-macos",
    ("win32",  "AMD64"):  "peach-windows.exe",
    ("win32",  "x86_64"): "peach-windows.exe",
}


def _resolve_binary_dir() -> Path:
    if getattr(sys, "frozen", False):
        # PyInstaller extracts data files to sys._MEIPASS when frozen.
        # --add-data places the binary at _MEIPASS/crush/bin/peach/. All
        # platforms build --onedir, so _MEIPASS is the persistent install
        # directory (not a per-process temp dir) -- peach can be launched
        # detached straight from here, it outlives crush.exe closing.
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
