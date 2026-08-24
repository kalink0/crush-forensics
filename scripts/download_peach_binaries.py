#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Download peach-forensics binaries for all supported platforms.

Run from the repository root:
    python scripts/download_peach_binaries.py

Downloads release assets from https://github.com/kalink0/peach-forensics
and places them in crush/bin/peach/ with the filenames expected by
crush.core.peach_launcher._select_binary(). Also writes VERSION.txt next to
them, read at runtime by peach_launcher.get_bundled_peach_version() to show
which version is actually bundled (About dialog).
"""
from __future__ import annotations

import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — bump VERSION when upgrading
# ---------------------------------------------------------------------------

VERSION = "0.2.0"

# (release_asset_name, target_filename_in_bin_dir)
_ASSETS: list[tuple[str, str]] = [
    (f"peach-linux-v{VERSION}.tar.gz", "peach-linux"),
    (f"peach-macos-arm-v{VERSION}.tar.gz", "peach-macos-arm"),
    (f"peach-macos-intel-v{VERSION}.tar.gz", "peach-macos-intel"),
    (f"peach-windows-v{VERSION}.zip", "peach-windows.exe"),
]

_BASE_URL = f"https://github.com/kalink0/peach-forensics/releases/download/v{VERSION}"

_BIN_DIR = Path(__file__).parent.parent / "crush" / "bin" / "peach"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path) -> None:
    print(f"  Downloading {url.split('/')[-1]} …", end="", flush=True)
    urllib.request.urlretrieve(url, dest)
    print(f" {dest.stat().st_size // 1024} KB")


def _extract_single_file(archive: Path, target: Path) -> None:
    """Extract the one file peach's release archives contain (flat, no nesting)."""
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if len(members) != 1:
                raise ValueError(f"Expected exactly one file in {archive.name}, found {len(members)}")
            target.write_bytes(zf.read(members[0].filename))
    else:
        with tarfile.open(archive, "r:gz") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            if len(members) != 1:
                raise ValueError(f"Expected exactly one file in {archive.name}, found {len(members)}")
            src = tf.extractfile(members[0])
            if src is None:
                raise ValueError(f"Could not read {members[0].name} from {archive.name}")
            target.write_bytes(src.read())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    _BIN_DIR.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []

    for asset_name, target_name in _ASSETS:
        target = _BIN_DIR / target_name
        archive = _BIN_DIR / asset_name
        url = f"{_BASE_URL}/{asset_name}"

        print(f"\n[{target_name}]")

        if target.exists():
            print("  Already present — skipping (delete to re-download)")
            continue

        try:
            _download(url, archive)
            _extract_single_file(archive, target)
            archive.unlink(missing_ok=True)

            if not target_name.endswith(".exe"):
                target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            print(f"  -> {target}")

        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: {exc}")
            errors.append(f"{target_name}: {exc}")
            archive.unlink(missing_ok=True)

    (_BIN_DIR / "VERSION.txt").write_text(VERSION)

    print()
    if errors:
        print("Some downloads failed:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("All binaries downloaded successfully.")


if __name__ == "__main__":
    main()
