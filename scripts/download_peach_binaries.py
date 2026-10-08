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

import hashlib
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — bump VERSION and update SHA256 when upgrading
# ---------------------------------------------------------------------------

# The only place the bundled version is set: the release and nightly
# workflows run this script too.
VERSION = "0.9.2"

# (release_asset_name, target_filename_in_bin_dir, sha256)
# sha256 of the release asset (GitHub shows it as the asset's digest).
# macOS is a single universal (arm64+x86_64) binary as of v0.2.1 -- peach used
# to ship two arch-specific downloads (peach-macos-arm / peach-macos-intel).
_ASSETS: list[tuple[str, str, str]] = [
    (
        f"peach-linux-v{VERSION}.tar.gz",
        "peach-linux",
        "124a7d6236783d708bb1931bd3ff823215d2e9679ae55ded3c692ff9560c6068",
    ),
    (
        f"peach-macos-v{VERSION}.tar.gz",
        "peach-macos",
        "27f8a4fd42e454c23164ca2876ebb3255405f81bcb419ab03404d81cdc0fd5d3",
    ),
    (
        f"peach-windows-v{VERSION}.zip",
        "peach-windows.exe",
        "13b4b289e88fb53f7808a5132f46ca9bc5e7e808adca7c364fb1ec46fb4ee4d5",
    ),
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


def _verify_sha256(path: Path, expected: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError(
            f"SHA-256 mismatch for {path.name}\n"
            f"  expected: {expected}\n"
            f"  got:      {digest}"
        )


def _extract_single_file(archive: Path, target: Path) -> None:
    """Extract the one file peach's release archives contain (flat, no nesting)."""
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zip_members = [i for i in zf.infolist() if not i.is_dir()]
            if len(zip_members) != 1:
                raise ValueError(f"Expected exactly one file in {archive.name}, found {len(zip_members)}")
            target.write_bytes(zf.read(zip_members[0].filename))
    else:
        with tarfile.open(archive, "r:gz") as tf:
            tar_members = [m for m in tf.getmembers() if m.isfile()]
            if len(tar_members) != 1:
                raise ValueError(f"Expected exactly one file in {archive.name}, found {len(tar_members)}")
            src = tf.extractfile(tar_members[0])
            if src is None:
                raise ValueError(f"Could not read {tar_members[0].name} from {archive.name}")
            target.write_bytes(src.read())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    _BIN_DIR.mkdir(parents=True, exist_ok=True)

    version_file = _BIN_DIR / "VERSION.txt"
    up_to_date = version_file.is_file() and version_file.read_text().strip() == VERSION

    errors: list[str] = []
    downloaded: list[str] = []
    skipped: list[str] = []

    for asset_name, target_name, expected_sha256 in _ASSETS:
        target = _BIN_DIR / target_name
        archive = _BIN_DIR / asset_name
        url = f"{_BASE_URL}/{asset_name}"

        print(f"\n[{target_name}]")

        if target.exists() and up_to_date:
            print(f"  Already present at v{VERSION} — skipping (delete to re-download)")
            skipped.append(target_name)
            continue

        try:
            _download(url, archive)
            _verify_sha256(archive, expected_sha256)
            print("  SHA-256 OK")
            _extract_single_file(archive, target)
            archive.unlink(missing_ok=True)

            if not target_name.endswith(".exe"):
                target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            print(f"  -> {target}")
            downloaded.append(target_name)

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
        print(
            f"Done — {len(downloaded)} downloaded, {len(skipped)} already up to date "
            f"at v{VERSION}."
        )


if __name__ == "__main__":
    main()
