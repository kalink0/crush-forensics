#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Download Mandiant unifiedlog_iterator binaries for all supported platforms.

Run from the repository root:
    python scripts/download_unifiedlog_binaries.py

Downloads release assets from https://github.com/mandiant/macos-UnifiedLogs
and places them in crush/bin/unifiedlog_iterator/ with the filenames expected
by UnifiedLogConverter._select_binary(). Also writes VERSION.txt next to
them, read at runtime by unified_log_parser.get_bundled_ul_version() to show
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

VERSION = "0.6.0"

# (release_asset_name, target_filename_in_bin_dir, sha256_or_None)
# sha256 is optional: set to None to skip verification, or fill in after
# downloading once and running: sha256sum <file>
_ASSETS: list[tuple[str, str, str | None]] = [
    (
        f"unifiedlog_iterator-v{VERSION}-x86_64-unknown-linux-gnu.tar.gz",
        "unifiedlog_iterator-x86_64-unknown-linux-gnu",
        None,
    ),
    (
        f"unifiedlog_iterator-v{VERSION}-aarch64-unknown-linux-gnu.tar.gz",
        "unifiedlog_iterator-aarch64-unknown-linux-gnu",
        None,
    ),
    (
        f"unifiedlog_iterator-v{VERSION}-x86_64-apple-darwin.tar.gz",
        "unifiedlog_iterator-x86_64-apple-darwin",
        None,
    ),
    (
        f"unifiedlog_iterator-v{VERSION}-aarch64-apple-darwin.tar.gz",
        "unifiedlog_iterator-aarch64-apple-darwin",
        None,
    ),
    (
        f"unifiedlog_iterator-v{VERSION}-x86_64-pc-windows-msvc.zip",
        "unifiedlog_iterator-x86_64-pc-windows-msvc.exe",
        None,
    ),
]

_BASE_URL = (
    f"https://github.com/mandiant/macos-UnifiedLogs/releases/download/"
    f"v{VERSION}"
)

_BIN_DIR = (
    Path(__file__).parent.parent / "crush" / "bin" / "unifiedlog_iterator"
)

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


def _extract_binary_from_tar(archive: Path, target: Path) -> None:
    # Match the exact basename, not a substring: release archives also
    # contain a README.md/LICENSE whose *path* contains "unifiedlog_iterator"
    # (the enclosing directory is named after the release asset) — a
    # substring match picks whichever of those come first in tar order,
    # which changed between v0.5.1 and v0.6.0 and silently extracted the
    # README as the "binary".
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and Path(member.name).name == "unifiedlog_iterator":
                src = tf.extractfile(member)
                if src is None:
                    continue
                target.write_bytes(src.read())
                return
    raise FileNotFoundError(
        f"unifiedlog_iterator binary not found inside {archive.name}"
    )


def _extract_binary_from_zip(archive: Path, target: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if not info.is_dir() and Path(info.filename).name == "unifiedlog_iterator.exe":
                target.write_bytes(zf.read(info.filename))
                return
    raise FileNotFoundError(
        f"unifiedlog_iterator binary not found inside {archive.name}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    _BIN_DIR.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []

    for asset_name, target_name, expected_sha256 in _ASSETS:
        target = _BIN_DIR / target_name
        archive = _BIN_DIR / asset_name
        url = f"{_BASE_URL}/{asset_name}"

        print(f"\n[{target_name}]")

        if target.exists():
            print("  Already present — skipping (delete to re-download)")
            continue

        try:
            _download(url, archive)

            if expected_sha256:
                _verify_sha256(archive, expected_sha256)
                print("  SHA-256 OK")

            if asset_name.endswith(".tar.gz"):
                _extract_binary_from_tar(archive, target)
            else:
                _extract_binary_from_zip(archive, target)

            archive.unlink(missing_ok=True)

            # Make POSIX binaries executable
            if not asset_name.endswith(".zip"):
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
