#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Download (or build) the FlatBuffers compiler flatc for Crush's platforms.

Run from the repository root:
    python scripts/download_flatc_binaries.py

flatc compiles a text schema (.fbs) to a binary schema (.bfbs), which the
FlatBuffers viewer and the BLOB Inspector decode with. Places the binaries in
crush/bin/flatc/ with the filenames expected by
crush.parsers.flatbuffers_schema._PLATFORM_BINARY_MAP, and writes VERSION.txt
next to them (read at runtime by get_bundled_flatc_version(), shown in the
About dialog and in a schema's "compiled by" note).

- Linux x86_64 and Windows x86_64: the official release binaries
  (https://github.com/google/flatbuffers/releases), downloaded on every OS.
- macOS (one universal arm64 + x86_64 binary) and Linux aarch64: built from
  the release's source tarball, only on that OS. The official macOS binaries
  require macOS 15.5, Crush runs on macOS 13 and later, so the build targets
  macOS 13.0; there is no official Linux aarch64 binary. Needs cmake and a
  C++ compiler.
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — bump VERSION and update every SHA-256 when upgrading
# ---------------------------------------------------------------------------

# The only place the bundled version is set: the release and nightly
# workflows run this script too.
VERSION = "25.12.19"

# (release_asset_name, target_filename_in_bin_dir, sha256 of the asset as
# GitHub lists it in the release's asset digest)
_ASSETS: list[tuple[str, str, str]] = [
    (
        "Linux.flatc.binary.g++-13.zip",
        "flatc-linux-x86_64",
        "9f87066dc5dfa7fe02090b55bab5f3e55df03e32c9b0cdf229004ade7d091039",
    ),
    (
        "Windows.flatc.binary.zip",
        "flatc-windows-x86_64.exe",
        "fff9445c9db907227bc64b54cc98743084c4949282aa4e576cff6a955724ddc8",
    ),
]

# Source tarball of the same release (sha256 as Homebrew pins it too).
_SOURCE_URL = f"https://github.com/google/flatbuffers/archive/refs/tags/v{VERSION}.tar.gz"
_SOURCE_SHA256 = "f81c3162b1046fe8b84b9a0dbdd383e24fdbcf88583b9cb6028f90d04d90696a"

# Lowest macOS the built binary runs on: Crush's own floor (PySide6 wheels).
_MACOS_DEPLOYMENT_TARGET = "13.0"

_BASE_URL = f"https://github.com/google/flatbuffers/releases/download/v{VERSION}"

_BIN_DIR = Path(__file__).parent.parent / "crush" / "bin" / "flatc"

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


def _extract_binary_from_zip(archive: Path, target: Path) -> None:
    # The release zips hold exactly the flatc / flatc.exe binary.
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if not info.is_dir() and Path(info.filename).name in ("flatc", "flatc.exe"):
                target.write_bytes(zf.read(info.filename))
                return
    raise FileNotFoundError(f"flatc binary not found inside {archive.name}")


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _check_version(binary: Path) -> None:
    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
    if VERSION not in out.stdout:
        raise ValueError(f"{binary.name} reports {out.stdout.strip()!r}, expected {VERSION}")


def _source_build_target() -> tuple[str, list[str]] | None:
    """(target filename, extra cmake args) when this OS builds flatc from
    source, else None."""
    if sys.platform == "darwin":
        return "flatc-macos", [
            "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64",
            f"-DCMAKE_OSX_DEPLOYMENT_TARGET={_MACOS_DEPLOYMENT_TARGET}",
        ]
    if sys.platform.startswith("linux") and platform.machine() == "aarch64":
        return "flatc-linux-aarch64", []
    return None


def _build_from_source(target: Path, cmake_args: list[str]) -> None:
    cmake = shutil.which("cmake")
    if cmake is None:
        raise FileNotFoundError("cmake not found on PATH (needed to build flatc from source)")
    with tempfile.TemporaryDirectory(prefix="flatc-src-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "source.tar.gz"
        _download(_SOURCE_URL, archive)
        _verify_sha256(archive, _SOURCE_SHA256)
        print("  SHA-256 OK")
        with tarfile.open(archive, "r:gz") as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(tmp_path, filter="data")
            else:  # Python without the extraction filters
                tf.extractall(tmp_path)  # noqa: S202 -- pinned, hash-verified archive
        source = tmp_path / f"flatbuffers-{VERSION}"
        build = tmp_path / "build"
        env = dict(os.environ)
        if sys.platform == "darwin":
            env["MACOSX_DEPLOYMENT_TARGET"] = _MACOS_DEPLOYMENT_TARGET
        subprocess.run(
            [
                cmake, "-S", str(source), "-B", str(build),
                "-DCMAKE_BUILD_TYPE=Release",
                "-DFLATBUFFERS_BUILD_TESTS=OFF",
                "-DFLATBUFFERS_BUILD_FLATLIB=OFF",
                "-DFLATBUFFERS_BUILD_FLATHASH=OFF",
                *cmake_args,
            ],
            check=True, env=env,
        )
        subprocess.run(
            [cmake, "--build", str(build), "--target", "flatc", "--config", "Release",
             "--parallel"],
            check=True, env=env,
        )
        built = next((p for p in build.rglob("flatc") if p.is_file()), None)
        if built is None:
            raise FileNotFoundError("flatc not found in the build directory")
        shutil.copyfile(built, target)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    _BIN_DIR.mkdir(parents=True, exist_ok=True)

    version_file = _BIN_DIR / "VERSION.txt"
    up_to_date = version_file.is_file() and version_file.read_text().strip() == VERSION

    errors: list[str] = []
    done: list[str] = []
    skipped: list[str] = []

    for asset_name, target_name, expected_sha256 in _ASSETS:
        target = _BIN_DIR / target_name
        archive = _BIN_DIR / asset_name
        print(f"\n[{target_name}]")
        if target.exists() and up_to_date:
            print(f"  Already present at v{VERSION} — skipping (delete to re-download)")
            skipped.append(target_name)
            continue
        try:
            _download(f"{_BASE_URL}/{asset_name}", archive)
            _verify_sha256(archive, expected_sha256)
            print("  SHA-256 OK")
            _extract_binary_from_zip(archive, target)
            archive.unlink(missing_ok=True)
            if not target_name.endswith(".exe"):
                _make_executable(target)
            print(f"  -> {target}")
            done.append(target_name)
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: {exc}")
            errors.append(f"{target_name}: {exc}")
            archive.unlink(missing_ok=True)

    build = _source_build_target()
    if build is None:
        print("\n[flatc-macos, flatc-linux-aarch64]")
        print("  Built from source on macOS / Linux aarch64 only — not on this OS")
    else:
        target_name, cmake_args = build
        target = _BIN_DIR / target_name
        print(f"\n[{target_name}] (built from source)")
        if target.exists() and up_to_date:
            print(f"  Already present at v{VERSION} — skipping (delete to rebuild)")
            skipped.append(target_name)
        else:
            try:
                _build_from_source(target, cmake_args)
                _make_executable(target)
                _check_version(target)
                print(f"  -> {target}")
                done.append(target_name)
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR: {exc}")
                errors.append(f"{target_name}: {exc}")

    (_BIN_DIR / "VERSION.txt").write_text(VERSION)

    print()
    if errors:
        print("Some binaries failed:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    print(f"Done — {len(done)} fetched/built, {len(skipped)} already up to date at v{VERSION}.")


if __name__ == "__main__":
    main()
