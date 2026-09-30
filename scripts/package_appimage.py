#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Package the PyInstaller build (dist/crush) as a Linux AppImage.

Run from the repository root after PyInstaller and the icon step:
    python scripts/package_appimage.py crush-linux-<version>.AppImage

The release and nightly workflows both call this, so the appimagetool and
AppImage runtime versions are pinned here and nowhere else. The type2
runtime is static: the AppImage runs without libfuse2, which current
distributions no longer install.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — bump a version together with its SHA-256 (the release
# asset's digest on GitHub)
# ---------------------------------------------------------------------------

APPIMAGETOOL_VERSION = "1.9.1"
APPIMAGETOOL_SHA256 = "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
RUNTIME_VERSION = "20251108"
RUNTIME_SHA256 = "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

_APPIMAGETOOL_URL = (
    "https://github.com/AppImage/appimagetool/releases/download/"
    f"{APPIMAGETOOL_VERSION}/appimagetool-x86_64.AppImage"
)
_RUNTIME_URL = (
    "https://github.com/AppImage/type2-runtime/releases/download/"
    f"{RUNTIME_VERSION}/runtime-x86_64"
)

_APPRUN = """#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/crush/crush" "$@"
"""

_DESKTOP = """[Desktop Entry]
Type=Application
Name=Crush
Exec=crush
Icon=crush
Categories=Utility;Security;
"""


def _download(url: str, dest: Path, expected_sha256: str) -> None:
    print(f"Downloading {url} …", flush=True)
    urllib.request.urlretrieve(url, dest)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != expected_sha256:
        sys.exit(
            f"SHA-256 mismatch for {dest.name}\n"
            f"  expected: {expected_sha256}\n"
            f"  got:      {digest}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="AppImage file to write")
    parser.add_argument("--dist", type=Path, default=Path("dist/crush"),
                        help="PyInstaller output folder (default: dist/crush)")
    parser.add_argument("--icon", type=Path, default=Path("crush_icon_256.png"),
                        help="PNG icon (default: crush_icon_256.png)")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        tool = work / "appimagetool"
        runtime = work / "runtime-x86_64"
        _download(_APPIMAGETOOL_URL, tool, APPIMAGETOOL_SHA256)
        _download(_RUNTIME_URL, runtime, RUNTIME_SHA256)
        tool.chmod(0o755)

        appdir = work / "AppDir"
        shutil.copytree(args.dist, appdir / "crush", symlinks=True)
        (appdir / "AppRun").write_text(_APPRUN)
        (appdir / "AppRun").chmod(0o755)
        (appdir / "crush.desktop").write_text(_DESKTOP)
        shutil.copyfile(args.icon, appdir / "crush.png")

        # --appimage-extract-and-run: CI runners have no FUSE to mount the tool.
        subprocess.run(
            [str(tool), "--appimage-extract-and-run", "--runtime-file", str(runtime),
             str(appdir), str(args.output.resolve())],
            check=True,
            env={**os.environ, "ARCH": "x86_64"},
        )


if __name__ == "__main__":
    main()
