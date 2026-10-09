#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""CI smoke test: does a frozen Crush build offer every curated analyzer module?

Runs the built executable exactly the way Run Analyzer does
(`<exe> --internal-analyzer-cli list-modules`) and fails unless every id in
crush.core.analyzer_launcher.CURATED_MODULE_IDS is listed. crush-analyze
discovers its vendored modules as .py files on disk, which a PyInstaller
build only contains if crush-analyze's hook bundles them -- v0.20.0-v0.22.0
shipped without, and Run Analyzer reported no modules.

Usage:
    python scripts/smoke_test_frozen_analyzers.py EXECUTABLE [ARG ...]

Extra ARGs go before the sentinel, e.g. `--appimage-extract-and-run` for an
AppImage on a runner without FUSE.
"""
from __future__ import annotations

import json
import subprocess
import sys

from crush.core.analyzer_launcher import CURATED_MODULE_IDS, INTERNAL_CLI_SENTINEL


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} EXECUTABLE [ARG ...]", file=sys.stderr)
        return 2

    command = [*sys.argv[1:], INTERNAL_CLI_SENTINEL, "list-modules"]
    print(f"Running: {' '.join(command)}")
    proc = subprocess.run(command, capture_output=True, text=True, timeout=600)
    if proc.stderr.strip():
        print(f"stderr:\n{proc.stderr.strip()}")
    if proc.returncode != 0:
        print(f"FAIL: exited {proc.returncode}")
        return 1

    try:
        listed = {module["id"] for module in json.loads(proc.stdout)}
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        print(f"FAIL: list-modules output is not a module list ({exc}):\n{proc.stdout}")
        return 1

    print(f"Listed modules: {', '.join(sorted(listed))}")
    missing = sorted(CURATED_MODULE_IDS - listed)
    if missing:
        print(f"FAIL: curated analyzer modules missing from the build: {', '.join(missing)}")
        return 1
    print("All curated analyzer modules present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
