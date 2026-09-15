# SPDX-License-Identifier: Apache-2.0
"""Invoke crush-analyze, the sibling tool providing small curated forensic
analyzer modules (see docs/design/analyzer-runner.md).

Unlike Peach (a separate Rust binary, launched fire-and-forget via
peach_launcher.py), crush-analyze is pure Python and ships as a regular pip
dependency of Crush -- there is no second binary to locate or bundle.
Invocation still goes through a real, isolated OS subprocess, but the
subprocess is Crush re-executing *itself* with a hidden internal-CLI
sentinel as its first argument, rather than shelling out to
`sys.executable -m crush_analyze`. The latter breaks in a PyInstaller
frozen build, where sys.executable is crush.exe itself, not a general
python.exe with crush_analyze on its path -- re-exec'ing the same frozen
executable works identically in dev and frozen builds, since __main__.py
checks for the sentinel before doing anything else (see its dispatch at
the top of main()).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

INTERNAL_CLI_SENTINEL = "--internal-analyzer-cli"


class AnalyzerRunError(Exception):
    """crush-analyze itself couldn't run at all (exit code 2, no JSON
    output) -- bad args, unknown module, or an unwritable output path. A
    module's own "status": "error" result is a normal, successfully
    parsed contract v1 dict, not this exception; contract v1 mandates that
    field exactly so callers can check it directly instead of relying on
    exception handling."""


def _self_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "crush"]


def list_analyzer_modules() -> list[dict[str, Any]]:
    """The bundled module manifest (id/name/module_version/requires) --
    cheap enough to call at Crush startup and cache in the caller."""
    proc = subprocess.run(
        [*_self_command(), INTERNAL_CLI_SENTINEL, "list-modules"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AnalyzerRunError(proc.stderr.strip() or "crush-analyze list-modules failed")
    return json.loads(proc.stdout)  # type: ignore[no-any-return]


def run_analyzer(input_path: Path, *, module_id: str) -> dict[str, Any]:
    """Runs one bundled analyzer module against *input_path* and returns
    the parsed contract v1 result dict."""
    with tempfile.TemporaryDirectory(prefix="crush-analyze-") as tmp:
        output_path = Path(tmp) / "result.json"
        cmd = [
            *_self_command(),
            INTERNAL_CLI_SENTINEL,
            "run",
            "--module",
            module_id,
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)

        if not output_path.exists():
            raise AnalyzerRunError(
                proc.stderr.strip() or f"crush-analyze exited {proc.returncode} with no output"
            )
        return json.loads(output_path.read_text())  # type: ignore[no-any-return]
