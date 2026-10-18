# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Start a new Crush process, for "Restart now" (View → Language).

What is started depends on how this Crush runs:

AppImage        $APPIMAGE -- the .AppImage file, not its mount point,
                which goes away when this process ends.
macOS bundle    `open -n <bundle>.app`, so the app starts as an app.
other frozen    sys.executable (Windows .exe, Linux build folder).
from source     sys.executable -m crush.

The new process gets no arguments: the restart opens an empty window, and
a --language from the original command line would override the language
just chosen.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path


def relaunch_command(
    *,
    frozen: bool | None = None,
    executable: str | None = None,
    environ: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> list[str]:
    """The command that starts Crush again the way it runs now."""
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    executable = sys.executable if executable is None else executable
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    if not frozen:
        return [executable, "-m", "crush"]
    appimage = environ.get("APPIMAGE")
    if appimage:
        return [appimage]
    if platform == "darwin":
        for parent in Path(executable).parents:
            if parent.suffix == ".app":
                return ["open", "-n", str(parent)]
    return [executable]


def relaunch() -> None:
    """Start a new, independent Crush process. Raises OSError when it
    can't be started."""
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        # A PyInstaller build started from itself would otherwise take the
        # running instance's unpacked files, which go away when it ends.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(
        relaunch_command(),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        **kwargs,
    )
