# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Crush — Digital Forensic Analysis Workbench."""

__version__ = "0.18.0"
__build__ = ""  # filled in by CI (e.g. "20260329-nightly")
__release_year__ = "2026"
__author__ = "Marco Neumann (kalink0)"


def display_version() -> str:
    """Return version string for UI display, appending build tag when set."""
    if __build__:
        return f"{__version__} ({__build__})"
    return __version__
