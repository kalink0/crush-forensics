# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Optional Pillow plugins for HEIF/HEIC/AVIF and JPEG XL, registered once.

Shared by the image parser (frame count) and the image viewer (decode), so
both see the same set of decodable formats.
"""
from __future__ import annotations

_missing: list[str] | None = None


def ensure_pil_plugins() -> list[str]:
    """Register the optional plugins (once) and return the names of the
    ones that are not installed."""
    global _missing
    if _missing is not None:
        return _missing
    missing: list[str] = []
    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except ImportError:
        missing.append("pillow-heif")
    try:
        import pillow_jxl  # noqa: F401
    except ImportError:
        missing.append("pillow-jxl-plugin")
    _missing = missing
    return missing
