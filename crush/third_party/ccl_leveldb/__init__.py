# SPDX-License-Identifier: MIT
# Copyright 2026 - now Marco Neumann (kalink0)
"""Vendored ccl_leveldb (see LICENSE)."""

import sys

# ccl_leveldb imports ccl_simplesnappy by its bare name, as an installed
# package ("import ccl_simplesnappy", "from ccl_simplesnappy.ccl_simplesnappy
# import check_masked_crc"). Registering the vendored copy under those names
# first resolves both from source and in a frozen (PyInstaller) build, as
# crush/core/raw_image.py does for ewfprobe.
from crush.third_party import ccl_simplesnappy as _ccl_simplesnappy
from crush.third_party.ccl_simplesnappy import ccl_simplesnappy as _ccl_simplesnappy_module

sys.modules.setdefault("ccl_simplesnappy", _ccl_simplesnappy)
sys.modules.setdefault("ccl_simplesnappy.ccl_simplesnappy", _ccl_simplesnappy_module)

from .ccl_leveldb import (  # noqa: E402,F401
    RawLevelDb,
    Record,
    FileType,
    KeyState,
)

__all__ = [
    "RawLevelDb",
    "Record",
    "FileType",
    "KeyState",
]
