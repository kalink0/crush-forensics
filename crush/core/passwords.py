# SPDX-License-Identifier: Apache-2.0
"""Shared password-flow exceptions for any password-protected source or artifact.

Any VFS backend or parser that supports password-protected content (iTunes
backup keybags, encrypted ZIP/TAR/7z archives, encrypted databases, ...) should
raise these rather than a bare exception, so the UI can react consistently
regardless of which format it was.
"""
from __future__ import annotations


class PasswordRequiredError(ValueError):
    """Raised when a source is password-protected and none was supplied."""


class WrongPasswordError(ValueError):
    """Raised when a supplied password fails to unlock/decrypt a source."""
