# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""A viewer's one-line "Value:" field (a read-only QLineEdit), always holding
the whole value.

QLineEdit.setText() cuts anything past maxLength() without notice, and
maxLength() defaults to 32,767 characters -- a long string or a blob of more
than ~10,900 bytes as hex used to end early while looking complete. That
default is only a setting: show_value() lifts it to the largest length Qt
takes, so the field holds the complete value.
"""
from __future__ import annotations

from PySide6.QtWidgets import QLineEdit

# The largest maxLength() QLineEdit accepts (a C int).
_NO_LIMIT = 2**31 - 1


def value_text(value: str | bytes) -> str:
    """*value* as the field shows (and Copy value copies) it: a blob as its
    bytes in space-separated hex, a string as it is."""
    return value.hex(" ") if isinstance(value, bytes) else value


def show_value(field: QLineEdit, value: str | bytes) -> None:
    """Put the whole of *value* into *field*, never cut."""
    if field.maxLength() != _NO_LIMIT:
        field.setMaxLength(_NO_LIMIT)
    field.setText(value_text(value))
    field.setCursorPosition(0)
