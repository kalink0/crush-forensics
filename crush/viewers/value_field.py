# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Text for a viewer's one-line "Value:" field (a read-only QLineEdit).

QLineEdit.setText() cuts anything past maxLength() (32,767 characters by
default) without notice -- a long string or a blob of more than ~10,900
bytes as hex would simply end early. These helpers show the whole value when
it fits and otherwise the start with an explicit note of the total, so the
field never looks complete when it isn't.
"""
from __future__ import annotations

from PySide6.QtCore import QT_TRANSLATE_NOOP
from PySide6.QtWidgets import QLineEdit

from crush.viewers.generated_text import Gen

_BYTES_NOTE = QT_TRANSLATE_NOOP(
    "GeneratedView", "… ({total:,} B in total; the field shows the first {shown:,})"
)
_TEXT_NOTE = QT_TRANSLATE_NOOP(
    "GeneratedView", "… ({total:,} characters in total; the field shows the first {shown:,})"
)


def _note(template: str, total: int, shown: int) -> str:
    return Gen(template, total=total, shown=shown).pair()[1]


def bytes_text(data: bytes, limit: int) -> str:
    """*data* as space-separated hex, cut with a note if longer than *limit*."""
    full = data.hex(" ")
    if len(full) <= limit:
        return full
    # Room for the note at its longest ("shown" never exceeds "total"), so
    # the actual note always fits; n bytes take 3n - 1 characters.
    room = limit - len(_note(_BYTES_NOTE, len(data), len(data))) - 1
    shown = max(0, (room + 1) // 3)
    return f"{data[:shown].hex(' ')} {_note(_BYTES_NOTE, len(data), shown)}"


def text_text(text: str, limit: int) -> str:
    """*text* as is, cut with a note if longer than *limit*."""
    if len(text) <= limit:
        return text
    shown = max(0, limit - len(_note(_TEXT_NOTE, len(text), len(text))) - 1)
    return f"{text[:shown]} {_note(_TEXT_NOTE, len(text), shown)}"


def show_value(field: QLineEdit, value: str | bytes) -> None:
    """Put *value* into *field* -- complete, or cut with an explicit note."""
    limit = field.maxLength()
    field.setText(bytes_text(value, limit) if isinstance(value, bytes) else text_text(value, limit))
    field.setCursorPosition(0)
