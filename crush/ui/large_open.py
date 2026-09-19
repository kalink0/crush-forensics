# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Ask before loading a file that could exhaust the machine's memory.

Nearly every parser and viewer needs a file's bytes in memory (often several
times over: raw bytes, decoded structures, Qt widgets). Loading a multi-GB
file that way gets Crush -- and whatever else is running -- killed by the OS.
Nothing is cut short here: the file is either opened whole or not at all, and
the user chooses what to do instead when it does not safely fit.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from PySide6.QtWidgets import QMessageBox, QWidget

from crush.core.sysmem import available_memory
from crush.ui.extract_dialog import format_size

# Share of free RAM above which opening a file is put to the user.
WARN_FRACTION = 0.25
# Share above which "open anyway" is not offered: the file (plus the copies
# parsers make of it) cannot realistically fit.
BLOCK_FRACTION = 0.80
# Stand-in for free RAM where the platform cannot report it.
FALLBACK_AVAILABLE = 4 * 1024**3


class Decision(Enum):
    PROCEED = "proceed"
    NEW_WINDOW = "new_window"
    EXPORT = "export"
    CANCEL = "cancel"


class Level(Enum):
    OK = "ok"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Assessment:
    size: int
    available: int | None
    level: Level

    @property
    def basis(self) -> int:
        return self.available if self.available is not None else FALLBACK_AVAILABLE


def assess(size: int, available: int | None) -> Assessment:
    basis = available if available is not None else FALLBACK_AVAILABLE
    if size > basis * BLOCK_FRACTION:
        level = Level.BLOCK
    elif size > basis * WARN_FRACTION:
        level = Level.WARN
    else:
        level = Level.OK
    return Assessment(size=size, available=available, level=level)


def confirm_large_open(
    parent: QWidget, name: str, size: int, *, can_open_as_source: bool
) -> Decision:
    """PROCEED when the file is small enough to just open; otherwise ask."""
    result = assess(size, available_memory())
    if result.level is Level.OK:
        return Decision.PROCEED

    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("Large file")
    ram = (
        f"{format_size(result.available)} of memory is free"
        if result.available is not None
        else "the free memory could not be determined"
    )
    if result.level is Level.WARN:
        box.setText(
            f"'{name}' is {format_size(size)}, and {ram}.\n\n"
            "Opening it loads the whole file into memory, usually several times over, "
            "and can slow down or crash Crush and other programs."
        )
    else:
        box.setText(
            f"'{name}' is {format_size(size)}, and {ram}.\n\n"
            "It cannot be loaded into memory safely, so it is not offered here."
        )

    proceed = None
    if result.level is Level.WARN:
        proceed = box.addButton("Open anyway", QMessageBox.ButtonRole.DestructiveRole)
    new_window = None
    if can_open_as_source:
        new_window = box.addButton("Open in New Window", QMessageBox.ButtonRole.AcceptRole)
    export = box.addButton("Export…", QMessageBox.ButtonRole.ActionRole)
    cancel = box.addButton(QMessageBox.StandardButton.Cancel)
    box.setDefaultButton(new_window or cancel)
    box.exec()

    clicked = box.clickedButton()
    if proceed is not None and clicked is proceed:
        return Decision.PROCEED
    if new_window is not None and clicked is new_window:
        return Decision.NEW_WINDOW
    if clicked is export:
        return Decision.EXPORT
    return Decision.CANCEL
