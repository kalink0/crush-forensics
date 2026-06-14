# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Properties panel — right dock, shows file metadata for the selected artifact."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QScrollArea,
    QWidget,
)

from crush.core.vfs import VFSNode

_SELECTABLE = (
    Qt.TextInteractionFlag.TextSelectableByMouse
    | Qt.TextInteractionFlag.TextSelectableByKeyboard
)


class PropertiesPanel(QScrollArea):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self._container = QWidget()
        self._layout = QFormLayout(self._container)
        self._layout.setContentsMargins(8, 8, 8, 8)
        self._layout.setSpacing(4)
        self.setWidget(self._container)

    def clear(self) -> None:
        while self._layout.rowCount():
            self._layout.removeRow(0)

    def update_properties(self, node: VFSNode, metadata: dict[str, Any]) -> None:
        """Repopulate the panel with metadata for the given node."""
        self.clear()

        # File name as header
        header = QLabel(f"<b>{node.name}</b>")
        header.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(header)

        # Path (may be long — allow wrapping)
        path_label = QLabel(node.path)
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow("Path:", path_label)

        # Timestamps (MACB) — always show all four, mark unavailable ones clearly
        self._add_timestamp("Modified (UTC)", node.modified)
        self._add_timestamp("Accessed (UTC)", node.accessed)
        self._add_timestamp("Changed (UTC)", node.changed)
        self._add_timestamp("Birth (UTC)", node.birth)

        has_modified = bool(node.modified)
        has_others = bool(node.accessed or node.changed or node.birth)
        if has_modified and not has_others:
            note = QLabel("<i>Only mtime is stored in ZIP/TAR archives.<br>"
                          "Accessed, Changed, and Birth are not available.</i>")
            note.setWordWrap(True)
            note.setStyleSheet("color: gray; font-size: 10px;")
            self._layout.addRow(note)

        # Parser-supplied metadata
        for key, val in metadata.items():
            lbl = QLabel(str(val))
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(f"{key}:", lbl)

    def _add_timestamp(self, label: str, ts_value: float) -> None:
        if ts_value:
            ts = datetime.fromtimestamp(ts_value, tz=timezone.utc)
            text = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            text = "—"
        lbl = QLabel(text)
        lbl.setTextInteractionFlags(_SELECTABLE)
        if not ts_value:
            lbl.setStyleSheet("color: gray;")
        self._layout.addRow(f"{label}:", lbl)
