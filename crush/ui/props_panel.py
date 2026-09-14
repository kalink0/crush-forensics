# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Properties panel — right dock, shows file metadata for the selected artifact."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QWidget,
)

from crush.core.vfs import VFS, ITunesBackupVFS, VFSNode
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll

_SELECTABLE = (
    Qt.TextInteractionFlag.TextSelectableByMouse
    | Qt.TextInteractionFlag.TextSelectableByKeyboard
)


class PropertiesPanel(QScrollArea):
    # (node, vfs) — emitted when the user clicks "Open Format Info…"; the
    # panel itself has no format knowledge base access, that's up to whoever
    # connects this (see MainWindow._show_format_info, which also already
    # handles the "no format identified" case gracefully).
    format_info_requested = Signal(object, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self._container = QWidget()
        self._layout = QFormLayout(self._container)
        self._layout.setContentsMargins(8, 8, 8, 8)
        self._layout.setSpacing(4)
        self.setWidget(self._container)
        install_horizontal_wheel_scroll(self, smooth_item_scroll=False)
        self._current_node: VFSNode | None = None
        self._current_vfs: VFS | None = None

    def clear(self) -> None:
        while self._layout.rowCount():
            self._layout.removeRow(0)

    def update_properties(
        self, node: VFSNode, metadata: dict[str, Any], vfs: VFS | None = None,
    ) -> None:
        """Repopulate the panel with metadata for the given node.

        *vfs*, when supplied alongside a format having actually been
        identified (metadata contains "Format"), enables an "Open Format
        Info…" button that re-identifies the format and opens the full
        reference dialog (all known links, not just one).
        """
        self.clear()
        self._current_node = node
        self._current_vfs = vfs

        # File name as header
        header = QLabel(f"<b>{node.name}</b>")
        header.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(header)

        # Path (may be long — allow wrapping)
        path_label = QLabel(node.path)
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow("Path:", path_label)

        # iTunes backups store files flat under a fileID (SHA1) sharded
        # directory layout; the tree above shows the resolved domain/
        # relativePath, but the original on-disk name is forensically
        # relevant too.
        if isinstance(vfs, ITunesBackupVFS):
            original = vfs.original_backup_path(node)
            if original is not None:
                orig_label = QLabel(original)
                orig_label.setWordWrap(True)
                orig_label.setTextInteractionFlags(_SELECTABLE)
                self._layout.addRow("Backup File ID:", orig_label)

        # Fixed position (not after the parser metadata, whose length varies)
        # and only shown once a format was actually identified.
        if vfs is not None and "Format" in metadata:
            info_btn = QPushButton("Open Format Info…")
            info_btn.clicked.connect(
                lambda: self.format_info_requested.emit(self._current_node, self._current_vfs)
            )
            self._layout.addRow(info_btn)

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

    def show_analyzer_result(self, result: dict[str, Any]) -> None:
        """Populates the panel with a crush-analyze contract v1 result's
        own analyzer/run metadata instead of file metadata.

        An analyzer result has no single owning VFSNode — its source was a
        temp extraction, already deleted by the time the tab is shown — so
        update_properties() doesn't apply here. Provenance (what ran, when,
        against what input, with which tool version) is the forensically
        relevant analogue: the same kind of question the timestamps/format
        info above answer for an ordinary file, answered for an analysis
        run instead.
        """
        self.clear()
        self._current_node = None
        self._current_vfs = None

        analyzer = result.get("analyzer", {})
        run = result.get("run", {})

        header = QLabel(f"<b>{analyzer.get('name', analyzer.get('id', 'Analyzer result'))}</b>")
        header.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(header)

        def _row(label: str, value: object) -> None:
            lbl = QLabel(str(value) if value not in (None, "") else "—")
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(f"{label}:", lbl)

        _row("Module ID", analyzer.get("id"))
        tool = f"{analyzer.get('tool', 'crush-analyze')} {analyzer.get('tool_version', '')}".strip()
        _row("Tool", tool)
        _row("Module version", analyzer.get("module_version"))
        _row("Input path", run.get("input_path"))
        _row("Started at", run.get("started_at"))
        _row("Duration", f"{run.get('duration_ms', 0):,} ms")

        status = result.get("status", "ok")
        status_lbl = QLabel(status)
        status_lbl.setTextInteractionFlags(_SELECTABLE)
        if status == "error":
            status_lbl.setStyleSheet("color: #b02a37; font-weight: bold;")
        elif status == "partial":
            status_lbl.setStyleSheet("color: #997404; font-weight: bold;")
        self._layout.addRow("Status:", status_lbl)

        warnings = result.get("warnings", [])
        if warnings:
            _row("Warnings", str(len(warnings)))

        if run.get("dev_mode"):
            dev_lbl = QLabel("Yes — unvetted external module")
            dev_lbl.setStyleSheet("color: #997404; font-weight: bold;")
            dev_lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow("Dev mode:", dev_lbl)

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
