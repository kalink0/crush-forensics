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
from crush.core.issues import render_value
from crush.ui import open_url
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.ui.i18n import translate

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
        header = QLabel(f"<b>{node.name}</b>")  # i18n: keep -- markup/layout only
        header.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(header)

        # Path (may be long — allow wrapping)
        path_label = QLabel(node.path)
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(translate("PropertiesPanel", "Path:"), path_label)

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
                self._layout.addRow(translate("PropertiesPanel", "Backup File ID:"), orig_label)

        # Fixed position (not after the parser metadata, whose length varies)
        # and only shown once a format was actually identified.
        if vfs is not None and "Format" in metadata:
            info_btn = QPushButton(translate("PropertiesPanel", "Open Format Info…"))
            info_btn.clicked.connect(
                lambda: self.format_info_requested.emit(self._current_node, self._current_vfs)
            )
            self._layout.addRow(info_btn)

        # Timestamps (MACB) — always show all four, mark unavailable ones clearly
        self._add_timestamp(translate("PropertiesPanel", "Modified (UTC)"), node.modified)
        self._add_timestamp(translate("PropertiesPanel", "Accessed (UTC)"), node.accessed)
        self._add_timestamp(translate("PropertiesPanel", "Changed (UTC)"), node.changed)
        self._add_timestamp(translate("PropertiesPanel", "Birth (UTC)"), node.birth)

        has_modified = bool(node.modified)
        has_others = bool(node.accessed or node.changed or node.birth)
        if has_modified and not has_others:
            note = QLabel(
                translate(
                    "PropertiesPanel",
                    "<i>Only mtime is stored in ZIP/TAR archives.<br>"
                    "Accessed, Changed, and Birth are not available.</i>",
                )
            )
            note.setWordWrap(True)
            note.setStyleSheet("color: gray; font-size: 10px;")
            self._layout.addRow(note)

        # Parser-supplied metadata (values may be ParseIssues)
        for key, val in metadata.items():
            lbl = QLabel(render_value(val))
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(translate("PropertiesPanel", "{key}:").format(key=key), lbl)

    def show_analyzer_result(
        self, result: dict[str, Any], title: str | None = None, relevance: str | None = None
    ) -> None:
        """Populates the panel with a crush-analyze contract v1 result's
        own analyzer/run metadata instead of file metadata.

        An analyzer result has no single owning VFSNode — its source was a
        temp extraction, already deleted by the time the tab is shown — so
        update_properties() doesn't apply here. Provenance (what ran, when,
        against what input, with which tool version) is the forensically
        relevant analogue: the same kind of question the timestamps/format
        info above answer for an ordinary file, answered for an analysis
        run instead -- including which underlying parser this result is
        actually based on: a "Source" link pinned to the exact upstream
        commit crush-analyze's vendored copy was fetched from (contract
        v1's `analyzer.source`). And which evidence this result is based
        on: every file that matched the module's own declared paths glob
        (`run.source_files`).

        *title* is the display name the caller already resolved for the tab
        (curated modules go through MainWindow's own
        _ANALYZER_MODULE_DISPLAY_NAMES override, e.g. "Installed
        Applications" instead of the contract's raw LEAPP-internal
        "Application State") -- passed in so the header matches the tab
        instead of re-deriving a possibly different name from the contract
        directly. Falls back to the contract's own name/id when the caller
        has none (e.g. a bare result with no tab context).

        *relevance* is Crush's own curated "what does this result actually
        tell you" text (MainWindow's `_ANALYZER_MODULE_FORENSIC_RELEVANCE`)
        -- the analyzer-module analogue of formats.db's hand-written
        forensic_relevance field, not something read from crush-analyze's
        own manifest. `None` for any module without a curated entry yet --
        omitted rather than shown empty.
        """
        self.clear()
        self._current_node = None
        self._current_vfs = None

        analyzer = result.get("analyzer", {})
        run = result.get("run", {})

        name = title or analyzer.get(
            "name", analyzer.get("id", translate("PropertiesPanel", "Analyzer result"))
        )
        header = QLabel(f"<b>{name}</b>")  # i18n: keep -- markup/layout only
        header.setTextInteractionFlags(_SELECTABLE)
        self._layout.addRow(header)

        if relevance:
            relevance_lbl = QLabel(relevance)
            relevance_lbl.setWordWrap(True)
            relevance_lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(relevance_lbl)

        def _row(label: str, value: object) -> None:
            lbl = QLabel(str(value) if value not in (None, "") else "—")
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(translate("PropertiesPanel", "{label}:").format(label=label), lbl)

        _row(translate("PropertiesPanel", "Module ID"), analyzer.get("id"))
        tool = f"{analyzer.get('tool', 'crush-analyze')} {analyzer.get('tool_version', '')}".strip()
        _row(translate("PropertiesPanel", "Tool"), tool)
        _row(translate("PropertiesPanel", "Module version"), analyzer.get("module_version"))

        # Which underlying parser this result is based on -- a curated
        # module's *own* version (module_version, above) is LEAPP's own
        # declared last-update date, not the same thing as which upstream
        # commit crush-analyze's vendored copy was fetched from. `source` is
        # None for the stub module (no commit to pin to).
        source = analyzer.get("source")
        if source:
            parser_file = source.get("path", "").rsplit("/", 1)[-1] or source.get("path")
            _row(translate("PropertiesPanel", "Parser file"), parser_file)
            repo_name = source.get("repo", "").rstrip("/").rsplit("/", 1)[-1]
            commit = source.get("commit", "")
            link_text = f"{repo_name} @ {commit[:8]}" if commit else repo_name
            link = QLabel(
                f'<a href="{source.get("url", "")}">{link_text}</a>'  # i18n: keep -- markup only
            )
            link.linkActivated.connect(open_url)
            link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            if commit:
                link.setToolTip(commit)
            self._layout.addRow(translate("PropertiesPanel", "Source:"), link)

        _row(translate("PropertiesPanel", "Input path"), run.get("input_path"))

        # Every file (relative to input_path) that matched the module's own
        # declared paths glob -- what the data in this result is actually
        # based on, the data-side analogue of the Source link above (which
        # answers the same question for the code). Missing on an older
        # crush-analyze result (added after this field existed) -> no row,
        # not a misleading empty one. Plain text, not rich text: these are
        # real filenames out of the analyzed evidence, not something Crush
        # itself controls -- must never be interpreted as HTML.
        source_files = run.get("source_files") or []
        if source_files:
            files_lbl = QLabel("\n".join(str(f) for f in source_files))
            files_lbl.setTextFormat(Qt.TextFormat.PlainText)
            files_lbl.setWordWrap(True)
            files_lbl.setTextInteractionFlags(_SELECTABLE)
            self._layout.addRow(
                translate("PropertiesPanel", "Source files ({source_files_count}):").format(
                    source_files_count=len(source_files)
                ),
                files_lbl,
            )

        _row("Started at", run.get("started_at"))
        _row("Duration", f"{run.get('duration_ms', 0):,} ms")

        status = result.get("status", "ok")
        status_lbl = QLabel(status)
        status_lbl.setTextInteractionFlags(_SELECTABLE)
        if status == "error":
            status_lbl.setStyleSheet("color: #b02a37; font-weight: bold;")
        elif status == "partial":
            status_lbl.setStyleSheet("color: #997404; font-weight: bold;")
        self._layout.addRow(translate("PropertiesPanel", "Status:"), status_lbl)

        warnings = result.get("warnings", [])
        if warnings:
            _row("Warnings", str(len(warnings)))

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
        self._layout.addRow(translate("PropertiesPanel", "{label}:").format(label=label), lbl)
