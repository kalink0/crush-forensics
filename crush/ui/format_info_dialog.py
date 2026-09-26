# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Format Info dialog — popup showing format knowledge for a single file."""
from __future__ import annotations

from PySide6.QtCore import Qt
from crush.ui import open_url as _open_link
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from crush.core.format_db import FormatMatch
from crush.core.vfs import VFSNode
from crush.ui.i18n import translate


class FormatInfoDialog(QDialog):
    def __init__(
        self,
        node: VFSNode | None,
        fmt: FormatMatch | None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate("FormatInfoDialog", "Format Info"))
        self.setMinimumWidth(420)
        self._build_ui(node, fmt)

    def _build_ui(self, node: VFSNode | None, fmt: FormatMatch | None) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header — file name when opened from file tree, format name when from reference
        title = node.name if node is not None else (fmt.name if fmt else "Format Info")
        header = QLabel(f"<b>{title}</b>")  # i18n: keep -- markup/layout only
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(header)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(6)

        if fmt:
            self._add_row(form, translate("FormatInfoDialog", "Format"), fmt.name)
            if fmt.short_name and fmt.short_name != fmt.name:
                self._add_row(form, translate("FormatInfoDialog", "Short name"), fmt.short_name)
            if fmt.category:
                self._add_row(
                    form, translate("FormatInfoDialog", "Category"), fmt.category.capitalize()
                )
            if fmt.platforms:
                self._add_row(
                    form,
                    translate("FormatInfoDialog", "Platforms"),
                    fmt.platforms.replace(",", ", "),
                )

            support = (
                translate("FormatInfoDialog", "Supported")
                if fmt.parser_class
                else translate("FormatInfoDialog", "Not yet supported")
            )
            support_lbl = QLabel(support)
            support_lbl.setStyleSheet(
                "color: green;" if fmt.parser_class else "color: gray;"
            )
            form.addRow(translate("FormatInfoDialog", "Analysis:"), support_lbl)

            if fmt.magic:
                lines = []
                for offset, pattern, description in fmt.magic:
                    hex_str = " ".join(f"{b:02X}" for b in pattern)
                    if offset is None:
                        offset_label = "offset unknown"
                    else:
                        offset_label = f"offset {offset} (0x{offset:X})"
                    if description:
                        lines.append(f"{hex_str}  —  {description} [{offset_label}]")
                    else:
                        lines.append(f"{hex_str}  [{offset_label}]")
                magic_lbl = QLabel("\n".join(lines))
                magic_lbl.setWordWrap(True)
                magic_lbl.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )
                magic_lbl.setStyleSheet("font-family: monospace;")
                form.addRow(translate("FormatInfoDialog", "Magic bytes:"), magic_lbl)

            if fmt.forensic_relevance:
                relevance = QLabel(fmt.forensic_relevance)
                relevance.setWordWrap(True)
                relevance.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )
                form.addRow(translate("FormatInfoDialog", "Forensic relevance:"), relevance)

            if fmt.links:
                for label, url in fmt.links:
                    link_lbl = QLabel(
                        f'<a href="{url}">{label}</a>'  # i18n: keep -- markup/layout only
                    )
                    link_lbl.linkActivated.connect(_open_link)
                    link_lbl.setTextInteractionFlags(
                        Qt.TextInteractionFlag.TextBrowserInteraction
                    )
                    form.addRow(translate("FormatInfoDialog", "Link:"), link_lbl)
        else:
            self._add_row(
                form,
                translate("FormatInfoDialog", "Format"),
                translate("FormatInfoDialog", "Unknown"),
            )
            note = QLabel(
                translate(
                    "FormatInfoDialog",
                    "No match found in the format knowledge base.\n"
                    "The file may be proprietary, encrypted, or not yet catalogued.",
                )
            )
            note.setWordWrap(True)
            note.setStyleSheet("color: gray;")
            form.addRow("", note)

        layout.addLayout(form)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _add_row(self, form: QFormLayout, label: str, value: str) -> None:
        lbl = QLabel(value)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(translate("FormatInfoDialog", "{label}:").format(label=label), lbl)
