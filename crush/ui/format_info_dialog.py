# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Format Info dialog — popup showing format knowledge for a single file."""
from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from crush.ui import open_url as _open_link
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from crush.core.format_db import FormatMatch
from crush.core.vfs import VFSNode
from crush.ui.i18n import translate
from crush.ui.knowledge_toggle import follow_knowledge_original, knowledge_original_checkbox


class FormatInfoDialog(QDialog):
    def __init__(
        self,
        node: VFSNode | None,
        fmt: FormatMatch | None,
        parent: QWidget | None = None,
        candidates: Sequence[FormatMatch] = (),
    ) -> None:
        """*candidates*: with no *fmt*, the formats the file's signature
        bytes match equally (none of them singled out)."""
        super().__init__(parent)
        self.setWindowTitle(translate("FormatInfoDialog", "Format Info"))
        self.setMinimumWidth(420)
        self._build_ui(node, fmt, candidates)
        self._fit_to_content()

    def _fit_to_content(self) -> None:
        """Open wide enough to read the knowledge texts and tall enough to
        show them whole, within 60 % / 80 % of the screen (capped at
        760 px wide); beyond that the rows scroll."""
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        width = max(self.minimumWidth(), min(760, int(avail.width() * 0.60)))
        # Everything but the scrolled rows, plus the rows at that width.
        chrome = self.sizeHint().height() - self._content.sizeHint().height()
        content = self._content.heightForWidth(width - 48)
        if content < 0:
            content = self._content.sizeHint().height()
        height = min(int(avail.height() * 0.80), max(chrome, 0) + content + 24)
        self.resize(width, height)

    def _build_ui(
        self, node: VFSNode | None, fmt: FormatMatch | None, candidates: Sequence[FormatMatch]
    ) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header — file name when opened from file tree, format name when from reference
        if node is not None:
            title = node.name
        else:
            title = fmt.name if fmt else translate("FormatInfoDialog", "Format Info")
        header = QLabel(f"<b>{title}</b>")  # i18n: keep -- markup/layout only
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(header)

        # The rows scroll; header, toggle and buttons stay in view.
        self._content = QWidget()
        form = QFormLayout(self._content)
        form.setContentsMargins(0, 0, 0, 0)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(6)

        if fmt:
            self._add_row(form, translate("FormatInfoDialog", "Format"), fmt.name)
            if fmt.short_name and fmt.short_name != fmt.name:
                self._add_row(form, translate("FormatInfoDialog", "Short name"), fmt.short_name)
            if fmt.category:
                category = fmt.category_text().localized()
                if category == fmt.category:  # untranslated: shown as it always was
                    category = category.capitalize()
                self._add_row(form, translate("FormatInfoDialog", "Category"), category)
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
                magic_lbl = QLabel(_magic_text(fmt))
                follow_knowledge_original(
                    magic_lbl, lambda: magic_lbl.setText(_magic_text(fmt))
                )
                magic_lbl.setWordWrap(True)
                magic_lbl.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )
                magic_lbl.setStyleSheet("font-family: monospace;")
                form.addRow(translate("FormatInfoDialog", "Magic bytes:"), magic_lbl)

            if fmt.forensic_relevance:
                relevance_text = fmt.relevance_text()
                relevance = QLabel(relevance_text.localized())
                follow_knowledge_original(
                    relevance, lambda: relevance.setText(relevance_text.localized())
                )
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

            self._add_row(
                form,
                translate("FormatInfoDialog", "Last reviewed"),
                fmt.last_reviewed or translate("FormatInfoDialog", "Not recorded"),
            )
        elif candidates:
            self._add_row(
                form,
                translate("FormatInfoDialog", "Format"),
                translate("FormatInfoDialog", "Not determined"),
            )
            note = QLabel(
                translate(
                    "FormatInfoDialog",
                    "The signature bytes don't single out one format; they match these "
                    "equally:\n{names}",
                ).format(names=", ".join(c.name for c in candidates))
            )
            note.setWordWrap(True)
            note.setStyleSheet("color: gray;")
            form.addRow("", note)
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

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self._content)
        layout.addWidget(scroll, 1)

        if fmt and (fmt.forensic_relevance or any(d for _o, _p, d in fmt.magic)):
            toggle = knowledge_original_checkbox(self)
            if toggle is not None:
                layout.addWidget(toggle)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _add_row(self, form: QFormLayout, label: str, value: str) -> None:
        lbl = QLabel(value)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(translate("FormatInfoDialog", "{label}:").format(label=label), lbl)


def _magic_text(fmt: FormatMatch) -> str:
    """One line per magic-byte pattern: hex, description (a knowledge
    text, in the UI language unless the English original is chosen) and
    offset."""
    lines = []
    for offset, pattern, description in fmt.magic:
        hex_str = " ".join(f"{b:02X}" for b in pattern)
        if offset is None:
            offset_label = translate("FormatInfoDialog", "offset unknown")
        else:
            offset_label = translate("FormatInfoDialog", "offset {offset} (0x{offset_hex})").format(
                offset=offset, offset_hex=f"{offset:X}"
            )
        if description:
            shown = fmt.magic_description_text(description).localized()
            lines.append(f"{hex_str}  —  {shown} [{offset_label}]")
        else:
            lines.append(f"{hex_str}  [{offset_label}]")
    return "\n".join(lines)
