# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Crush's own words inside a viewer's data views (headers, labels, status
values, explanations -- not file data), shown in the UI language while
export and copy keep the English original.

Translation context "GeneratedView". Mark a text with
QT_TRANSLATE_NOOP("GeneratedView", ...) where it's written and wrap it in
Gen(...); a plain str is file data and is never translated.
"""
from __future__ import annotations

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel

from crush.core.issues import ParseIssue, render_value
from crush.ui.i18n import translate

# A generated view (Summary, DB Info, WAL Frames, Freelist Recovery, ...)
# shows Crush's own words -- headers, view names, explanations, status
# values -- in the UI language. CSV export and copy always write the English
# original, so the same analysis exports identically whatever language each
# analyst's UI is in: it's kept in this role wherever the display differs.
# File data never carries it (it's shown and exported as it is).
EXPORT_TEXT_ROLE = Qt.ItemDataRole.UserRole + 28


def gen_text(english: str) -> str:
    """Display text for Crush's own words in a generated view. *english*
    is marked QT_TRANSLATE_NOOP("GeneratedView", ...) where it's written (or
    listed in a viewer's own marked values); unmarked text comes back unchanged."""
    return translate("GeneratedView", english)  # i18n: keep -- marked where written


class Localized:
    """A text already built in both forms: (English original, display)."""

    __slots__ = ("english", "display")

    def __init__(self, english: str, display: str) -> None:
        self.english = english
        self.display = display

    def pair(self) -> tuple[str, str]:
        return self.english, self.display


def _param_pair(value: object) -> tuple[object, object]:
    """(English, display) form of one Gen param: a nested Gen / Localized,
    or a ParseIssue (or list of them) rendered English vs. translated."""
    if isinstance(value, (Gen, Localized)):
        return value.pair()
    if isinstance(value, ParseIssue) or (
        isinstance(value, (list, tuple)) and any(isinstance(v, ParseIssue) for v in value)
    ):
        return render_value(value), render_value(value, localized=True)
    return value, value


class Gen:
    """Crush's own words in a generated view (not file data): a marked
    English template plus its params. A param may itself be a Gen (e.g. a
    status value inside a label), a Localized pair or a ParseIssue; each is
    shown translated and exported in English."""

    __slots__ = ("template", "params")

    def __init__(self, template: str, **params: object) -> None:
        self.template = template
        self.params = params

    def pair(self) -> tuple[str, str]:
        """(English original, display text). A translation whose
        placeholders don't fit falls back to English."""
        pairs = {k: _param_pair(v) for k, v in self.params.items()}
        english_params = {k: english for k, (english, _display) in pairs.items()}
        display_params = {k: display for k, (_english, display) in pairs.items()}
        english = self.template.format(**english_params) if self.params else self.template
        display = gen_text(self.template)
        if self.params:
            try:
                display = display.format(**display_params)
            except (KeyError, IndexError, ValueError):
                display = english
        return english, display


def mark_generated(item: QStandardItem, text: Gen) -> QStandardItem:
    """Show *text* on *item* in the UI language, the English original kept
    for export."""
    english, display = text.pair()
    item.setText(display)
    if display != english:
        item.setData(english, EXPORT_TEXT_ROLE)
    return item


def gen_item(text: Gen) -> QStandardItem:
    return mark_generated(QStandardItem(), text)


def set_headers(model: QStandardItemModel, labels: list[str | Gen]) -> None:
    """Horizontal headers: a Gen label (Crush's own word) is translated for
    display with its English original kept for export; a plain str (a real
    column name from the file) is shown as it is."""
    pairs = [label.pair() if isinstance(label, Gen) else (label, label) for label in labels]
    model.setHorizontalHeaderLabels([display for _english, display in pairs])
    for col, (english, display) in enumerate(pairs):
        if display != english:
            model.setHeaderData(col, Qt.Orientation.Horizontal, english, EXPORT_TEXT_ROLE)


def gens(*labels: str) -> list[str | Gen]:
    """Gen for each (marked) label -- a header row of Crush's own words."""
    return [Gen(label) for label in labels]


def export_cell_text(model: QAbstractItemModel, index: QModelIndex) -> str:
    """What CSV export and copy write for a cell: the English original of a
    generated-view text, else the displayed text (file data)."""
    original = model.data(index, EXPORT_TEXT_ROLE)
    if original is not None:
        return str(original)
    shown = model.data(index)
    return "" if shown is None else str(shown)


def export_header_text(model: QAbstractItemModel, col: int) -> str:
    original = model.headerData(col, Qt.Orientation.Horizontal, EXPORT_TEXT_ROLE)
    if original is not None:
        return str(original)
    shown = model.headerData(col, Qt.Orientation.Horizontal)
    return "" if shown is None else str(shown)
