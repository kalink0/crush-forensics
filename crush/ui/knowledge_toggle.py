# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The "Show English original" checkbox for knowledge texts.

Knowledge texts (a format's forensic relevance, magic-byte descriptions,
an analyzer module's relevance -- issues.CatalogText with knowledge=True)
are translated like the rest of the UI. Every place that shows one offers
this checkbox; all of them switch the same saved setting
(i18n.KNOWLEDGE_ORIGINAL_KEY), and every open view follows it. With no
translation loaded there is nothing to switch, so no checkbox is shown.
"""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QSettings
from PySide6.QtWidgets import QCheckBox, QWidget

from crush.core import issues
from crush.ui import i18n
from crush.ui.i18n import translate


def _app_settings() -> QSettings:
    return QSettings("Crush DFIR", "Crush")


def knowledge_original_checkbox(
    parent: QWidget | None = None, settings: QSettings | None = None
) -> QCheckBox | None:
    """The checkbox, bound to the shared setting -- or None while the UI is
    English. *settings* defaults to the application's own."""
    if not issues.translation_loaded():
        return None
    box = QCheckBox(translate("KnowledgeText", "Show English original"), parent)
    box.setToolTip(
        translate(
            "KnowledgeText",
            "Show format and analyzer descriptions in the English they were written in",
        )
    )
    box.setChecked(issues.knowledge_original())
    box.toggled.connect(
        lambda on: i18n.set_knowledge_original(settings or _app_settings(), on)
    )
    # A method of the box itself: Qt drops the connection when the box goes.
    i18n.knowledge_original_signal().changed.connect(box.setChecked)
    return box


class _Follower(QObject):
    def __init__(self, owner: QObject, update: Callable[[], None]) -> None:
        super().__init__(owner)
        self._update = update
        i18n.knowledge_original_signal().changed.connect(self._on_changed)

    def _on_changed(self, _on: bool) -> None:
        self._update()


def follow_knowledge_original(owner: QObject, update: Callable[[], None]) -> None:
    """Call *update* whenever the setting is switched, for as long as
    *owner* exists (the connection goes with it)."""
    _Follower(owner, update)
