# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Combined decoded-tree + raw-text viewer, used for JSON, XML, and plist."""
from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from crush.viewers.text_viewer import TextView
from crush.viewers.tree_viewer import TreeViewer
from crush.ui.i18n import translate


class TreeTextViewer(QWidget):
    """Tabbed viewer: decoded tree structure alongside the raw/reconstructed text."""

    def __init__(
        self,
        data: Any,
        parent: QWidget | None = None,
        raw_text: str | bytes = "",
    ) -> None:
        super().__init__(parent)
        self._raw_text = raw_text
        self._text_view: TextView | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.addTab(TreeViewer(data, self._tabs), translate("TreeTextViewer", "Decoded"))
        # The Text tab is built when first shown: laying out and highlighting
        # a large file takes seconds that shouldn't delay the tree.
        self._text_tab = QWidget()
        text_layout = QVBoxLayout(self._text_tab)
        text_layout.setContentsMargins(0, 0, 0, 0)
        self._tabs.addTab(self._text_tab, translate("TreeTextViewer", "Text"))
        self._tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self._tabs)

    def _on_tab_changed(self, index: int) -> None:
        if self._text_view is not None or self._tabs.widget(index) is not self._text_tab:
            return
        self._text_view = TextView(self._raw_text, self._text_tab)
        self._text_tab.layout().addWidget(self._text_view)
