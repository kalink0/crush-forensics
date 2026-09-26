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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        tabs = QTabWidget()
        tabs.addTab(TreeViewer(data, tabs), translate("TreeTextViewer", "Decoded"))
        tabs.addTab(TextView(raw_text, tabs), translate("TreeTextViewer", "Text"))
        layout.addWidget(tabs)
