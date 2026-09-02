# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ABX viewer — split pane showing the parsed tree and reconstructed XML.

The left pane reuses the standard TreeViewer for the nested dict structure.
The right pane shows the reconstructed human-readable XML for copy/reference.
The data dict passed in has the shape:

    {
        "tree":    { ... },   # nested dict for TreeViewer
        "xml_str": "..."      # reconstructed XML string
    }
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from crush.viewers.text_viewer import TextView
from crush.viewers.tree_viewer import TreeViewer


class AbxViewer(QWidget):
    """Split-pane viewer for Android Binary XML (ABX) files."""

    def __init__(self, data: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui(data)

    def _build_ui(self, data: dict) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: tree view of parsed structure
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        left_header = QLabel("  Parsed structure")
        left_header.setFixedHeight(28)
        left_header.setStyleSheet(
            "background: palette(mid); color: palette(text); font-size: 11px;"
        )
        left_layout.addWidget(left_header)

        tree_widget = TreeViewer(data.get("tree", {}), self)
        left_layout.addWidget(tree_widget)
        splitter.addWidget(left)

        # Right: reconstructed XML
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        right_header = QLabel("  Reconstructed XML")
        right_header.setFixedHeight(28)
        right_header.setStyleSheet(
            "background: palette(mid); color: palette(text); font-size: 11px;"
        )
        right_layout.addWidget(right_header)

        # TextView brings its own XML syntax highlighting (auto-detected from
        # the leading "<?xml") plus a Ctrl+F search bar with regex/case
        # options and hit navigation — no need to duplicate either here.
        xml_view = TextView(data.get("xml_str", ""), right)
        right_layout.addWidget(xml_view)

        splitter.addWidget(right)
        splitter.setSizes([400, 400])

        layout.addWidget(splitter)
