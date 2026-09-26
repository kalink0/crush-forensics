# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Viewer factory — maps ParseResult.viewer_type to the right QWidget."""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QWidget

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import ParseResult
from crush.core.viewer_registry import ViewerRegistry
from crush.ui.i18n import translate


def make_viewer(result: ParseResult, node: VFSNode, vfs: VFS, parent: QWidget) -> QWidget:
    """Return the appropriate viewer widget for the given ParseResult."""
    import crush.viewers  # noqa: F401 - ensures built-in viewers are registered

    vtype = result.viewer_type
    factory = ViewerRegistry.get(vtype)
    if factory is not None:
        return factory(result, node, vfs, parent)

    # Unknown type — show a placeholder
    placeholder = QLabel(
        translate("ViewerFactory", "No viewer available for type: {vtype!r}").format(vtype=vtype)
    )
    return placeholder
