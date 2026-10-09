# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Opening bytes from inside a viewer as a new tab.

A viewer that can hand bytes to the main window declares
``open_bytes_with_format_requested = Signal(bytes, str, object, dict)``
(data, tab path, parser display name or None / "__hex__" / "__text__",
provenance metadata); the main window connects it for the viewer it shows
and sets that viewer's ``crush_source_path`` property to the file it shows.

Widgets nested inside a viewer -- a table in the Realm viewer, a tree in a
plist page, the BLOB Inspector opened from any of them -- don't need to
forward the signal themselves: :func:`request_open_bytes` walks up their
parents to the first viewer whose signal is connected.
"""
from __future__ import annotations

from PySide6.QtCore import QMetaMethod, QObject

SIGNAL_NAME = "open_bytes_with_format_requested"
SOURCE_PATH_PROPERTY = "crush_source_path"


def _host(widget: QObject | None) -> QObject | None:
    """The nearest of *widget* and its parents whose open-bytes signal is connected."""
    obj = widget
    while obj is not None:
        signal = getattr(obj, SIGNAL_NAME, None)
        if signal is not None:
            try:
                if obj.isSignalConnected(QMetaMethod.fromSignal(signal)):
                    return obj
            except (TypeError, RuntimeError):
                pass
        obj = obj.parent()
    return None


def can_open_bytes(widget: QObject | None) -> bool:
    return _host(widget) is not None


def request_open_bytes(
    widget: QObject | None,
    data: bytes,
    path: str,
    parser_display_name: object,
    metadata: dict[str, str],
) -> bool:
    """Ask the main window to open *data* as a new tab; False when no viewer
    above *widget* is connected to it."""
    host = _host(widget)
    if host is None:
        return False
    getattr(host, SIGNAL_NAME).emit(data, path, parser_display_name, metadata)
    return True


def source_path_of(widget: QObject | None) -> str:
    """The file the viewer containing *widget* shows ("" when unknown)."""
    obj = widget
    while obj is not None:
        value = obj.property(SOURCE_PATH_PROPERTY)
        if value:
            return str(value)
        obj = obj.parent()
    return ""
