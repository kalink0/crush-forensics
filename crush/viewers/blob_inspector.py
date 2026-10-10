# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""BLOB Inspector dialog with a chainable decode pipeline and multi-view panel."""
from __future__ import annotations

import base64
import html
import json as _json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QT_TRANSLATE_NOOP, QBuffer, QIODevice, Qt
from PySide6.QtGui import QAction, QColor, QContextMenuEvent, QImage, QShowEvent
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from crush.core.blob_decode import (
    Decoded,
    DecodeError,
    decode_base64,
    decode_base64url,
    decode_hex,
    decompress_gzip,
    decompress_lzfse,
    decompress_zlib,
)
from crush.core.blob_export import (
    OUTPUT_BYTES,
    OUTPUT_RENDERED_PNG,
    PipelineStep,
    build_sidecar,
    sidecar_json,
    sidecar_path,
)
from crush.core.formatters import (
    bytes_to_hexview,
    plist_text,
    xml_text,
)
from crush.parsers.protobuf_schema import (
    SchemaLoadError,
    decode_message_with_schema,
    load_descriptor_set,
)
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.hex_viewer import HexViewer
from crush.viewers.open_bytes import can_open_bytes as request_can_open
from crush.viewers.open_bytes import request_open_bytes, source_path_of
from crush.ui.i18n import translate

if TYPE_CHECKING:
    from crush.parsers.base import ParseResult

_HEX_VIEW = "Hex view"
_JSON_UNESCAPED = "JSON (unescaped from a string)"

# Metadata fields on the first line above the Plist page's tree (what the
# data is, whether it was resolved); every other field goes on the second.
_PLIST_SUMMARY_FIRST_LINE = ("Format", "Status")
# The same for the Image page: what the image is, whether it was decoded,
# and whether only its first frame is shown.
_IMAGE_SUMMARY_FIRST_LINE = ("Format", "Decode status", "Frames")


def _summary_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _summary_html(metadata: dict, first_line: tuple[str, ...]) -> str:
    """A parser's metadata as one or two lines: the *first_line* fields,
    then every other one; field names in bold. Values come from the blob
    (e.g. Top keys, EXIF text), so they're escaped."""
    from crush.core.issues import render_value

    lines: list[list[str]] = [[], []]
    for key, value in metadata.items():
        if key == "File size":
            continue
        label = html.escape(translate("MetadataLabel", key))  # i18n: keep -- marked in metadata_labels
        shown = html.escape(render_value(value, localized=True))
        lines[0 if key in first_line else 1].append(f"<b>{label}:</b> {shown}")
    # Only the space after "·" can break: a wrapped line starts with a
    # field, not a blank.
    return "<br>".join("&nbsp;&nbsp;·&nbsp; ".join(parts) for parts in lines if parts)

# Crush's own names for interpretations and pipeline steps: the English name
# is the key everywhere (item data, _cached_results, _INTERMEDIATE); only the
# lists show it translated. Format names (JSON, XML, Plist, ABX) stay as they are.
_ENTRY_NAMES = (
    QT_TRANSLATE_NOOP("BlobInspector", "Hex view"),
    QT_TRANSLATE_NOOP("BlobInspector", "Image"),
    QT_TRANSLATE_NOOP("BlobInspector", "Decoded (from table)"),
    QT_TRANSLATE_NOOP("BlobInspector", "UTF-8 text"),
    QT_TRANSLATE_NOOP("BlobInspector", "Latin-1 text"),
    QT_TRANSLATE_NOOP("BlobInspector", "JSON (unescaped from a string)"),
    QT_TRANSLATE_NOOP("BlobInspector", "Protobuf (schema-less)"),
    QT_TRANSLATE_NOOP("BlobInspector", "Base64 (decode)"),
    QT_TRANSLATE_NOOP("BlobInspector", "Base64url (decode)"),
    QT_TRANSLATE_NOOP("BlobInspector", "Hex → Bytes"),
    QT_TRANSLATE_NOOP("BlobInspector", "zlib decompress"),
    QT_TRANSLATE_NOOP("BlobInspector", "gzip decompress"),
    QT_TRANSLATE_NOOP("BlobInspector", "lzfse decompress"),
)
_SCHEMA_PREFIX = "Protobuf (schema: "


def _entry_label(name: str) -> str:
    """Display name of an interpretation / pipeline step key."""
    if name.startswith(_SCHEMA_PREFIX) and name.endswith(")"):
        return translate("BlobInspector", "Protobuf (schema: {message})").format(
            message=name[len(_SCHEMA_PREFIX):-1]
        )
    return translate("BlobInspector", name)  # i18n: keep -- marked in _ENTRY_NAMES

_PROTOBUF_INTERP_SKIP = {"uint64", "uint32"}


# ---------------------------------------------------------------------------
# Render functions — terminal (bytes → str). Each raises with the reason
# when the bytes aren't in its format; the panel shows that reason.
# ---------------------------------------------------------------------------

def _no_bytes(data: bytes) -> None:
    if not data:
        raise ValueError(translate("BlobInspector", "no bytes"))


def _try_utf8(data: bytes) -> str:
    _no_bytes(data)
    return data.decode("utf-8")


def _try_latin1(data: bytes) -> str:
    _no_bytes(data)
    return data.decode("latin-1")


def _try_json(data: bytes) -> str:
    _no_bytes(data)
    return _json.dumps(_json.loads(data.decode("utf-8")), indent=2, ensure_ascii=False)


# JSON's insignificant whitespace around a value (RFC 8259 §2).
_JSON_WS = " \t\r\n"


def _try_json_unescaped(data: bytes) -> str:
    """JSON stored as the content of a JSON string (escaped quotes, \\n, \\uXXXX …).

    Whether the bytes come from a JSON string is an assumption, so the
    output says so; resolving the escapes follows the JSON spec (RFC 8259 §7).
    Whitespace around the escaped text is ignored, as JSON ignores it around
    a value -- and the output says how much."""
    _no_bytes(data)
    full = data.decode("utf-8")
    text = full.strip(_JSON_WS)
    ignored = len(full) - len(text)
    try:
        direct = _json.loads(text)
    except ValueError:
        try:
            inner = _json.loads('"' + text + '"')
        except ValueError as exc:
            raise ValueError(
                translate("BlobInspector", "not the content of a JSON string: {reason}").format(
                    reason=exc
                )
            ) from exc
        if inner == text:
            raise ValueError(translate("BlobInspector", "contains no escape sequences"))
    else:
        if not isinstance(direct, str):
            raise ValueError(translate("BlobInspector", "the bytes are JSON themselves (see JSON)"))
        inner = direct
    pretty = _json.dumps(_json.loads(inner), indent=2, ensure_ascii=False)
    note = translate(
        "BlobInspector",
        "# Assumption: these bytes are the content of a JSON string. Shown after\n"
        "# resolving its escape sequences; the stored bytes hold the escaped form.",
    )
    if ignored:
        note += "\n" + translate(
            "BlobInspector",
            "# {count} whitespace character(s) before/after the escaped text ignored.",
        ).format(count=ignored)
    return f"{note}\n\n{pretty}"


def _try_plist(data: bytes) -> str:
    return plist_text(data)


def _try_xml(data: bytes) -> str:
    return xml_text(data)


def _try_protobuf(data: bytes) -> str:
    _no_bytes(data)
    from crush.core.vfs import BytesVFS
    from crush.parsers.protobuf_parser import ProtobufParser

    # The parser's own result: its warning and nesting-limit note come from
    # its metadata, the same ones the Protobuf viewer shows.
    vfs = BytesVFS(data, name="blob")
    parsed = ProtobufParser().parse(vfs.root(), vfs)
    result = _render_protobuf(parsed.data["decoded"].get("entries", []))
    nesting = parsed.metadata.get("Nesting")
    if nesting:
        result = f"# {nesting}\n\n{result}"
    warning = parsed.metadata.get("Parse warning")
    if warning:
        result = f"# Warning: {warning}\n\n{result}"
    return result


def _try_abx(data: bytes) -> str:
    from crush.parsers.abx_decoder import decode_abx
    return decode_abx(data).xml


# ---------------------------------------------------------------------------
# Format registries — add a new format by adding one entry here
# ---------------------------------------------------------------------------

# bytes → Decoded; raises DecodeError with the reason on failure
_INTERMEDIATE: dict[str, Callable[[bytes], Decoded]] = {
    "Base64 (decode)":   decode_base64,
    "Base64url (decode)": decode_base64url,
    "Hex → Bytes":       decode_hex,
    "zlib decompress":   decompress_zlib,
    "gzip decompress":   decompress_gzip,
    "lzfse decompress":  decompress_lzfse,
}

# bytes → str; raises with the reason on failure
_TERMINAL_TEXT: dict[str, Callable[[bytes], str]] = {
    "UTF-8 text":               _try_utf8,
    "Latin-1 text":             _try_latin1,
    "JSON":                     _try_json,
    _JSON_UNESCAPED:            _try_json_unescaped,
    "Plist / bplist":           _try_plist,
    "XML":                      _try_xml,
    "Protobuf (schema-less)":   _try_protobuf,
    "Android Binary XML (ABX)": _try_abx,
}

# Subset of _TERMINAL_TEXT keys tried by auto-detection, in priority order
_AUTO_ORDER: tuple[str, ...] = (
    "Plist / bplist",
    "XML",
    "JSON",
    "UTF-8 text",
    "Latin-1 text",
)

# Not a confirmation of the format: it (almost) always produces output, or
# its reading rests on an assumption its output states.
_PERMISSIVE: frozenset[str] = frozenset(
    {"Latin-1 text", "Protobuf (schema-less)", _JSON_UNESCAPED}
)

_INTERMEDIATE_FORMATS: tuple[str, ...] = tuple(_INTERMEDIATE)


def _step_note(result: Decoded) -> str:
    """What a step left undecoded, for its hint line ("" when nothing)."""
    notes: list[str] = []
    if result.trailing_offset is not None:
        notes.append(
            translate(
                "BlobInspector",
                "{size:,} B after the end of the stream at offset {offset:#x} not decoded",
            ).format(size=result.trailing_size, offset=result.trailing_offset)
        )
        if result.trailing_reason:
            notes.append(result.trailing_reason)
    if result.end_marker_missing:
        notes.append(translate("BlobInspector", "no end-of-stream block (bvx$)"))
    return "\n".join(notes)


def _reason(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__


def _image_result(data: bytes) -> ParseResult | None:
    """The image parser's result for *data* when its signature bytes are an
    image format Crush recognises (the same check as for files), else None."""
    from crush.core.vfs import BytesVFS
    from crush.parsers.image_parser import ImageParser

    parser = ImageParser()
    if not parser.can_parse("", data[:64]):
        return None
    vfs = BytesVFS(data, name="blob")
    return parser.parse(vfs.root(), vfs)


def _is_protobuf_entry(name: str) -> bool:
    return name == "Protobuf (schema-less)" or name.startswith("Protobuf (schema: ")


def _render_protobuf(entries: list, indent: int = 0) -> str:
    lines: list[str] = []
    pad = "  " * indent
    ipad = pad + "    "
    for entry in entries:
        field = entry.get("field", "?")
        wt = entry.get("wire_type", "?")
        val = entry.get("value")
        raw = entry.get("raw")  # full payload; only set for length-delimited entries
        interpretations = [
            i for i in entry.get("interpretations", [])
            if i.label not in _PROTOBUF_INTERP_SKIP
        ]
        if isinstance(val, dict):
            vtype = val.get("type")
            if vtype == "message":
                lines.append(f"{pad}{field} {{")
                lines.append(_render_protobuf(val.get("entries", []), indent + 1))
                lines.append(f"{pad}}}")
            elif vtype == "string":
                lines.append(f'{pad}{field}: "{val.get("text", "")}"')
            else:
                # hex_preview is capped at 64 bytes by the parser — show the complete
                # payload here instead of repeating that truncated preview.
                hex_full = raw.hex(" ") if raw else val.get("hex_preview", "")
                lines.append(f"{pad}{field}: <{hex_full}>")
        elif isinstance(val, bytes):
            lines.append(f"{pad}{field}: {val.hex()}")
        else:
            lines.append(f"{pad}{field} [{wt}]: {val}")
        for interp in interpretations:
            if interp.label == "raw bytes" and raw:
                # Same 64-byte-capped preview as above — use the full payload.
                lines.append(f"{ipad}# {interp.label}: {raw.hex(' ')}")
            else:
                lines.append(f"{ipad}# {interp.label}: {interp.value}")
    return "\n".join(lines)


class _BlobViewerEdit(QPlainTextEdit):
    """QPlainTextEdit with a Copy All context-menu entry."""

    def __init__(self, panel: "_BlobPanel") -> None:
        super().__init__()
        self._panel = panel

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = self.createStandardContextMenu()
        menu.addSeparator()
        menu.addAction(translate("_BlobViewerEdit", "Copy All")).triggered.connect(
            self._panel._copy_all
        )
        menu.exec(event.globalPos())


_STEP_LIST_MAX_VISIBLE = 5


def _list_width_for(lst: QListWidget, texts: list[str]) -> int:
    """Width at which *lst* shows the longest of *texts* without a horizontal
    scroll bar (room for the vertical one included)."""
    fm = lst.fontMetrics()
    text_w = max((fm.horizontalAdvance(t) for t in texts), default=0)
    scroll_w = lst.style().pixelMetric(QStyle.PixelMetric.PM_ScrollBarExtent)
    # Item padding/focus frame on either side, as the style draws it.
    return text_w + scroll_w + 2 * lst.frameWidth() + 16


def _step_labels() -> list[str]:
    return [_entry_label(key) for key in _INTERMEDIATE_FORMATS]


def _interpretation_labels() -> list[str]:
    names = [_HEX_VIEW, "Image", "Decoded (from table)", *_TERMINAL_TEXT]
    # "✓  " / "~  " / "    " prefix as the list shows them.
    return [f"✓  {_entry_label(name)}" for name in names]



class _StepRow(QWidget):
    """One transform step in the decode pipeline: label + format list + size hint."""

    def __init__(self, number: int, inspector: "_BlobPanel") -> None:
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(2)

        header = QHBoxLayout()
        self._num_label = QLabel(translate("_StepRow", "Step {number}:").format(number=number))
        header.addWidget(self._num_label)
        header.addStretch()
        remove_btn = QPushButton("✕")
        remove_btn.setFixedSize(22, 22)
        remove_btn.setToolTip(translate("_StepRow", "Remove this step"))
        remove_btn.clicked.connect(lambda: inspector._remove_step(self))
        header.addWidget(remove_btn)
        layout.addLayout(header)

        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        # Item data is the step's key into _INTERMEDIATE; the text is only
        # its (translated) name.
        for key in _INTERMEDIATE_FORMATS:
            item = QListWidgetItem(_entry_label(key))
            item.setData(Qt.ItemDataRole.UserRole, key)
            self._list.addItem(item)
        self._list.setCurrentRow(0)
        # At most _STEP_LIST_MAX_VISIBLE rows; more scroll vertically. Wide
        # enough for every name next to that scroll bar, so no horizontal
        # one covers the last row.
        visible = min(len(_INTERMEDIATE_FORMATS), _STEP_LIST_MAX_VISIBLE)
        row_h = self._list.sizeHintForRow(0)
        self._list.setFixedHeight(visible * row_h + 2 * self._list.frameWidth())
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setMinimumWidth(_list_width_for(self._list, _step_labels()))
        self._list.currentItemChanged.connect(lambda *_: inspector._recompute())
        layout.addWidget(self._list)

        self._hint = QLabel("")
        self._hint.setStyleSheet("color: gray;")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)

    def format(self) -> str:
        item = self._list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def set_number(self, n: int) -> None:
        self._num_label.setText(translate("_StepRow", "Step {n}:").format(n=n))

    def set_hint(self, text: str) -> None:
        self._hint.setText(text)


class _BlobPanel(QWidget):
    """Three-column BLOB inspection panel reused by BlobInspector and PasteDecodeDialog."""

    def __init__(
        self,
        blob: bytes,
        parent: QWidget | None = None,
        *,
        display_text: str | None = None,
        artifact_path: str = "",
        provenance: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._blob = blob
        self._display_text = display_text
        # Where the inspected bytes come from: the tab path an opened tab
        # gets, and the fields (table/row, key, "Inspected bytes" …) it and
        # an export's sidecar carry.
        self._artifact_path = artifact_path
        self._provenance: dict[str, str] = dict(provenance or {})
        self._steps: list[_StepRow] = []
        # Each step's result, in order; None when a step failed (then
        # there are no bytes after the pipeline to copy, export or open).
        self._pipeline: list[PipelineStep] | None = []
        self._cached_results: dict[str, str] = {}
        # Why each interpretation that failed didn't apply.
        self._failed_reasons: dict[str, str] = {}
        # The image parser's result when the data is an image, and the data
        # the Image page currently shows.
        self._image: ParseResult | None = None
        self._image_view_data: bytes | None = None
        # The data the interpretations are computed from (after the pipeline
        # steps) -- shown complete in the paged Hex Viewer page.
        self._current_data = b""
        self._hex_view_data: bytes | None = None
        # The data the Plist page currently shows (built once per data).
        self._plist_view_data: bytes | None = None
        self._schema_pool = None
        self._schema_message: str | None = None
        self._build_panel()
        self._recompute()

    def set_provenance(self, artifact_path: str, provenance: dict[str, str]) -> None:
        self._artifact_path = artifact_path
        self._provenance = dict(provenance)

    def _show_no_bytes(self, message: str) -> None:
        """No bytes to interpret: say why in the content view instead of an
        empty one, and offer nothing to copy, export or open."""
        self._pipeline = None
        self._update_bytes_actions()
        self._format_list.blockSignals(True)
        self._format_list.clear()
        self._format_list.blockSignals(False)
        self._viewer.setPlainText(message)
        self._stack.setCurrentWidget(self._viewer)
        self._copy_shown_action.setEnabled(False)
        self._schema_toolbar.setVisible(False)

    def show_unreadable_input(self, reason: str) -> None:
        """The input couldn't be turned into bytes (e.g. pasted text that
        isn't valid hex): show *reason* rather than zero bytes."""
        self._blob = b""
        for step in self._steps:
            step.set_hint("")
        self._show_no_bytes(
            translate("BlobInspector", "[No bytes: {reason}]").format(reason=reason)
        )

    def update_blob(self, blob: bytes) -> None:
        """Replace the inspected bytes and refresh all interpretations."""
        self._blob = blob
        for step in self._steps:
            step.set_hint("")
        self._recompute()

    def _build_panel(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # --- Column 1: Decode pipeline ---
        pipeline_widget = QWidget()
        pipeline_col = QVBoxLayout(pipeline_widget)
        pipeline_col.setContentsMargins(0, 0, 4, 0)
        pipeline_col.setSpacing(4)

        lbl_pipeline = QLabel(translate("_BlobPanel", "Decode pipeline"))
        lbl_pipeline.setStyleSheet("font-weight: bold;")
        pipeline_col.addWidget(lbl_pipeline)

        # The steps scroll vertically once they don't fit the dialog's
        # height; "Add step" stays visible below them.
        steps_container = QWidget()
        self._pipeline_layout = QVBoxLayout(steps_container)
        self._pipeline_layout.setContentsMargins(0, 0, 0, 0)
        self._pipeline_layout.setSpacing(0)
        self._pipeline_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._steps_scroll = QScrollArea()
        self._steps_scroll.setWidgetResizable(True)
        self._steps_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._steps_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._steps_scroll.setWidget(steps_container)
        # After "Add step" the column follows the new (last) step through
        # every resize the layout makes for it (the step, then its hint
        # wrapping), until the analyst scrolls or removes a step.
        self._scroll_to_last_step = False
        steps_bar = self._steps_scroll.verticalScrollBar()
        steps_bar.rangeChanged.connect(self._on_steps_range_changed)
        steps_bar.actionTriggered.connect(self._stop_following_last_step)
        pipeline_col.addWidget(self._steps_scroll, stretch=1)

        self._add_btn = QPushButton(translate("_BlobPanel", "＋  Add step"))
        self._add_btn.clicked.connect(self._push_step)
        pipeline_col.addWidget(self._add_btn)
        # As wide as a step's list needs from the start, plus room for the
        # steps' own vertical scroll bar -- so the column doesn't open
        # narrower than its steps (the splitter's initial sizes are applied
        # before the dialog has its size).
        probe = QListWidget()
        pipeline_widget.setMinimumWidth(
            _list_width_for(probe, _step_labels())
            + probe.style().pixelMetric(QStyle.PixelMetric.PM_ScrollBarExtent)
            + pipeline_col.contentsMargins().right()
        )

        splitter.addWidget(pipeline_widget)

        # --- Column 2: Interpretations ---
        interp_widget = QWidget()
        interp_col = QVBoxLayout(interp_widget)
        interp_col.setContentsMargins(4, 0, 4, 0)
        interp_col.setSpacing(4)

        lbl_interp = QLabel(translate("_BlobPanel", "Interpretations"))
        lbl_interp.setStyleSheet("font-weight: bold;")
        interp_col.addWidget(lbl_interp)

        self._format_list = QListWidget()
        self._format_list.setMinimumWidth(
            _list_width_for(self._format_list, _interpretation_labels())
        )
        self._format_list.currentItemChanged.connect(self._on_item_changed)
        interp_col.addWidget(self._format_list)

        splitter.addWidget(interp_widget)

        # --- Column 3: Content view ---
        content_widget = QWidget()
        content_col = QVBoxLayout(content_widget)
        content_col.setContentsMargins(4, 0, 0, 0)
        content_col.setSpacing(4)

        self._schema_toolbar = QWidget()
        schema_row = QHBoxLayout(self._schema_toolbar)
        schema_row.setContentsMargins(0, 0, 0, 0)
        schema_row.setSpacing(4)
        self._schema_load_btn = QPushButton(translate("_BlobPanel", "Load .proto schema…"))
        self._schema_load_btn.setToolTip(
            translate("_BlobPanel", "Load a .proto/.pb/.desc/.fds schema for Protobuf decoding")
        )
        self._schema_load_btn.clicked.connect(self._on_load_schema)
        schema_row.addWidget(self._schema_load_btn)
        self._schema_combo = QComboBox()
        self._schema_combo.setPlaceholderText(translate("_BlobPanel", "No schema loaded"))
        self._schema_combo.setEnabled(False)
        self._schema_combo.currentTextChanged.connect(self._on_schema_message_changed)
        schema_row.addWidget(self._schema_combo, stretch=1)
        self._schema_clear_btn = QPushButton("✕")
        self._schema_clear_btn.setFixedWidth(22)
        self._schema_clear_btn.setToolTip(translate("_BlobPanel", "Clear loaded schema"))
        self._schema_clear_btn.setEnabled(False)
        self._schema_clear_btn.clicked.connect(self._on_clear_schema)
        schema_row.addWidget(self._schema_clear_btn)
        self._schema_toolbar.setVisible(False)
        content_col.addWidget(self._schema_toolbar)

        self._stack = QStackedWidget()

        self._viewer = _BlobViewerEdit(self)
        self._viewer.setReadOnly(True)
        self._viewer.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        install_horizontal_wheel_scroll(self._viewer, smooth_item_scroll=False)
        self._stack.addWidget(self._viewer)

        # "Image": the image viewer on the blob, with the image parser's
        # Format / Decode status / Frames and the rest of its metadata
        # (EXIF, C2PA …) above -- the same as an image file.
        self._image_page = QWidget()
        image_layout = QVBoxLayout(self._image_page)
        image_layout.setContentsMargins(0, 0, 0, 0)
        self._image_summary = _summary_label()
        summary_scroll = QScrollArea()
        summary_scroll.setWidgetResizable(True)
        summary_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        summary_scroll.setWidget(self._image_summary)
        summary_scroll.setMaximumHeight(self.fontMetrics().lineSpacing() * 5 + 8)
        image_layout.addWidget(summary_scroll)
        self._image_view: QWidget | None = None
        self._stack.addWidget(self._image_page)

        # "Hex view": the paged Hex Viewer, so the whole blob is shown
        # however large it is (a text dump of it would freeze the dialog).
        self._hex_view = HexViewer(b"", self)
        self._stack.addWidget(self._hex_view)

        # "Plist / bplist": the plist file viewer on the blob (tree, Stored
        # archive tab for an NSKeyedArchiver archive, text), with the plist
        # parser's Format/Status/archive counts in a line above -- the same
        # as a plist file or a cell opened as a new tab.
        self._plist_page = QWidget()
        plist_layout = QVBoxLayout(self._plist_page)
        plist_layout.setContentsMargins(0, 0, 0, 0)
        self._plist_summary = _summary_label()
        plist_layout.addWidget(self._plist_summary)
        self._plist_view: QWidget | None = None
        self._stack.addWidget(self._plist_page)

        content_col.addWidget(self._stack, stretch=1)

        # Copy / Export / Open in new tab. Apart from "Shown text", they
        # all take the bytes after the decode pipeline, whatever
        # interpretation is selected.
        copy_row = QHBoxLayout()
        copy_btn = QPushButton(translate("_BlobPanel", "Copy"))
        copy_menu = QMenu(copy_btn)
        self._copy_shown_action = copy_menu.addAction(translate("_BlobPanel", "Shown text"))
        self._copy_shown_action.triggered.connect(self._copy_current)
        copy_menu.addSeparator()
        self._bytes_actions: list[QAction] = []
        for label, fmt in (
            (QT_TRANSLATE_NOOP("_BlobPanel", "Bytes as hex"), "hex"),
            (QT_TRANSLATE_NOOP("_BlobPanel", "Bytes as Base64"), "base64"),
            (QT_TRANSLATE_NOOP("_BlobPanel", "Bytes as Python literal"), "python"),
        ):
            action = copy_menu.addAction(translate("_BlobPanel", label))  # i18n: keep -- marked above
            action.triggered.connect(lambda _checked=False, f=fmt: self._copy_bytes(f))
            self._bytes_actions.append(action)
        copy_btn.setMenu(copy_menu)
        copy_row.addWidget(copy_btn)

        export_btn = QPushButton(translate("_BlobPanel", "Export"))
        export_menu = QMenu(export_btn)
        export_bytes = export_menu.addAction(translate("_BlobPanel", "Bytes…"))
        export_bytes.triggered.connect(self._export_bytes)
        self._bytes_actions.append(export_bytes)
        self._export_image_action = export_menu.addAction(
            translate("_BlobPanel", "Rendered image (PNG)…")
        )
        self._export_image_action.triggered.connect(self._export_rendered_image)
        export_btn.setMenu(export_menu)
        copy_row.addWidget(export_btn)

        self._open_btn = QPushButton(translate("_BlobPanel", "Open in new tab"))
        open_menu = QMenu(self._open_btn)
        # The same choices as a table cell's "Open as new tab".
        for label, fmt in (
            (QT_TRANSLATE_NOOP("_BlobPanel", "Auto-detect"), None),
            (QT_TRANSLATE_NOOP("_BlobPanel", "Hex"), "__hex__"),
            (QT_TRANSLATE_NOOP("_BlobPanel", "Text"), "__text__"),
            (QT_TRANSLATE_NOOP("_BlobPanel", "Protobuf (schema-less)"), "Protobuf (schema-less)"),
        ):
            action = open_menu.addAction(translate("_BlobPanel", label))  # i18n: keep -- marked above
            action.triggered.connect(lambda _checked=False, f=fmt: self._open_in_tab(f))
            self._bytes_actions.append(action)
        self._open_btn.setMenu(open_menu)
        copy_row.addWidget(self._open_btn)
        copy_row.addStretch()
        content_col.addLayout(copy_row)

        splitter.addWidget(content_widget)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 0)
        splitter.setStretchFactor(2, 1)
        splitter.setSizes([185, 170, 505])

        outer.addWidget(splitter, stretch=1)

    def _on_load_schema(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            translate("_BlobPanel", "Load Protobuf schema"),
            "",
            translate("BlobInspector", "Protobuf schema")
            + " (*.proto *.pb *.desc *.fds);;"  # i18n: keep -- file filter pattern
            + translate("BlobInspector", "All files")
            + " (*)",  # i18n: keep -- file filter pattern
        )
        if not path:
            return
        try:
            loaded = load_descriptor_set(Path(path))
        except SchemaLoadError as exc:
            self._viewer.setPlainText(
                translate("BlobInspector", "[schema load failed: {error}]").format(error=exc)
            )
            return
        self._schema_pool = loaded["pool"]
        self._schema_combo.blockSignals(True)
        self._schema_combo.clear()
        self._schema_combo.addItems(loaded["message_names"])
        self._schema_combo.setCurrentIndex(0)
        self._schema_combo.blockSignals(False)
        self._schema_combo.setEnabled(True)
        self._schema_clear_btn.setEnabled(True)
        self._schema_message = self._schema_combo.currentText() or None
        self._recompute()
        if self._schema_message:
            self._select_format(f"Protobuf (schema: {self._schema_message})")

    def _on_clear_schema(self) -> None:
        self._schema_pool = None
        self._schema_message = None
        self._schema_combo.blockSignals(True)
        self._schema_combo.clear()
        self._schema_combo.blockSignals(False)
        self._schema_combo.setEnabled(False)
        self._schema_clear_btn.setEnabled(False)
        self._recompute()
        self._select_format("Protobuf (schema-less)")

    def _on_schema_message_changed(self, name: str) -> None:
        self._schema_message = name or None
        self._recompute()
        if self._schema_message:
            self._select_format(f"Protobuf (schema: {self._schema_message})")

    def _select_format(self, name: str) -> None:
        for i in range(self._format_list.count()):
            item = self._format_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == name:
                self._format_list.setCurrentItem(item)
                return

    def _push_step(self) -> None:
        number = len(self._steps) + 1
        step = _StepRow(number, self)
        self._steps.append(step)
        self._pipeline_layout.addWidget(step)
        self._recompute()
        self._scroll_to_last_step = True

    def _on_steps_range_changed(self, _minimum: int, maximum: int) -> None:
        if self._scroll_to_last_step:
            self._steps_scroll.verticalScrollBar().setValue(maximum)

    def _stop_following_last_step(self, _action: int = 0) -> None:
        self._scroll_to_last_step = False

    def _remove_step(self, step: _StepRow) -> None:
        self._stop_following_last_step()
        idx = self._steps.index(step)
        self._steps.pop(idx)
        self._pipeline_layout.removeWidget(step)
        step.deleteLater()
        for i, s in enumerate(self._steps):
            s.set_number(i + 1)
        self._recompute()

    def _recompute(self) -> None:
        current = self._blob
        pipeline: list[PipelineStep] = []

        for i, step in enumerate(self._steps):
            fmt = step.format()
            try:
                result = _INTERMEDIATE[fmt](current)
            except DecodeError as exc:
                self._pipeline = None
                self._update_bytes_actions()
                step.set_hint(
                    translate("BlobInspector", "→ failed: {reason}").format(reason=_reason(exc))
                )
                for s in self._steps[i + 1:]:
                    s.set_hint("")
                self._show_no_bytes(
                    translate("BlobInspector", "[step {number}: {step} failed: {reason}]").format(
                        number=i + 1, step=_entry_label(fmt), reason=_reason(exc)
                    )
                )
                return
            hint = f"→ {len(result.data):,} B"
            note = _step_note(result)
            step.set_hint(f"{hint}\n{note}" if note else hint)
            pipeline.append(PipelineStep(fmt, result))
            current = result.data

        self._pipeline = pipeline
        self._update_bytes_actions()
        self._populate_format_list(current)

    def _populate_format_list(self, data: bytes) -> None:
        self._cached_results = {}
        self._failed_reasons = {}
        self._image = None
        self._image_view_data = None
        self._current_data = data
        self._hex_view_data = None
        self._plist_view_data = None

        confident: list[str] = []
        uncertain: list[str] = []
        failed: list[str] = []

        if self._display_text is not None:
            confident.append("Decoded (from table)")
            self._cached_results["Decoded (from table)"] = self._display_text

        try:
            self._image = _image_result(data)
        except Exception as exc:
            self._failed_reasons["Image"] = _reason(exc)
        if self._image is not None:
            confident.append("Image")
        else:
            self._failed_reasons.setdefault(
                "Image", translate("BlobInspector", "no image signature Crush recognises")
            )
            failed.append("Image")

        ordered_keys = list(_AUTO_ORDER) + [k for k in _TERMINAL_TEXT if k not in set(_AUTO_ORDER)]
        for key in ordered_keys:
            try:
                result = _TERMINAL_TEXT[key](data)
            except Exception as exc:
                self._failed_reasons[key] = _reason(exc)
                failed.append(key)
                continue
            self._cached_results[key] = result
            if key in _PERMISSIVE:
                uncertain.append(key)
            else:
                confident.append(key)

        if self._schema_pool is not None and self._schema_message:
            label = f"Protobuf (schema: {self._schema_message})"
            try:
                from google.protobuf import json_format
                msg = decode_message_with_schema(self._schema_pool, self._schema_message, data)
                self._cached_results[label] = json_format.MessageToJson(
                    msg,
                    preserving_proto_field_name=True,
                    always_print_fields_with_no_presence=True,
                )
                confident.append(label)
            except Exception as exc:
                self._cached_results[label] = f"[schema decode failed: {exc}]"
                failed.append(label)


        prev = self._format_list.currentItem()
        prev_name: str | None = prev.data(Qt.ItemDataRole.UserRole) if prev else None

        muted = QColor(128, 128, 128)

        self._format_list.blockSignals(True)
        self._format_list.clear()

        def _sep() -> None:
            s = QListWidgetItem("─" * 18)
            s.setFlags(Qt.ItemFlag.NoItemFlags)
            s.setForeground(muted)
            self._format_list.addItem(s)

        hex_item = QListWidgetItem(_entry_label(_HEX_VIEW))
        hex_item.setData(Qt.ItemDataRole.UserRole, _HEX_VIEW)
        self._format_list.addItem(hex_item)

        if confident:
            _sep()
            for name in confident:
                item = QListWidgetItem(f"✓  {_entry_label(name)}")  # i18n: keep -- layout
                item.setData(Qt.ItemDataRole.UserRole, name)
                self._format_list.addItem(item)

        if uncertain:
            _sep()
            for name in uncertain:
                item = QListWidgetItem(f"~  {_entry_label(name)}")  # i18n: keep -- layout
                item.setData(Qt.ItemDataRole.UserRole, name)
                item.setForeground(muted)
                self._format_list.addItem(item)

        if failed:
            _sep()
            for name in failed:
                item = QListWidgetItem(f"    {_entry_label(name)}")  # i18n: keep -- layout
                item.setData(Qt.ItemDataRole.UserRole, name)
                item.setForeground(muted)
                self._format_list.addItem(item)

        to_select: str
        prev_still_valid = prev_name is not None and (
            prev_name == _HEX_VIEW
            or prev_name in self._cached_results
            or (prev_name == "Image" and self._image is not None)
        )
        if prev_still_valid:
            to_select = prev_name  # type: ignore[assignment]
        elif self._display_text is not None:
            to_select = "Decoded (from table)"
        elif self._image is not None:
            to_select = "Image"
        else:
            to_select = next((k for k in _AUTO_ORDER if k in self._cached_results and k not in _PERMISSIVE), _HEX_VIEW)

        for i in range(self._format_list.count()):
            item = self._format_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == to_select:
                self._format_list.setCurrentItem(item)
                break

        self._format_list.blockSignals(False)

        current_item = self._format_list.currentItem()
        self._on_format_selected(current_item.data(Qt.ItemDataRole.UserRole) if current_item else "")

    def _on_item_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            return
        name: str = current.data(Qt.ItemDataRole.UserRole)
        if not name:
            return
        self._on_format_selected(name)

    def _on_format_selected(self, name: str) -> None:
        if not name:
            return

        self._schema_toolbar.setVisible(_is_protobuf_entry(name))

        if name == "Image" and self._image is not None:
            self._show_image(self._image, self._current_data)
            return

        if name == _HEX_VIEW:
            if self._hex_view_data is not self._current_data:
                self._hex_view.set_data(self._current_data)
                self._hex_view_data = self._current_data
            self._stack.setCurrentWidget(self._hex_view)
            self._copy_shown_action.setEnabled(True)
            return

        self._stack.setCurrentWidget(self._viewer)
        if name in self._cached_results:
            self._copy_shown_action.setEnabled(True)
            # Stays the text Copy / Copy all take, also on the Plist page.
            self._viewer.setPlainText(self._cached_results[name])
            if name == "Plist / bplist" and self._show_plist(self._current_data):
                self._stack.setCurrentWidget(self._plist_page)
        else:
            self._copy_shown_action.setEnabled(False)
            reason = self._failed_reasons.get(name, "")
            self._viewer.setPlainText(
                translate("BlobInspector", "[{name}: not recognised: {reason}]").format(
                    name=_entry_label(name), reason=reason
                )
                if reason
                else translate("BlobInspector", "[{name}: not recognised]").format(
                    name=_entry_label(name)
                )
            )

    def _show_image(self, result: ParseResult, data: bytes) -> None:
        """Put the image parser's result for *data* on the Image page: the
        image viewer, or -- for a texture that couldn't be decoded -- the
        parser's reason as text."""
        self._copy_shown_action.setEnabled(False)
        if self._image_view_data is not data:
            if self._image_view is not None:
                self._image_view.deleteLater()
            if result.viewer_type == "image":
                from crush.viewers.image_viewer import ImageViewer
                self._image_view = ImageViewer(result.data, self._image_page)
            else:
                text = QPlainTextEdit(str(result.data), self._image_page)
                text.setReadOnly(True)
                self._image_view = text
            self._image_page.layout().addWidget(self._image_view)
            self._image_summary.setText(_summary_html(result.metadata, _IMAGE_SUMMARY_FIRST_LINE))
            self._image_view_data = data
        self._stack.setCurrentWidget(self._image_page)

    def _show_plist(self, data: bytes) -> bool:
        """Put the plist parser's result for *data* on the Plist page; False
        if the parser doesn't read it as a plist (the text page stays)."""
        if self._plist_view_data is data and self._plist_view is not None:
            return True
        from crush.core.vfs import BytesVFS
        from crush.parsers.plist_parser import PlistParser
        from crush.viewers.tree_text_viewer import TreeTextViewer

        vfs = BytesVFS(data, name="blob")
        result = PlistParser().parse(vfs.root(), vfs)
        if result.viewer_type != "tree_text":
            return False
        if self._plist_view is not None:
            self._plist_view.deleteLater()
        # The status is on the summary's first line above; not twice.
        hints = {k: v for k, v in result.viewer_hints.items() if k != "status"}
        self._plist_view = TreeTextViewer(result.data, self._plist_page, **hints)
        self._plist_page.layout().addWidget(self._plist_view)
        # What the plist is and whether it was resolved on the first line,
        # the archive's counts on the second.
        self._plist_summary.setText(_summary_html(result.metadata, _PLIST_SUMMARY_FIRST_LINE))
        self._plist_view_data = data
        return True

    def _update_bytes_actions(self) -> None:
        ok = self._pipeline is not None
        for action in self._bytes_actions:
            action.setEnabled(ok)
        # No viewer above this inspector may open tabs (e.g. no main window);
        # checked again when shown, as a dialog's owner connects it last.
        can_open = request_can_open(self)
        self._open_btn.setEnabled(can_open)
        self._open_btn.setToolTip(
            "" if can_open
            else translate("_BlobPanel", "Opening a tab is not available from here.")
        )

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._update_bytes_actions()

    def _pipeline_text(self) -> str:
        """The decode pipeline for the Properties panel: each step with its
        input and output size and what it left undecoded."""
        if not self._pipeline:
            return translate("_BlobPanel", "none (the inspected bytes as they are)")
        parts: list[str] = []
        size_in = len(self._blob)
        for step in self._pipeline:
            size_out = len(step.result.data)
            part = f"{_entry_label(step.name)} ({size_in:,} B → {size_out:,} B)"
            note = _step_note(step.result).replace("\n", "; ")
            if note:
                part += f" [{note}]"
            parts.append(part)
            size_in = size_out
        return " → ".join(parts)

    def _tab_path(self) -> str:
        """Tab path for the bytes after the pipeline: the inspected bytes'
        path plus the steps, so different pipelines get different tabs."""
        base = self._artifact_path or "/virtual/blob"
        steps = "+".join(
            "".join(c if c.isalnum() else "-" for c in step.name.lower()).strip("-")
            for step in (self._pipeline or [])
        )
        return f"{base}/inspector/{steps or 'as-is'}"

    def _tab_provenance(self) -> dict[str, str]:
        meta = dict(self._provenance)
        meta["Decode pipeline"] = self._pipeline_text()
        return meta

    def _open_in_tab(self, parser_display_name: object) -> None:
        if self._pipeline is None:
            return
        request_open_bytes(
            self, self._current_data, self._tab_path(), parser_display_name,
            self._tab_provenance(),
        )

    def _copy_bytes(self, fmt: str) -> None:
        if self._pipeline is None:
            return
        data = self._current_data
        if fmt == "hex":
            text = data.hex()
        elif fmt == "base64":
            text = base64.b64encode(data).decode("ascii")
        else:
            text = repr(data)
        QApplication.clipboard().setText(text)

    def _export_bytes(self) -> None:
        if self._pipeline is None:
            return
        self._export(self._current_data, OUTPUT_BYTES, None, "")

    def _export_rendered_image(self) -> None:
        image = self._rendered_image()
        if image is None:
            QMessageBox.information(
                self,
                translate("_BlobPanel", "Export rendered image"),
                translate(
                    "_BlobPanel",
                    "There is no decoded image to export: select the Image interpretation "
                    "of bytes Crush recognises and decodes as an image.",
                ),
            )
            return
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        image.save(buffer, "PNG")
        rendering = {
            "renderer": "Crush image viewer (Qt / Pillow)",
            "frame": "first",
            "orientation": "as decoded; the viewer's rotation is not applied",
            "pixel_format": image.format().name,
        }
        self._export(bytes(buffer.data().data()), OUTPUT_RENDERED_PNG, rendering, ".png")

    def _rendered_image(self) -> QImage | None:
        from crush.viewers.image_viewer import ImageViewer

        if self._image is None or self._image_view_data is not self._current_data:
            return None
        if not isinstance(self._image_view, ImageViewer):
            return None
        return self._image_view.decoded_image()

    def _export(
        self, data: bytes, kind: str, rendering: dict[str, str] | None, suffix: str
    ) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            translate("_BlobPanel", "Export"),
            "inspected" + (suffix or ".bin"),  # i18n: keep -- default file name
            translate("_BlobPanel", "All files") + " (*)",  # i18n: keep -- file filter pattern
        )
        if not path:
            return
        sidecar = sidecar_path(path)
        if Path(sidecar).exists():
            answer = QMessageBox.question(
                self,
                translate("_BlobPanel", "Export"),
                translate("_BlobPanel", "{name} already exists. Overwrite it?").format(
                    name=Path(sidecar).name
                ),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        from crush import display_version

        source = dict(self._provenance)
        source_file = source_path_of(self)
        if source_file:
            source.setdefault("Source file", source_file)
        content = build_sidecar(
            tool_version=display_version(),
            source=source,
            inspected=self._blob,
            steps=list(self._pipeline or []),
            output_file=Path(path).name,
            output_kind=kind,
            output=data,
            rendering=rendering,
        )
        try:
            Path(path).write_bytes(data)
            Path(sidecar).write_text(sidecar_json(content), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, translate("_BlobPanel", "Export"), str(exc))

    def _copy_current(self) -> None:
        if self._stack.currentWidget() is self._hex_view:
            # The whole blob as a text hex dump, built only when asked for.
            QApplication.clipboard().setText(bytes_to_hexview(self._current_data))
            return
        QApplication.clipboard().setText(self._viewer.toPlainText())

    def _copy_all(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())


class BlobInspector(QDialog):
    """Non-modal dialog wrapping _BlobPanel for inspecting a single binary BLOB."""

    def __init__(
        self,
        blob: bytes,
        parent: QWidget | None = None,
        *,
        display_text: str | None = None,
        artifact_path: str = "",
        provenance: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(
            translate("BlobInspector", "BLOB Inspector ({blob_count:,} B)").format(
                blob_count=len(blob)
            )
        )
        self.resize(900, 560)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        outer.addWidget(
            _BlobPanel(
                blob, self, display_text=display_text,
                artifact_path=artifact_path, provenance=provenance,
            ),
            stretch=1,
        )

        bottom = QHBoxLayout()
        bottom.addStretch()
        close_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_box.rejected.connect(self.reject)
        bottom.addWidget(close_box)
        outer.addLayout(bottom)
