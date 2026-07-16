# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""PDF viewer — rendered pages (pypdfium2) alongside the extracted text."""
from __future__ import annotations

import difflib

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPixmap, QTextCharFormat
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSlider,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from crush.parsers.pdf_parser import PdfRevision
from crush.ui.wheel_scroll import install_horizontal_wheel_scroll
from crush.viewers.text_viewer import TextView

# ~144 DPI (PDF page units are 72/inch) -- sharp enough for on-screen
# reading without rendering every page at a wasteful resolution.
_RENDER_SCALE = 2.0


def _pil_to_pixmap(img: object) -> QPixmap:
    """Same raw-pixel-transfer approach as image_viewer.py's _pillow_decode."""
    rgba = img.convert("RGBA")  # type: ignore[attr-defined]
    w, h = rgba.size
    raw = rgba.tobytes("raw", "RGBA")
    qimg = QImage(raw, w, h, w * 4, QImage.Format.Format_RGBA8888)
    return QPixmap.fromImage(qimg)


class _PdfPagesView(QWidget):
    """Page-by-page rendered view with prev/next navigation and zoom.

    Renders lazily, one page at a time, and caches only the current page's
    pixmap -- a forensic PDF can run into hundreds of pages, so eagerly
    rendering the whole document up front is out of the question.
    """

    def __init__(
        self, data: bytes, password: str | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._page = 0
        self._scale = 1.0
        self._page_pixmap: QPixmap | None = None
        self._page_pixmap_index = -1
        self._doc: object | None = None
        self._page_count = 0
        self._build_ui()
        self._open(data, password)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        nav_row = QHBoxLayout()
        nav_row.setSpacing(8)
        self._prev_btn = QPushButton("◀ Prev")
        self._prev_btn.clicked.connect(self._prev_page)
        nav_row.addWidget(self._prev_btn)
        self._page_label = QLabel("")
        nav_row.addWidget(self._page_label)
        self._next_btn = QPushButton("Next ▶")
        self._next_btn.clicked.connect(self._next_page)
        nav_row.addWidget(self._next_btn)
        nav_row.addStretch(1)
        layout.addLayout(nav_row)

        zoom_row = QHBoxLayout()
        zoom_row.setSpacing(8)
        zoom_out_btn = QPushButton("-")
        zoom_out_btn.setFixedWidth(28)
        zoom_out_btn.clicked.connect(lambda: self._zoom_to(self._scale / 1.25))
        zoom_row.addWidget(zoom_out_btn)
        self._zoom_slider = QSlider(Qt.Orientation.Horizontal)
        self._zoom_slider.setRange(10, 400)
        self._zoom_slider.setValue(100)
        self._zoom_slider.setFixedWidth(140)
        self._zoom_slider.valueChanged.connect(lambda v: self._zoom_to(v / 100.0))
        zoom_row.addWidget(self._zoom_slider)
        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedWidth(28)
        zoom_in_btn.clicked.connect(lambda: self._zoom_to(self._scale * 1.25))
        zoom_row.addWidget(zoom_in_btn)
        self._zoom_label = QLabel("100%")
        zoom_row.addWidget(self._zoom_label)
        zoom_row.addStretch(1)
        layout.addLayout(zoom_row)

        self._scroll = QScrollArea()
        self._scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidgetResizable(False)
        install_horizontal_wheel_scroll(self._scroll, smooth_item_scroll=False)
        self._page_image_label = QLabel()
        self._page_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidget(self._page_image_label)
        layout.addWidget(self._scroll)

    def _open(self, data: bytes, password: str | None) -> None:
        try:
            import pypdfium2 as pdfium

            self._doc = pdfium.PdfDocument(data, password=password)
            self._page_count = len(self._doc)  # type: ignore[arg-type]
        except Exception as exc:
            self._page_image_label.setText(f"Unable to render PDF: {exc}")
            self._prev_btn.setEnabled(False)
            self._next_btn.setEnabled(False)
            return
        self._load_page()

    def _render_current_page(self) -> QPixmap | None:
        if self._doc is None or self._page_count == 0:
            return None
        if self._page_pixmap is not None and self._page_pixmap_index == self._page:
            return self._page_pixmap
        page = self._doc[self._page]  # type: ignore[index]
        bitmap = page.render(scale=_RENDER_SCALE)
        pixmap = _pil_to_pixmap(bitmap.to_pil())
        self._page_pixmap = pixmap
        self._page_pixmap_index = self._page
        return pixmap

    def _load_page(self) -> None:
        pixmap = self._render_current_page()
        if pixmap is None:
            return
        self._page_label.setText(f"Page {self._page + 1} / {self._page_count}")
        self._prev_btn.setEnabled(self._page > 0)
        self._next_btn.setEnabled(self._page < self._page_count - 1)
        self._apply_scale(pixmap)

    def _apply_scale(self, pixmap: QPixmap) -> None:
        scaled = pixmap.scaled(
            int(pixmap.width() * self._scale),
            int(pixmap.height() * self._scale),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._page_image_label.setPixmap(scaled)
        self._page_image_label.resize(scaled.size())

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._load_page()

    def _next_page(self) -> None:
        if self._page < self._page_count - 1:
            self._page += 1
            self._load_page()

    def _zoom_to(self, scale: float) -> None:
        scale = max(0.1, min(scale, 4.0))
        self._scale = scale
        pixmap = self._render_current_page()
        if pixmap is not None:
            self._apply_scale(pixmap)
        self._zoom_label.setText(f"{int(scale * 100)}%")
        self._zoom_slider.blockSignals(True)
        self._zoom_slider.setValue(int(scale * 100))
        self._zoom_slider.blockSignals(False)

    def wheelEvent(self, event: object) -> None:  # type: ignore[override]
        # Same Ctrl+wheel-to-zoom convention as image_viewer.py.
        if hasattr(event, "modifiers") and hasattr(event, "angleDelta"):
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                delta = event.angleDelta().y()
                if delta > 0:
                    self._zoom_to(self._scale * 1.1)
                elif delta < 0:
                    self._zoom_to(self._scale / 1.1)
                return
        super().wheelEvent(event)  # type: ignore[arg-type]


_SIZE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"]


def _format_size(size: int) -> str:
    """Mirrors fs_panel.py's _format_size -- kept local since this
    codebase already has one small copy per module rather than a shared
    utility for this."""
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(_SIZE_UNITS) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {_SIZE_UNITS[unit_index]}"
    return f"{value:.1f} {_SIZE_UNITS[unit_index]}"


class _PdfAttachmentsView(QWidget):
    """Embedded-file list (ISO 32000-1 7.11) -- double-click or right-click
    -> Open as New Tab routes the bytes through the same generic
    open_bytes_requested mechanism the BLOB Inspector / TableViewer already
    use (see main_window.py's _open_bytes_as_artifact), so an attachment is
    identified and displayed by whichever parser actually matches it,
    rather than assuming it's any particular format."""

    open_bytes_requested = Signal(bytes, str)

    def __init__(
        self, attachments: list[tuple[str, bytes]], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._attachments = attachments
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = QTableWidget(len(attachments), 2, self)
        self._table.setHorizontalHeaderLabels(["Name", "Size"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        self._table.cellDoubleClicked.connect(lambda row, _col: self._open_as_new_tab(row))
        for row, (name, data) in enumerate(attachments):
            self._table.setItem(row, 0, QTableWidgetItem(name))
            self._table.setItem(row, 1, QTableWidgetItem(_format_size(len(data))))
        layout.addWidget(self._table)

    def _open_as_new_tab(self, row: int) -> None:
        name, data = self._attachments[row]
        self.open_bytes_requested.emit(data, name)

    def _export(self, row: int) -> None:
        name, data = self._attachments[row]
        path, _ = QFileDialog.getSaveFileName(self, "Export Attachment", name, "All files (*)")
        if not path:
            return
        with open(path, "wb") as f:
            f.write(data)

    def _on_context_menu(self, pos: object) -> None:
        row = self._table.rowAt(pos.y())  # type: ignore[attr-defined]
        if row < 0:
            return
        menu = QMenu(self)
        open_action = menu.addAction("Open as New Tab")
        export_action = menu.addAction("Export…")
        action = menu.exec(self._table.viewport().mapToGlobal(pos))  # type: ignore[arg-type]
        if action == open_action:
            self._open_as_new_tab(row)
        elif action == export_action:
            self._export(row)


_DIFF_ADD_BG = QColor(46, 160, 67, 60)    # translucent green tint
_DIFF_DEL_BG = QColor(220, 60, 60, 60)    # translucent red tint


class _PdfDiffView(QWidget):
    """Line-level text diff (stdlib difflib) between any two revisions --
    picks the last two by default, since "what changed in the last save"
    is the common question. Colors are translucent tints over whatever
    the widget's actual background is, rather than a fixed opaque color,
    so it reads reasonably across this app's Light/Dark/Geek/rainbow
    themes without per-theme tuning.

    Text-only: a black box drawn *over* text without touching the
    underlying content stream changes nothing in extracted text between
    revisions, so this catches content edits, not purely visual ones --
    see the sibling "Visual" sub-tab (_PdfVisualDiffView) for a
    pixel-level page diff, which does catch that case.
    """

    def __init__(self, revisions: list[PdfRevision], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._revisions = revisions
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        picker_row = QHBoxLayout()
        picker_row.setSpacing(6)
        picker_row.addWidget(QLabel("Compare:"))
        self._combo_a = QComboBox()
        self._combo_b = QComboBox()
        for i, _rev in enumerate(revisions):
            label = f"Revision {i + 1}" + (" (current)" if i == len(revisions) - 1 else "")
            self._combo_a.addItem(label, i)
            self._combo_b.addItem(label, i)
        self._combo_a.setCurrentIndex(max(0, len(revisions) - 2))
        self._combo_b.setCurrentIndex(len(revisions) - 1)
        picker_row.addWidget(self._combo_a)
        picker_row.addWidget(QLabel("→"))
        picker_row.addWidget(self._combo_b)
        picker_row.addStretch(1)
        layout.addLayout(picker_row)

        self._diff_view = QPlainTextEdit()
        self._diff_view.setReadOnly(True)
        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._diff_view.setFont(font)
        layout.addWidget(self._diff_view)

        self._combo_a.currentIndexChanged.connect(self._update_diff)
        self._combo_b.currentIndexChanged.connect(self._update_diff)
        self._update_diff()

    def _update_diff(self) -> None:
        idx_a = self._combo_a.currentData()
        idx_b = self._combo_b.currentData()
        self._diff_view.clear()
        if idx_a is None or idx_b is None:
            return
        rev_a = self._revisions[idx_a]
        rev_b = self._revisions[idx_b]
        diff_lines = list(difflib.unified_diff(
            rev_a.text.splitlines(), rev_b.text.splitlines(),
            fromfile=f"Revision {idx_a + 1}", tofile=f"Revision {idx_b + 1}",
            lineterm="", n=2,
        ))
        cursor = self._diff_view.textCursor()
        if not diff_lines:
            cursor.insertText("No text differences between these revisions.\n")
            return
        for line in diff_lines:
            fmt = QTextCharFormat()
            if line.startswith(("+++", "---")):
                fmt.setForeground(QColor(128, 128, 128))
            elif line.startswith("@@"):
                fmt.setForeground(QColor(96, 160, 200))
            elif line.startswith("+"):
                fmt.setBackground(_DIFF_ADD_BG)
            elif line.startswith("-"):
                fmt.setBackground(_DIFF_DEL_BG)
            cursor.insertText(line + "\n", fmt)


def _render_pdf_page_pil(data: bytes, password: str | None, page_index: int) -> object | None:
    """Render one page of a PDF revision slice to a PIL RGB Image, or
    None if the page doesn't exist / the slice fails to open."""
    try:
        import pypdfium2 as pdfium

        doc = pdfium.PdfDocument(data, password=password)
        if page_index >= len(doc):
            return None
        bitmap = doc[page_index].render(scale=_RENDER_SCALE)
        return bitmap.to_pil().convert("RGB")
    except Exception:
        return None


def _pdf_page_count(data: bytes, password: str | None) -> int:
    try:
        import pypdfium2 as pdfium

        return len(pdfium.PdfDocument(data, password=password))
    except Exception:
        return 0


class _PdfVisualDiffView(QWidget):
    """Pixel-level page diff between two revisions -- catches purely
    visual changes a text diff can't see, e.g. a black redaction box
    drawn *over* text whose underlying content stream is untouched (no
    text-diff signal at all), or a swapped/removed image. Differing
    pixels (per-channel luminance difference above a small noise
    threshold) are highlighted with a translucent red overlay on top of
    the newer revision's own rendering.

    Rendered on demand when the revision pair or page changes, not
    cached -- there are O(N^2) possible revision pairs, so caching every
    combination isn't worth it; a single re-render is cheap enough.
    """

    _DIFF_THRESHOLD = 24  # luminance-difference noise floor, not a guess
    # at content -- pypdfium2 renders deterministically, so any value
    # above this for a truly identical source page would itself be a bug
    # worth seeing, not something to hide by raising the threshold further.

    def __init__(
        self, revisions: list[PdfRevision], password: str | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._revisions = revisions
        self._password = password
        self._page = 0
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        picker_row = QHBoxLayout()
        picker_row.setSpacing(6)
        picker_row.addWidget(QLabel("Compare:"))
        self._combo_a = QComboBox()
        self._combo_b = QComboBox()
        for i, _rev in enumerate(revisions):
            label = f"Revision {i + 1}" + (" (current)" if i == len(revisions) - 1 else "")
            self._combo_a.addItem(label, i)
            self._combo_b.addItem(label, i)
        self._combo_a.setCurrentIndex(max(0, len(revisions) - 2))
        self._combo_b.setCurrentIndex(len(revisions) - 1)
        picker_row.addWidget(self._combo_a)
        picker_row.addWidget(QLabel("→"))
        picker_row.addWidget(self._combo_b)
        picker_row.addSpacing(16)
        self._prev_btn = QPushButton("◀ Prev page")
        self._prev_btn.clicked.connect(self._prev_page)
        picker_row.addWidget(self._prev_btn)
        self._page_label = QLabel("")
        picker_row.addWidget(self._page_label)
        self._next_btn = QPushButton("Next page ▶")
        self._next_btn.clicked.connect(self._next_page)
        picker_row.addWidget(self._next_btn)
        picker_row.addStretch(1)
        layout.addLayout(picker_row)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)
        self._status_label.setStyleSheet("padding: 2px 8px;")
        layout.addWidget(self._status_label)

        self._scroll = QScrollArea()
        self._scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidgetResizable(False)
        install_horizontal_wheel_scroll(self._scroll, smooth_item_scroll=False)
        self._image_label = QLabel()
        self._image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidget(self._image_label)
        layout.addWidget(self._scroll)

        self._combo_a.currentIndexChanged.connect(self._on_pair_changed)
        self._combo_b.currentIndexChanged.connect(self._on_pair_changed)
        self._update()

    def _on_pair_changed(self) -> None:
        self._page = 0
        self._update()

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._update()

    def _next_page(self) -> None:
        self._page += 1
        self._update()

    def _update(self) -> None:
        idx_a = self._combo_a.currentData()
        idx_b = self._combo_b.currentData()
        if idx_a is None or idx_b is None:
            return
        rev_a = self._revisions[idx_a]
        rev_b = self._revisions[idx_b]

        page_count = max(
            _pdf_page_count(rev_a.data, self._password),
            _pdf_page_count(rev_b.data, self._password),
        )
        self._page_label.setText(f"Page {self._page + 1} / {max(page_count, 1)}")
        self._prev_btn.setEnabled(self._page > 0)
        self._next_btn.setEnabled(self._page + 1 < page_count)

        img_a = _render_pdf_page_pil(rev_a.data, self._password, self._page)
        img_b = _render_pdf_page_pil(rev_b.data, self._password, self._page)
        if img_a is None or img_b is None:
            self._status_label.setText(
                "This page doesn't exist in one of the two selected revisions."
            )
            self._image_label.clear()
            return
        if img_a.size != img_b.size:
            self._status_label.setText(
                f"Page size differs between revisions ({img_a.size[0]}×{img_a.size[1]} vs "
                f"{img_b.size[0]}×{img_b.size[1]}) -- not diffed to avoid a misleading "
                "resize; showing the newer revision only."
            )
            pixmap = _pil_to_pixmap(img_b)
            self._image_label.setPixmap(pixmap)
            self._image_label.resize(pixmap.size())
            return

        from PIL import Image, ImageChops

        diff_gray = ImageChops.difference(img_a, img_b).convert("L")
        mask = diff_gray.point(lambda p: 255 if p > self._DIFF_THRESHOLD else 0)
        changed_px = mask.histogram()[255]
        total_px = mask.size[0] * mask.size[1]

        if changed_px == 0:
            self._status_label.setText("No visual differences on this page.")
            pixmap = _pil_to_pixmap(img_b)
        else:
            pct = 100.0 * changed_px / total_px
            self._status_label.setText(
                f"{pct:.2f}% of pixels differ on this page (highlighted in red)."
            )
            red_layer = Image.new("RGBA", img_b.size, (255, 0, 0, 130))
            overlay = Image.new("RGBA", img_b.size, (255, 0, 0, 0))
            overlay.paste(red_layer, mask=mask)
            composited = img_b.convert("RGBA")
            composited.alpha_composite(overlay)
            pixmap = _pil_to_pixmap(composited)

        self._image_label.setPixmap(pixmap)
        self._image_label.resize(pixmap.size())


class _PdfHistoryView(QWidget):
    """Revision-by-revision view of a PDF's incremental-update chain
    (see PDFParser._split_revisions / PdfRevision). Each revision is a
    complete, independently valid PDF slice -- earlier ones may show
    content ("redacted" text, removed images, a JavaScript payload or
    attachment later stripped) that the current/final revision no longer
    exposes. Three sub-tabs: Browse (one revision at a time, full
    Pages/Text/Attachments), Diff (line-level text diff between any two
    revisions -- see _PdfDiffView), and Visual (pixel-level page diff --
    see _PdfVisualDiffView).

    Built lazily: only the currently selected revision's sub-view is
    constructed, and it's cached afterward -- the same "don't do work
    nobody asked for" rule _PdfPagesView already applies per-page,
    extended here to per-revision (N revisions x M pages would otherwise
    all render up front).
    """

    open_bytes_requested = Signal(bytes, str)

    def __init__(
        self, revisions: list[PdfRevision], password: str | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._revisions = revisions
        self._password = password
        self._built: dict[int, QWidget] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        sub_tabs = QTabWidget()
        sub_tabs.addTab(self._build_browse_tab(), "Browse")
        sub_tabs.addTab(_PdfDiffView(revisions, sub_tabs), "Text Diff")
        sub_tabs.addTab(_PdfVisualDiffView(revisions, password, sub_tabs), "Visual Diff")
        layout.addWidget(sub_tabs)

    def _build_browse_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        selector_row = QHBoxLayout()
        selector_row.setSpacing(4)
        for i, rev in enumerate(self._revisions):
            label = f"Revision {i + 1}" + (" (current)" if i == len(self._revisions) - 1 else "")
            if rev.has_javascript or rev.signatures != "None" or rev.attachments:
                label += " ⚠"
            btn = QPushButton(label)
            btn.clicked.connect(lambda _checked=False, idx=i: self._select(idx))
            selector_row.addWidget(btn)
        selector_row.addStretch(1)
        layout.addLayout(selector_row)

        self._stack = QStackedWidget()
        layout.addWidget(self._stack)
        self._select(0)
        return container

    def _select(self, index: int) -> None:
        if index not in self._built:
            self._built[index] = self._build_revision_view(self._revisions[index])
            self._stack.addWidget(self._built[index])
        self._stack.setCurrentWidget(self._built[index])

    def _build_revision_view(self, rev: PdfRevision) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        info = QLabel(
            f"JavaScript: {'Present' if rev.has_javascript else 'Not present'}"
            f"    ·    Signatures: {rev.signatures}"
            f"    ·    Attachments: {len(rev.attachments)} file(s)"
        )
        info.setStyleSheet("padding: 4px 8px; color: palette(mid);")
        layout.addWidget(info)

        tabs = QTabWidget()
        tabs.addTab(_PdfPagesView(rev.data, self._password, tabs), "Pages")
        tabs.addTab(TextView(rev.text, tabs), "Text")
        if rev.attachments:
            attachments_view = _PdfAttachmentsView(rev.attachments, tabs)
            attachments_view.open_bytes_requested.connect(self.open_bytes_requested)
            tabs.addTab(attachments_view, f"Attachments ({len(rev.attachments)})")
        layout.addWidget(tabs)
        return container


class PDFViewer(QWidget):
    """Tabbed PDF viewer: rendered pages plus the parser's extracted text
    and, when present, Attachments and History tabs."""

    open_bytes_requested = Signal(bytes, str)

    def __init__(
        self,
        data: bytes,
        parent: QWidget | None = None,
        extracted_text: str = "",
        password: str | None = None,
        attachments: list[tuple[str, bytes]] | None = None,
        revisions: list[PdfRevision] | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.addTab(_PdfPagesView(data, password, self), "Pages")
        tabs.addTab(TextView(extracted_text, self), "Text")
        if attachments:
            attachments_view = _PdfAttachmentsView(attachments, self)
            attachments_view.open_bytes_requested.connect(self.open_bytes_requested)
            tabs.addTab(attachments_view, f"Attachments ({len(attachments)})")
        if revisions:
            history_view = _PdfHistoryView(revisions, password, self)
            history_view.open_bytes_requested.connect(self.open_bytes_requested)
            tabs.addTab(history_view, f"History ({len(revisions)})")
        layout.addWidget(tabs)
