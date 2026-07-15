# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""PDF viewer — rendered pages (pypdfium2) alongside the extracted text."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSlider,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

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


class PDFViewer(QWidget):
    """Tabbed PDF viewer: rendered pages plus the parser's extracted text."""

    def __init__(
        self,
        data: bytes,
        parent: QWidget | None = None,
        extracted_text: str = "",
        password: str | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.addTab(_PdfPagesView(data, password, self), "Pages")
        tabs.addTab(TextView(extracted_text, self), "Text")
        layout.addWidget(tabs)
