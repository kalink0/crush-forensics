# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Image viewer — displays image files with fit-to-window scaling and zoom."""
from __future__ import annotations

import io

from PySide6.QtCore import Qt, QEvent, QPoint, QTimer
from PySide6.QtGui import QImage, QPixmap, QResizeEvent, QCursor, QTransform
from PySide6.QtWidgets import (
    QLabel,
    QHBoxLayout,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from crush.ui.wheel_scroll import install_horizontal_wheel_scroll


_exotic_registered = False


def _ensure_exotic_formats() -> None:
    """Register optional Pillow plugins for HEIF/HEIC/AVIF and JPEG XL (once)."""
    global _exotic_registered
    if _exotic_registered:
        return
    _exotic_registered = True
    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except ImportError:
        pass
    try:
        import pillow_jxl  # type: ignore[import-untyped]  # noqa: F401
    except ImportError:
        pass


def _pillow_decode(data: bytes) -> QPixmap | None:
    """Decode image bytes via Pillow and return a QPixmap using raw pixel transfer."""
    try:
        import PIL.Image as PilImage  # type: ignore[import-untyped]
        _ensure_exotic_formats()
        img = PilImage.open(io.BytesIO(data))
        img = img.convert("RGBA")
        w, h = img.size
        raw = img.tobytes("raw", "RGBA")
        qimg = QImage(raw, w, h, w * 4, QImage.Format.Format_RGBA8888)
        px = QPixmap.fromImage(qimg)
        return px if not px.isNull() else None
    except Exception:
        return None


class ImageViewer(QWidget):
    """Viewer for image files (JPEG, PNG, GIF, BMP, WebP, TIFF, HEIC, HEIF, AVIF, JXL)."""

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw = data
        self._pixmap = QPixmap()
        self._scale = 1.0
        self._fit_to_window = True
        self._magnifier_on = False
        self._magnifier_zoom = 3.0
        self._magnifier_size = 180
        self._rotation = 0
        self._rotated_cache: QPixmap | None = None
        self._rotated_cache_angle = -1
        self._build_ui()
        self._load(data)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        toolbar = QWidget()
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(6)

        self._fit_btn = QPushButton("Fit")
        self._fit_btn.clicked.connect(self._fit)
        tb_layout.addWidget(self._fit_btn)

        self._rotate_left_btn = QPushButton("↶")
        self._rotate_left_btn.setFixedWidth(28)
        self._rotate_left_btn.setToolTip("Rotate left 90°")
        self._rotate_left_btn.clicked.connect(lambda: self._rotate(-90))
        tb_layout.addWidget(self._rotate_left_btn)

        self._rotate_right_btn = QPushButton("↷")
        self._rotate_right_btn.setFixedWidth(28)
        self._rotate_right_btn.setToolTip("Rotate right 90°")
        self._rotate_right_btn.clicked.connect(lambda: self._rotate(90))
        tb_layout.addWidget(self._rotate_right_btn)

        self._zoom_out = QPushButton("-")
        self._zoom_out.setFixedWidth(28)
        self._zoom_out.clicked.connect(lambda: self._zoom_to(self._scale / 1.25))
        tb_layout.addWidget(self._zoom_out)

        self._zoom_slider = QSlider(Qt.Orientation.Horizontal)
        self._zoom_slider.setRange(10, 400)
        self._zoom_slider.setValue(100)
        self._zoom_slider.setFixedWidth(140)
        self._zoom_slider.valueChanged.connect(self._on_slider_zoom)
        tb_layout.addWidget(self._zoom_slider)

        self._zoom_in = QPushButton("+")
        self._zoom_in.setFixedWidth(28)
        self._zoom_in.clicked.connect(lambda: self._zoom_to(self._scale * 1.25))
        tb_layout.addWidget(self._zoom_in)

        self._zoom_label = QLabel("100%")
        tb_layout.addWidget(self._zoom_label)

        self._magnifier_btn = QPushButton("Magnifier")
        self._magnifier_btn.setCheckable(True)
        self._magnifier_btn.toggled.connect(self._toggle_magnifier)
        tb_layout.addWidget(self._magnifier_btn)

        tb_layout.addStretch()
        layout.addWidget(toolbar)

        self._scroll = QScrollArea()
        self._scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidgetResizable(False)
        install_horizontal_wheel_scroll(self._scroll, smooth_item_scroll=False)
        self._scroll.viewport().setMouseTracking(True)

        self._image_label = QLabel()
        self._image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._image_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self._image_label.setMouseTracking(True)
        self._image_label.installEventFilter(self)

        self._scroll.setWidget(self._image_label)
        layout.addWidget(self._scroll)

        # Magnifier overlay (hidden by default)
        self._magnifier = QLabel(self._scroll.viewport())
        self._magnifier.setFixedSize(self._magnifier_size, self._magnifier_size)
        self._magnifier.setStyleSheet("background: #111; border: 1px solid #444;")
        self._magnifier.setVisible(False)
        self._magnifier.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def _load(self, data: bytes) -> None:
        loaded = self._pixmap.loadFromData(data)
        if not loaded or self._pixmap.isNull():
            px = _pillow_decode(data)
            if px is not None:
                self._pixmap = px
                loaded = True
        if not loaded or self._pixmap.isNull():
            self._image_label.setText("Unable to decode image.")
            return
        self._set_scale(1.0)
        QTimer.singleShot(0, self._fit)

    def _fit(self) -> None:
        self._fit_to_window = True
        self._apply_fit_scale()

    def _rotated_pixmap(self) -> QPixmap:
        if self._rotation == 0:
            return self._pixmap
        if self._rotated_cache is not None and self._rotated_cache_angle == self._rotation:
            return self._rotated_cache
        transform = QTransform().rotate(self._rotation)
        self._rotated_cache = self._pixmap.transformed(
            transform, Qt.TransformationMode.SmoothTransformation
        )
        self._rotated_cache_angle = self._rotation
        return self._rotated_cache

    def _rotate(self, degrees: int) -> None:
        if self._pixmap.isNull():
            return
        self._rotation = (self._rotation + degrees) % 360
        if self._fit_to_window:
            self._apply_fit_scale()
        else:
            self._set_scale(self._scale)

    def _apply_fit_scale(self) -> None:
        pixmap = self._rotated_pixmap()
        if pixmap.isNull():
            return
        viewport = self._scroll.viewport().size()
        if viewport.width() <= 0 or viewport.height() <= 0:
            self._set_scale(1.0, from_fit=True)
            return
        scale_x = viewport.width() / pixmap.width()
        scale_y = viewport.height() / pixmap.height()
        scale = min(scale_x, scale_y)
        self._set_scale(scale, from_fit=True)

    def _set_scale(self, scale: float, from_fit: bool = False) -> None:
        pixmap = self._rotated_pixmap()
        if pixmap.isNull():
            return
        self._fit_to_window = from_fit
        scale = max(0.1, min(scale, 4.0))
        self._scale = scale
        scaled = pixmap.scaled(
            int(pixmap.width() * scale),
            int(pixmap.height() * scale),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._image_label.setPixmap(scaled)
        self._image_label.resize(scaled.size())
        self._zoom_label.setText(f"{int(self._scale * 100)}%")
        self._zoom_slider.blockSignals(True)
        self._zoom_slider.setValue(int(self._scale * 100))
        self._zoom_slider.blockSignals(False)

    def _on_slider_zoom(self, value: int) -> None:
        self._zoom_to(value / 100.0)

    def _zoom_to(self, scale: float, anchor_viewport: QPoint | None = None) -> None:
        if self._pixmap.isNull():
            return
        if anchor_viewport is None:
            # Prefer current cursor position if over viewport; otherwise center
            cursor_pos = QCursor.pos()
            anchor_viewport = self._scroll.viewport().mapFromGlobal(cursor_pos)
            if not self._scroll.viewport().rect().contains(anchor_viewport):
                anchor_viewport = QPoint(
                    self._scroll.viewport().width() // 2,
                    self._scroll.viewport().height() // 2,
                )

        # Map anchor point to image coordinates using current scale
        label_pos = self._image_label.mapFrom(self._scroll.viewport(), anchor_viewport)
        if self._scale > 0:
            img_x = label_pos.x() / self._scale
            img_y = label_pos.y() / self._scale
        else:
            img_x = 0.0
            img_y = 0.0

        self._set_scale(scale)

        # Keep the same image point under the cursor after scaling
        new_label_x = int(img_x * self._scale)
        new_label_y = int(img_y * self._scale)
        hbar = self._scroll.horizontalScrollBar()
        vbar = self._scroll.verticalScrollBar()
        hbar.setValue(max(0, new_label_x - anchor_viewport.x()))
        vbar.setValue(max(0, new_label_y - anchor_viewport.y()))

    def _toggle_magnifier(self, enabled: bool) -> None:
        self._magnifier_on = enabled
        self._magnifier.setVisible(enabled)

    def _update_magnifier(self, pos: QPoint) -> None:
        if not self._magnifier_on or self._pixmap.isNull():
            return
        # Map cursor position in scaled label to rotated-image coordinates
        label_pix = self._image_label.pixmap()
        if label_pix is None:
            return
        pixmap = self._rotated_pixmap()
        label_pos = self._image_label.mapFrom(self._scroll.viewport(), pos)
        if label_pos.x() < 0 or label_pos.y() < 0:
            return
        if label_pos.x() >= label_pix.width() or label_pos.y() >= label_pix.height():
            return
        src_x = int(label_pos.x() / self._scale)
        src_y = int(label_pos.y() / self._scale)
        half = int(self._magnifier_size / (2 * self._magnifier_zoom))
        x0 = max(0, src_x - half)
        y0 = max(0, src_y - half)
        x1 = min(pixmap.width(), src_x + half)
        y1 = min(pixmap.height(), src_y + half)
        crop = pixmap.copy(x0, y0, max(1, x1 - x0), max(1, y1 - y0))
        mag = crop.scaled(
            self._magnifier_size,
            self._magnifier_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._magnifier.setPixmap(mag)
        offset = QPoint(16, 16)
        self._magnifier.move(pos + offset)

    def eventFilter(self, obj: object, event: QEvent) -> bool:  # type: ignore[override]
        if obj is self._image_label:
            if event.type() == QEvent.Type.MouseMove:
                if hasattr(event, "position"):
                    pos = event.position().toPoint()
                else:
                    pos = event.pos()
                self._update_magnifier(self._image_label.mapTo(self._scroll.viewport(), pos))
            if event.type() == QEvent.Type.Leave:
                self._magnifier.setVisible(False)
            if event.type() == QEvent.Type.Enter and self._magnifier_on:
                self._magnifier.setVisible(True)
        return super().eventFilter(obj, event)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self._fit_to_window:
            self._apply_fit_scale()

    def wheelEvent(self, event: object) -> None:  # type: ignore[override]
        if hasattr(event, "modifiers") and hasattr(event, "angleDelta"):
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                delta = event.angleDelta().y()
                anchor = None
                if hasattr(event, "position"):
                    anchor = event.position().toPoint()
                elif hasattr(event, "pos"):
                    anchor = event.pos()
                if delta > 0:
                    self._zoom_to(self._scale * 1.1, anchor_viewport=anchor)
                elif delta < 0:
                    self._zoom_to(self._scale / 1.1, anchor_viewport=anchor)
                return
        super().wheelEvent(event)  # type: ignore[arg-type]
