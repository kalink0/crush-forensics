"""Generate platform icon files from the crush SVG icon.

macOS  → crush.icns  (via iconutil, built-in)
Windows → crush.ico  (via Pillow — pip install Pillow)

Run headlessly on any platform:
    QT_QPA_PLATFORM=offscreen python scripts/make_icons.py
"""
from __future__ import annotations

import io
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QIODevice
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

SVG = os.path.join(
    os.path.dirname(__file__), "..", "crush", "resources", "icons", "crush_icon_128.svg"
)


def _render_png(size: int) -> bytes:
    renderer = QSvgRenderer(SVG)
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(0)
    p = QPainter(img)
    renderer.render(p)
    p.end()
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(buf.data().data())


def make_icns(out: str = "crush.icns") -> None:
    import shutil
    import subprocess

    iconset = out.replace(".icns", ".iconset")
    os.makedirs(iconset, exist_ok=True)
    for size, name in [
        (16,   "icon_16x16"),
        (32,   "icon_16x16@2x"),
        (32,   "icon_32x32"),
        (64,   "icon_32x32@2x"),
        (128,  "icon_128x128"),
        (256,  "icon_128x128@2x"),
        (256,  "icon_256x256"),
        (512,  "icon_256x256@2x"),
        (512,  "icon_512x512"),
        (1024, "icon_512x512@2x"),
    ]:
        with open(f"{iconset}/{name}.png", "wb") as f:
            f.write(_render_png(size))
    subprocess.run(["iconutil", "-c", "icns", iconset, "-o", out], check=True)
    shutil.rmtree(iconset)
    print(f"Created: {out}")


def make_ico(out: str = "crush.ico") -> None:
    from PIL import Image

    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [Image.open(io.BytesIO(_render_png(s))).convert("RGBA") for s in sizes]
    images[0].save(
        out,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    print(f"Created: {out}")


def main() -> None:
    app = QGuiApplication(sys.argv)  # noqa: F841  (keeps Qt alive)
    if sys.platform == "darwin":
        make_icns()
    elif sys.platform == "win32":
        make_ico()
    else:
        with open("crush_icon_256.png", "wb") as f:
            f.write(_render_png(256))
        print("Created: crush_icon_256.png")


if __name__ == "__main__":
    main()
