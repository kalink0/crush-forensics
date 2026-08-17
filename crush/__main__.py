"""Entry point."""
import argparse
import os
import sys


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="crush", description="Crush — Digital Forensic Analysis Workbench")
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="File(s) or folder(s) to open on startup (shorthand for --open PATH)",
    )
    parser.add_argument(
        "--open",
        action="append",
        dest="open_paths",
        metavar="PATH",
        help="File or folder to open on startup (repeatable)",
    )
    return parser.parse_args(argv)


def _icon_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.join(sys._MEIPASS, "crush", "resources", "icons")  # type: ignore[attr-defined]
        for name in ("crush_icon_256.png", "crush_icon_128.svg"):
            p = os.path.join(base, name)
            if os.path.exists(p):
                return p
        return ""
    return os.path.join(os.path.dirname(__file__), "resources", "icons", "crush_icon_128.svg")


def main() -> None:
    args = _parse_args(sys.argv[1:])
    open_paths = list(args.paths) + list(args.open_paths or [])

    import crush
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from crush.ui.main_window import MainWindow
    app = QApplication(sys.argv)
    # The native style on Windows and macOS partially ignores QPalette, causing
    # tab backgrounds, close buttons, and tree branch arrows to ignore the app
    # theme.  Fusion is Qt's cross-platform style that honours QPalette fully.
    if sys.platform.startswith("win") or sys.platform == "darwin":
        app.setStyle("Fusion")
    app.setApplicationName("Crush")
    app.setApplicationVersion(crush.display_version())
    app.setOrganizationName("Crush DFIR")
    app.setDesktopFileName("crush")  # Wayland app-id → taskbar icon association
    icon_path = _icon_path()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    window = MainWindow()
    window.show()
    for path in open_paths:
        window._load_source(path, open_after_load=True, append_to_tree=True)
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
