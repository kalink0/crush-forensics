"""Entry point."""
import argparse
import logging
import os
import sys

from crush.core.analyzer_launcher import INTERNAL_CLI_SENTINEL


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
    parser.add_argument(
        "--image",
        action="append",
        dest="image_paths",
        metavar="PATH",
        help=(
            "Disk image to open on startup (repeatable): raw/dd, split .001 set, "
            "EWF (.E01) or flash dump. A disk image is only read as one when "
            "opened this way (or via File → Open disk image…)"
        ),
    )
    parser.add_argument(
        "--focus",
        dest="focus_path",
        metavar="REL_PATH",
        help=(
            "Path, relative to the root of the single file/folder being opened, "
            "of a file to select and open automatically. Only valid when exactly "
            "one PATH/--open target is given."
        ),
    )
    parser.add_argument(
        "--language",
        metavar="CODE",
        help=(
            "UI language for this run only (e.g. de, or pseudo for the translation "
            "test locale); overrides the saved View → Language setting without "
            "changing it. Loads any compiled translation, also one not yet complete "
            "enough to be offered in the menu"
        ),
    )
    args = parser.parse_args(argv)
    open_paths = list(args.paths) + list(args.open_paths or []) + list(args.image_paths or [])
    if args.focus_path and len(open_paths) != 1:
        parser.error(
            "--focus requires exactly one file/folder/image to open (via PATH, --open or --image)"
        )
    return args


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
    argv = sys.argv[1:]
    # Re-exec'd by crush.core.analyzer_launcher to run crush-analyze in an
    # isolated subprocess -- checked before any Qt import, since this
    # path never touches the GUI at all. See analyzer_launcher's module
    # docstring for why this is a self-re-exec rather than a second binary
    # or `sys.executable -m crush_analyze` (the latter breaks in a frozen
    # build, where sys.executable is crush.exe itself).
    if argv and argv[0] == INTERNAL_CLI_SENTINEL:
        from crush_analyze.cli import main as _analyzer_main
        sys.exit(_analyzer_main(argv[1:]))

    args = _parse_args(argv)
    open_paths = list(args.paths) + list(args.open_paths or [])

    import crush
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QSettings
    from crush.ui import i18n
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
    # Before any widget exists: translated text is read when widgets are built.
    language = args.language or i18n.saved_language(QSettings("Crush DFIR", "Crush"))
    language_note = i18n.load_language(app, language)
    if language_note:
        print(language_note, file=sys.stderr)
    window = MainWindow()
    window.show()
    if language_note:
        logging.getLogger("crush.i18n").warning("%s", language_note)
        window.statusBar().showMessage(language_note)
    for path in open_paths:
        window._load_source(
            path, open_after_load=True, append_to_tree=True, focus_path=args.focus_path
        )
    for path in args.image_paths or []:
        window._load_source(
            path, open_after_load=True, append_to_tree=True, focus_path=args.focus_path,
            as_disk_image=True,
        )
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
