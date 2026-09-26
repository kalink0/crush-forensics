# SPDX-License-Identifier: Apache-2.0
"""Guards the UI translation: in converted modules every text handed to a
Qt display call goes through translate(), and every translate() call is
one lupdate can extract.

A deliberate exception (a technical value that is never translated) is
marked on its line with `# i18n: keep -- <reason>`.

CONVERTED grows with each converted module; at the end of the conversion
it is every module under crush/ui and crush/viewers.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1]

CONVERTED: list[str] = [
    "ui/about_dialog.py",
    "ui/busy_dialog.py",
    "ui/extract_dialog.py",
    "ui/format_info_dialog.py",
    "ui/format_reference.py",
    "ui/fs_panel.py",
    "ui/i18n.py",
    "ui/large_open.py",
    "ui/loading_dialog.py",
    "ui/log_scope.py",
    "ui/main_window.py",
    "ui/mmkv_key_dialog.py",
    "ui/paste_decode_dialog.py",
    "ui/props_panel.py",
    "ui/search_panel.py",
    "ui/sqlcipher_dialog.py",
    "ui/viewer_factory.py",
    "ui/wheel_scroll.py",
]

# Qt calls (functions, constructors, methods) whose string arguments are
# shown to the analyst.
UI_CALLS = {
    "QAction", "QCheckBox", "QDockWidget", "QGroupBox", "QLabel", "QMessageBox", "QProgressDialog",
    "QPushButton", "QRadioButton", "QToolButton",
    "addAction", "addButton", "addItem", "addItems", "addMenu", "addRow", "addSection",
    "addTab", "critical", "getExistingDirectory", "getInt", "getItem", "getOpenFileName",
    "getSaveFileName", "getText", "information", "insertItem", "insertTab", "question",
    "setDetailedText", "setHeaderLabels", "setHorizontalHeaderLabels", "setHtml",
    "setInformativeText", "setItemText", "setLabelText", "setMarkdown",
    "setPlaceholderText", "setPrefix", "setSpecialValueText", "setStatusTip", "setSuffix",
    "setTabText", "setTabToolTip", "setText", "setTitle", "setToolTip",
    "setVerticalHeaderLabels", "setWhatsThis", "setWindowTitle", "showMessage", "warning",
    "getOpenFileNames",
    # Crush's own helpers that show the text they're given.
    "FolderDiscoveryDialog", "LoadingDialog", "_with_reason", "busy_call",
    "run_with_busy_dialog", "set_text",
}
KEEP_MARKER = "# i18n: keep"
# Also logger methods -- the log stays English. Counted only on QMessageBox.
MESSAGE_BOX_ONLY = {"critical", "information", "question", "warning"}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def is_ui_call(node: ast.Call) -> bool:
    name = _call_name(node)
    if name not in UI_CALLS:
        return False
    if name in MESSAGE_BOX_ONLY:
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "QMessageBox"
        )
    return True


def _is_text(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    return (
        isinstance(node, ast.Constant) and isinstance(node.value, str)
        and any(c.isalpha() for c in node.value)
    )


def _text_nodes(node: ast.expr) -> list[ast.expr]:
    """The string literals an argument can evaluate to: the argument
    itself, list/tuple items, both branches of `a if c else b`, and the
    operands of `+`."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return [t for item in node.elts for t in _text_nodes(item)]
    if isinstance(node, ast.IfExp):
        return _text_nodes(node.body) + _text_nodes(node.orelse)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _text_nodes(node.left) + _text_nodes(node.right)
    return [node] if _is_text(node) else []


def _marked(lines: list[str], node: ast.AST) -> bool:
    first = getattr(node, "lineno", 0)
    last = getattr(node, "end_lineno", first) or first
    return any(KEEP_MARKER in lines[i - 1] for i in range(first, last + 1))


def problems(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        where = f"{path.relative_to(PACKAGE.parent)}:{node.lineno}"
        if name == "tr" and isinstance(node.func, ast.Attribute):
            found.append(f"{where}: self.tr() -- use translate(\"Context\", ...)")
        elif name == "translate":
            if _marked(lines, node):
                continue
            args = node.args
            if len(args) < 2 or not all(
                isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args[:2]
            ):
                found.append(
                    f"{where}: translate() needs a literal context and a literal text "
                    "(lupdate can't extract anything else; fill values with .format())"
                )
        elif is_ui_call(node):
            candidates: list[ast.expr] = list(node.args) + [k.value for k in node.keywords]
            for arg in candidates:
                for item in _text_nodes(arg):
                    if not _marked(lines, item):
                        text = ast.get_source_segment(source, item) or ""
                        found.append(f"{where}: {name}({text[:60]}) not translated")
    return found


def _translate_calls(path: Path) -> set[tuple[str, str]]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call) and _call_name(node) == "translate"
            and len(node.args) >= 2
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str)
                    for a in node.args[:2])
        ):
            found.add((node.args[0].value, node.args[1].value))
    return found


def test_lupdate_extracts_every_translate_call(tmp_path: Path) -> None:
    """lupdate silently skips a text it can't parse (e.g. adjacent string
    literals inside extra parentheses); the AST check above can't see that."""
    here = Path(sys.executable).parent
    lupdate = shutil.which("pyside6-lupdate") or shutil.which(
        "pyside6-lupdate", path=f"{here}{os.pathsep}{here / 'Scripts'}"
    )
    assert lupdate, "pyside6-lupdate not found (installed with PySide6)"
    ts = tmp_path / "ui.ts"
    files = [str(PACKAGE / m) for m in CONVERTED]
    subprocess.run([lupdate, *files, "-ts", str(ts)], check=True, capture_output=True)
    extracted = {
        (ctx.findtext("name"), m.findtext("source"))
        for ctx in ET.parse(ts).getroot().iter("context")
        for m in ctx.iter("message")
    }
    expected = set().union(*(_translate_calls(PACKAGE / m) for m in CONVERTED))
    assert expected - extracted == set()


def test_converted_modules_exist() -> None:
    for module in CONVERTED:
        assert (PACKAGE / module).is_file(), module


@pytest.mark.parametrize("module", CONVERTED)
def test_ui_text_translated(module: str) -> None:
    assert problems(PACKAGE / module) == []
