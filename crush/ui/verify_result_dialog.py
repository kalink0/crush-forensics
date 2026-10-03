# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The result of Verify Acquisition Hash, laid out to be read and copied.

One block per check -- a hash of the whole disk the acquisition recorded,
or one of the container's own checks (a UDIF image's data, block table and
master checksums, an AFF4's stream and map hashes) -- with the stored and
the recomputed value on lines of their own, every value in full. A
recomputed value is marked green when it matches the stored one and red
when it doesn't.
"""
from __future__ import annotations

import html
from functools import partial
from typing import Any

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout, QWidget

from crush.ui.i18n import translate

# Every use is a text node: only &, < and > need escaping.
_esc = partial(html.escape, quote=False)

_GREEN = "#2e7d32"
_RED = "#c62828"


def _value_rows(stored: object, computed: object, match: bool) -> str:
    """The stored and recomputed value of one check, the latter marked."""
    colour = _GREEN if match else _RED
    mark = "✓" if match else "✗ " + _esc(translate("VerifyResultDialog", "MISMATCH"))
    shown = (
        _esc(str(computed)) if computed is not None
        else _esc(translate("VerifyResultDialog", "(not computed)"))
    )
    return (
        "<table cellspacing='0' cellpadding='1' style='margin-left:16px'>"
        f"<tr><td>{_esc(translate('VerifyResultDialog', 'stored'))}</td>"
        f"<td><code>{_esc(str(stored))}</code></td></tr>"
        f"<tr><td>{_esc(translate('VerifyResultDialog', 'computed'))}</td>"
        f"<td style='color:{colour}'><code>{shown}</code> <b>{mark}</b></td></tr>"
        "</table>"
    )


def _block(title: str, stored: object, computed: object, match: bool) -> str:
    return f"<p style='margin-bottom:2px'><b>{_esc(title)}</b></p>" + _value_rows(
        stored, computed, match
    )


def verify_report_html(result: dict[str, Any], findings: list[str]) -> str:
    """The whole report for ewfprobe's verify() *result*, as rich text.
    *findings* are what was found while reading (failed chunk checksums,
    missing pages, mismatching container checks), already worded."""
    stored: dict[str, str] = result.get("stored") or {}
    computed: dict[str, str] = result.get("computed") or {}
    checks: list[dict[str, Any]] = result.get("container_checks") or []

    parts: list[str] = []
    if not stored:
        headline = (
            translate("VerifyResultDialog", "This acquisition recorded no hash of the whole disk "
                      "to verify against.")
            if checks else
            translate("VerifyResultDialog", "This acquisition recorded no hash to verify against.")
        )
        parts.append(f"<p><b>{_esc(headline)}</b></p>")
    elif result.get("match"):
        parts.append(
            f"<p style='color:{_GREEN}'><b>"
            + _esc(translate(
                "VerifyResultDialog",
                "MATCH — the acquisition's own recorded hash matches its data",
            ))
            + "</b></p>"
        )
    else:
        parts.append(
            f"<p style='color:{_RED}'><b>"
            + _esc(translate(
                "VerifyResultDialog",
                "MISMATCH — the acquisition's data does not match its own recorded hash",
            ))
            + "</b></p>"
        )

    if findings:
        parts.append(
            f"<p style='color:{_RED}'>"
            + "<br>".join(_esc(f) for f in findings)
            + "</p>"
        )

    if stored:
        parts.append(
            "<h3>" + _esc(translate("VerifyResultDialog", "Hash of the whole disk"))
            + "</h3>"
        )
        for name in sorted(stored):
            got = computed.get(name)
            parts.append(_block(name, stored[name], got, got == stored[name]))

    if checks:
        parts.append(
            "<h3>" + _esc(translate("VerifyResultDialog", "The container's own checks"))
            + "</h3>"
        )
        for check in checks:
            title = translate("VerifyResultDialog", "{what} ({algorithm})").format(
                what=check.get("what"), algorithm=check.get("algorithm"),
            )
            parts.append(_block(
                title, check.get("stored"), check.get("computed"), bool(check.get("match")),
            ))
    return "".join(parts)


class VerifyResultDialog(QDialog):
    """Shows verify_report_html(); its text is selectable and copyable."""

    def __init__(self, parent: QWidget | None, title: str, report_html: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.setHtml(report_html)
        layout.addWidget(self.browser)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
