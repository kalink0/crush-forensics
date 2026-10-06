# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The result of Verify Acquisition Hash, laid out to be read and copied.

One block per check -- a hash of the whole disk (or, for logical evidence,
the whole image) the acquisition recorded, or one of the container's own
checks (a UDIF image's data, block table and master checksums, an AFF4's
stream and map hashes) -- with the stored and the recomputed value on lines
of their own, every value in full. A recomputed value is marked green when
it matches the stored one and red when it doesn't. Logical evidence also
records a hash of each file: how many were checked, every file whose hash
doesn't match, by path, and how many files have no recorded hash (or one
the reader doesn't check) and so were not checked.
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


def _file_hash_rows(algorithm: str, checked: int, mismatched: list[str]) -> str:
    """How many files' recorded *algorithm* hashes were recomputed, and
    every file whose hash doesn't match -- all of them, by path."""
    if not mismatched:
        line = translate(
            "VerifyResultDialog", "{algorithm}: {count} file(s) checked, all match"
        ).format(algorithm=algorithm, count=f"{checked:,}")
        return f"<p style='color:{_GREEN}'>{_esc(line)}</p>"
    line = translate(
        "VerifyResultDialog", "{algorithm}: {bad} of {count} file(s) checked do not match:"
    ).format(algorithm=algorithm, bad=f"{len(mismatched):,}", count=f"{checked:,}")
    paths = "<br>".join(f"<code>{_esc(p)}</code>" for p in mismatched)
    return f"<p style='color:{_RED}'>{_esc(line)}<br>{paths}</p>"


def verify_report_html(
    result: dict[str, Any], findings: list[str], *, holds_files: bool = False
) -> str:
    """The whole report for ewfprobe's verify() *result*, as rich text.
    *findings* are what was found while reading (failed chunk checksums,
    missing pages, mismatching container checks, files whose recorded hash
    doesn't match), already worded. *holds_files*: the acquisition is
    logical evidence, which holds files rather than a disk."""
    if "recorded_files" in result:
        return _recorded_files_report(result, findings)
    stored: dict[str, str] = result.get("stored") or {}
    computed: dict[str, str] = result.get("computed") or {}
    checks: list[dict[str, Any]] = result.get("container_checks") or []
    md5_checked = int(result.get("entry_md5_checked") or 0)
    sha1_checked = int(result.get("entry_sha1_checked") or 0)

    parts: list[str] = []
    if not stored:
        if holds_files:
            headline = (
                translate("VerifyResultDialog", "This acquisition recorded no hash of its whole "
                          "data; the hashes it recorded of its files were checked.")
                if md5_checked or sha1_checked else
                translate("VerifyResultDialog",
                          "This acquisition recorded no hash to verify against.")
            )
        elif checks:
            headline = translate(
                "VerifyResultDialog",
                "This acquisition recorded no hash of the whole disk to verify against.",
            )
        else:
            headline = translate(
                "VerifyResultDialog", "This acquisition recorded no hash to verify against."
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

    # An AD1 doesn't hold its image hash: it is read from FTK Imager's log, a
    # separate text file beside the image.
    if "ad1_log_expected" in result:
        log = result.get("ad1_log")
        note = (
            translate(
                "VerifyResultDialog",
                "An AD1 doesn't hold its image hash: the recorded hash was read from FTK "
                "Imager's log beside it, {log} — a separate text file.",
            ).format(log=log)
            if log else
            translate(
                "VerifyResultDialog",
                "An AD1 doesn't hold its image hash: FTK Imager writes it to its log beside "
                "the image ({log}), which was not found.",
            ).format(log=result["ad1_log_expected"])
        )
        parts.append(f"<p>{_esc(note)}</p>")

    if findings:
        parts.append(
            f"<p style='color:{_RED}'>"
            + "<br>".join(_esc(f) for f in findings)
            + "</p>"
        )

    if stored:
        heading = (
            translate("VerifyResultDialog", "Hash of the whole image")
            if holds_files else
            translate("VerifyResultDialog", "Hash of the whole disk")
        )
        parts.append("<h3>" + _esc(heading) + "</h3>")
        for name in sorted(stored):
            got = computed.get(name)
            parts.append(_block(name, stored[name], got, got == stored[name]))

    if holds_files:
        parts.append(
            "<h3>" + _esc(translate("VerifyResultDialog", "Recorded hashes of the files"))
            + "</h3>"
        )
        if not md5_checked and not sha1_checked:
            parts.append(
                "<p>" + _esc(translate("VerifyResultDialog",
                                       "No file has a recorded hash to check.")) + "</p>"
            )
        if md5_checked:
            parts.append(_file_hash_rows(
                "MD5", md5_checked, list(result.get("entry_md5_mismatched") or []),
            ))
        if sha1_checked:
            parts.append(_file_hash_rows(
                "SHA-1", sha1_checked, list(result.get("entry_sha1_mismatched") or []),
            ))
        # What was not checked, counted, so "all match" isn't read as "all checked".
        total = int(result.get("entry_count") or 0)
        not_checked: list[str] = []
        for algorithm, key in (("MD5", "entry_md5_missing"), ("SHA-1", "entry_sha1_missing")):
            missing = int(result.get(key) or 0)
            if missing:
                not_checked.append(translate(
                    "VerifyResultDialog",
                    "{missing} of {total} file(s) have no recorded {algorithm} and were not "
                    "checked against one.",
                ).format(missing=f"{missing:,}", total=f"{total:,}", algorithm=algorithm))
        unchecked_sha1 = int(result.get("entry_sha1_unchecked") or 0)
        if unchecked_sha1:
            not_checked.append(translate(
                "VerifyResultDialog",
                "{count} file(s) have a recorded SHA-1, which was not checked: the reader "
                "checks an L01's recorded MD5 only.",
            ).format(count=f"{unchecked_sha1:,}"))
        if not_checked:
            parts.append("<p><b>" + "<br>".join(_esc(t) for t in not_checked) + "</b></p>")

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


def _recorded_files_report(result: dict[str, Any], findings: list[str]) -> str:
    """The report for an acquisition that records a hash of each of its
    files rather than of a disk (a Cellebrite UFD): one block per file, a
    file it names but that isn't there as a failed check, and its HMAC as
    recorded but not checked."""
    files: list[dict[str, Any]] = result.get("recorded_files") or []
    parts: list[str] = []
    if not files:
        headline = translate("VerifyResultDialog",
                             "This acquisition recorded no hash to verify against.")
        parts.append(f"<p><b>{_esc(headline)}</b></p>")
    elif result.get("match"):
        parts.append(
            f"<p style='color:{_GREEN}'><b>" + _esc(translate(
                "VerifyResultDialog",
                "MATCH — every file hash the acquisition recorded matches its file",
            )) + "</b></p>"
        )
    else:
        parts.append(
            f"<p style='color:{_RED}'><b>" + _esc(translate(
                "VerifyResultDialog",
                "MISMATCH — not every file matches the hash the acquisition recorded for it",
            )) + "</b></p>"
        )
    if findings:
        parts.append(f"<p style='color:{_RED}'>" + "<br>".join(_esc(f) for f in findings) + "</p>")
    if files:
        parts.append(
            "<h3>" + _esc(translate("VerifyResultDialog", "Recorded hashes of the acquisition's files"))
            + "</h3>"
        )
    for entry in files:
        title = translate("VerifyResultDialog", "{what} ({algorithm})").format(
            what=entry.get("name"), algorithm=entry.get("algorithm"),
        )
        if not entry.get("found"):
            computed: object = translate("VerifyResultDialog", "(file not found)")
        else:
            computed = entry.get("computed")
        parts.append(_block(title, entry.get("stored"), computed, bool(entry.get("match"))))
    hmac = result.get("recorded_hmac")
    if hmac:
        note = translate(
            "VerifyResultDialog",
            "The acquisition also records an HMAC ({hmac}). It is keyed with the acquisition "
            "tool vendor's key and can't be recomputed: not checked.",
        ).format(hmac=hmac)
        parts.append(f"<p>{_esc(note)}</p>")
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
