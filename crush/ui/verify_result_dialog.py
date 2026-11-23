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
doesn't match, by path, how many files have no recorded hash (or one the
reader doesn't check) and so were not checked, and every file whose content
the acquisition didn't collect. Damage found while reading (unreadable
chunks and files, chunk tables failing their checksum, segments of another
acquisition, AD1 bytes the item tree doesn't reach) is listed in full, and
the headline never reads as a clean match while there is any.
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
_AMBER = "#b26a00"


def verify_damage_found(result: dict[str, Any]) -> bool:
    """True when the reader found damage while verifying: chunks that fail
    their own checksum, hold less data than they cover, or can't be read;
    pages the acquisition doesn't hold; files that can't be read; chunk
    tables failing their checksum (with or without a copy that passes);
    segments recording another acquisition; AD1 bytes the item tree
    doesn't reach. A hash that matches doesn't make any of these go away."""
    return bool(
        result.get("checksum_errors")
        or result.get("padded_chunks")
        or result.get("missing_page_count")
        or result.get("unreadable_chunks")
        or result.get("entry_unreadable")
        or result.get("table_errors")
        or result.get("segment_set_errors")
        or result.get("logical_unreached_bytes")
    )


def _listing(line: str, items: list[str]) -> str:
    """*line*, then every one of *items* on a line of its own."""
    rows = "<br>".join(f"<code>{_esc(i)}</code>" for i in items)
    return f"<p style='color:{_RED}'>{_esc(line)}<br>{rows}</p>"


def _damage_rows(result: dict[str, Any]) -> list[str]:
    """Every damage the reader found while verifying, each item listed."""
    parts: list[str] = []
    chunks: list[dict[str, Any]] = result.get("unreadable_chunks") or []
    if chunks:
        parts.append(_listing(
            translate("VerifyResultDialog", "{count} chunk(s) could not be read:").format(
                count=f"{len(chunks):,}"),
            [translate("VerifyResultDialog", "chunk {chunk} at byte {offset}: {error}").format(
                chunk=f"{int(c.get('chunk') or 0):,}", offset=f"{int(c.get('offset') or 0):,}",
                error=c.get("error")) for c in chunks],
        ))
    entries: list[dict[str, Any]] = result.get("entry_unreadable") or []
    if entries:
        parts.append(_listing(
            translate("VerifyResultDialog", "{count} file(s) could not be read:").format(
                count=f"{len(entries):,}"),
            [f"{e.get('path')}: {e.get('error')}" for e in entries],
        ))
    tables: list[dict[str, Any]] = result.get("table_errors") or []
    if tables:
        rows = []
        for t in tables:
            where = dict(file=t.get("file"), offset=f"{int(t.get('offset') or 0):,}")
            rows.append(
                translate("VerifyResultDialog", "{file}, chunk table at byte {offset}: its copy "
                          "(table2) passes and was read in its place").format(**where)
                if t.get("used") == "table2" else
                translate("VerifyResultDialog", "{file}, chunk table at byte {offset}: no copy "
                          "passes; the table was read as stored").format(**where)
            )
        parts.append(_listing(
            translate("VerifyResultDialog", "{count} chunk table(s) fail their checksum:").format(
                count=f"{len(tables):,}"),
            rows,
        ))
    segments: list[dict[str, Any]] = result.get("segment_set_errors") or []
    if segments:
        parts.append(_listing(
            translate("VerifyResultDialog",
                      "{count} segment file(s) record a different acquisition:").format(
                count=f"{len(segments):,}"),
            [translate("VerifyResultDialog", "{file} records a different acquisition than "
                       "{expected}").format(file=s.get("file"), expected=s.get("expected_file"))
             for s in segments],
        ))
    unreached = int(result.get("logical_unreached_bytes") or 0)
    if unreached:
        spans: list[dict[str, Any]] = result.get("logical_unreached_spans") or []
        line = translate(
            "VerifyResultDialog",
            "{count} byte(s) of the AD1's logical space are not reached from its item tree.",
        ).format(count=f"{unreached:,}")
        if spans:
            parts.append(_listing(
                line + " " + translate(
                    "VerifyResultDialog", "Where (the reader lists at most 5 spans):"),
                [translate("VerifyResultDialog", "{length} byte(s) at byte {offset}").format(
                    length=f"{int(s.get('length') or 0):,}",
                    offset=f"{int(s.get('offset') or 0):,}") for s in spans],
            ))
        else:
            parts.append(f"<p style='color:{_RED}'>{_esc(line)}</p>")
    return parts


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
    damaged = verify_damage_found(result)

    parts: list[str] = []
    if not stored:
        if holds_files:
            headline = (
                translate("VerifyResultDialog", "This acquisition recorded no hash of its whole "
                          "data; the hashes it recorded of its files were checked.")
                if md5_checked or sha1_checked else
                translate("VerifyResultDialog", "This acquisition recorded no hash of its whole "
                          "data; the files it recorded a hash of hold no collected content "
                          "and were not checked.")
                if result.get("entry_content_not_collected") else
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
    elif result.get("match") and damaged:
        parts.append(
            f"<p style='color:{_AMBER}'><b>"
            + _esc(translate(
                "VerifyResultDialog",
                "The acquisition's own recorded hash matches its data, but damage was found "
                "while reading it (see below)",
            ))
            + "</b></p>"
        )
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

    damage = _damage_rows(result)
    if damage:
        parts.append(
            "<h3>" + _esc(translate("VerifyResultDialog", "Damage found while reading"))
            + "</h3>"
        )
        parts.extend(damage)

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
        # A file recorded with a hash but not its content has one, unchecked:
        # it is listed below instead.
        if not md5_checked and not sha1_checked and not result.get("entry_content_not_collected"):
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
        if not_checked:
            parts.append("<p><b>" + "<br>".join(_esc(t) for t in not_checked) + "</b></p>")
        # Skipped by the reader, so in none of the counts above.
        not_collected = [str(p) for p in result.get("entry_content_not_collected") or []]
        if not_collected:
            line = translate(
                "VerifyResultDialog",
                "{count} of {total} file(s) were not checked against any recorded hash: the "
                "acquisition did not collect their content:",
            ).format(count=f"{len(not_collected):,}", total=f"{total:,}")
            paths = "<br>".join(f"<code>{_esc(p)}</code>" for p in not_collected)
            parts.append(f"<p><b>{_esc(line)}</b><br>{paths}</p>")

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
    file it names but that isn't there as a failed check, an entry with a
    status (a UFDX extraction that wasn't opened) as a failed check with its
    reason, and its HMAC as recorded but not checked."""
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
        status = entry.get("status")
        if status is not None:
            # Nothing was checked for it (a listed extraction that wasn't
            # opened): why, in place of a stored and a computed value.
            parts.append(
                f"<p style='margin-bottom:2px'><b>{_esc(str(entry.get('name')))}</b></p>"
                f"<p style='margin-left:16px; color:{_RED}'>{_esc(str(status))} <b>✗</b></p>"
            )
            continue
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
