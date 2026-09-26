#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Maintain Crush's translation catalogs (Qt Linguist).

    python scripts/i18n.py update [--add CODE]   refresh crush/i18n/crush_*.ts
    python scripts/i18n.py release               compile .ts -> .qm + languages.json
    python scripts/i18n.py pseudo                build the pseudo test locale

update   extracts every translatable string from crush/ (tests and
         third_party excluded) into each existing catalog; --add CODE starts
         a new one (e.g. --add es, --add pt_BR). Strings no longer in the
         code are dropped (git history keeps them), and no source line
         numbers are stored, so a catalog only changes when its strings do.
release  compiles every catalog and records per-language completeness in
         languages.json (View → Language offers a language from 90 %).
         Compiles a copy merged with the current code, in which every text
         without a finished translation carries its English source -- so
         an untranslated text shows English, never the translation of
         another text with the same wording. The catalogs are not changed.
pseudo   writes crush_pseudo.ts with every string "translated" into
         accented, bracketed, ~30 % longer text, and compiles it. Run
         Crush with --language pseudo: any plain English text left in the
         UI is not translatable yet, a missing closing bracket shows
         truncation. Placeholders ({name}, {count:,}, %1), HTML tags,
         entities and the letter after a & mnemonic are left as they are.

lupdate/lrelease come with PySide6 (pyside6-lupdate / pyside6-lrelease).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "crush"
I18N_DIR = PACKAGE / "i18n"
EXCLUDED_DIRS = {"tests", "third_party", "__pycache__"}
PSEUDO = "pseudo"
MANIFEST_NAME = "languages.json"
_CODE_RE = re.compile(r"^[a-z]{2,3}(?:_[A-Za-z0-9]{2,4})?$")


def _tool(name: str) -> str:
    """Path of pyside6-<name>; also found next to the running interpreter
    (a venv's bin/Scripts dir that isn't on PATH)."""
    exe = f"pyside6-{name}"
    here = Path(sys.executable).parent
    found = shutil.which(exe) or shutil.which(exe, path=f"{here}{os.pathsep}{here / 'Scripts'}")
    if not found:
        sys.exit(f"{exe} not found -- it is installed with PySide6 (pip install PySide6)")
    return found


def _sources() -> list[Path]:
    return sorted(
        p for p in PACKAGE.rglob("*.py")
        if not EXCLUDED_DIRS.intersection(p.relative_to(PACKAGE).parts)
    )


def _catalogs(include_pseudo: bool = False) -> list[Path]:
    return sorted(
        p for p in I18N_DIR.glob("crush_*.ts")
        if include_pseudo or p.stem != f"crush_{PSEUDO}"
    )


def _code(ts: Path) -> str:
    return ts.stem.removeprefix("crush_")


def _lupdate(ts: Path, code: str, quiet: bool = False) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False, encoding="utf-8") as lst:
        lst.write("\n".join(str(p) for p in _sources()) + "\n")
    try:
        subprocess.run(
            [_tool("lupdate"), f"@{lst.name}", "-no-obsolete", "-locations", "none",
             "-target-language", code, "-ts", str(ts)],
            check=True, capture_output=quiet,
        )
    finally:
        Path(lst.name).unlink()


def cmd_update(add: str | None) -> None:
    I18N_DIR.mkdir(exist_ok=True)
    catalogs = _catalogs()
    if add:
        if not _CODE_RE.match(add):
            sys.exit(f"{add!r} is not a language code (e.g. de, es, pt_BR)")
        new = I18N_DIR / f"crush_{add}.ts"
        if new in catalogs:
            sys.exit(f"{new.relative_to(ROOT)} already exists")
        catalogs.append(new)
    if not catalogs:
        print("No catalogs yet -- start one with: python scripts/i18n.py update --add CODE")
        return
    for ts in catalogs:
        _lupdate(ts, _code(ts))


def _is_translated(message: ET.Element) -> bool:
    translation = message.find("translation")
    if translation is None or translation.get("type") in ("unfinished", "obsolete", "vanished"):
        return False
    forms = translation.findall("numerusform")
    if forms:
        return all((f.text or "").strip() for f in forms)
    return bool((translation.text or "").strip())


def count_messages(ts: Path) -> tuple[int, int]:
    """(translated, total) for the current (non-obsolete) messages of *ts*."""
    translated = total = 0
    for message in ET.parse(ts).getroot().iter("message"):
        translation = message.find("translation")
        if translation is not None and translation.get("type") in ("obsolete", "vanished"):
            continue
        total += 1
        translated += _is_translated(message)
    return translated, total


def _fill_untranslated(ts: Path) -> None:
    """Give every message without a finished translation its English
    source text as its own finished translation.

    Without an entry of its own, Qt's lookup falls back to the translation
    of *another* message with the identical source text (a different
    ParseIssue code with the same English wording) -- which may mean
    something else. With one, an untranslated text is always shown in
    English. Drafts still marked unfinished are replaced the same way:
    only finished translations are shown.
    """
    tree = ET.parse(ts)
    for message in tree.getroot().iter("message"):
        if _is_translated(message):
            continue
        source = message.findtext("source") or ""
        translation = message.find("translation")
        if translation is None:
            translation = ET.SubElement(message, "translation")
        translation.attrib.pop("type", None)
        forms = translation.findall("numerusform")
        if forms:
            for form in forms:
                form.text = source
        else:
            translation.text = source
    tree.write(ts, encoding="utf-8", xml_declaration=True)


def compile_catalog(ts: Path, qm: Path) -> tuple[int, int]:
    """Compile *ts* to *qm*; return (translated, total).

    Works on a temporary copy, the catalog itself is left as it is:
    1. the copy is merged with the strings in the code now, so a text added
       since the catalog was last updated is counted and gets an entry;
    2. every text without a finished translation gets its English source
       as its own entry (see _fill_untranslated), so no text ever shows
       another text's translation.
    The counts are taken after step 1, i.e. against the current code.
    """
    with tempfile.TemporaryDirectory() as tmp:
        merged = Path(tmp) / ts.name
        shutil.copyfile(ts, merged)
        _lupdate(merged, _code(ts), quiet=True)
        counts = count_messages(merged)
        _fill_untranslated(merged)
        subprocess.run(
            [_tool("lrelease"), "-silent", str(merged), "-qm", str(qm)], check=True
        )
    return counts


def cmd_release() -> None:
    manifest: dict[str, dict[str, int]] = {}
    for ts in _catalogs(include_pseudo=True):
        translated, total = compile_catalog(ts, ts.with_suffix(".qm"))
        manifest[_code(ts)] = {"translated": translated, "total": total}
        share = f"{translated / total:.0%}" if total else "n/a"
        print(f"{_code(ts)}: {translated}/{total} translated ({share})")
    I18N_DIR.mkdir(exist_ok=True)
    (I18N_DIR / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


# -- Pseudo locale ------------------------------------------------------------

_ACCENTED = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ȧƀƈḓḗƒɠħīĵķŀḿƞǿƥɋřşŧŭṽẇẋẏẑȦƁƇḒḖƑƓĦĪĴĶĿḾȠǾƤɊŘŞŦŬṼẆẊẎẐ",
)
# Left untouched: format placeholders, Qt %1 args, HTML tags and entities,
# a & mnemonic together with its letter (so the shortcut key stays), &&.
_PROTECTED = re.compile(
    r"\{[^{}]*\}|%\d+|%[a-zA-Z]|<[^<>]+>|&[a-zA-Z]+;|&#\d+;|&&|&\w"
)


def pseudo_translate(text: str) -> str:
    parts: list[str] = []
    pos = 0
    for m in _PROTECTED.finditer(text):
        parts.append(text[pos:m.start()].translate(_ACCENTED))
        parts.append(m.group())
        pos = m.end()
    parts.append(text[pos:].translate(_ACCENTED))
    padding = "~" * max(1, round(len(text) * 0.3))
    return f"[{''.join(parts)} {padding}]"


def cmd_pseudo() -> None:
    ts = I18N_DIR / f"crush_{PSEUDO}.ts"
    I18N_DIR.mkdir(exist_ok=True)
    ts.unlink(missing_ok=True)
    _lupdate(ts, "en")
    tree = ET.parse(ts)
    for message in tree.getroot().iter("message"):
        source = message.findtext("source") or ""
        translation = message.find("translation")
        if translation is None:
            translation = ET.SubElement(message, "translation")
        translation.attrib.pop("type", None)
        forms = translation.findall("numerusform")
        if forms:
            for form in forms:
                form.text = pseudo_translate(source)
        else:
            translation.text = pseudo_translate(source)
    tree.write(ts, encoding="utf-8", xml_declaration=True)
    cmd_release()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    update = sub.add_parser("update", help="refresh the .ts catalogs from the code")
    update.add_argument("--add", metavar="CODE", help="start a catalog for a new language")
    sub.add_parser("release", help="compile .ts to .qm and write languages.json")
    sub.add_parser("pseudo", help="build the pseudo test locale (then --language pseudo)")
    args = parser.parse_args(argv)
    if args.command == "update":
        cmd_update(args.add)
    elif args.command == "release":
        cmd_release()
    else:
        cmd_pseudo()


if __name__ == "__main__":
    main()
