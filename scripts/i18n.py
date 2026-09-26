#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Maintain Crush's translation catalogs (Qt Linguist).

    python scripts/i18n.py update [--add CODE]   refresh crush/i18n/crush_*.ts
    python scripts/i18n.py release               compile .ts -> .qm + languages.json
    python scripts/i18n.py pseudo                build the pseudo test locale
    python scripts/i18n.py check                 translations fit their English text

update   extracts every translatable string from crush/ (tests and
         third_party excluded) into each existing catalog; --add CODE starts
         a new one (e.g. --add es, --add pt_BR). Strings no longer in the
         code are dropped (git history keeps them), and no source line
         numbers are stored, so a catalog only changes when its strings do.
         Also writes glossary.qph (a Qt Linguist phrase book) from
         glossary.csv.
release  compiles every catalog and records per-language completeness in
         languages.json (View → Language offers a language from 90 %).
         Compiles a copy merged with the current code, in which every text
         without a finished translation carries its English source -- so
         an untranslated text shows English, never the translation of
         another text with the same wording. A translation that fails
         `check` is left out (reported; the English text is shipped). The
         catalogs are not changed.
pseudo   writes crush_pseudo.ts with every string "translated" into
         accented, bracketed, ~30 % longer text, and compiles it. Run
         Crush with --language pseudo: any plain English text left in the
         UI is not translatable yet, a missing closing bracket shows
         truncation. Placeholders ({name}, {count:,}, %1), HTML tags,
         entities and the letter after a & mnemonic are left as they are.
check    every finished translation keeps the English text's {placeholders}
         (same names and format specs), %1/%n arguments and HTML tags, and
         has balanced braces. The UI fills values in after translating, so
         a translation that doesn't would crash or lose a value. Runs in CI.

lupdate/lrelease come with PySide6 (pyside6-lupdate / pyside6-lrelease).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import string
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
GLOSSARY_CSV = I18N_DIR / "glossary.csv"
GLOSSARY_QPH = I18N_DIR / "glossary.qph"
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


# -- Glossary -----------------------------------------------------------------

_RULE_TEXT = {
    "do-not-translate": "Do not translate",
    "translate": "Translate, always the same way",
}


def glossary_phrasebook(csv_text: str) -> str:
    """glossary.csv as a Qt Linguist phrase book: Linguist then shows the
    glossary terms found in each text, with their rule, while translating.
    A do-not-translate term's target is the term itself; a translate term
    has none -- each language records its choice in its own phrase book."""
    root = ET.Element("QPH", sourcelanguage="en")
    for row in csv.DictReader(io.StringIO(csv_text)):
        phrase = ET.SubElement(root, "phrase")
        ET.SubElement(phrase, "source").text = row["term"]
        target = row["term"] if row["rule"] == "do-not-translate" else ""
        ET.SubElement(phrase, "target").text = target
        ET.SubElement(phrase, "definition").text = f"{_RULE_TEXT[row['rule']]} -- {row['note']}"
    ET.indent(root)
    return "<!DOCTYPE QPH>\n" + ET.tostring(root, encoding="unicode") + "\n"


def write_glossary_phrasebook() -> None:
    GLOSSARY_QPH.write_text(
        glossary_phrasebook(GLOSSARY_CSV.read_text(encoding="utf-8")), encoding="utf-8"
    )


def cmd_update(add: str | None) -> None:
    I18N_DIR.mkdir(exist_ok=True)
    write_glossary_phrasebook()
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


# -- Translation checks -------------------------------------------------------

_QT_ARG = re.compile(r"%(?:\d+|n)")
_TAG = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^<>]*>")


def _format_fields(text: str) -> set[str] | None:
    """The {name!conv:spec} fields of a str.format() template, or None if
    *text* doesn't parse as one (unbalanced braces)."""
    fields = set()
    try:
        for _literal, name, spec, conv in string.Formatter().parse(text):
            if name is not None:
                fields.add(f"{{{name}{'!' + conv if conv else ''}{':' + spec if spec else ''}}}")
    except ValueError:
        return None
    return fields


def translation_problems(source: str, translation: str) -> list[str]:
    """Why *translation* can't stand in for *source* -- empty if it can.

    The UI fills values in with .format() after translating: a placeholder
    that is missing, renamed or has another format spec would raise (or
    drop a fact), and unbalanced braces make the whole text unusable. Qt's
    %1/%n arguments and the HTML tags must match too."""
    problems = []
    src_fields = _format_fields(source)
    if src_fields is None:
        # Not a format template: its braces are literal text and must stay.
        if (source.count("{"), source.count("}")) != (
            translation.count("{"), translation.count("}")
        ):
            problems.append("braces {…} differ from the English text")
    else:
        fields = _format_fields(translation)
        if fields is None:
            problems.append("unbalanced { or } (write a literal brace as {{ or }})")
        elif fields != src_fields:
            missing = ", ".join(sorted(src_fields - fields))
            extra = ", ".join(sorted(fields - src_fields))
            detail = "; ".join(
                part for part in (missing and f"missing {missing}", extra and f"unknown {extra}")
                if part
            )
            problems.append(f"placeholders differ from the English text ({detail})")
    if sorted(_QT_ARG.findall(source)) != sorted(_QT_ARG.findall(translation)):
        problems.append("%1/%n arguments differ from the English text")
    src_tags = sorted(m.lower() for m in _TAG.findall(source))
    if src_tags != sorted(m.lower() for m in _TAG.findall(translation)):
        problems.append("HTML tags differ from the English text")
    return problems


def _translation_texts(message: ET.Element) -> list[str]:
    translation = message.find("translation")
    if translation is None:
        return []
    forms = translation.findall("numerusform")
    return [f.text or "" for f in forms] if forms else [translation.text or ""]


def catalog_problems(ts: Path) -> list[str]:
    """Every finished translation in *ts* that can't stand in for its
    English text (see translation_problems)."""
    found = []
    for context in ET.parse(ts).getroot().iter("context"):
        name = context.findtext("name") or ""
        for message in context.iter("message"):
            if not _is_translated(message):
                continue
            source = message.findtext("source") or ""
            for text in _translation_texts(message):
                for problem in translation_problems(source, text):
                    found.append(f"{ts.name} [{name}] {source[:60]!r}: {problem}")
    return found


def _drop_broken(ts: Path) -> int:
    """Mark every finished translation that fails translation_problems as
    unfinished, so release ships the English text instead; return how many."""
    tree = ET.parse(ts)
    dropped = 0
    for message in tree.getroot().iter("message"):
        if not _is_translated(message):
            continue
        source = message.findtext("source") or ""
        if any(translation_problems(source, t) for t in _translation_texts(message)):
            message.find("translation").set("type", "unfinished")  # type: ignore[union-attr]
            dropped += 1
    tree.write(ts, encoding="utf-8", xml_declaration=True)
    return dropped


def cmd_check() -> int:
    problems = [p for ts in _catalogs() for p in catalog_problems(ts)]
    print("\n".join(problems) or f"{len(_catalogs())} catalog(s), no problems")
    return 1 if problems else 0


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
    2. a translation whose placeholders, %1 arguments or HTML tags don't
       match its English text (see translation_problems) is left out and
       reported -- it would break or drop a fact when filled in;
    3. every text without a finished translation gets its English source
       as its own entry (see _fill_untranslated), so no text ever shows
       another text's translation.
    The counts are taken after step 2, i.e. against the current code and
    without the translations left out.
    """
    with tempfile.TemporaryDirectory() as tmp:
        merged = Path(tmp) / ts.name
        shutil.copyfile(ts, merged)
        _lupdate(merged, _code(ts), quiet=True)
        for problem in catalog_problems(merged):
            print(f"left out (shown in English): {problem}", file=sys.stderr)
        _drop_broken(merged)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    update = sub.add_parser("update", help="refresh the .ts catalogs from the code")
    update.add_argument("--add", metavar="CODE", help="start a catalog for a new language")
    sub.add_parser("release", help="compile .ts to .qm and write languages.json")
    sub.add_parser("pseudo", help="build the pseudo test locale (then --language pseudo)")
    sub.add_parser("check", help="check every catalog's translations can stand in for the English")
    args = parser.parse_args(argv)
    if args.command == "update":
        cmd_update(args.add)
    elif args.command == "release":
        cmd_release()
    elif args.command == "check":
        return cmd_check()
    else:
        cmd_pseudo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
