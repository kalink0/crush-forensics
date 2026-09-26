# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""UI language: which translation is loaded at startup.

The source language is English. A language is switched only at startup
(the choice is saved and applies after a restart); with no translation
loaded, every tr()/translate() returns the English source text, so an
English session is exactly the untranslated UI.

What the analyst chose is the saved `language` setting (View → Language).
The menu offers only languages whose catalog is at least
COMPLETENESS_THRESHOLD translated. The `--language CODE` command-line
option loads any compiled translation for one run -- also one below the
threshold, and the `pseudo` test locale -- so translators and developers
can check their work; it doesn't change the saved setting.

A requested language that can't be loaded is never silently replaced:
load_language() returns a note saying so, and the caller shows it.

Only UI text is translated. Timestamps, exports and the log stay English
/ ISO (QLocale.setDefault is deliberately not called: number and date
formatting doesn't change with the UI language).

Files: crush/i18n/crush_<code>.ts (source catalogs, in git) are compiled
by `python scripts/i18n.py release` into crush_<code>.qm plus
languages.json (per-language completeness); both are build output.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import (
    QCoreApplication,
    QLibraryInfo,
    QLocale,
    QSettings,
    QTranslator,
)

from crush.core import issues

_log = logging.getLogger(__name__)

SOURCE_LANGUAGE = "en"
PSEUDO_LANGUAGE = "pseudo"
SETTINGS_KEY = "language"
# A language appears in View → Language once this share of its catalog is
# translated (agreed 2026-09-24). --language ignores it.
COMPLETENESS_THRESHOLD = 0.90
MANIFEST_NAME = "languages.json"

# ll, lll, ll_CC, ll_Script -- or the pseudo locale. Anything else is
# rejected before it becomes part of a file name.
_CODE_RE = re.compile(r"^(?:[a-z]{2,3}(?:_[A-Za-z0-9]{2,4})?|pseudo)$")

# Translators kept alive for the application's lifetime (Qt doesn't own them).
_installed: list[QTranslator] = []


def translations_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "crush" / "i18n"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent / "i18n"


@dataclass(frozen=True)
class Language:
    code: str
    translated: int
    total: int

    @property
    def completeness(self) -> float:
        return self.translated / self.total if self.total else 0.0

    @property
    def offered(self) -> bool:
        """Listed in View → Language (the pseudo locale never is)."""
        return self.code != PSEUDO_LANGUAGE and self.completeness >= COMPLETENESS_THRESHOLD


def available_languages(directory: Path | None = None) -> list[Language]:
    """The compiled translations, as recorded in languages.json.

    Only entries whose .qm file is actually present are returned.
    """
    directory = directory or translations_dir()
    manifest = directory / MANIFEST_NAME
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        _log.warning("Translation manifest %s could not be read: %s", manifest, exc)
        return []
    result = []
    for code, counts in sorted(data.items()):
        if not _CODE_RE.match(code) or not (directory / f"crush_{code}.qm").is_file():
            continue
        try:
            result.append(Language(code, int(counts["translated"]), int(counts["total"])))
        except (KeyError, TypeError, ValueError):
            _log.warning("Translation manifest entry for %r is malformed: %r", code, counts)
    return result


def display_name(code: str) -> str:
    """The language's own name plus its English name, e.g. "Deutsch — German",
    "Português (Brasil) — Portuguese (Brazil)"."""
    if code == SOURCE_LANGUAGE:
        return "English"
    if code == PSEUDO_LANGUAGE:
        return "Pseudo (translation test)"
    locale = QLocale(code)
    if locale.language() == QLocale.Language.C:
        return code
    native = locale.nativeLanguageName()
    native = native[:1].upper() + native[1:]
    english = QLocale.languageToString(locale.language())
    if "_" in code:
        native += f" ({locale.nativeTerritoryName()})"
        english += f" ({QLocale.territoryToString(locale.territory())})"
    return native if native == english else f"{native} — {english}"


def saved_language(settings: QSettings) -> str:
    value = settings.value(SETTINGS_KEY, SOURCE_LANGUAGE)
    return value if isinstance(value, str) and value else SOURCE_LANGUAGE


def save_language(settings: QSettings, code: str) -> None:
    settings.setValue(SETTINGS_KEY, code)


def _qt_translate(context: str, source: str, disambiguation: str) -> str:
    return QCoreApplication.translate(context, source, disambiguation)


def load_language(
    app: QCoreApplication, code: str, directory: Path | None = None
) -> str | None:
    """Install the translation for *code* on *app*.

    Returns None when *code* is now in effect, otherwise a note saying why
    the UI stays English (unknown code, no compiled translation, a .qm Qt
    can't read).
    """
    if code == SOURCE_LANGUAGE:
        return None
    if not _CODE_RE.match(code):
        return f"Language {code!r} is not a valid language code; the UI is shown in English"
    directory = directory or translations_dir()
    qm = directory / f"crush_{code}.qm"
    if not qm.is_file():
        if getattr(sys, "frozen", False):
            return (
                f"Language {code!r} is not included in this build; "
                f"the UI is shown in English"
            )
        return (
            f"No compiled translation for language {code!r} ({qm} not found; "
            f"run: python scripts/i18n.py release); the UI is shown in English"
        )
    translator = QTranslator(app)
    if not translator.load(str(qm)):
        return f"Translation {qm} could not be loaded; the UI is shown in English"
    app.installTranslator(translator)
    _installed.append(translator)
    issues.set_translator(_qt_translate)
    _log.info("UI language: %s (%s)", code, qm)

    # Qt's own strings (standard dialog buttons, QFileDialog, ...). Absent
    # for most languages Qt doesn't ship -- those strings stay English.
    if code != PSEUDO_LANGUAGE:
        qt_dir = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        qt_translator = QTranslator(app)
        if qt_translator.load(QLocale(code), "qtbase", "_", qt_dir):
            app.installTranslator(qt_translator)
            _installed.append(qt_translator)
        else:
            _log.info("No Qt base translation for %s in %s", code, qt_dir)
    return None
