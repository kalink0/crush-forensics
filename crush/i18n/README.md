# Translation catalogs

`crush_<code>.ts` — one Qt Linguist catalog per UI language (source language:
English). Maintained with `scripts/i18n.py`:

- `python scripts/i18n.py update --add <code>` starts a catalog for a new language
- `python scripts/i18n.py update` refreshes every catalog from the code
- `python scripts/i18n.py release` compiles them (`.qm`, `languages.json` — build
  output, not in git)
- `python scripts/i18n.py pseudo` builds the pseudo test locale

Run `crush --language <code>` to try a catalog before it is complete enough
(90 %) to be offered under View → Language.
