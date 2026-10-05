# Translation catalogs

`crush_<code>.ts` — one Qt Linguist catalog per UI language (source language:
English). Maintained with `scripts/i18n.py`:

- `python scripts/i18n.py update --add <code>` starts a catalog for a new language
- `python scripts/i18n.py update` refreshes every catalog from the code
- `python scripts/i18n.py release` compiles them (`.qm`, `languages.json` — build
  output, not in git)
- `python scripts/i18n.py pseudo` builds the pseudo test locale
- `python scripts/i18n.py check` checks that every translation keeps its
  placeholders, `%1` arguments and HTML tags (runs in CI)

`glossary.csv` — terms that stay English (`do-not-translate`) or are always translated
the same way (`translate`). `glossary.qph` is the same list as a Qt Linguist phrase book,
written by `update` (a test fails while it is out of date). `glossary_<code>.qph` holds a
language's own choices for the `translate` terms, kept by its translators.

Maintainer: translators download the catalogs from GitHub, so run `update` and commit the
catalogs whenever texts have changed, at least before each release; a new language is
started on request with `update --add <code>`. A catalog sent in an issue (or a pull
request) may be older than the one in git: put it in place, run `update` (brings it up to
the current texts, keeps its translations) and `check`, then commit it.

Run `crush --language <code>` to try a catalog before it is complete enough
(90 %) to be offered under View → Language.

Contexts starting with `Website` (from `crush/data/format_pages_text.py`) are texts of the
format reference website, not of the app. They are in the catalogs so translators can do
them too, but `release` doesn't count them towards the 90 %.

How to translate: [TRANSLATING.md](../../TRANSLATING.md).
