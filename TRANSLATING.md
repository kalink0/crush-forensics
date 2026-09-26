# Translating Crush

Thank you for helping. Crush is a forensic tool: analysts rely on what it tells them, so a
translation has to say exactly what the English says — no more, no less. This page walks you
through it step by step. You don't need to program or know Git.

## What is translated — and what isn't

**Translated:** the application's user interface — menus, dialogs, buttons, tooltips, status
messages, the explanations Crush shows next to data, and the format knowledge texts (what a
file format contains, what its magic bytes are).

**Not translated** (these stay English on purpose, so results look the same for every analyst
and can be compared or exchanged):

- the Feature Reference (`crush/docs/feature-reference.md`) and the other documentation (for now)
- exports (CSV, JSON, reports), copied table content and the log file
- timestamps (always ISO format, UTC) and number formatting (`12,345`)
- file format names, spec terms and values (`WAL`, `PRAGMA`, `BLOB`, `NONE`/`FULL` …)
- Crush's own feature names (`Value Inspector`, `BLOB Inspector`, `Multi-Log Studio` …), so
  they match the Feature Reference

## How it works

Each language is **one file**: `crush/i18n/crush_<code>.ts` — `crush_es.ts` for Spanish,
`crush_pt_BR.ts` for Brazilian Portuguese. It holds every English text of Crush and, next to
it, its translation. You edit that file in **Qt Linguist**, a free translation editor, and send
it back through GitHub. A check runs automatically on what you send, and once it's accepted,
the next nightly build of Crush contains your translation.

One person or team can own a language independently of all others.

## Step by step

### 1. Find your language — or ask for it

Look in [`crush/i18n/`](crush/i18n/) for `crush_<code>.ts` with your language's code.

- **It's there:** also glance at the open
  [pull requests](https://github.com/kalink0/crush-forensics/pulls) — if someone is working
  on it right now, you may want to coordinate with them. Then go on to step 2.
- **It isn't there:** open an [issue](https://github.com/kalink0/crush-forensics/issues)
  "Please add &lt;language&gt; (&lt;code&gt;) for translation". The file is created for you,
  usually within a few days — you don't need to do anything technical for that.

### 2. Install Qt Linguist

Qt Linguist comes with PySide6. With [Python](https://www.python.org/downloads/) 3.11 or
newer installed, run in a terminal (Command Prompt on Windows):

```
pip install pyside6
```

Start it with `pyside6-linguist`.

### 3. Download the files

From [`crush/i18n/`](crush/i18n/) on GitHub, download (open the file, then the download
button):

- `crush_<code>.ts` — the file you translate
- `glossary.qph` — the glossary (see [Glossary](#glossary))
- `glossary_<code>.qph`, if it exists — the term choices already made for your language

Always download a fresh copy when you start a new session: the files on GitHub are updated
with Crush's new texts regularly.

### 4. Translate

1. In Qt Linguist, open `crush_<code>.ts` (**File → Open**).
2. Open the glossary: **Phrases → Open Phrase Book…** → `glossary.qph` (and
   `glossary_<code>.qph`, if you have it).
3. Pick a text in the list and type the translation below it. The **Phrases and Guesses**
   panel shows the glossary terms that occur in this text and what to do with them — see
   [Glossary](#glossary).
4. When a translation is done, mark it **finished** (the check mark, or **Done and Next**). Only
   finished translations are used; everything else is shown in English.
5. Save (**File → Save**). You don't have to translate everything at once.

Texts are grouped by *context* — the window or part of Crush they appear in. Some texts carry
a note below the English: for a parser message it is the message's code, for a format
knowledge text the format's name. The same English text can appear in two contexts and be
translated differently there.

### 5. Send it back

On GitHub (you need a free account):

1. Open [`crush/i18n/`](crush/i18n/) and choose **Add file → Upload files**. GitHub offers to
   make your own copy of the project ("fork") — accept.
2. Drop in your `crush_<code>.ts` (and `glossary_<code>.qph`, if you made one — see
   [Glossary](#glossary)).
3. Choose **Propose changes**, then **Create pull request**.

An automatic check then looks at every finished translation: placeholders, `%1`, HTML tags and
braces must be exactly as in the English (see [Rules](#rules)). If something is wrong, the
pull request shows which text — fix it in Qt Linguist and upload the file again the same way.

One language per pull request. Contributors are credited in the changelog.

### 6. See it in Crush

Once your pull request is merged, the next
[nightly build](https://github.com/kalink0/crush-forensics/releases/tag/nightly) contains your
translation. Start it with your language:

```
crush --language <code>
```

(Windows: `crush.exe --language <code>` in Command Prompt; macOS:
`open -a Crush --args --language <code>`.) Look around: text that is cut off, doesn't fit or
reads oddly is easiest to spot in the running program. Fixes go back the same way, step 5.

## Rules

- **Placeholders stay exactly as they are.** `{count:,}`, `{name}`, `{path}`, `%1` are filled
  in by Crush. Move them wherever your grammar needs them, but don't rename, translate,
  remove or add any, and keep the part after the colon (`{count:,}` stays `{count:,}`). A
  literal brace is written `{{` or `}}`.
- **HTML tags stay.** `<b>…</b>`, `<i>`, `<br>` — translate the text between them.
- **Keyboard shortcuts:** `&` marks the letter used with Alt (`&Open`). Put it on a letter of
  your translation; avoid two items in the same menu using the same letter.
- **Plurals:** Crush writes `file(s)` style or two separate sentences — translate each as it is.
- **Knowledge texts:** don't soften or strengthen a statement ("may contain" stays "may
  contain"). If you're not sure what a forensic statement means, leave it unfinished — an
  English sentence is better than a wrong one. Analysts can switch these texts back to the
  English original in Crush at any time, so they can check them.
- **Status values** in data views (`Active`, `Superseded`, `MISMATCH` …) may be translated or
  left in English, whichever analysts in your language expect — but use one choice throughout.

## Glossary

Some words must not be translated freely: names that have to stay English, and forensic
terms that must always be translated the same way. The glossary lists them. In Qt Linguist
(opened as a phrase book, step 4) it shows up by itself: whenever a text contains one of
these words, the **Phrases and Guesses** panel shows it with its rule.

There are two rules:

- **Do not translate** — leave the word in English, exactly as written. These are names:
  file formats (SQLite, Realm), operating systems (iOS, Windows), terms from a format's
  specification (WAL, BLOB, PRAGMA) and the names of Crush's own tools (Value Inspector,
  Multi-Log Studio). The panel offers the English word as it is.

  Example: "Open the BLOB Inspector" becomes in German "BLOB Inspector öffnen" — not
  "BLOB-Prüfer öffnen".

- **Translate, always the same way** — translate the word, but choose one translation and use
  it every time. Analysts must be able to tell that two messages are about the same thing.

  Example: if "carved" becomes "gecarvt" once, it is "gecarvt" everywhere — not
  "wiederhergestellt" in another place (that is the translation of "recovered", a different
  word in the glossary).

**Your language's choices:** keep the translations you chose for these words in a phrase book
of their own, `glossary_<code>.qph` (for German `glossary_de.qph`): **Phrases → New Phrase
Book…**, then add each word with **Phrases → Edit Phrase Book…**. Send it along with your
translation (step 5). Whoever works on your language next opens it too and sees your choices
while translating.

The glossary's source is [`crush/i18n/glossary.csv`](crush/i18n/glossary.csv) — the same list
in plain text, if you'd like to read it outside Qt Linguist.

## When your language appears in Crush

A language is offered under **View → Language** once at least **90 %** of its texts are
translated. Below that it can only be tried with `--language <code>`. English is used for
every text not translated yet.

## When Crush changes

Crush changes, and so do its texts. When an English text changes, its old translation no
longer matches, and that text is shown in English until it is translated again — so a
translation never describes something that has changed since. The files on GitHub are updated
with new and changed texts regularly; they appear as unfinished in Qt Linguist the next time
you download the file.

## For developers: working in a clone

With the repository cloned and set up ([CONTRIBUTING.md](CONTRIBUTING.md#development-setup)):

```
python scripts/i18n.py update --add <code>   # start a language
python scripts/i18n.py update                # add Crush's current texts to every catalog
python scripts/i18n.py check                 # placeholders, %1, HTML tags, braces
python scripts/i18n.py release               # compile; prints how much is translated
python -m crush --language <code>            # run Crush in that language
```

`release` leaves out any translation that fails `check` (that text is then shown in English)
and says which. Don't commit `.qm` files or `languages.json` — they are built from the
catalogs.
