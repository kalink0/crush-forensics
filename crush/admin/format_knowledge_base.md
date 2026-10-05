# Format Knowledge Base — Admin Guide

## Overview

Crush maintains a bundled format knowledge base that identifies file formats and surfaces forensic context in the UI — even for formats that have no parser yet.

There is **one source of truth**: `crush/data/build_formats_db.py`.
Everything else is generated from it.

```
crush/data/build_formats_db.py   ← edit this
crush/data/formats.db            ← generated artifact (commit both)
crush/core/format_db.py          ← runtime wrapper (do not edit for data changes)
scripts/build_format_pages.py    ← format reference site on GitHub Pages (generated in CI)
```

---

## Adding or Editing a Format

Open `crush/data/build_formats_db.py` and find the `FORMATS` list. Each entry is a plain Python dict:

```python
{
    "name": "SQLite Database",           # Full human-readable name shown in UI
    "short_name": "SQLite",              # Abbreviation; permanent site address, never change
    "category": "database",             # See Categories below
    "forensic_relevance": "...",         # What an investigator finds here
    "platforms": ["iOS", "macOS", "Android"],  # List of platform strings
    "parser_class": "SQLiteParser",     # Class name in crush/parsers/, or None
    "magic": [
        {"offset": 0, "value": b"SQLite format 3\x00", "description": "SQLite header"},
    ],
    "extensions": [".db", ".sqlite"],   # Lowercase with dot (currently not used for identification)
    "links": [("Format spec", "https://...")],  # List of (label, url) tuples
    "status": "reviewed",              # "draft" (not in formats.db) or "reviewed"
},
```

After editing, regenerate the database:

```bash
python -m crush.data.build_formats_db
```

Commit **both** `build_formats_db.py` and `formats.db`.

---

## Fields Reference

| Field | Required | Notes |
|---|---|---|
| `name` | Yes | Shown in Properties panel and Format Reference dialog |
| `short_name` | Yes | Abbreviation for compact display, and the format's permanent address on the format reference site (`/formats/<short_name in lower case, other characters as ->/`). **Never change it once published**: links to the old address break. A new format adds its address to `scripts/format_pages/published_slugs.txt` (`test_format_pages` checks the list). |
| `category` | No | See Categories below |
| `forensic_relevance` | No | Shown in Properties panel — explain what an analyst finds here |
| `platforms` | No | List of strings from `PLATFORMS`: `"Windows"`, `"macOS"`, `"Linux"`, `"iOS"`, `"Android"`, `"QNX"` (stored in that order); `ALL_PLATFORMS` for a format not tied to any operating system |
| `parser_class` | No | Class name of the Crush parser, e.g. `"SQLiteParser"`. `None` = unsupported |
| `magic` | No | List of `{"offset": int | None, "value": bytes, "description": str}`. Each entry is checked on its own: every matching entry adds its length to the format's score (see [How Identification Works at Runtime](#how-identification-works-at-runtime)). Use `offset: None` for trailer/unknown offsets, a signature another entry shares, or one too short to identify the format on its own (informational only, never matched; the description says why). |
| `extensions` | No | Extension metadata (not used for identification). Lowercase, include the dot |
| `links` | No | List of `(label, url)` tuples — opened from Format Info and Format Reference dialogs |
| `status` | Yes | `"draft"`: compiled from a brief web search (search engine or AI-assisted), nothing more; not in formats.db, published on the format reference site marked as draft. `"reviewed"`: checked manually — sources verified and refined; signatures and structural details checked against the specification where one exists, for undocumented formats against published reverse-engineering research and own research; practical knowledge from casework and the DFIR community; in formats.db. |

### Categories

| Value | Used for |
|---|---|
| `database` | SQLite, LevelDB, Core Data |
| `configuration` | Plists, settings, structured configs |
| `log` | Unified Log, SEGB/Biome, EVTX, crash reports |
| `execution` | DEX, OAT, Mach-O, ELF, binaries |
| `document` | PDF, Office, text documents |
| `filesystem` | Filesystem metadata, catalog formats |
| `disk_image` | DMG, sparse images, raw images |
| `archive` | ZIP, TAR, backup containers |
| `serialization` | Protobuf, MessagePack, CBOR |
| `memory` | Memory dumps, hibernation |
| `network` | PCAP and network traces |
| `uncategorized` | Anything else / TBD |

---

## Adding a Format with No Parser

If you want Crush to identify a file and show forensic context without parsing it, set `parser_class: None`. The hex fallback will show the format name, platforms, and forensic relevance in the Properties panel automatically.

```python
{
    "name": "Apple Unified Log (tracev3)",
    "short_name": "tracev3",
    "category": "log",
    "forensic_relevance": "System and app logs since iOS 10 ...",
    "platforms": ["iOS", "macOS"],
    "parser_class": None,
    "magic": [
        {"offset": 0, "value": b"\x30\x74\x72\x33", "description": "tracev3 magic"},
    ],
    "extensions": [".tracev3"],
    "links": [("Source code", "https://github.com/mandiant/macos-UnifiedLogs")],
},
```

---

## Adding a Format with a New Parser

1. Write the parser in `crush/parsers/your_parser.py` (subclass `AbstractParser`)
2. Register it in `crush/parsers/__init__.py`
3. Add an entry to `FORMATS` in `build_formats_db.py` with `"parser_class": "YourParser"`
4. Run `python -m crush.data.build_formats_db`

The parser carries **no metadata** — all format knowledge lives in `build_formats_db.py`.

---

## Upgrading an Unsupported Format to Supported

Find the existing entry and set `parser_class` to the new parser class name:

```python
# Before
"parser_class": None,

# After
"parser_class": "TraceV3Parser",
```

Then rebuild the DB. No other files need to change.

---

## How Identification Works at Runtime

1. **Magic bytes** — every `{"offset", "value"}` entry that matches adds its length to its format's score; the highest score wins (`FormatDatabase.identify()`). Entries with `offset: None` are informational and never matched. When several formats share the top score, no format is chosen: the Properties panel and Format Info list the tied candidates instead.
2. **Parser class lookup** — when a file is successfully parsed, `FormatDatabase.for_parser()` looks up the format by the parser's class name. A parser that reads several formats (e.g. `ImageParser`, `MediaParser`) has one entry per format; the magic bytes then pick among those entries only, and when they don't single one out, the candidates are listed instead of one entry's knowledge.

Every format with a matchable signature must be identified as itself (`test_every_format_identifies_itself` in `crush/tests/test_format_db.py`). A signature that two entries share therefore belongs to one entry only, or is `offset: None` in both, with the reason in its description.

For **unsupported files** (handled by `HexFallbackParser`), magic identification runs and the result is shown in the Properties panel alongside the raw hex view.

---

## Realm Notes

Realm files expose a 24-byte header in unencrypted files. The mnemonic signature
`T-DB` lives at offset 16 (bytes `54 2D 44 42`). Encrypted Realm files may not
expose this mnemonic, so `RealmParser.can_parse` also accepts the `.realm`
extension as a fallback. That fallback is in the parser only: formats.db
identification never uses extensions.

---

## Format Reference Dialog

**Help → Format Reference…** opens a searchable table of all formats in `formats.db`.

- Supported formats (with a parser) are shown in normal text.
- Unsupported formats are shown in grey.
- Selecting a row and clicking **View Details…** (or double-clicking it) opens the Format Info dialog for that format, with its signatures and its `links` as clickable references.

---

## Format Reference Site

`scripts/build_format_pages.py` publishes every entry of `FORMATS` on GitHub
Pages at <https://kalink0.github.io/crush-forensics/formats/>: one page per
format, an overview with filter and signature lookup, `formats.json` and
`formats.db`. It reads the entries through `entry()`, the same normalisation
`build()` writes to formats.db, and shows the texts unchanged. Drafts are
included and marked.

`.github/workflows/pages.yml` rebuilds it with every build (nightly or
release), so it shows the state of the latest build. Each page names the
commit it was built from. Build it locally with:

```bash
python scripts/build_format_pages.py --out site --commit "$(git rev-parse HEAD)"
```
