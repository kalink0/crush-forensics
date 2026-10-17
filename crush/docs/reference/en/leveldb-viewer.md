### LevelDB Viewer

Opens LevelDB database directories (used by Chrome, Android apps, and iOS apps) in a tabbed viewer.

**RocksDB** (a fork of LevelDB) uses the same file names but other table, log and MANIFEST formats. A directory is recognised as RocksDB by its contents — an `OPTIONS-…` file naming a RocksDB version, a table file ending in a RocksDB table magic, or a MANIFEST tag only RocksDB writes, in a record whose stored checksum matches (a damaged record can hold any number) — and is then not read: the Overview says so, lists what showed it is RocksDB, and lists every file. A MANIFEST tag that neither defines stops reading that MANIFEST at that point, with its offset and whether its record's checksum matches.

**Overview tab** — MANIFEST metadata for the database:
- All `MANIFEST-*` files in the directory are parsed; the active one (pointed to by `CURRENT`) is labelled *(current)* and gives the Files tab its levels, sizes and key ranges. Older manifests expose compaction history from before the last recovery and may reference file numbers no longer on disk. A MANIFEST numbered higher than the one `CURRENT` names (LevelDB writes a new MANIFEST before it switches `CURRENT` to it) is marked as such.
- **CURRENT** — the MANIFEST it names. When `CURRENT` is missing, can't be read, doesn't name a MANIFEST, or names one that isn't there or can't be read, no MANIFEST is labelled *(current)* and files have no level; the entry says why. A `CURRENT` without the line break LevelDB requires at its end is still followed; both it and the MANIFEST it names say that LevelDB treats it as corrupt.
- Comparator name, last sequence number, log number, and prev log number (when present). A MANIFEST that records none of these and no files (or is empty) is still listed, with a note.
- Files grouped by compaction level, as the MANIFEST's edits leave them: a file a later edit deleted (e.g. compacted away) is no longer listed on its old level; the compaction history still shows both edits.
- **Read problems** — every file that could not be opened or read to its end, or holds records whose stored checksum doesn't match, with the reason (and, for one that stopped partway, after how many records). Each file is read on its own: one damaged file doesn't hide the others' records, and the records read from it before the failure are shown. In a `.log`, a damaged part (an unknown record type, a record part without its start or end, a length past its block or the file) is skipped and reading goes on after it, as LevelDB itself reads a log; each skipped part is listed with its offset — including those LevelDB drops without a word, such as a record the writer didn't finish before the file ends. Every `.log` record's and MANIFEST edit's stored checksum is checked: one that doesn't match is kept (LevelDB wouldn't apply it), marked in the Records tab's **Checksum** column or counted in the MANIFEST's **Checksum** entry with its offsets. The Properties panel's **Parse warning** says how many data files and records were affected.

**Files tab** — one row per data file (`.ldb` / `.sst`) and WAL log file that could be opened, including one that holds no records:

| Column | Content |
|---|---|
| Filename | File name in the database directory |
| Type | `Ldb` / `Log` |
| Level | Compaction level (data files only) |
| Size (B) | On-disk size from the MANIFEST (`—` for log files) |
| Smallest Key / Largest Key (text) / (hex) | Inclusive key-range boundaries: the user key as UTF-8 text (empty when it isn't valid UTF-8) and as hex, in separate columns |
| Note | A key-range boundary shorter than the 8-byte sequence/type tag every internal key ends with: not a valid internal key, shown as stored |
| Live / Deleted / Unknown | Record counts; rows with deleted records are highlighted red |

**Records tab** — all records across all files in a single table. Deleted records are shown inline in red alongside live records so the examiner sees the full write history.

| Column | Content |
|---|---|
| File | Source file |
| Seq | LevelDB sequence number |
| Type | `Live`, `Deleted`, or `Unknown` |
| Offset | Byte offset of the record within the source file (hex): for a `.log` record its type byte, for a record of an uncompressed table block its entry; for a record of a compressed table block the block's offset, shared by all its records |
| User Key (text) / (hex) | Key decoded as UTF-8 and as hex |
| Value (text) / (hex) | Value decoded as UTF-8 and as hex. A key or value that isn't text shows `<binary N B>` in its text column; sorting a text column puts these together, ordered by size |
| Internal Key (hex) | Full internal key (user key + 8-byte sequence/type suffix) for `.ldb`/`.sst` records |
| Checksum | For a `.log` record, whether its stored checksum matches (*matches* / *doesn't match*); *not checked* for `.ldb`/`.sst` records, whose block checksums aren't checked |

Toolbar controls:

| Control | Action |
|---|---|
| **All / Live / Deleted / Unknown** | Filter records by state |
| **Search** | Case-insensitive filter across all columns; combines with the state filter |
| **Export CSV…** | Save currently visible rows to a UTF-8 CSV file; includes full-length hex columns and the Internal Key |

Selecting a row fills the tabbed hex pane below the table:

| Tab | Content |
|---|---|
| **In file** | The record's whole source file, with the record's parts highlighted where they are stored. A label above names each highlighted part with its offsets and size. For a `.log` record: the entry, its batch's header (sequence number and count, shared by the batch's records), type, user key and value — a part that crosses a log block boundary is highlighted in each of its pieces, in one color. For a record of an uncompressed table block: the entry, user key, tag (8-byte sequence/type) and value; a key's first bytes that are prefix-compressed against the keys before it are stored in earlier entries and highlighted there. For a record of a **compressed** (Snappy) block, the record's own bytes exist only after decompression and can't be pointed at in the file: the whole compressed block and its trailer are highlighted, and the label says so and how many records were read from the block |
| **Decompressed block** | For a record of a compressed table block only: the block after Snappy decompression, labelled as derived, with the record's parts highlighted; offsets there are in the decompressed block, not in the file. For other records it says why there is nothing to show |
| **Key** / **Value** / **Internal Key** | The decoded bytes on their own; *Internal Key* is the full internal key for `.ldb`/`.sst` records |

Right-click any record row to open the [BLOB Inspector](blob-inspector.md) for the key, value, or internal key of that record.

**LOG tabs** — if `LOG` or `LOG.old` files exist in the directory, each gets a dedicated read-only tab showing the complete file content with a *Find* toolbar.

