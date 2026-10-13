### SQLite / Database Viewer

The table dropdown at the top switches between database tables, views, and seven always-shown generated analysis pages (plus WAL Frames, an eighth, when a `-wal` companion file is present). All generated entries are labelled `(generated)` to make clear they are computed by Crush rather than read directly from the database.

#### Generated views

**Summary (generated)** — the default view when a database is opened. Lists every table and view with its row count. The status line shows the full schema object count (tables, views, indexes, triggers) at a glance. Double-click any row to navigate directly to that table.

**DB Structure (generated)** — lists all schema objects (tables, views, indexes, triggers) with structural details:

| Object type | Info column |
|---|---|
| Table | Column list, e.g. `(id, name, created_at)` |
| View | Full `CREATE VIEW` SQL on one line |
| Index | `ON table (column, …)` — shows which table and columns are indexed |
| Trigger | First line of `CREATE TRIGGER …` |

**DB Info (generated)** — shows 9 PRAGMA settings in a three-column layout (Setting / Value / Description), styled after the *Edit Pragma* view of DB Browser for SQLite. Only PRAGMAs actually persisted in the SQLite file header are shown (`application_id`, `user_version`, `schema_version`, `encoding`, `page_size`, `page_count`, `freelist_count`, `journal_mode`, `auto_vacuum`) — most other PRAGMAs are per-connection settings that reset to the linked SQLite library's own default on every new connection, so displaying them would show Crush's own runtime environment rather than anything about the examined file's history. Enum values are decoded to their named constant (e.g. `2 — FULL` for `auto_vacuum`), booleans show as `1 — ON` / `0 — OFF`. When a WAL companion is present, six WAL forensic metrics appear at the top of this view before the PRAGMA list (see *WAL forensic analysis* below).

**WAL Frames (generated)** — appears when a `-wal` companion file is present. Shows a full frame inventory (Frame / Page / Transaction / Status / Table / Offset) with every frame classified by forensic status:

| Status | Colour | Meaning |
|---|---|---|
| **Active** | Default | Newest occurrence of this page within the last committed transaction — what SQLite currently reads |
| **Superseded** | Amber | An older version of a page that was later overwritten by a newer frame; may contain previously committed data |
| **Uncommitted** | Blue | Frames beyond the last commit marker, written during an incomplete transaction |
| **WAL slack** | Grey | Salt-mismatch frames from a previous WAL generation cycle (Sanderson's term); these pages predate the current WAL cycle and are not read by SQLite |

The **Table** column shows which database table owns each page, resolved by tracing the B-tree structure from `sqlite_master`. Double-click any frame row to open its raw page bytes in the hex viewer, labelled `WAL frame N — page M`.

#### WAL forensic analysis

When a `-wal` companion is present, Crush automatically reads and classifies every WAL frame. This gives the examiner three complementary views of any past database state:

1. **DB Info WAL summary** — six metrics (WAL file size, total frames, active / superseded / uncommitted / WAL-slack counts) with amber and blue highlights on non-zero forensic counts.
2. **WAL Frames inventory** — full frame list with table attribution and double-click raw page access (see above).
3. **Show WAL history toggle** — a **Show WAL history** checkbox appears in the table toolbar whenever the currently selected table has Superseded, Uncommitted, or WAL-slack frames in the WAL. When enabled:
   - A **WAL Source** column is added to the right of the table.
   - Rows decoded from historical WAL frames are appended below the current data, with the WAL Source cell identifying the frame status and frame number (e.g. `WAL Superseded (frame 3)`).
   - Row text is colour-coded: amber for Superseded, blue for Uncommitted, grey for WAL slack.
   - The row count label shows how many additional rows were recovered, e.g. `(42 rows)  +7 from WAL`.

This lets you answer questions such as: *what rows existed in this table before the last UPDATE or DELETE?* — without any specialist carving tool.

> **Tip:** An empty WAL history for a table does not mean the data was never modified — it only means there are no current non-Active frames for that table's pages. For a complete picture, also check the Superseded and Uncommitted counts in DB Info.

#### Freelist Recovery

Appears when `PRAGMA freelist_count` is greater than zero. SQLite doesn't zero a page's content when it's freed by `DELETE`/`DROP` — only when a later allocation actually reuses it — so a freed page can still hold its original table-leaf cells intact. This tab walks the freelist trunk chain and carves any leftover rows it finds.

Recovered rows show generic column headers (`col0`, `col1`, …) rather than the original column names — a freed page is no longer referenced by any table's B-tree, so the source table can't be determined with certainty. A **Candidate Tables** column lists every table whose column count matches, as a heuristic hint, not a definitive attribution. Values whose payload spilled onto overflow pages are reconstructed by following the overflow chain, but only through pages still confirmed unmodified on the freelist — a chain that steps onto a reused or trunk page (trunk pages are overwritten with the freelist's own bookkeeping the moment they become a trunk) is left as `<OVERFLOW>` rather than risk splicing in unrelated data. Double-click a row to open its raw page in the Hex Viewer.

#### Freeblocks

Always shown. Catches the far more common case Freelist Recovery can't: an ordinary single-row `DELETE` that never frees a whole page. SQLite splices the deleted cell into the page's own in-page freeblock list instead of zeroing it. Since the page is still part of a live table's B-tree, the **Table** column here is a definite match, not a heuristic guess. Cell content is shown raw rather than decoded into columns, since the freeblock's own 4-byte header overwrites the start of the original cell.

#### Unallocated Space

Always shown. Displays the raw bytes sitting in the gap between a page's cell-pointer array and its cell-content area, for manual review. Unlike Freeblocks, SQLite makes no guarantee anything meaningful survives here — it's often all-zero, or stale 2-byte pointer values left over from a shrunk pointer array, rather than recoverable row text. All-zero gaps aren't shown at all; only non-empty ones are, so you can judge each entry yourself.

Freeblocks and Unallocated Space rows can also be double-clicked to open that row's whole containing page as an isolated tab in the Hex Viewer, same as Freelist Recovery above.

#### Strings

Always shown. Lists every text run in the raw bytes of the database file and, when present, its `-wal` and `-journal` file — one row per run at its own offset: equal values are not merged, nothing is trimmed, and there is no cap on the number of rows. Each row shows the file, offset and length in bytes, encoding, page, the region its bytes sit in, and the value.

- **Encodings:** ASCII and UTF-8 (printable characters plus tab, LF and CR, and any well-formed multi-byte UTF-8 character; one row per run, labelled ASCII when it holds no multi-byte character), and UTF-16LE / UTF-16BE (only U+0020–U+007E and U+00A0–U+00FF plus tab, LF and CR, at even and odd offsets). Other scripts in UTF-16 are not found. The same bytes can show up both as a UTF-16LE run and, one byte shifted, as a UTF-16BE run; both are listed.
- **Min. length** (toolbar, default 4 characters) is a threshold: shorter runs exist in the file but are not listed. Changing it scans again.
- **Region** comes from the file format: in the database file the b-trees are walked from `sqlite_master`, overflow pages are the chains their cells point to, the freelist is its trunk chain, and pointer-map and lock-byte pages follow from the header and page size. On b-tree pages the area is named too: database header, page header, cell pointer array, unallocated, freeblock, cell content area, reserved bytes. In the `-wal`, the header and frame headers are their own regions, and a frame's page is labelled with its frame number and status; the frame the database currently reads a page from gets that page's role from the same walk with the `-wal` applied. A page copy no walk reaches — an older WAL frame, a journal record, an orphaned page — is labelled from its own b-tree type byte and marked **(type byte only)**. A string that runs across regions lists each of them.

With **Show Hex** on, selecting a row marks the string's bytes in its own file (switching between database, `-wal` and `-journal` file as needed), and clicking a byte inside a string selects its row. A file that can't be read, an empty companion file, or a chain that couldn't be followed is named in the status line above the table.

#### File Structure (generated)

Always shown. A physical, page-by-page view of the database file itself — header fields, B-tree page headers, cell-pointer arrays, individual cells, freeblocks, and unallocated space — independent of the logical table/row view the other generated pages give you. Each page's own row/column detail is decoded lazily, only the first time you expand it, so opening a database with many rows stays responsive instead of decoding everything up front. Selecting a structure item and the embedded Show Hex pane (see below) stay in sync in both directions.

There is no text/content search across the whole structure tree — full search would mean decoding every page up front, reintroducing the exact hang lazy loading exists to avoid, and searching only already-expanded pages would be a silently incomplete search, unacceptable for a forensic tool. To find specific content: run a SQL query against the table itself (works for any value, including numeric ones an on-disk byte search never can), use a cell's **Open in Hex** action, or search directly in the Hex pane below — hex search hits sync back into the structure tree the same way tree selections sync into hex.

#### Show Hex pane

The table view, WAL Frames, and File Structure pages all have a **Show Hex** toggle button that opens an embedded hex pane alongside the current view, bidirectionally synced with it: selecting a row/cell/structure item highlights its exact on-disk bytes, and clicking a highlighted byte in the hex pane selects the matching row/cell/item back.

- **Table view:** selecting a cell highlights its whole row (pale) and that column's own bytes (stronger, drawn on top). A row or value that spans overflow pages is highlighted on every page, all pieces of it in the same colour. A row whose current version is only in a not-yet-checkpointed `-wal` frame switches the pane to that file instead of the base file's stale bytes. A **Show WAL history** row (see above) gets the same column-precise treatment, keyed by its own frame bytes rather than a rowid.
- **WAL Frames:** selecting a frame highlights its exact header+page bytes in the `-wal` file.
- **Strings:** selecting a row highlights the string's exact bytes in its own file.
- **File Structure:** selecting any structure item — a header field, a page, a cell, a freeblock, an unallocated-space gap — highlights its exact bytes (a column value on overflow pages on every page, in one colour), across whichever of the base file or `-wal` file it actually lives in.

Freelist Recovery does not have the embedded Show Hex pane (its rows use double-click to open the whole containing page in an isolated tab instead, see above).

#### SQL bar

The SQL bar below the toolbar accepts any `SELECT`, `WITH`, or `PRAGMA` statement.

| Action | How |
|---|---|
| Execute query | Click **Run** or press **F5** |
| Execute selected text only | Highlight a fragment in the SQL editor and press **F5** or click **Run** — only the selection is sent |
| Syntax highlighting | Keywords, strings, numbers, and comments are highlighted; colours adapt to the active light/dark theme |
| Autocomplete | Press **Tab** or **Ctrl+Space** — table and view names are suggested after `FROM`/`JOIN`; column names are suggested after `table.` dot notation; aliases are resolved automatically |
| Resize SQL vs. results | Drag the splitter between the SQL editor and the results table |

Status feedback appears below the input field: red on error (with the error message), default colour on success.

#### Table controls

| Control | Action |
|---|---|
| **Table** dropdown | Switch between tables, views, and generated pages |
| **Search** field | Filter visible rows — matches any column |
| **Show WAL history** | Reveal historical rows from WAL frames (shown only when WAL data is available for the current table) |
| **Run / F5** | Execute the SQL query |
| **Export CSV…** | Export the current view (filtered or query result) to a CSV file |

**Row limit notice:** if a table has more rows than the display limit, a notice appears in the row count. Use a SQL query with `LIMIT` / `WHERE` to load a specific subset.

**Timestamp column decoding:** right-click any column header to decode its values as timestamps — including numbers stored as text (`'1713884690406'`; only plain decimal numbers, nothing else is guessed). Choose a format from the **Decode column as timestamp** submenu, grouped into Unix, Apple, Windows and Other:

| Format | Value | Epoch / layout |
|---|---|---|
| Unix — seconds / milliseconds / microseconds | number | 1970-01-01 |
| Cocoa / Mac Absolute Time — seconds / nanoseconds | number | 2001-01-01 |
| HFS+ — seconds | number | 1904-01-01 |
| Windows FILETIME — 100 ns | number | 1601-01-01 |
| Windows SYSTEMTIME | BLOB or hex text, 16 bytes | 8 little-endian WORDs: year, month, day of week, day, hour, minute, second, ms |
| .NET Ticks — 100 ns | number | 0001-01-01 |
| OLE Automation Date — days | number | 1899-12-30; the fraction is the time of day, also for negative values |
| FAT / exFAT (MS-DOS) | integer | 32-bit packed: date word high, time word low, 2 s resolution |
| Chrome / WebKit — µs | number | 1601-01-01 |
| Twitter / X Snowflake ID | integer | upper 42 bits: ms since 2010-11-04 01:42:54.657 UTC |
| UUID v1 | UUID text, or 16-byte BLOB in RFC 9562 (big-endian) order | 100 ns since 1582-10-15 |
| BCD | BLOB or hex text, 7 bytes | `YYYY MM DD HH mm SS`, two decimal digits per byte |

Every timestamp format of the [Value Inspector](value-inspector.md) is offered except GPS time. No plausibility window is applied: whatever the chosen format can represent is decoded.

Values are displayed as `YYYY-MM-DD HH:MM:SS[.fraction] UTC`. The conversion is exact — integers stay integers and decimals are read digit for digit — and the fraction shows every sub-second digit the value carries (e.g. `.1234567` for a FILETIME, `.5` for 500 ms), none for a whole second. The column header shows the active format as a suffix (e.g. `created_at [unix ms]`). Sorting remains chronologically correct. A cell that can't be decoded (non-numeric text, a value out of range for the chosen format, a BLOB of the wrong length, invalid date fields, a UUID that isn't version 1) is shown as stored, in orange, with the reason in its tooltip; the header tooltip says how many values were affected, and the header reads `[… : none decodable]` if nothing in the column decoded. Empty and `NULL` cells are left alone, and so are BLOB cells under a number format. Select **Clear timestamp format** to revert to the raw values.

**Timestamp as SQL:** once a column is decoded, **Copy as SQL expression** in the same header menu copies the bare conversion of that column for use in your own `SELECT` — plain SQLite, so it also runs in other SQLite tools. For a Unix-milliseconds column `created` it is `datetime("created" / 1000, 'unixepoch') || rtrim(printf('.%03d', "created" % 1000), '.0')`. It gives `YYYY-MM-DD HH:MM:SS[.fraction]` without a time zone, with every sub-second digit of an integer value, and is available for the Unix, Cocoa, HFS+, FILETIME, .NET Ticks, Chrome / WebKit, FAT and Snowflake formats and BCD. It has no per-row checks: it is exact for INTEGER values (and plain-digit text) — not negative ones for formats with sub-second units — and for BCD for 7-byte BLOBs. A REAL value loses its fraction, and other values give a wrong date or NULL; when copying, Crush says how many values of the column that applies to. OLE Automation Date, SYSTEMTIME and UUID v1 have no plain-SQLite conversion; the menu entry is greyed out for them, with the reason in its tooltip.

**Cell inspection:** right-click any cell for options including:
- **Inspect Cell…** — preview the raw value, attempt base64/plist/XML decode
- **Open in Hex** — view cell bytes as hex
- **Open as new tab** — submenu: **Auto-detect** (best-guess parser, e.g. a plist stored inside a SQLite column), or force **Hex** / **Text** / **Protobuf**. Each cell opens in its own tab — opening several cells from the same column (or from different rows of an ad-hoc SQL query) never collides into one shared tab. The tab tooltip and Properties panel show where the artifact came from: source table or full query text, column, row, and the originating database file
- **Export…** — save the cell value to disk
- **Copy cell / Copy row / Copy selection**

