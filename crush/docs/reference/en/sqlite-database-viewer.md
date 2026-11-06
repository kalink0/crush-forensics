### SQLite / Database Viewer

The table dropdown at the top switches between database tables, views, and seven always-shown generated analysis pages (plus WAL Frames, an eighth, when a `-wal` companion file is present, and the Core Data views for a [Core Data store](#core-data-stores)). All generated entries are labelled `(generated)` to make clear they are computed by Crush rather than read directly from the database.

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

#### Core Data stores

An Apple Core Data store is an SQLite file with tables Crush recognises by their content: `Z_PRIMARYKEY` (`Z_ENT`, `Z_NAME`, `Z_SUPER`, `Z_MAX`) and `Z_METADATA` (`Z_VERSION`, `Z_UUID`, `Z_PLIST`), whatever the file is called. With both, six more generated views appear in the table list; with only part of them, the Properties panel's **Core Data** row names what is missing and no Core Data view is offered. Every plain table, SQL result and existing view stays exactly as stored. The views read the same database state the table grid shows: `-wal` applied, the rollback-recovered state, SQLCipher with the key it was opened with.

Apple does not document this storage layout. Crush's interpretation is based on observed stores (iOS extractions), not on a specification. A failure in this layer never stops the SQLite view itself. The Properties panel shows the Core Data Store format knowledge, with SQLite as its base format; **Open Format Info…** shows Core Data for a store that is open, and SQLite for one that isn't (it doesn't open the database to find out).

**Heuristics.** Some links in these views are not stored in the file but follow a naming convention or an order seen in real stores. Each one is marked `heuristic` where it applies — in the row, or in the column header when it applies to a whole grid column — and the stored value it rests on is next to it, so it can be checked:

| Where | Heuristic | Stored value next to it |
|---|---|---|
| Entities, Model | Property-to-column link by name: Z + uppercase property name. **heuristic: name match** means one such column and no numbered sibling; only then are values decoded by model type. **ambiguous** lists every candidate (`ZMAXIMUMVALUE`, `ZMAXIMUMVALUE1`) and chooses none; **no column found** says so. | the column, its raw value |
| Entities, Model, Keys | Entity-to-table link, one rule: A + uppercase root entity name for Core Data's own entities, by their exact `Z_NAME` (`CHANGE`, `TRANSACTION`, `TRANSACTIONSTRING`, `NSCK*`); Z + uppercase name for every other. Shown as `ZASSET (heuristic)`. No other table is taken in its place: when that table is missing, the entity shows no rows and its status says so, naming the other prefix's table when it exists (its rows stay in that plain table). The History view reads only `A` tables. | the table |
| Entities | Relationship link: the to-one column (`Z<n>_<NAME>` holding the target's `Z_ENT`), the inverse to-one column, a join table `Z_<entity number><NAME>`, or a destination column `Z<entity number><NAME>`, ordered by its `Z_FOK_` column (`Z_FOK_2ACTIONS` for `Z2ACTIONS`). Shown as `heuristic: <column or table>`. An ordered relationship without an order column says its order is not the stored one. A relationship no rule resolves shows no link: candidates in the record's own row with their values, candidates in another table by name and table only (seen: numbered column collisions between subentities, reflexive join tables). A relationship the model stores no destination entity for says so (seen in TipKit stores). | the stored key, the join table |
| Entities, History | A date read from `ATRANSACTION.ZTIMESTAMP`, which is declared `FLOAT`: Cocoa seconds by its observed values. Columns declared `TIMESTAMP` are read as Cocoa seconds without this mark. | the stored number |
| History | Tombstone slot to attribute: the entity's attributes flagged for tombstones (`NSFlagsKey` 16, inherited ones included) in alphabetical order of their names. Shown as `uuid = 7B08… (heuristic)`; a slot whose value doesn't fit, or that lies beyond the list, stays unassigned with all candidates. A 16-byte value is shown as a UUID only when its attribute is a UUID; any other bytes as hex. | every raw `ZTOMBSTONE` column |
| History | `ZCOLUMNS` set bits: numbered byte × 8 + bit, least significant bit first — an assumed order. What a bit stands for is unknown. | `ZCOLUMNS` as stored (hex) |
| External Data, cell menu | Reference to an externally stored value by its byte pattern (exactly 38 bytes, `0x02` + 36-character UUID + `0x00`), the `0x01` prefix of an inline value, and the folder name `.<store name without extension>_SUPPORT`. | the raw cell |

For important findings, check the raw values.

- **Core Data Entities (generated)** — the entities of `Z_PRIMARYKEY` as a tree (subentities nested under their parent, each with the rows it shows, or why they couldn't be counted), every entity included: Core Data's own history entities, CloudKit `NSCK*` entities and any other entity not in the model are listed with the status *not in the model* and shown with their column names and declared types. A root entity shows every row of its table, a parent its own rows and those of its subentities; the **entity [derived]** column names each row's concrete entity from its `Z_ENT`. Every column of the table is shown as stored, named after the property it is linked to. A date, boolean or UUID column also gets a decoded column before it (marked *[derived]*): a column declared `TIMESTAMP` (and `ATRANSACTION.ZTIMESTAMP`) as Cocoa seconds in UTC, a boolean 0/1 as false/true, a 16-byte UUID as its canonical text — anything that doesn't fit stays as stored with a status, and a stored 0 is marked as the Cocoa reference date itself. There is no row limit. The detail pane below lists the selected record's properties by model type with their stored value and column, every other column of the row (`Z_ENT`, `Z_OPT`, a to-one link's entity column, columns no property names), and its relationships; an ambiguous property lists each candidate column with its own stored value. The **Stored** column shows the value as stored, a BLOB longer than 16 bytes as a labelled preview; double-click the row to inspect all of its bytes (the provenance names the SQL column). The pane keeps showing its record when a search hides it or clears the selection; following a relationship and **Back** start from that record. Double-click a related object to select it (**Back** returns). A target row that doesn't exist is shown as such. Sorting, search, CSV export, the cell actions and Show Hex work as in a table; the row count reads *3 of 5,000 rows* while the search filters. A decoded cell opens in a tab of its own, not in the stored value's. When the records can't be read, the grid is empty and the status line says which read failed. A jump to a record the search hides clears the search and shows it.
  - The view holds the current rows only; deleted data can be in the History view (tombstones) and in WAL Frames, Freelist Recovery, Freeblocks and Unallocated Space.
- **Core Data Store (generated)** — `Z_VERSION`, `Z_UUID` and every key of `Z_PLIST` with its value (nothing filtered, app-set keys included), the model's status, the persistent history's status and the external-data folder's status.
- **Core Data Model (generated)** — one row per property as each entity lists it (inherited ones included, also when the model lists them through a proxy object): entity, `Z_ENT`, superentity, root table, property, the entity that declares it, kind, class, type name and number, value class, transformer, raw flags, the column candidates with their declared SQL types and mapping status, and for relationships destination, inverse, min/max count, delete rule, ordering and the rule that resolves it. Selecting a row shows every key the property, its entity and the model store (fetch indexes, compound indexes, user info, version hashes, renaming identifiers, ...). A class Crush doesn't know keeps its row, with its class name. The model comes from `Z_MODELCACHE`; without it (or when it can't be read) this view says why.
- **Core Data History (generated)** — only when the store has persistent history tables. One row per change, no limit: transaction, time (UTC, with the stored value), author, bundle ID, process and context resolved through `ATRANSACTIONSTRING` next to the stored references, change type, entity number and name, primary key, whether the object exists in the current database state (*unknown* when its table can't be read), `ZCOLUMNS` as stored with its set bit numbers, and the tombstones with every raw `ZTOMBSTONE` column (see Heuristics above). A change whose transaction row is missing, a string reference with no name and a change type other than 0–2 say so in the derived cell. Rows have no byte location: with Show Hex on, nothing is highlighted. Double-click a change to show its object in Core Data Entities. A store without history, or with an empty history, says so in Core Data Store — history can be purged, so that doesn't mean nothing changed.
- **Core Data Keys (generated)** — per root entity: `Z_MAX`, row count, lowest and highest `Z_PK`, how many keys below the highest are missing (and which), and `Z_MAX` minus the highest key. These are facts; what caused missing keys (deletion, migration, an app's own cleanup) is not determined by them. A `Z_PK` that isn't an integer is counted as a row and named in the status, not as a key.
- **Core Data External Data (generated)** — always shown for a store. Every row of every table is scanned for a reference to an externally stored value by its byte pattern, in any column (the model's external-storage flag is shown next to it, not required). Each reference shows its table, column, `Z_PK`, `Z_ENT`, UUID, the raw cell and whether its file in `.<store name without extension>_SUPPORT/_EXTERNAL_DATA/` next to the store was found, with its path, size and content type by its bytes. The folder is looked for in the source; only for a store file opened on its own also next to it on disk — never on the examiner's machine for a path inside an archive or image. A folder that can't be listed is listed with the reason, and a reference whose file would be in it reads *unknown*, not *not found*. Every other file in the `_SUPPORT` folder is listed too: one in `_EXTERNAL_DATA` that no reference names as *no reference in the current database state*, others (such as `_FBF`) as found. A `0x02` value of another shape in an external-storage column is listed as *unrecognised shape*. When the source doesn't hold the store's folder (a store file opened on its own), the view says the folder is not available in this source — that says nothing about whether the files exist. Double-click a row with a file to open it in a new tab, with store, table, `Z_PK`, UUID and path as provenance.

In a store's plain tables, a `Z_ENT` cell shows the entity name as its tooltip, and the cell menu gains **Open external file** on a reference cell and **Open without the 0x01 prefix** on a value starting with `0x01` in a column of an attribute flagged for external storage (an inline value: the content starts at byte 1). The opened tab's provenance says the first byte was removed and from which cell; the cell itself is unchanged.

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
- **Open as new tab** — submenu: **Auto-detect** (best-guess parser, e.g. a plist stored inside a SQLite column), or force **Hex** / **Text** / **Protobuf** / **FlatBuffers**. Each cell opens in its own tab — opening several cells from the same column (or from different rows of an ad-hoc SQL query) never collides into one shared tab. The tab tooltip and Properties panel show where the artifact came from: source table or full query text, column, row, and the originating database file
- **Export…** — save the cell value to disk
- **Copy cell / Copy row / Copy selection**

